# authentik/providers/saml/resolve.py
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from authentik.crypto.models import CertificateKeyPair
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLProvider
from authentik.sources.saml.processors.constants import NS_MAP, NS_SAML_ASSERTION, NS_SAML_PROTOCOL

ERROR_ACS_URL_MISMATCH = "AssertionConsumerServiceURL does not match configured ACS URL"
ERROR_BINDING_MISMATCH = "ProtocolBinding does not match configured binding"

def find_first_element(root, qnames: Iterable[str]):
    """Return the first matching direct child element for any QName in order.

    Works with ElementTree/defusedxml elements (duck-typed: .find).
    Returns None if no element matches.
    """
    for qname in qnames:
        el = root.find(qname)
        if el is not None:
            return el
    return None

def find_first_text(root, qnames: Iterable[str]) -> str | None:
    """Return .text of the first matching direct child element for any QName in order.

    Works with ElementTree/defusedxml elements (duck-typed: .find).
    Returns None if no element matches or text is empty/blank.
    """
    for qname in qnames:
        el = root.find(qname)
        if el is None:
            continue
        text = el.text
        if text is None:
            continue
        text = text.strip()
        if text:
            return text
    return None

def _resolve_kp_with_override(
    local_obj: Any,
    *,
    override_attr: str,  # e.g. "verification_kp_override"
    kp_attr: str,        # e.g. "verification_kp"
    fallback_kp: CertificateKeyPair | None,
) -> CertificateKeyPair | None:
    if local_obj is None:
        return fallback_kp
    if getattr(local_obj, override_attr, False):
        return getattr(local_obj, kp_attr, None)  # may be None => disabled
    return fallback_kp
@dataclass(slots=True)
class ResolvedRequestTarget:
    """Resolved target runtime values for an incoming AuthnRequest/LogoutRequest."""

    sp: object | None
    acs_url: str | None
    sp_binding: str | None

def _norm(v):
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return v

def _pick(sp, provider, attr: str):
    sv = _norm(getattr(sp, attr, None)) if sp is not None else None
    return sv if sv is not None else _norm(getattr(provider, attr, None))

def _norm_str(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None

def resolve_request_target(
    provider: SAMLProvider,
    sp,  # SAMLSP | None (duck-typed for now)
    *,
    request_acs_url: str | None = None,
    request_sp_binding: str | None = None,
) -> ResolvedRequestTarget:
    """Resolve request target values from provider/SP config plus request attributes.

    Assumptions:
    - `sp` is already resolved from issuer (or None if unmatched).
    - strict ACS behavior is controlled by provider.strict_acs_url (default True).
    - binding mismatch is treated as non-fatal unless you choose to enforce it.

    Resolution policy:
    - If SP exists, target ACS/binding defaults come from SP.
    - Else, defaults come from provider.
    - If request ACS is present:
        - strict mode: must match resolved configured ACS
        - soft mode: request ACS wins
    - If request ACS is absent: configured ACS is used
    - If request binding is present:
        - If it mismatches configured binding, currently request binding is accepted
          (compatibility-oriented). Change this to raise if you want strict enforcement.
    """
    request_acs_url = _norm_str(request_acs_url)
    request_sp_binding = _norm_str(request_sp_binding)

    configured_acs = _norm_str(getattr(sp, "acs_url", None)) if sp else _norm_str(provider.acs_url)
    configured_sp_binding = (
        _norm_str(getattr(sp, "sp_binding", None)) if sp else _norm_str(getattr(provider, "sp_binding", None))
    )

    strict_acs = bool(getattr(provider, "strict_acs_url", True))

    # ACS resolution
    if request_acs_url:
        if strict_acs:
            # In strict mode, request ACS must match configured ACS (if configured exists)
            if configured_acs and request_acs_url != configured_acs:
                raise CannotHandleAssertion(ERROR_ACS_URL_MISMATCH)
            acs_url = request_acs_url
        else:
            # In soft mode, request ACS overrides config
            acs_url = request_acs_url
    else:
        # No ACS in request: fallback to configured target ACS
        acs_url = configured_acs

    # Binding resolution
    # Compatibility-first behavior:
    # - If request binding exists, accept it (even if mismatch), but prefer configured when absent.
    # If you want strict enforcement, swap the mismatch branch to raise.
    if request_sp_binding:
        if configured_sp_binding and request_sp_binding != configured_sp_binding:
            # Optional strict behavior:
            # raise CannotHandleAssertion(ERROR_BINDING_MISMATCH)
            sp_binding = request_sp_binding
        else:
            sp_binding = request_sp_binding
    else:
        sp_binding = configured_sp_binding

    return ResolvedRequestTarget(
        sp=sp,
        acs_url=acs_url,
        sp_binding=sp_binding,
    )

@dataclass(slots=True)
class SAMLSPRuntimeConfig:
    sp: object | None

    # target (request-aware)
    acs_url: str | None
    sp_binding: str | None

    # provider/SP resolved runtime
    sls_url: str | None
    sls_binding: str | None
    logout_method: str | None

    digest_algorithm: str
    signature_algorithm: str

    verification_kp: CertificateKeyPair | None
    signing_kp: CertificateKeyPair | None
    encryption_kp: CertificateKeyPair | None

    property_mappings: object


def build_samlsp_config(provider: SAMLProvider, sp=None, *, target=None) -> SAMLSPRuntimeConfig:
    target_sp = sp
    if target is not None and getattr(target, "sp", None) is not None:
        target_sp = target.sp

    if target is not None:
        acs_url = target.acs_url
        sp_binding = target.sp_binding
    else:
        acs_url = _pick(target_sp, provider, "acs_url")
        sp_binding = _pick(target_sp, provider, "sp_binding")

    verification_kp = _resolve_kp_with_override(
        target_sp,
        override_attr="verification_kp_override",
        kp_attr="verification_kp",
        fallback_kp=getattr(provider, "verification_kp", None),
    )
    signing_kp = _resolve_kp_with_override(
        target_sp,
        override_attr="signing_kp_override",
        kp_attr="signing_kp",
        fallback_kp=getattr(provider, "signing_kp", None),
    )
    encryption_kp = _resolve_kp_with_override(
        target_sp,
        override_attr="encryption_kp_override",
        kp_attr="encryption_kp",
        fallback_kp=getattr(provider, "encryption_kp", None),
    )

    property_mappings = _pick_property_mappings(provider, target_sp)

    return SAMLSPRuntimeConfig(
        sp=target_sp,
        acs_url=acs_url,
        sp_binding=sp_binding,
        sls_url=_pick(target_sp, provider, "sls_url"),
        sls_binding=_pick(target_sp, provider, "sls_binding"),
        logout_method=_pick(target_sp, provider, "logout_method"),

        digest_algorithm=provider.digest_algorithm,
        signature_algorithm=provider.signature_algorithm,

        verification_kp=verification_kp,
        signing_kp=signing_kp,
        encryption_kp=encryption_kp,
        property_mappings=property_mappings,
    )

def _pick_property_mappings(provider: SAMLProvider, sp):
    # Provider-only if no SP or no relation
    if sp is None or not hasattr(sp, "property_mappings"):
        return provider.property_mappings.all()

    # Explicit override switch (default False)
    if not bool(getattr(sp, "property_mappings_override", False)):
        return provider.property_mappings.all()

    # Override ON:
    # - return SP mappings as-is
    # - empty queryset means "no attributes"
    return sp.property_mappings.all()

def peek_issuer(root: Any) -> str | None:
    """Peek Issuer text from a SAML XML root without validation.

    Supports both:
    - xml.etree / defusedxml ElementTree elements (find/findall)
    - lxml elements (xpath)

    Intended for early entityID/issuer extraction before resolver selection.
    """

    # lxml path (Response processor etc.)
    xpath = getattr(root, "xpath", None)
    if callable(xpath):
        issuers = root.xpath("/samlp:Response/saml:Issuer", namespaces=NS_MAP)
        if not issuers:
            issuers = root.xpath("/samlp:Response/saml:Assertion/saml:Issuer", namespaces=NS_MAP)
        if not issuers:
            # tolerant fallback for request-like roots parsed via lxml
            issuers = root.xpath("./samlp:Issuer", namespaces=NS_MAP) or root.xpath(
                "./saml:Issuer", namespaces=NS_MAP
            )
        if not issuers:
            return None
        return issuers[0].text or None

    # ElementTree path (AuthnRequest / LogoutRequest parser etc.)
    findall = getattr(root, "findall", None)
    if callable(findall):
        issuers = root.findall(f"{{{NS_SAML_PROTOCOL}}}Issuer")
        if not issuers:
            issuers = root.findall(f"{{{NS_SAML_ASSERTION}}}Issuer")
        if not issuers:
            return None
        return issuers[0].text or None

    # Unknown root type
    return None
