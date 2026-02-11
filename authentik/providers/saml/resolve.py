# authentik/providers/saml/resolve.py
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from authentik.crypto.models import CertificateKeyPair
from authentik.providers.saml.context import get_current_sp
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

def _sp_value(sp, attr: str):
    if not sp:
        return None
    v = getattr(sp, attr, None)
    # normalize empty strings
    if isinstance(v, str) and v.strip() == "":
        return None
    return v

def _sp_mode(sp, attr: str) -> str | None:
    """Read mode field from SP, keeping duck-typed compatibility."""
    if not sp:
        return None
    v = getattr(sp, attr, None)
    if isinstance(v, str):
        v = v.strip().lower()
    return v or None

def _resolve_kp_with_mode(
    sp,
    *,
    mode_attr: str,
    kp_attr: str,
    provider_kp: CertificateKeyPair | None,
) -> CertificateKeyPair | None:
    """Resolve keypair using SAMLSP tri-state mode if present.

    Supported mode values (string-based for compatibility):
    - "inherit": use provider keypair
    - "set":     use SP local keypair (may be None on inconsistent data)
    - "none":    explicitly disable keypair
    If mode is missing/unknown, fallback to legacy behavior:
    - SP local keypair wins, then provider fallback.
    """
    mode = _sp_mode(sp, mode_attr)
    local_kp = _sp_value(sp, kp_attr)

    if mode == "none":
        return None
    if mode == "set":
        return local_kp
    if mode == "inherit":
        return provider_kp

    # Legacy fallback (mode field absent during migration / older rows)
    return local_kp or provider_kp

def resolve_acs_url(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "acs_url") or provider.acs_url


def resolve_sp_binding(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "sp_binding") or provider.sp_binding


def resolve_sls_url(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "sls_url") or provider.sls_url


def resolve_sls_binding(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "sls_binding") or provider.sls_binding


def resolve_logout_method(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "logout_method") or provider.logout_method


def resolve_digest_algorithm(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "digest_algorithm") or provider.digest_algorithm


def resolve_signature_algorithm(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "signature_algorithm") or provider.signature_algorithm


def resolve_verification_kp(provider: SAMLProvider) -> CertificateKeyPair | None:
    sp = get_current_sp()
    return _resolve_kp_with_mode(
        sp,
        mode_attr="verification_kp_mode",
        kp_attr="verification_kp",
        provider_kp=provider.verification_kp,
    )


def resolve_signing_kp(provider: SAMLProvider) -> CertificateKeyPair | None:
    sp = get_current_sp()
    return _resolve_kp_with_mode(
        sp,
        mode_attr="signing_kp_mode",
        kp_attr="signing_kp",
        provider_kp=provider.signing_kp,
    )


def resolve_encryption_kp(provider: SAMLProvider) -> CertificateKeyPair | None:
    sp = get_current_sp()
    return _resolve_kp_with_mode(
        sp,
        mode_attr="encryption_kp_mode",
        kp_attr="encryption_kp",
        provider_kp=provider.encryption_kp,
    )
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
    # request-target-aware target selection
    target_sp = sp
    if target is not None and getattr(target, "sp", None) is not None:
        target_sp = target.sp

    # target values (request attrs may override)
    if target is not None:
        acs_url = target.acs_url
        sp_binding = target.sp_binding
    else:
        acs_url = _pick(target_sp, provider, "acs_url")
        sp_binding = _pick(target_sp, provider, "sp_binding")

    # IMPORTANT: key resolution must use explicit target_sp, not context/global resolve
    verification_kp = _pick_kp_with_mode(
        target_sp, provider, mode_attr="verification_kp_mode", kp_attr="verification_kp"
    )
    signing_kp = _pick_kp_with_mode(
        target_sp, provider, mode_attr="signing_kp_mode", kp_attr="signing_kp"
    )
    encryption_kp = _pick_kp_with_mode(
        target_sp, provider, mode_attr="encryption_kp_mode", kp_attr="encryption_kp"
    )

    property_mappings = _pick_property_mappings(provider, target_sp)

    return SAMLSPRuntimeConfig(
        sp=target_sp,
        acs_url=acs_url,
        sp_binding=sp_binding,
        sls_url=_pick(target_sp, provider, "sls_url"),
        sls_binding=_pick(target_sp, provider, "sls_binding"),
        logout_method=_pick(target_sp, provider, "logout_method"),
        digest_algorithm=_pick(target_sp, provider, "digest_algorithm"),
        signature_algorithm=_pick(target_sp, provider, "signature_algorithm"),
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

def _pick_kp_with_mode(sp, provider, *, mode_attr: str, kp_attr: str):
    return _resolve_kp_with_mode(
        sp,
        mode_attr=mode_attr,
        kp_attr=kp_attr,
        provider_kp=getattr(provider, kp_attr, None),
    )

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
