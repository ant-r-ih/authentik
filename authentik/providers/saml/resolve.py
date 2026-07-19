"""Resolve SAML Provider/Source parameters from Issuer and request hints."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from authentik.common.saml.constants import (
    NS_MAP,
    NS_SAML_ASSERTION,
    NS_SAML_PROTOCOL,
    SAML_BINDING_POST,
    SAML_BINDING_REDIRECT,
)
from authentik.crypto.models import CertificateKeyPair, CertificateKeyPairRing
from authentik.providers.saml.models import (
    SAMLIDP,
    SAMLSP,
    SAMLBindings,
    SAMLPropertyMapping,
    SAMLProvider,
)
from authentik.sources.saml.models import SAMLSource


def find_first_element(root: Any, qnames: Iterable[str]):
    """Return first matching element for any qname via .find()."""
    for qname in qnames:
        element = root.find(qname)
        if element is not None:
            return element
    return None


def find_first_text(root: Any, qnames: Iterable[str]) -> str | None:
    """Return first non-empty stripped text for any qname via .find()."""
    for qname in qnames:
        element = root.find(qname)
        if element is None or not element.text:
            continue
        text = element.text.strip()
        if text:
            return text
    return None


def peek_issuer(root: Any) -> str | None:
    """Extract Issuer for Response/Assertion or AuthnRequest roots."""
    xpath = getattr(root, "xpath", None)
    if callable(xpath):
        issuers = root.xpath("/samlp:Response/saml:Issuer", namespaces=NS_MAP)
        if not issuers:
            issuers = root.xpath("/samlp:Response/saml:Assertion/saml:Issuer", namespaces=NS_MAP)
        if not issuers:
            issuers = root.xpath("/samlp:AuthnRequest/saml:Issuer", namespaces=NS_MAP)
        if not issuers:
            issuers = root.xpath("./samlp:Issuer", namespaces=NS_MAP) or root.xpath(
                "./saml:Issuer", namespaces=NS_MAP
            )
        if not issuers:
            return None
        text = issuers[0].text
        return text.strip() if text else None

    findall = getattr(root, "findall", None)
    if callable(findall):
        issuers = root.findall(f"{{{NS_SAML_PROTOCOL}}}Issuer")
        if not issuers:
            issuers = root.findall(f"{{{NS_SAML_ASSERTION}}}Issuer")
        if not issuers:
            return None
        text = issuers[0].text
        return text.strip() if text else None

    return None


def _norm(value: Any) -> Any:
    """Normalize str by stripping and mapping empty to None."""
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return value


def _norm_str(value: str | None) -> str | None:
    """Normalize optional str by stripping and mapping empty to None."""
    if value is None:
        return None
    value = value.strip()
    return value or None


def _pick(local_obj: Any, fallback_obj: Any, attr: str) -> Any:
    """Pick normalized local attr if set, else normalized fallback attr."""
    local_value = _norm(getattr(local_obj, attr, None)) if local_obj is not None else None
    if local_value is not None:
        return local_value
    return _norm(getattr(fallback_obj, attr, None))


def _prefer(local_obj: Any, attr: str, fallback: Any) -> Any:
    """Return local_obj.attr if defined, otherwise fallback."""
    if local_obj is None:
        return fallback
    value = getattr(local_obj, attr, None)
    return fallback if value is None else value


def _resolve_kp_with_override(
    entity: Any,
    owner: Any,
    slot: str,
) -> tuple[CertificateKeyPair | None, CertificateKeyPairRing | None]:
    """Resolve <slot>_kp/<slot>_kp_ring honoring <slot>_kp_override."""
    if entity is None:
        return (
            getattr(owner, f"{slot}_kp", None),
            getattr(owner, f"{slot}_kp_ring", None),
        )
    if getattr(entity, f"{slot}_kp_override", False):
        # Explicit override means local values are authoritative; None disables inheritance.
        return (
            getattr(entity, f"{slot}_kp", None),
            getattr(entity, f"{slot}_kp_ring", None),
        )
    return (
        getattr(owner, f"{slot}_kp", None),
        getattr(owner, f"{slot}_kp_ring", None),
    )


def _normalize_binding(value: str | None) -> str | None:
    """Normalize SAML binding URI/token into provider binding token."""
    if value is None:
        return None
    if value == SAML_BINDING_POST:
        return SAMLBindings.POST
    if value == SAML_BINDING_REDIRECT:
        return SAMLBindings.REDIRECT
    if value in (SAMLBindings.POST, SAMLBindings.REDIRECT):
        return value
    return None


@dataclass(slots=True)
class KeyMaterial:
    """Resolved algorithm and keypair material for SAML operations."""

    digest_algorithm: str
    signature_algorithm: str
    verification_kp: CertificateKeyPair | None
    verification_kp_ring: CertificateKeyPairRing | None
    signing_kp: CertificateKeyPair | None
    signing_kp_ring: CertificateKeyPairRing | None
    encryption_kp: CertificateKeyPair | None
    encryption_kp_ring: CertificateKeyPairRing | None


@dataclass(slots=True)
class ResolvedRequestTarget:
    """Resolved SP target parameters for current request."""

    sp: SAMLSP | None
    acs_url: str | None
    sp_binding: str | None


def resolve_request_target(
    provider: SAMLProvider,
    sp: SAMLSP | None,
    *,
    request_acs_url: str | None = None,
    request_sp_binding: str | None = None,
) -> ResolvedRequestTarget:
    """Resolve request ACS/binding from provider/SP defaults and request hints."""
    configured_acs = _norm_str(getattr(sp, "acs_url", None)) if sp else _norm_str(provider.acs_url)
    configured_binding = _normalize_binding(
        getattr(sp, "sp_binding", None) if sp else getattr(provider, "sp_binding", None)
    )

    acs_url = _norm_str(request_acs_url) or configured_acs
    sp_binding = configured_binding or _normalize_binding(request_sp_binding)
    return ResolvedRequestTarget(sp=sp, acs_url=acs_url, sp_binding=sp_binding)


@dataclass(slots=True)
class SPConfig:
    """Resolved SP config bundle used by provider runtime processors."""

    sp: SAMLSP | None
    acs_url: str | None
    sp_binding: str | None
    sls_url: str | None
    sls_binding: str | None
    logout_method: str | None
    keys: KeyMaterial
    property_mappings: list[SAMLPropertyMapping]


@dataclass(slots=True)
class IDPConfig:
    """Resolved IdP config bundle used by source runtime processors."""

    source: SAMLSource
    idp: SAMLIDP | None
    sso_url: str
    slo_url: str | None
    allow_idp_initiated: bool
    signed_assertion: bool
    signed_response: bool
    name_id_policy: str
    binding_type: str
    keys: KeyMaterial


def _pick_property_mappings(provider: SAMLProvider, sp: SAMLSP | None) -> list[SAMLPropertyMapping]:
    """Return SP override mappings when enabled, else provider mappings."""
    if sp is not None and getattr(sp, "property_mappings_override", False):
        return list(sp.property_mappings.all().order_by("saml_name"))
    if not provider._is_pk_set():
        return []
    return list(SAMLPropertyMapping.objects.filter(provider=provider).order_by("saml_name"))


def build_sp_config(
    provider: SAMLProvider,
    sp: SAMLSP | None = None,
    *,
    target: ResolvedRequestTarget | None = None,
) -> SPConfig:
    """Build SP config from provider defaults with optional SP overrides."""
    target_sp = target.sp if target is not None and target.sp is not None else sp
    acs_url = target.acs_url if target is not None else _pick(target_sp, provider, "acs_url")
    sp_binding = (
        target.sp_binding
        if target is not None
        else _normalize_binding(_pick(target_sp, provider, "sp_binding"))
    )

    verification_kp, verification_kp_ring = _resolve_kp_with_override(
        target_sp,
        provider,
        "verification",
    )
    signing_kp, signing_kp_ring = _resolve_kp_with_override(target_sp, provider, "signing")
    encryption_kp, encryption_kp_ring = _resolve_kp_with_override(target_sp, provider, "encryption")

    keys = KeyMaterial(
        digest_algorithm=str(getattr(provider, "digest_algorithm", "")),
        signature_algorithm=str(getattr(provider, "signature_algorithm", "")),
        verification_kp=verification_kp,
        verification_kp_ring=verification_kp_ring,
        signing_kp=signing_kp,
        signing_kp_ring=signing_kp_ring,
        encryption_kp=encryption_kp,
        encryption_kp_ring=encryption_kp_ring,
    )

    return SPConfig(
        sp=target_sp,
        acs_url=acs_url,
        sp_binding=sp_binding,
        sls_url=_pick(target_sp, provider, "sls_url"),
        sls_binding=_normalize_binding(_pick(target_sp, provider, "sls_binding")),
        logout_method=_pick(target_sp, provider, "logout_method"),
        keys=keys,
        property_mappings=_pick_property_mappings(provider, target_sp),
    )


def build_idp_config(source: SAMLSource, idp: SAMLIDP | None = None) -> IDPConfig:
    """Build IdP config from source defaults with optional IdP overrides."""
    verification_kp, verification_kp_ring = _resolve_kp_with_override(idp, source, "verification")
    signing_kp, signing_kp_ring = _resolve_kp_with_override(idp, source, "signing")
    encryption_kp, encryption_kp_ring = _resolve_kp_with_override(idp, source, "encryption")

    keys = KeyMaterial(
        digest_algorithm=str(
            _prefer(idp, "digest_algorithm", getattr(source, "digest_algorithm", ""))
        ),
        signature_algorithm=str(
            _prefer(idp, "signature_algorithm", getattr(source, "signature_algorithm", ""))
        ),
        verification_kp=verification_kp,
        verification_kp_ring=verification_kp_ring,
        signing_kp=signing_kp,
        signing_kp_ring=signing_kp_ring,
        encryption_kp=encryption_kp,
        encryption_kp_ring=encryption_kp_ring,
    )

    return IDPConfig(
        source=source,
        idp=idp,
        sso_url=str(_prefer(idp, "sso_url", getattr(source, "sso_url", ""))),
        slo_url=_prefer(idp, "slo_url", getattr(source, "slo_url", None)),
        allow_idp_initiated=bool(
            _prefer(idp, "allow_idp_initiated", getattr(source, "allow_idp_initiated", False))
        ),
        signed_assertion=bool(
            _prefer(idp, "signed_assertion", getattr(source, "signed_assertion", True))
        ),
        signed_response=bool(
            _prefer(idp, "signed_response", getattr(source, "signed_response", False))
        ),
        name_id_policy=str(_prefer(idp, "name_id_policy", getattr(source, "name_id_policy", ""))),
        binding_type=str(_prefer(idp, "binding_type", getattr(source, "binding_type", ""))),
        keys=keys,
    )
