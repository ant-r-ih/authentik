"""Resolve effective SAML Source / IdP settings without context.

Design:
- Keep resolve_* helpers for existing call sites.
- Add build_samlidp_config() as the primary API for processors.
- Keypairs use tri-state mode when present on SAMLIDP:
    - inherit: fallback to source.<kp>
    - set:     use idp.<kp>
    - none:    disable (None)
  If mode fields are absent (older rows), fallback to legacy behavior:
    idp.<kp> if set, else source.<kp>.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from authentik.providers.saml.resolve import _resolve_kp_with_override

if TYPE_CHECKING:
    from authentik.crypto.models import CertificateKeyPair
    from authentik.sources.saml.models import SAMLIDP, SAMLSource


# ----------------------------
# Generic helpers
# ----------------------------

def _prefer_idp_attr(idp: "SAMLIDP | None", attr: str, fallback):
    """Return idp.<attr> if idp exists and value is not None, else fallback."""
    if idp is None:
        return fallback
    value = getattr(idp, attr, None)
    return fallback if value is None else value


def _norm_mode(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        v = v.strip().lower()
    return v or None


def _get(obj, attr: str):
    if obj is None:
        return None
    return getattr(obj, attr, None)

# ----------------------------
# build_* API
# ----------------------------

@dataclass(slots=True)
class SAMLIDPRuntimeConfig:
    """Resolved runtime config for SAMLSource + optional additional IdP (SAMLIDP)."""

    source: "SAMLSource"
    idp: "SAMLIDP | None"

    # endpoints
    sso_url: str
    slo_url: str | None

    # behavior flags
    allow_idp_initiated: bool
    signed_assertion: bool
    signed_response: bool

    # algorithms
    digest_algorithm: str
    signature_algorithm: str

    # keys
    verification_kp: "CertificateKeyPair | None"
    signing_kp: "CertificateKeyPair | None"
    encryption_kp: "CertificateKeyPair | None"

    # misc (client request formatting)
    name_id_policy: str
    binding_type: str


def build_samlidp_config(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> SAMLIDPRuntimeConfig:
    # endpoints/flags are still simple "prefer idp if not None"
    sso_url = _prefer_idp_attr(idp, "sso_url", source.sso_url)
    slo_url = _prefer_idp_attr(idp, "slo_url", source.slo_url)

    allow_idp_initiated = bool(_prefer_idp_attr(idp, "allow_idp_initiated", source.allow_idp_initiated))
    signed_assertion = bool(_prefer_idp_attr(idp, "signed_assertion", source.signed_assertion))
    signed_response = bool(_prefer_idp_attr(idp, "signed_response", source.signed_response))

    digest_algorithm = str(_prefer_idp_attr(idp, "digest_algorithm", source.digest_algorithm))
    signature_algorithm = str(_prefer_idp_attr(idp, "signature_algorithm", source.signature_algorithm))

    # key resolution with mode (idp-side)
    verification_kp = _resolve_kp_with_override(
        idp,
        override_attr="verification_kp_override",
        kp_attr="verification_kp",
        fallback_kp=getattr(source, "verification_kp", None),
    )
    signing_kp = _resolve_kp_with_override(
        idp,
        override_attr="signing_kp_override",
        kp_attr="signing_kp",
        fallback_kp=getattr(source, "signing_kp", None),
    )
    encryption_kp = _resolve_kp_with_override(
        idp,
        override_attr="encryption_kp_override",
        kp_attr="encryption_kp",
        fallback_kp=getattr(source, "encryption_kp", None),
    )

    name_id_policy = str(_prefer_idp_attr(idp, "name_id_policy", source.name_id_policy))
    binding_type = str(_prefer_idp_attr(idp, "binding_type", source.binding_type))

    return SAMLIDPRuntimeConfig(
        source=source,
        idp=idp,
        sso_url=str(sso_url),
        slo_url=slo_url,
        allow_idp_initiated=allow_idp_initiated,
        signed_assertion=signed_assertion,
        signed_response=signed_response,
        digest_algorithm=digest_algorithm,
        signature_algorithm=signature_algorithm,
        verification_kp=verification_kp,
        signing_kp=signing_kp,
        encryption_kp=encryption_kp,
        name_id_policy=name_id_policy,
        binding_type=binding_type,
    )


# ----------------------------
# Compatibility resolve_* API
# ----------------------------
# (Keep existing helpers so call sites don't need immediate changes.)

# def resolve_verification_kp(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> "CertificateKeyPair | None":
#     return build_samlidp_config(source, idp).verification_kp


# def resolve_encryption_kp(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> "CertificateKeyPair | None":
#     return build_samlidp_config(source, idp).encryption_kp


# def resolve_signing_kp(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> "CertificateKeyPair | None":
#     return build_samlidp_config(source, idp).signing_kp


# def resolve_allow_idp_initiated(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> bool:
#     return build_samlidp_config(source, idp).allow_idp_initiated


# def resolve_signed_assertion(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> bool:
#     return build_samlidp_config(source, idp).signed_assertion


# def resolve_signed_response(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> bool:
#     return build_samlidp_config(source, idp).signed_response


# def resolve_sso_url(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> str:
#     return build_samlidp_config(source, idp).sso_url


# def resolve_slo_url(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> str | None:
#     return build_samlidp_config(source, idp).slo_url


# def resolve_name_id_policy(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> str:
#     return build_samlidp_config(source, idp).name_id_policy


# def resolve_binding_type(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> str:
#     return build_samlidp_config(source, idp).binding_type


# def resolve_digest_algorithm(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> str:
#     return build_samlidp_config(source, idp).digest_algorithm


# def resolve_signature_algorithm(source: "SAMLSource", idp: "SAMLIDP | None" = None) -> str:
#     return build_samlidp_config(source, idp).signature_algorithm
