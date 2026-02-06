# authentik/providers/saml/resolve.py
from __future__ import annotations

from authentik.crypto.models import CertificateKeyPair
from authentik.providers.saml.context import get_current_sp
from authentik.providers.saml.models import SAMLProvider

# NOTE: sp should be SAMLSP, but be duck on development.


def _sp_value(sp, attr: str):
    if not sp:
        return None
    return getattr(sp, attr, None)


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
    # allow override but keep provider default if missing
    return _sp_value(sp, "logout_method") or provider.logout_method


def resolve_digest_algorithm(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "digest_algorithm") or provider.digest_algorithm


def resolve_signature_algorithm(provider: SAMLProvider) -> str:
    sp = get_current_sp()
    return _sp_value(sp, "signature_algorithm") or provider.signature_algorithm


def resolve_verification_kp(provider: SAMLProvider) -> CertificateKeyPair | None:
    sp = get_current_sp()
    return _sp_value(sp, "verification_kp") or provider.verification_kp


def resolve_signing_kp(provider: SAMLProvider) -> CertificateKeyPair | None:
    sp = get_current_sp()
    return _sp_value(sp, "signing_kp") or provider.signing_kp


def resolve_encryption_kp(provider: SAMLProvider) -> CertificateKeyPair | None:
    sp = get_current_sp()
    return _sp_value(sp, "encryption_kp") or provider.encryption_kp
