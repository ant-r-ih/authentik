# authentik/providers/saml/processors/import_sp.py

from __future__ import annotations

from base64 import b64decode
from datetime import UTC, datetime

from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate
from django.db import transaction
from lxml import etree  # nosec

from authentik.crypto.models import fingerprint_sha256
from authentik.providers.saml.models import SAMLSP, SAMLBindings, SAMLProvider
from authentik.providers.saml.processors.feed_extract import (
    extract_default_acs,
    extract_sp_descriptor,
    extract_x509_b64_list,
    get_or_create_cert_kp_from_x509_b64,
)
from authentik.providers.saml.utils.certrefs import sync_saml_sp_cert_refs


@transaction.atomic
def import_sp_from_entity_descriptor(
    *,
    provider: SAMLProvider,
    entity: etree._Element,
    enabled: bool = True,
    overwrite: bool = True,
) -> tuple[SAMLSP, bool]:
    """Create or update SAMLSP from EntityDescriptor.

    overwrite=False:
      - If the SP already exists, do not update any fields (idempotent no-op).
      - If it does not exist, create it from metadata.
    overwrite=True:
      - Update metadata-derived fields (user overrides should be separate).
    """
    entity_id = entity.attrib.get("entityID")
    if not entity_id:
        raise ValueError("EntityDescriptor missing entityID")

    # Fast no-op path when overwrite is disabled and the SP already exists.
    if not overwrite:
        existing = SAMLSP.objects.filter(provider=provider, entity_id=entity_id).first()
        if existing:
            return existing, False

    sp_desc = extract_sp_descriptor(entity)
    acs_url, acs_binding_uri = extract_default_acs(sp_desc)

    sp_binding = (
        SAMLBindings.POST if "HTTP-POST" in (acs_binding_uri or "") else SAMLBindings.REDIRECT
    )

    # Certificate handling (verification)
    certs = extract_x509_b64_list(sp_desc)
    chosen = pick_preferred_x509_b64(certs)  # ordered list, best-first
    verification_kp = None
    if chosen:
        verification_kp = get_or_create_cert_kp_from_x509_b64(
            x509_b64=chosen[0],
            name_prefix=f"SAMLSP {provider.name} verification",
        )

    defaults = {
        "name": entity_id,
        "enabled": enabled,
        "acs_url": acs_url,
        "sp_binding": sp_binding,
        "authn_requests_signed": (sp_desc.attrib.get("AuthnRequestsSigned", "").lower() == "true"),
        "want_assertions_signed": (
            sp_desc.attrib.get("WantAssertionsSigned", "").lower() == "true"
        ),
        "verification_kp": verification_kp,
    }

    if overwrite:
        sp, created = SAMLSP.objects.update_or_create(
            provider=provider,
            entity_id=entity_id,
            defaults=defaults,
        )
    else:
        sp, created = SAMLSP.objects.get_or_create(
            provider=provider,
            entity_id=entity_id,
            defaults=defaults,
        )

    sync_saml_sp_cert_refs(sp)
    return sp, created


def _cert_validity_utc(cert) -> tuple[datetime, datetime]:
    """Return (not_before, not_after) as timezone-aware UTC datetimes."""
    nb = getattr(cert, "not_valid_before_utc", None)
    na = getattr(cert, "not_valid_after_utc", None)
    if nb is None or na is None:
        nb = cert.not_valid_before
        na = cert.not_valid_after

    if nb.tzinfo is None:
        nb = nb.replace(tzinfo=UTC)
    if na.tzinfo is None:
        na = na.replace(tzinfo=UTC)
    return nb, na


def pick_preferred_x509_b64(
    certs_b64: list[str],
    *,
    now: datetime | None = None,
) -> list[str]:
    """Pick preferred certificates from base64 DER X.509 strings.

    Strategy:
      1) Parse candidates (skip unparsable).
      2) Prefer currently valid certificates.
      3) If multiple are valid, prefer later notAfter (more stable under rotation).
      4) If none valid, keep parsed order (metadata order).
      5) If nothing parsed, keep raw metadata order.
    """
    if not certs_b64:
        return []

    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    parsed: list[tuple[str, datetime, datetime, str]] = []
    for x509_b64 in certs_b64:
        try:
            cert_der = b64decode(x509_b64)
            cert = load_der_x509_certificate(cert_der, default_backend())
            not_before, not_after = _cert_validity_utc(cert)
            fp = fingerprint_sha256(cert)
            parsed.append((x509_b64, not_before, not_after, fp))
        except Exception:  # noqa: BLE001
            continue

    if not parsed:
        # Nothing parsed -> preserve raw metadata order
        return list(certs_b64)

    valid = [c for c in parsed if c[1] <= now <= c[2]]
    if valid:
        valid.sort(key=lambda c: (c[2], c[3]), reverse=True)
        return [c[0] for c in valid]

    # None valid -> preserve parsed order (which follows metadata order)
    return [c[0] for c in parsed]
