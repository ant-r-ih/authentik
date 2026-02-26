from __future__ import annotations

from typing import Any

from django.db import transaction
from django.utils import timezone
from lxml import etree  # nosec
from structlog import get_logger

from authentik.crypto.models import CertificateKeyPair
from authentik.providers.saml.processors.feed_extract import (
    extract_x509_b64_list,
    get_or_create_cert_kp_from_x509_b64,
    pick_preferred_x509_b64,
)
from authentik.providers.saml.processors.import_sp import best_effort_display_name
from authentik.providers.saml.utils.certrefs import sync_saml_idp_cert_refs
from authentik.sources.saml.federation import SAMLIDP
from authentik.sources.saml.models import SAMLSource
from authentik.sources.saml.processors.idp_extract import (
    extract_idp_descriptor,
    extract_idp_slo_url,
    extract_idp_sso_url,
)
from authentik.sources.saml.processors.snapshot import (
    compute_snapshot_hash,
    normalize_snapshot,
)

LOGGER = get_logger()

@transaction.atomic
def import_idp_from_entity_descriptor(
    *,
    source: SAMLSource,
    entity: etree._Element,
    enabled: bool | None = None,
    overwrite: bool = True,
) -> tuple[SAMLIDP, bool]:
    """Import additional IdP config (SAMLIDP) from EntityDescriptor.

    Design:
    - Default IdP remains in SAMLSource (not modified).
    - This creates/updates SAMLIDP under the given source.
    - Snapshot/hash/last_import are updated every import (same semantics as SAMLSP).
    - verification_kp is derived from IdP metadata (IdP signing certs) but:
        - not overwritten when freeze_verification_kp=True
        - not overwritten when verification_kp_mode != INHERIT
    - signing_kp/encryption_kp are local/private-key concerns (UI/API managed), not set from metadata here.
    """

    entity_id = entity.attrib.get("entityID")
    if not entity_id:
        raise ValueError("EntityDescriptor missing entityID")

    # Lock existing row to prevent concurrent imports from fighting over enabled/state.
    existing = (
        SAMLIDP.objects.select_for_update()
        .filter(source=source, entity_id=entity_id)
        .first()
    )

    # If it exists and overwrite is disabled, do nothing.
    if existing and not overwrite:
        return existing, False

    # Resolve enabled behavior:
    # - If enabled is None: new => False, existing => keep current value
    # - If enabled is True/False: always apply that explicit value
    if enabled is None:
        enabled_final = False if existing is None else existing.enabled
    else:
        enabled_final = enabled

    idp_desc = extract_idp_descriptor(entity)
    sso_url = extract_idp_sso_url(idp_desc)
    slo_url = extract_idp_slo_url(idp_desc)

    # --------------------------------------------------------
    # Extract IdP certificates
    # --------------------------------------------------------
    # For SAML Source, verification_kp validates incoming assertion signatures.
    # That corresponds to IdP's signing certs (public certs).
    signing_b64 = (
        extract_x509_b64_list(idp_desc, use="signing")
        or extract_x509_b64_list(idp_desc, use=None)
    )
    preferred_signing = pick_preferred_x509_b64(signing_b64)

    verification_kp: CertificateKeyPair | None = None
    if preferred_signing:
        try:
            verification_kp = get_or_create_cert_kp_from_x509_b64(
                x509_b64=preferred_signing[0],
                name_prefix=f"SAMLIDP {source.name} verification",
            )
        except Exception as exc:
            LOGGER.warning("Invalid signing certificate, skipping", exc_info=exc)
            verification_kp = None

    # --------------------------------------------------------
    # Snapshot/hash (always updated)
    # --------------------------------------------------------
    display_name = best_effort_display_name(entity)
    desired_name = display_name or entity_id
    name_for_defaults = desired_name
    if existing:
        cur = (existing.name or "").strip()
        if cur and cur != entity_id:
            name_for_defaults = existing.name

    snapshot: dict[str, Any] = {
        "sso_url": sso_url,
        "slo_url": slo_url,
        # keep this coarse: presence only (no fingerprint/ID)
        "has_signing_cert": bool(signing_b64),
    }
    snapshot_hash = compute_snapshot_hash(normalize_snapshot(snapshot))

    defaults: dict[str, Any] = {
        "name": name_for_defaults,
        "enabled": enabled_final,
        "sso_url": sso_url,
        "slo_url": slo_url,
        "metadata_snapshot": snapshot,
        "metadata_hash": snapshot_hash,
        "metadata_last_import": timezone.now(),
    }

    can_update_verification = True
    if existing:
        if getattr(existing, "freeze_verification_kp", False):
            can_update_verification = False
        if getattr(existing, "verification_kp_override", False):
            can_update_verification = False

    if can_update_verification:
        if verification_kp is not None:
            defaults["verification_kp"] = verification_kp
            defaults["verification_kp_override"] = True
        else:
            defaults["verification_kp"] = None
            defaults["verification_kp_override"] = False

    idp, created = SAMLIDP.objects.update_or_create(
        source=source,
        entity_id=entity_id,
        defaults=defaults,
    )

    sync_saml_idp_cert_refs(idp)
    return idp, created
