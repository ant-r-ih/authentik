# authentik/providers/saml/processors/import_sp.py

from __future__ import annotations

import re

from django.db import transaction
from django.utils import timezone
from lxml import etree  # nosec
from structlog import get_logger

from authentik.providers.saml.federation import (
    SAMLSP,
    build_runtime_from_snapshot,
    compute_signature_hash,
    normalize_signature,
)
from authentik.providers.saml.models import SAMLProvider
from authentik.providers.saml.processors.feed_extract import (
    NS_MAP,
    extract_all_acs,
    extract_all_sls,
    extract_sp_descriptor,
    extract_x509_b64_list,
    get_or_create_cert_kp_from_x509_b64,
    pick_preferred_x509_b64,
)
from authentik.providers.saml.utils.certrefs import sync_saml_sp_cert_refs

_MDUI_NS = "urn:oasis:names:tc:SAML:metadata:ui"
_XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"

LOGGER = get_logger()

@transaction.atomic
def import_sp_from_entity_descriptor(
    *,
    provider: SAMLProvider,
    entity: etree._Element,
    enabled: bool | None = None,
    overwrite: bool = True,
) -> tuple[SAMLSP, bool]:
    entity_id = entity.attrib.get("entityID")
    if not entity_id:
        raise ValueError("EntityDescriptor missing entityID")

    # Lock existing row to prevent concurrent imports from fighting over enabled/state.
    existing = (
        SAMLSP.objects.select_for_update()
        .filter(provider=provider, entity_id=entity_id)
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

    sp_desc = extract_sp_descriptor(entity)

    # --------------------------------------------------------
    # Extract metadata
    # --------------------------------------------------------

    acs_list = extract_all_acs(sp_desc)
    sls_list = extract_all_sls(sp_desc)

    verification_b64 = (
        extract_x509_b64_list(sp_desc, use="signing")
        or extract_x509_b64_list(sp_desc, use=None)
    )
    encryption_b64 = extract_x509_b64_list(sp_desc, use="encryption")

    preferred_verification = pick_preferred_x509_b64(verification_b64)
    preferred_encryption = pick_preferred_x509_b64(encryption_b64)

    verification_kp = None
    if preferred_verification:
        try:
            verification_kp = get_or_create_cert_kp_from_x509_b64(
                x509_b64=preferred_verification[0],
                name_prefix=f"SAMLSP {provider.name} verification",
            )
        except Exception as exc:
            LOGGER.warning("Invalid verification certificate, skipping", exc_info=exc)
            verification_kp = None

    encryption_kp = None
    try:
        if preferred_encryption:
            encryption_kp = get_or_create_cert_kp_from_x509_b64(
                x509_b64=preferred_encryption[0],
                name_prefix=f"SAMLSP {provider.name} encryption",
            )
    except Exception as exc:
        LOGGER.warning("Invalid encryption certificate, skipping", exc_info=exc)

    display_name = best_effort_display_name(entity)
    desired_name = display_name or entity_id
    name_for_defaults = desired_name
    if existing:
        cur = (existing.name or "").strip()
        if cur and cur != entity_id:
            name_for_defaults = existing.name

    # --------------------------------------------------------
    # Build snapshot
    # --------------------------------------------------------

    snapshot = {
        "acs": acs_list,
        "sls": sls_list,
        "authn_requests_signed": (sp_desc.attrib.get("AuthnRequestsSigned", "").lower() == "true"),
        "want_assertions_signed": (sp_desc.attrib.get("WantAssertionsSigned", "").lower() == "true"),
        "has_verification_cert": bool(verification_b64),
        "has_encryption_cert": bool(encryption_b64),
    }

    snapshot_hash = compute_signature_hash(normalize_signature(snapshot))
    runtime_defaults = build_runtime_from_snapshot(snapshot, provider=provider)

    # NOTE:
    # - enabled must never be None here.
    # - metadata_last_import is updated on every import (even if unchanged),
    #   which matches "import action happened" semantics. If you want "only when changed",
    #   add a conditional on snapshot_hash vs existing.metadata_hash.
    defaults = {
        "name": name_for_defaults,
        "enabled": enabled_final,
        "metadata_snapshot": snapshot,
        "metadata_hash": snapshot_hash,
        "metadata_last_import": timezone.now(),
        **runtime_defaults,
    }

    if verification_kp is not None:
        defaults["verification_kp"] = verification_kp
        defaults["verification_kp_override"] = True
    else:
        # metadata に無いなら inherit（＝override off）
        defaults["verification_kp"] = None
        defaults["verification_kp_override"] = False

    # encryption cert
    if encryption_kp is not None:
        defaults["encryption_kp"] = encryption_kp
        defaults["encryption_kp_override"] = True
    else:
        defaults["encryption_kp"] = None
        defaults["encryption_kp_override"] = False

    if overwrite:
        sp, created = SAMLSP.objects.update_or_create(
            provider=provider,
            entity_id=entity_id,
            defaults=defaults,
        )
    else:
        # At this point existing is None (because existing && not overwrite returned above),
        # but keep the get_or_create structure if you prefer symmetry.
        sp, created = SAMLSP.objects.get_or_create(
            provider=provider,
            entity_id=entity_id,
            defaults=defaults,
        )

    sync_saml_sp_cert_refs(sp)
    return sp, created

def _norm_label(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())

def best_effort_display_name(entity: etree._Element) -> str | None:
    ns = {
        **NS_MAP,  # expects "md" and "ds" at least
        "mdui": _MDUI_NS,
    }

    # 1) mdui:UIInfo/mdui:DisplayName[@xml:lang='en']
    nodes = entity.xpath(".//mdui:UIInfo/mdui:DisplayName", namespaces=ns)
    for n in nodes:
        if (n.attrib.get(_XML_LANG) or "").lower() == "en":
            t = _norm_label(n.text or "")
            if t:
                return t

    # 2) md:Organization/md:OrganizationDisplayName[@xml:lang='en']
    nodes = entity.xpath(".//md:Organization/md:OrganizationDisplayName", namespaces=ns)
    for n in nodes:
        if (n.attrib.get(_XML_LANG) or "").lower() == "en":
            t = _norm_label(n.text or "")
            if t:
                return t

    # 3) md:Organization/md:OrganizationName[@xml:lang='en']
    nodes = entity.xpath(".//md:Organization/md:OrganizationName", namespaces=ns)
    for n in nodes:
        if (n.attrib.get(_XML_LANG) or "").lower() == "en":
            t = _norm_label(n.text or "")
            if t:
                return t

    return None
