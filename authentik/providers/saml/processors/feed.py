# authentik/providers/saml/processors/feed.py
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import xmlsec
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from defusedxml.lxml import fromstring
from lxml import etree  # nosec

from authentik.crypto.models import CertificateKeyPair
from authentik.sources.saml.processors.constants import (
    NS_ENC,
    NS_SAML_METADATA,
    NS_SIGNATURE,
    SAML_BINDING_POST,
    SAML_BINDING_REDIRECT,
)

NS_MAP = {
    "md": NS_SAML_METADATA,
    "ds": NS_SIGNATURE,
    "xenc": NS_ENC,
}

BINDING_URI_TO_TOKEN: dict[str, str] = {
    SAML_BINDING_POST: "post",
    SAML_BINDING_REDIRECT: "redirect",
}

class SignatureStatus(str, Enum):
    OK = "ok"
    STALE = "stale"          # signature OK, but validUntil is in the past
    INVALID = "invalid"      # signature present but verification failed
    UNSIGNED = "unsigned"    # no ds:Signature found where expected
    ERROR = "error"          # parse or unexpected failure
@dataclass(frozen=True, slots=True)
class EntityDescriptorItem:
    entity_id: str
    xml: etree._Element
    from_aggregate: bool
    container_name_chain: tuple[str, ...]
    container_label: str

def iter_entity_descriptors(raw_xml: str | bytes) -> Iterator[EntityDescriptorItem]:
    """Public API: accept raw metadata as str/bytes, parse once, then walk."""
    if isinstance(raw_xml, str):
        data = raw_xml.encode("utf-8")
    else:
        data = raw_xml
    root = fromstring(data)
    yield from iter_entity_descriptors_root(root)


def iter_entity_descriptors_root(root: etree._Element) -> Iterator[EntityDescriptorItem]:
    """Internal API: accept already-parsed lxml root element."""

    def walk(
        node: etree._Element,
        chain: tuple[str, ...],
        aggregated: bool,
    ) -> Iterator[EntityDescriptorItem]:
        qn = etree.QName(node)
        if qn.namespace != NS_SAML_METADATA:
            # If root isn't md:* then it's not SAML2 metadata aggregate.
            raise ValueError("Unsupported metadata namespace/root")

        local = qn.localname

        if local == "EntityDescriptor":
            entity_id = node.attrib.get("entityID")
            if not entity_id:
                raise ValueError("EntityDescriptor missing entityID")
            yield EntityDescriptorItem(
                entity_id=entity_id,
                xml=node,
                from_aggregate=aggregated,
                container_name_chain=chain,
                container_label=" / ".join([c for c in chain if c]),
            )
            return

        if local != "EntitiesDescriptor":
            raise ValueError("Unsupported metadata root element")

        name = node.attrib.get("Name")
        next_chain = chain + ((name,) if name else ())

        for child in node:
            if not isinstance(child.tag, str):
                continue
            cqn = etree.QName(child)
            if cqn.namespace != NS_SAML_METADATA:
                # Ignore Signature/Extensions/other namespaces.
                continue
            if cqn.localname in ("EntityDescriptor", "EntitiesDescriptor"):
                yield from walk(child, next_chain, True)

    yield from walk(root, (), False)


def is_idp_entity(entity: etree._Element) -> bool:
    """Return True if EntityDescriptor contains an IDPSSODescriptor."""
    return bool(entity.xpath("./md:IDPSSODescriptor", namespaces=NS_MAP))


def is_sp_entity(entity: etree._Element) -> bool:
    """Return True if EntityDescriptor contains an SPSSODescriptor."""
    return bool(entity.xpath("./md:SPSSODescriptor", namespaces=NS_MAP))


def _binding_token(binding_uri: str | None) -> str | None:
    if not binding_uri:
        return None
    return BINDING_URI_TO_TOKEN.get(binding_uri, binding_uri)


def _get_bool_attr(node: etree._Element, attr: str, default: bool = False) -> bool:
    raw = node.attrib.get(attr)
    if raw is None:
        return default
    return raw.lower() == "true"


def _first_text(nodes: list[etree._Element]) -> str | None:
    if not nodes:
        return None
    txt = nodes[0].text
    return txt.strip() if txt else None


def _extract_nameid_formats(descriptor: etree._Element) -> list[str]:
    vals: list[str] = []
    for el in descriptor.xpath("./md:NameIDFormat", namespaces=NS_MAP):
        if el.text and el.text.strip():
            vals.append(el.text.strip())
    # de-dup stable
    seen: set[str] = set()
    out: list[str] = []
    for v in vals:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


def _extract_acs_list(sp_descriptor: etree._Element) -> list[dict[str, Any]]:
    """Extract AssertionConsumerService entries."""
    items: list[dict[str, Any]] = []
    for acs in sp_descriptor.xpath("./md:AssertionConsumerService", namespaces=NS_MAP):
        items.append(
            {
                "binding": _binding_token(acs.attrib.get("Binding")),
                "location": acs.attrib.get("Location"),
                "index": acs.attrib.get("index"),
                "is_default": (acs.attrib.get("isDefault", "").lower() == "true"),
            }
        )
    return items


def _extract_sls_list(descriptor: etree._Element) -> list[dict[str, Any]]:
    """Extract SingleLogoutService entries. Works for both SPSSODescriptor and IDPSSODescriptor."""
    items: list[dict[str, Any]] = []
    for sls in descriptor.xpath("./md:SingleLogoutService", namespaces=NS_MAP):
        items.append(
            {
                "binding": _binding_token(sls.attrib.get("Binding")),
                "location": sls.attrib.get("Location"),
                "response_location": sls.attrib.get("ResponseLocation"),
            }
        )
    return items


def _count_x509_certs(descriptor: etree._Element) -> dict[str, int]:
    """
    Count X509Certificate elements grouped by KeyDescriptor@use.

    NOTE:
    - Counts X509Certificate nodes (not KeyDescriptor nodes).
    - De-duplicates by certificate text within each use bucket.
    """
    buckets: dict[str, set[str]] = {
        "signing": set(),
        "encryption": set(),
        "unspecified": set(),
    }

    key_descs = descriptor.xpath("./md:KeyDescriptor", namespaces=NS_MAP)
    for kd in key_descs:
        use = (kd.attrib.get("use") or "unspecified").lower()
        if use not in buckets:
            use = "unspecified"

        cert_nodes = kd.xpath(".//ds:X509Certificate", namespaces=NS_MAP)
        for n in cert_nodes:
            txt = (n.text or "").strip()
            if txt:
                buckets[use].add(txt)

    return {k: len(v) for k, v in buckets.items()}


def _extract_entity_org_display_name(entity: etree._Element) -> str | None:
    """Optional: OrganizationDisplayName from metadata (nice for UI)."""
    nodes = entity.xpath(
        "./md:Organization/md:OrganizationDisplayName",
        namespaces=NS_MAP,
    )
    return _first_text(nodes)


def summarize_entity_descriptor(entity: etree._Element) -> dict[str, Any]:
    """
    Create a JSON-serializable summary for catalog/listing purposes.

    Input: <md:EntityDescriptor ...> element
    Output: dict (safe to JSON dump)
    """
    qn = etree.QName(entity)
    if qn.namespace != NS_SAML_METADATA or qn.localname != "EntityDescriptor":
        raise ValueError("summarize_entity_descriptor expects md:EntityDescriptor")

    entity_id = entity.attrib.get("entityID")
    if not entity_id:
        raise ValueError("EntityDescriptor missing entityID")

    # Determine roles present
    sp_descs = entity.xpath("./md:SPSSODescriptor", namespaces=NS_MAP)
    idp_descs = entity.xpath("./md:IDPSSODescriptor", namespaces=NS_MAP)

    kind: list[str] = []
    if sp_descs:
        kind.append("sp")
    if idp_descs:
        kind.append("idp")
    if not kind:
        kind.append("unknown")

    # Minimal top-level summary
    summary: dict[str, Any] = {
        "entity_id": entity_id,
        "kind": kind,
        "display_name": _extract_entity_org_display_name(entity),
        "sp": None,
        "idp": None,
        "certs": {
            "signing": 0,
            "encryption": 0,
            "unspecified": 0,
        },
    }

    # --- SP summary (endpoints from first descriptor; cert counts aggregated) ---
    if sp_descs:
        # Aggregate cert counts across all SP descriptors.
        agg = {"signing": 0, "encryption": 0, "unspecified": 0}
        for spd in sp_descs:
            c = _count_x509_certs(spd)
            for k, v in c.items():
                agg[k] = agg.get(k, 0) + v

        sp0 = sp_descs[0]
        summary["sp"] = {
            # NOTE: first descriptor only (keep behavior simple)
            "acs": _extract_acs_list(sp0),
            "sls": _extract_sls_list(sp0),
            "authn_requests_signed": _get_bool_attr(sp0, "AuthnRequestsSigned", False),
            "want_assertions_signed": _get_bool_attr(sp0, "WantAssertionsSigned", False),
            "name_id_formats": _extract_nameid_formats(sp0),
        }
        for k, v in agg.items():
            summary["certs"][k] = summary["certs"].get(k, 0) + v

    # --- IdP summary (endpoints from first descriptor; cert counts aggregated) ---
    if idp_descs:
        agg = {"signing": 0, "encryption": 0, "unspecified": 0}
        for idpd in idp_descs:
            c = _count_x509_certs(idpd)
            for k, v in c.items():
                agg[k] = agg.get(k, 0) + v

        idp0 = idp_descs[0]
        summary["idp"] = {
            # NOTE: first descriptor only (keep behavior simple)
            "sso": [
                {
                    "binding": _binding_token(n.attrib.get("Binding")),
                    "location": n.attrib.get("Location"),
                }
                for n in idp0.xpath("./md:SingleSignOnService", namespaces=NS_MAP)
            ],
            "sls": _extract_sls_list(idp0),
            "want_authn_requests_signed": _get_bool_attr(idp0, "WantAuthnRequestsSigned", False),
            "name_id_formats": _extract_nameid_formats(idp0),
        }
        for k, v in agg.items():
            summary["certs"][k] = summary["certs"].get(k, 0) + v

    return summary
class SignatureStatus(str, Enum):
    OK = "ok"
    STALE = "stale"          # signature OK, but validUntil is in the past
    INVALID = "invalid"      # signature present but verification failed
    UNSIGNED = "unsigned"    # no ds:Signature found where expected
    ERROR = "error"          # parse or unexpected failure


@dataclass(frozen=True, slots=True)
class SignatureVerificationResult:
    status: SignatureStatus
    message: str

    # Aggregate metadata identification
    root_tag: str | None = None
    metadata_id: str | None = None
    metadata_name: str | None = None

    # validUntil
    valid_until: datetime | None = None
    is_stale: bool | None = None

    # Extra debug (optional)
    signature_nodes: int | None = None


def _parse_valid_until(raw: str | None) -> datetime | None:
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None

    # common patterns:
    #  - 2026-03-11T14:00:00Z
    #  - 2026-03-11T14:00:00+00:00
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _ensure_cert_pem_is_valid(cert_pem: str) -> None:
    # sanity check so verification errors are more predictable
    x509.load_pem_x509_certificate(cert_pem.encode("utf-8"), default_backend())


def verify_entities_descriptor_signature(
    raw_xml: str | bytes,
    *,
    signing_cert: CertificateKeyPair,
    now_utc: datetime | None = None,
) -> SignatureVerificationResult:
    """
    Verify XML signature of an aggregate SAML metadata document (EntitiesDescriptor).

    Policy:
      - Only checks the aggregate root signature: /md:EntitiesDescriptor/ds:Signature
      - Uses external certificate (CertificateKeyPair.certificate_data). Does NOT trust KeyInfo in XML.
      - Returns STALE if signature OK but validUntil is in the past.

    Notes:
      - xmlsec expects the referenced ID attribute to be registered. We add_ids(["ID"]).
      - This verifies the ds:Signature node, which should cover the referenced root by URI="#<ID>".
    """
    try:
        if now_utc is None:
            now_utc = datetime.now(timezone.utc)
        else:
            if now_utc.tzinfo is None:
                now_utc = now_utc.replace(tzinfo=timezone.utc)
            now_utc = now_utc.astimezone(timezone.utc)

        data = raw_xml.encode("utf-8") if isinstance(raw_xml, str) else raw_xml
        root = fromstring(data)

        qn = etree.QName(root)
        root_tag = f"{{{qn.namespace}}}{qn.localname}"

        if qn.namespace != NS_SAML_METADATA or qn.localname != "EntitiesDescriptor":
            return SignatureVerificationResult(
                status=SignatureStatus.ERROR,
                message="Unsupported root element (expected md:EntitiesDescriptor).",
                root_tag=root_tag,
            )

        meta_id = root.attrib.get("ID")
        meta_name = root.attrib.get("Name")
        valid_until = _parse_valid_until(root.attrib.get("validUntil"))

        # locate signature
        sig_nodes = root.xpath("./ds:Signature", namespaces=NS_MAP)
        if len(sig_nodes) != 1:
            return SignatureVerificationResult(
                status=SignatureStatus.UNSIGNED,
                message="No (or multiple) ds:Signature found on EntitiesDescriptor.",
                root_tag=root_tag,
                metadata_id=meta_id,
                metadata_name=meta_name,
                valid_until=valid_until,
                is_stale=(valid_until is not None and valid_until < now_utc),
                signature_nodes=len(sig_nodes),
            )

        signature_node = sig_nodes[0]

        cert_pem = (signing_cert.certificate_data or "").strip()
        if not cert_pem:
            return SignatureVerificationResult(
                status=SignatureStatus.ERROR,
                message="Signing certificate is empty.",
                root_tag=root_tag,
                metadata_id=meta_id,
                metadata_name=meta_name,
                valid_until=valid_until,
                is_stale=(valid_until is not None and valid_until < now_utc),
                signature_nodes=1,
            )

        _ensure_cert_pem_is_valid(cert_pem)

        # Register ID attribute for xmlsec reference resolution
        xmlsec.tree.add_ids(root, ["ID"])

        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(
            cert_pem,
            xmlsec.constants.KeyDataFormatCertPem,
            None,
        )
        ctx.key = key

        try:
            ctx.verify(signature_node)
        except xmlsec.Error as exc:
            return SignatureVerificationResult(
                status=SignatureStatus.INVALID,
                message=f"Signature verification failed: {exc!s}",
                root_tag=root_tag,
                metadata_id=meta_id,
                metadata_name=meta_name,
                valid_until=valid_until,
                is_stale=(valid_until is not None and valid_until < now_utc),
                signature_nodes=1,
            )

        stale = valid_until is not None and valid_until < now_utc
        return SignatureVerificationResult(
            status=SignatureStatus.STALE if stale else SignatureStatus.OK,
            message="Signature verified." + (" (validUntil is in the past)" if stale else ""),
            root_tag=root_tag,
            metadata_id=meta_id,
            metadata_name=meta_name,
            valid_until=valid_until,
            is_stale=stale,
            signature_nodes=1,
        )

    except Exception as exc:
        return SignatureVerificationResult(
            status=SignatureStatus.INVALID,
            message=f"Signature verification failed: {exc!s}",
        )
