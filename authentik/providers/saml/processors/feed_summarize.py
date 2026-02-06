# authentik/providers/saml/processors/feed_summarize.py

from __future__ import annotations

from typing import Any

from lxml import etree  # nosec

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

# Map full Binding URIs -> short token used by your API
BINDING_URI_TO_TOKEN = {
    SAML_BINDING_POST: "post",
    SAML_BINDING_REDIRECT: "redirect",
    # add more if you care
}


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
    seen = set()
    out: list[str] = []
    for v in vals:
        if v not in seen:
            out.append(v)
            seen.add(v)
    return out


def _extract_acs_list(sp_descriptor: etree._Element) -> list[dict[str, Any]]:
    """
    Extract AssertionConsumerService entries.
    """
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
    """
    Extract SingleLogoutService entries.
    Works for both SPSSODescriptor and IDPSSODescriptor.
    """
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
      - This counts certificates (X509Certificate), not KeyDescriptor nodes.
      - We de-duplicate by certificate text within each use bucket.
    """
    buckets: dict[str, set[str]] = {"signing": set(), "encryption": set(), "unspecified": set()}

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
    """
    Optional: OrganizationDisplayName from metadata (nice for UI).
    """
    # Keep it minimal; your feed might use multiple languages etc.
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
    sp_desc = entity.xpath("./md:SPSSODescriptor", namespaces=NS_MAP)
    idp_desc = entity.xpath("./md:IDPSSODescriptor", namespaces=NS_MAP)

    kind: list[str] = []
    if sp_desc:
        kind.append("sp")
    if idp_desc:
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
            # keep it small here; you can add fingerprints later
            "signing": 0,
            "encryption": 0,
            "unspecified": 0,
        },
    }

    # SP summary (use first descriptor for now)
    if sp_desc:
        sp0 = sp_desc[0]
        sp_key_counts = _count_x509_certs(sp0)

        summary["sp"] = {
            "acs": _extract_acs_list(sp0),
            "sls": _extract_sls_list(sp0),
            "authn_requests_signed": _get_bool_attr(sp0, "AuthnRequestsSigned", False),
            "want_assertions_signed": _get_bool_attr(sp0, "WantAssertionsSigned", False),
            "name_id_formats": _extract_nameid_formats(sp0),
        }
        # merge counts
        for k, v in sp_key_counts.items():
            summary["certs"][k] = summary["certs"].get(k, 0) + v

    # IdP summary (use first descriptor for now)
    if idp_desc:
        idp0 = idp_desc[0]
        idp_key_counts = _count_x509_certs(idp0)

        summary["idp"] = {
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
        # merge counts
        for k, v in idp_key_counts.items():
            summary["certs"][k] = summary["certs"].get(k, 0) + v

    return summary
