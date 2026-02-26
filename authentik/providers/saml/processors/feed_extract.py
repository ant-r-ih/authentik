# authentik/providers/saml/processors/sp_extract.py

from __future__ import annotations

from base64 import b64decode
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_der_x509_certificate
from defusedxml.lxml import fromstring
from django.db import IntegrityError, transaction
from lxml import etree  # nosec

from authentik.crypto.models import CertificateKeyPair, fingerprint_sha256
from authentik.providers.saml.models import (
    SAMLBindings,
)
from authentik.sources.saml.processors.constants import (
    NS_SAML_METADATA,
    NS_SIGNATURE,
)

NS_MAP = {
    "md": NS_SAML_METADATA,
    "ds": NS_SIGNATURE,
}


def extract_sp_descriptor(entity: etree._Element) -> etree._Element:
    sp = entity.xpath("./md:SPSSODescriptor", namespaces=NS_MAP)
    if not sp:
        raise ValueError("EntityDescriptor has no SPSSODescriptor")
    return sp[0]


def extract_default_acs(sp: etree._Element) -> tuple[str, str]:
    """
    Return (acs_url, binding)
    """
    acs_list = sp.xpath("./md:AssertionConsumerService", namespaces=NS_MAP)
    if not acs_list:
        raise ValueError("SPSSODescriptor has no AssertionConsumerService")

    # Prefer isDefault=true, fallback to index=0, then first
    for acs in acs_list:
        if acs.attrib.get("isDefault", "").lower() == "true":
            return acs.attrib["Location"], acs.attrib["Binding"]

    for acs in acs_list:
        if acs.attrib.get("index") == "0":
            return acs.attrib["Location"], acs.attrib["Binding"]

    acs = acs_list[0]
    return acs.attrib["Location"], acs.attrib["Binding"]

def extract_x509_b64_list(
    sp_desc: etree._Element,
    *,
    use: str | None = None,
) -> list[str]:
    """
    Extract X509Certificate values from KeyDescriptor.

    Args:
        use:
            - "signing"
            - "encryption"
            - None  -> no @use filter (unspecified only)

    Returns:
        Ordered list (metadata order), duplicates removed.
    """
    if use == "signing":
        xp = "./md:KeyDescriptor[@use='signing']//ds:X509Certificate"
    elif use == "encryption":
        xp = "./md:KeyDescriptor[@use='encryption']//ds:X509Certificate"
    elif use is None:
        xp = "./md:KeyDescriptor[not(@use)]//ds:X509Certificate"
    else:
        raise ValueError("Invalid use value")

    out: list[str] = []
    seen: set[str] = set()

    for n in sp_desc.xpath(xp, namespaces=NS_MAP):
        txt = (n.text or "").strip()
        if txt and txt not in seen:
            out.append(txt)
            seen.add(txt)

    return out

def extract_preferred_x509_b64_list(
    sp_desc: etree._Element,
    *,
    preferred_uses: tuple[str, ...] = ("signing", "unspecified", "encryption"),
) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    for use in preferred_uses:
        if use == "unspecified":
            xp = "./md:KeyDescriptor[not(@use)]//ds:X509Certificate"
        else:
            xp = f"./md:KeyDescriptor[@use='{use}']//ds:X509Certificate"

        for n in sp_desc.xpath(xp, namespaces=NS_MAP):
            txt = (n.text or "").strip()
            if txt and txt not in seen:
                out.append(txt)
                seen.add(txt)

    return out


def get_or_create_cert_kp_from_x509_b64(*, x509_b64: str, name_prefix: str) -> CertificateKeyPair:
    """
    Get or create CertificateKeyPair from a base64 DER X.509 certificate.

    Dedupe strategy:
      - Deduplicate by SHA256 fingerprint of certificate_data (kp.fingerprint_sha256).
      - CertificateReference is NOT used for dedupe (it's usage tracking only).

    Notes:
      - We store certificate_data as PEM (authentik style).
      - Name is unique in the model, so we include the full fingerprint to avoid collisions.
    """
    cert_der = b64decode(x509_b64)
    cert = load_der_x509_certificate(cert_der, default_backend())

    fp = fingerprint_sha256(cert)  # e.g. "aa:bb:cc:..."
    fp_norm = fp.replace(":", "").lower()

    # 1) Try to reuse an existing keypair by fingerprint.
    # This is O(n) but acceptable for now; later you can add indexed fingerprint storage.
    for kp in CertificateKeyPair.objects.all():
        if kp.fingerprint_sha256.replace(":", "").lower() == fp_norm:
            return kp

    # 2) Create a new keypair (PEM-encoded certificate_data).
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    name = f"{name_prefix} {fp}"  # IMPORTANT: full fingerprint, do not shorten

    try:
        with transaction.atomic():
            return CertificateKeyPair.objects.create(
                name=name,
                certificate_data=pem,
            )
    except IntegrityError:
        # Another concurrent import (or buggy prior run) created the same name.
        # Fall back to fetching by name.
        return CertificateKeyPair.objects.get(name=name)


def parse_entity_descriptor_xml(entity_xml: str | bytes) -> etree._Element:
    """Parse a single md:EntityDescriptor XML (string/bytes) into an lxml element.

    Security:
      - Use defusedxml to mitigate XXE / billion laughs style attacks.
    """
    if isinstance(entity_xml, str):
        data = entity_xml.encode("utf-8")
    else:
        data = entity_xml

    try:
        el = fromstring(data)
    except (ValueError, etree.XMLSyntaxError) as exc:
        # Keep message stable for API clients/tests.
        raise ValueError("Invalid XML syntax") from exc

    qn = etree.QName(el)
    if qn.namespace != NS_SAML_METADATA or qn.localname != "EntityDescriptor":
        raise ValueError("Expected md:EntityDescriptor")

    entity_id = el.attrib.get("entityID")
    if not entity_id:
        raise ValueError("EntityDescriptor missing entityID")

    return el

def extract_all_acs(sp_desc: etree._Element) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for acs in sp_desc.findall(".//md:AssertionConsumerService", namespaces=NS_MAP):
        url = acs.attrib.get("Location")
        binding_uri = acs.attrib.get("Binding")

        if not url or not binding_uri:
            continue

        binding = normalize_binding(binding_uri)
        if not binding:
            continue

        index = int(acs.attrib.get("index", 0))

        results.append({
            "url": url,
            "binding": binding,
            "index": index,
        })

    results.sort(key=lambda x: x["index"])
    return results


def extract_all_sls(sp_desc: etree._Element) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    for sls in sp_desc.findall(".//md:SingleLogoutService", namespaces=NS_MAP):
        url = sls.attrib.get("Location")
        binding_uri = sls.attrib.get("Binding")

        if not url or not binding_uri:
            continue

        binding = normalize_binding(binding_uri)
        if not binding:
            continue

        results.append({
            "url": url,
            "binding": binding,
        })

    return results

def normalize_binding(binding_uri: str) -> str | None:
    if "HTTP-POST" in binding_uri:
        return SAMLBindings.POST
    if "HTTP-Redirect" in binding_uri:
        return SAMLBindings.REDIRECT
    return None

def pick_default_acs(acs_list: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not acs_list:
        return None

    for acs in acs_list:
        if acs["binding"] == SAMLBindings.POST:
            return acs

    return acs_list[0]


def pick_default_sls(sls_list: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not sls_list:
        return None
    return sls_list[0]


# ============================================================
# Certificate selection
# ============================================================

def _cert_validity_utc(cert) -> tuple[datetime, datetime]:
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

    if not certs_b64:
        return []

    if now is None:
        now = datetime.now(UTC)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    parsed = []

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
        return list(certs_b64)

    valid = [c for c in parsed if c[1] <= now <= c[2]]

    if valid:
        valid.sort(key=lambda c: (c[2], c[3]), reverse=True)
        return [c[0] for c in valid]

    return [c[0] for c in parsed]
