# authentik/sources/saml/processors/idp_extract.py
from __future__ import annotations

from lxml import etree  # nosec

from authentik.providers.saml.processors.feed_extract import NS_MAP


def extract_idp_descriptor(entity: etree._Element) -> etree._Element:
    """Return IDPSSODescriptor element from EntityDescriptor."""
    # Prefer SAML2.0 IdPSSODescriptor
    idp = entity.find(".//md:IDPSSODescriptor", namespaces=NS_MAP)
    if idp is None:
        raise ValueError("EntityDescriptor missing IDPSSODescriptor")
    return idp


def extract_idp_sso_url(idp_desc: etree._Element) -> str:
    """Pick SingleSignOnService Location (prefer HTTP-Redirect then POST)."""
    # Prefer Redirect binding
    n = idp_desc.find(
        "./md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']",
        namespaces=NS_MAP,
    )
    if n is None:
        n = idp_desc.find(
            "./md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']",
            namespaces=NS_MAP,
        )
    if n is None:
        n = idp_desc.find("./md:SingleSignOnService", namespaces=NS_MAP)
    if n is None or "Location" not in n.attrib:
        raise ValueError("IDPSSODescriptor missing SingleSignOnService Location")
    return n.attrib["Location"]


def extract_idp_slo_url(idp_desc: etree._Element) -> str | None:
    """Pick SingleLogoutService Location if present."""
    n = idp_desc.find(
        "./md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']",
        namespaces=NS_MAP,
    )
    if n is None:
        n = idp_desc.find(
            "./md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']",
            namespaces=NS_MAP,
        )
    if n is None:
        n = idp_desc.find("./md:SingleLogoutService", namespaces=NS_MAP)
    if n is None:
        return None
    return n.attrib.get("Location")
