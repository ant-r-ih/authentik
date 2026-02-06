# authentik/providers/saml/processors/feed.py

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from defusedxml.lxml import fromstring
from lxml import etree  # nosec

from authentik.sources.saml.processors.constants import (
    NS_SAML_METADATA,
)

NS_MAP = {"md": NS_SAML_METADATA}


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
        node: etree._Element, chain: tuple[str, ...], aggregated: bool
    ) -> Iterator[EntityDescriptorItem]:
        qn = etree.QName(node)
        if qn.namespace != NS_SAML_METADATA:
            # If the root isn't md:* then it's not SAML2 metadata aggregate.
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
        next_chain = chain + ((name,) if name else tuple())

        for child in node:
            if not isinstance(child.tag, str):
                continue
            cqn = etree.QName(child)
            if cqn.namespace != NS_SAML_METADATA:
                # ignore Signature/Extensions/other namespaces
                continue
            if cqn.localname in ("EntityDescriptor", "EntitiesDescriptor"):
                yield from walk(child, next_chain, True)

    yield from walk(root, (), False)


def is_idp_entity(entity: etree._Element) -> bool:
    """Return True if EntityDescriptor contains an IDPSSODescriptor."""
    return bool(entity.xpath(".//md:IDPSSODescriptor", namespaces=NS_MAP))


def is_sp_entity(entity: etree._Element) -> bool:
    """Return True if EntityDescriptor contains an SPSSODescriptor."""
    return bool(entity.xpath(".//md:SPSSODescriptor", namespaces=NS_MAP))
