from django.test import TestCase

from authentik.providers.saml.processors.feed import (
    EntityDescriptorItem,
    iter_entity_descriptors,
)

XML_SINGLE_ENTITY = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                    entityID="https://sp.example.org/metadata">
</md:EntityDescriptor>
"""

XML_ENTITIES_TWO = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Name="root">
  <md:EntityDescriptor entityID="https://sp1.example.org/metadata"/>
  <md:EntityDescriptor entityID="https://sp2.example.org/metadata"/>
</md:EntitiesDescriptor>
"""

XML_ENTITIES_NESTED = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Name="root">
  <md:EntitiesDescriptor Name="sub">
    <md:EntityDescriptor entityID="https://nested.example.org/metadata"/>
  </md:EntitiesDescriptor>
</md:EntitiesDescriptor>
"""

XML_ENTITIES_WITH_SIGNATURE_NODE = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                      xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Name="root">
  <ds:Signature/>
  <md:EntityDescriptor entityID="https://sp.example.org/metadata"/>
</md:EntitiesDescriptor>
"""

XML_UNSUPPORTED_ROOT = """<?xml version="1.0" encoding="UTF-8"?>
<foo xmlns="urn:example">nope</foo>
"""


class TestFeedUnwrap(TestCase):
    def test_single_entity_descriptor(self):
        items = list(iter_entity_descriptors(XML_SINGLE_ENTITY))
        self.assertEqual(len(items), 1)

        it = items[0]
        self.assertIsInstance(it, EntityDescriptorItem)
        self.assertEqual(it.entity_id, "https://sp.example.org/metadata")
        self.assertFalse(it.from_aggregate)
        self.assertEqual(it.container_name_chain, ())

    def test_entities_descriptor_two_entities(self):
        items = list(iter_entity_descriptors(XML_ENTITIES_TWO))
        self.assertEqual(
            [i.entity_id for i in items],
            [
                "https://sp1.example.org/metadata",
                "https://sp2.example.org/metadata",
            ],
        )
        self.assertTrue(all(i.from_aggregate for i in items))
        self.assertEqual(items[0].container_name_chain, ("root",))
        self.assertEqual(items[1].container_name_chain, ("root",))

    def test_entities_descriptor_nested(self):
        items = list(iter_entity_descriptors(XML_ENTITIES_NESTED))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].entity_id, "https://nested.example.org/metadata")
        # chain は root -> sub
        self.assertEqual(items[0].container_name_chain, ("root", "sub"))
        self.assertTrue(items[0].from_aggregate)

    def test_entities_descriptor_ignores_other_nodes(self):
        items = list(iter_entity_descriptors(XML_ENTITIES_WITH_SIGNATURE_NODE))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].entity_id, "https://sp.example.org/metadata")

    def test_unsupported_root_raises(self):
        with self.assertRaises(ValueError):
            list(iter_entity_descriptors(XML_UNSUPPORTED_ROOT))
