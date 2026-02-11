from django.test import TestCase

from authentik.lib.tests.utils import load_fixture
from authentik.providers.saml.processors.feed import (
    EntityDescriptorItem,
    is_idp_entity,
    is_sp_entity,
    iter_entity_descriptors,
)
from authentik.providers.saml.processors.feed_summarize import summarize_entity_descriptor

# FIXTURE_XML = "fixtures/edugain-v2-20250822.xml"
# EXPECTED_TOTAL = 9907
# EXPECTED_IDP = 6096
# EXPECTED_SP = 3829

FIXTURE_XML = "fixtures/gakunin-metadata.xml"
EXPECTED_TOTAL = 636
EXPECTED_IDP = 404
EXPECTED_SP = 232

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
class TestCatalogUnwrap(TestCase):
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

class TestCatalogExtract(TestCase):
    def test_feed_counts_idp_sp(self):
        raw = load_fixture(FIXTURE_XML)
        items = list(iter_entity_descriptors(raw))

        idp = 0
        sp = 0
        both = 0
        neither = 0

        for it in items:
            is_idp = is_idp_entity(it.xml)
            is_sp = is_sp_entity(it.xml)
            if is_idp:
                idp += 1
            if is_sp:
                sp += 1
            if is_idp and is_sp:
                both += 1
            if not is_idp and not is_sp:
                neither += 1

        self.assertGreater(len(items), 0)

        self.assertEqual(len(items), EXPECTED_TOTAL)
        self.assertEqual(idp, EXPECTED_IDP)
        self.assertEqual(sp, EXPECTED_SP)

        self.assertEqual(both, 0)
        self.assertEqual(neither, 0)

    def test_feed_summarize(self):
        raw = load_fixture(FIXTURE_XML)
        items = []
        for item in iter_entity_descriptors(raw):
            summary = summarize_entity_descriptor(item.xml)
            summary["from_aggregate"] = item.from_aggregate
            summary["container_name_chain"] = list(item.container_name_chain)
            items.append(summary)

        self.assertEqual(len(items), 636)
        self.assertEqual(
            items[0],
            {
                "certs": {"encryption": 0, "signing": 0, "unspecified": 1},
                "container_name_chain": ["GakuNin"],
                "display_name": "National Institute of Informatics",
                "entity_id": "https://idp.nii.ac.jp/idp/shibboleth",
                "from_aggregate": True,
                "idp": {
                    "name_id_formats": [
                        "urn:mace:shibboleth:1.0:nameIdentifier",
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
                    ],
                    "sls": [],
                    "sso": [
                        {
                            "binding": "urn:mace:shibboleth:1.0:profiles:AuthnRequest",
                            "location": "https://idp.nii.ac.jp/idp/profile/Shibboleth/SSO",
                        },
                        {
                            "binding": "post",
                            "location": "https://idp.nii.ac.jp/idp/profile/SAML2/POST/SSO",
                        },
                        {
                            "binding": "redirect",
                            "location": "https://idp.nii.ac.jp/idp/profile/SAML2/Redirect/SSO",
                        },
                    ],
                    "want_authn_requests_signed": False,
                },
                "kind": ["idp"],
                "sp": None,
            },
        )
        self.assertEqual(
            items[459],
            {
                "certs": {"encryption": 1, "signing": 0, "unspecified": 0},
                "container_name_chain": ["GakuNin"],
                "display_name": "Nature Research",
                "entity_id": "https://secure.nature.com/shibboleth",
                "from_aggregate": True,
                "idp": None,
                "kind": ["sp"],
                "sp": {
                    "acs": [
                        {
                            "binding": "post",
                            "index": "0",
                            "is_default": True,
                            "location": "https://secure.nature.com/oa/auth/rcv/saml2/post",
                        },
                        {
                            "binding": "post",
                            "index": "1",
                            "is_default": False,
                            "location": "http://secure.nature.com/oa/auth/rcv/saml2/post",
                        },
                    ],
                    "authn_requests_signed": False,
                    "name_id_formats": [],
                    "sls": [],
                    "want_assertions_signed": False,
                },
            },
        )
        self.assertEqual(items[409]["certs"]["encryption"], 4)
