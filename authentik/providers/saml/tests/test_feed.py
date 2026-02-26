from datetime import datetime, timezone

from django.test import TestCase

from authentik.crypto.models import CertificateKeyPair, format_cert
from authentik.lib.tests.utils import load_fixture
from authentik.providers.saml.processors.feed import (
    NS_MAP,
    EntityDescriptorItem,
    SignatureStatus,
    is_idp_entity,
    is_sp_entity,
    iter_entity_descriptors,
    summarize_entity_descriptor,
    verify_entities_descriptor_signature,
)

#FIXTURE_XML = "fixtures/edugain-v2-20250822.xml"
#EXPECTED_TOTAL = 9907
#EXPECTED_IDP = 6096
#EXPECTED_SP = 3829

FIXTURE_XML = "fixtures/gakunin-metadata.xml"
EXPECTED_TOTAL = 641
EXPECTED_IDP = 410
EXPECTED_SP = 231

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

def _kp_from_entitiesdescriptor_x509(raw: str) -> CertificateKeyPair:
    from defusedxml.lxml import fromstring

    root = fromstring(raw.encode("utf-8"))
    nodes = root.xpath("./ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()", namespaces=NS_MAP)
    if not nodes:
        raise AssertionError("fixture does not include ds:X509Certificate")
    pem = format_cert(nodes[0])
    return CertificateKeyPair(certificate_data=pem)

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

        self.assertEqual(len(items), EXPECTED_TOTAL)
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
        for item in items:
            if item["entity_id"] == "https://secure.nature.com/shibboleth":
                break
        self.assertEqual(
            item,
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
        for item in items:
            if item["entity_id"] == "https://atlases.muni.cz/shibboleth":
                break
        self.assertEqual(item["certs"]["encryption"], 4)
    def test_signature_unsigned(self):
        raw = """<?xml version="1.0" encoding="UTF-8"?>
        <md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="X" Name="root">
          <md:EntityDescriptor entityID="https://sp.example.org/metadata"/>
        </md:EntitiesDescriptor>
        """
        kp = CertificateKeyPair(certificate_data="")  # unused
        r = verify_entities_descriptor_signature(raw, signing_cert=kp)
        self.assertEqual(r.status, SignatureStatus.UNSIGNED)

    def test_signature_ok(self):
        raw = load_fixture(FIXTURE_XML)
        kp = _kp_from_entitiesdescriptor_x509(raw)

        r = verify_entities_descriptor_signature(raw, signing_cert=kp)
        self.assertEqual(r.status, SignatureStatus.OK)
        self.assertIsNotNone(r.valid_until)
        self.assertFalse(r.is_stale)

    def test_signature_stale(self):
        raw = load_fixture(FIXTURE_XML)
        kp = _kp_from_entitiesdescriptor_x509(raw)

        now_utc = datetime(2100, 1, 1, tzinfo=timezone.utc)

        r = verify_entities_descriptor_signature(raw, signing_cert=kp, now_utc=now_utc)
        self.assertEqual(r.status, SignatureStatus.STALE)
        self.assertTrue(r.is_stale)

    def test_signature_invalid_wrong_cert(self):
        raw = load_fixture(FIXTURE_XML)
        kp_good = _kp_from_entitiesdescriptor_x509(raw)

        bad_pem = kp_good.certificate_data.replace("A", "B", 1)
        kp_bad = CertificateKeyPair(certificate_data=bad_pem)

        r = verify_entities_descriptor_signature(raw, signing_cert=kp_bad)
        self.assertEqual(r.status, SignatureStatus.INVALID)

    def test_signature_error_missing_id_attribute(self):
        raw = load_fixture(FIXTURE_XML)

        raw2 = raw.replace(' ID="', ' ID_REMOVED="', 1)

        kp = _kp_from_entitiesdescriptor_x509(raw)
        r = verify_entities_descriptor_signature(raw2, signing_cert=kp)

        self.assertIn(r.status, {SignatureStatus.ERROR, SignatureStatus.INVALID})
