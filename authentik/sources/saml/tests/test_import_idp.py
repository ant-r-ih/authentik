# authentik/sources/saml/tests/test_import_idp.py

from __future__ import annotations

from django.test import TestCase

from authentik.core.tests.utils import create_test_flow
from authentik.lib.generators import generate_id
from authentik.lib.tests.utils import load_fixture
from authentik.providers.saml.processors.feed import iter_entity_descriptors
from authentik.sources.saml.models import SAMLIDP, SAMLSource
from authentik.sources.saml.processors.import_idp import import_idp_from_entity_descriptor

FIXTURE_XML = "fixtures/gakunin-metadata.xml"

# Candidate IdPs (may or may not exist in fixture depending on version)
ENTITY_NII_IDP = "https://idp.nii.ac.jp/idp/shibboleth"
ENTITY_RIKEN_IDP = "https://sh-idp.riken.jp/idp/shibboleth"


def _is_idp_entity(entity) -> bool:
    # Minimal + robust: IDPSSODescriptor exists => IdP
    # entity is lxml Element (EntityDescriptor)
    return (
        entity.find(
            ".//md:IDPSSODescriptor",
            namespaces={"md": "urn:oasis:names:tc:SAML:2.0:metadata"},
        )
        is not None
    )

class TestImportIDPFromGakunin(TestCase):
    def setUp(self):
        self.source = SAMLSource.objects.create(
            name=generate_id(),
            slug=generate_id(),
            issuer="authentik",
            allow_idp_initiated=False,
            sso_url="https://default.example/sso",
            pre_authentication_flow=create_test_flow(),
        )

    def _get_entity_or_fallback(self, raw: str, wanted: list[str]) -> list:
        """Return up to 2 IdP EntityDescriptor elements.
        Prefer wanted entityIDs, else fallback to first two IdPs in fixture.
        """
        found = []
        wanted_set = set(wanted)

        # 1) try pick wanted entityIDs
        for item in iter_entity_descriptors(raw):
            if item.entity_id not in wanted_set:
                continue
            if not _is_idp_entity(item.xml):
                self.fail(f"Entity {item.entity_id} exists but is not an IdP")
            found.append(item.xml)
            if len(found) >= 2:
                return found

        # 2) fallback to first two IdPs in fixture
        for item in iter_entity_descriptors(raw):
            if not _is_idp_entity(item.xml):
                continue
            found.append(item.xml)
            if len(found) >= 2:
                return found

        self.fail("No IdP EntityDescriptor found in fixture")

    def test_import_two_idps_from_gakunin_fixture(self):
        raw = load_fixture(FIXTURE_XML)
        ent1, ent2 = self._get_entity_or_fallback(raw, [ENTITY_NII_IDP, ENTITY_RIKEN_IDP])

        # --- Import #1
        idp1, created1 = import_idp_from_entity_descriptor(
            source=self.source,
            entity=ent1,
            enabled=True,
        )
        self.assertTrue(created1)
        self.assertEqual(idp1.source_id, self.source.pk)
        self.assertTrue(idp1.entity_id)
        self.assertTrue(idp1.enabled)

        # snapshot fields (SAMLSP方式)
        self.assertIsNotNone(idp1.metadata_snapshot)
        self.assertIsInstance(idp1.metadata_snapshot, dict)
        self.assertTrue(idp1.metadata_hash)
        self.assertIsNotNone(idp1.metadata_last_import)

        # extracted endpoints
        self.assertTrue(idp1.sso_url)

        # verification_kp is optional depending on entity
        if idp1.verification_kp_id:
            self.assertTrue(idp1.verification_kp.certificate_data)

        # --- Import #2
        idp2, created2 = import_idp_from_entity_descriptor(
            source=self.source,
            entity=ent2,
            enabled=True,
        )
        self.assertTrue(created2)
        self.assertEqual(idp2.source_id, self.source.pk)
        self.assertTrue(idp2.entity_id)
        self.assertTrue(idp2.sso_url)
        self.assertIsNotNone(idp2.metadata_hash)

        self.assertEqual(SAMLIDP.objects.filter(source=self.source).count(), 2)

        # --- Import again should update, not create (enabled flag flips)
        idp1b, created1b = import_idp_from_entity_descriptor(
            source=self.source,
            entity=ent1,
            enabled=False,
        )
        self.assertFalse(created1b)
        idp1b.refresh_from_db()
        self.assertFalse(idp1b.enabled)

        idp2b, created2b = import_idp_from_entity_descriptor(
            source=self.source,
            entity=ent2,
            enabled=False,
        )
        self.assertFalse(created2b)
        idp2b.refresh_from_db()
        self.assertFalse(idp2b.enabled)
