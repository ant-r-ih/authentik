# authentik/providers/saml/tests/test_import_sp.py

from __future__ import annotations

from django.test import TestCase

from authentik.core.tests.utils import create_test_flow
from authentik.crypto.models import CertificateReference
from authentik.lib.generators import generate_id
from authentik.lib.tests.utils import load_fixture
from authentik.providers.saml.models import SAMLSP, SAMLBindings, SAMLProvider
from authentik.providers.saml.processors.feed import is_sp_entity, iter_entity_descriptors
from authentik.providers.saml.processors.import_sp import import_sp_from_entity_descriptor
from authentik.providers.saml.utils.certrefs import REF_MODEL_SAML_SP

FIXTURE_XML = "fixtures/gakunin-metadata.xml"

# Stable sample SPs from the existing feed_summarize test
ENTITY_NATURE = "https://secure.nature.com/shibboleth"
ENTITY_ATLASES = "https://atlases.muni.cz/shibboleth"


class TestImportSPFromGakunin(TestCase):
    def _get_entity(self, raw: str, entity_id: str):
        # Find the EntityDescriptor by entityID, and ensure it's an SP.
        for item in iter_entity_descriptors(raw):
            if item.entity_id != entity_id:
                continue
            if not is_sp_entity(item.xml):
                self.fail(f"Entity {entity_id} exists but is not an SP")
            return item.xml
        self.fail(f"Entity {entity_id} not found in fixture")

    def _assert_cert_ref_exists(self, sp: SAMLSP, *, count: int = 1):
        qs = CertificateReference.objects.filter(
            ref_model=REF_MODEL_SAML_SP,
            ref_pk=str(sp.pk),
            usage=CertificateReference.Usage.SAML_VERIFICATION,
        )
        self.assertEqual(
            qs.count(),
            count,
            msg=f"Expected {count} CertificateReference rows for SAMLSP {sp.pk}, got {qs.count()}",
        )
        if count > 0:
            # fingerprint_sha256 is required in your model; ensure it's populated.
            self.assertTrue(qs.first().fingerprint_sha256)

    def test_import_two_sps_from_gakunin_fixture(self):
        raw = load_fixture(FIXTURE_XML)

        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",  # whatever required by your model/validators
        )

        ent_nature = self._get_entity(raw, ENTITY_NATURE)
        ent_atlases = self._get_entity(raw, ENTITY_ATLASES)

        # --- Import #1: Nature
        sp1, created1 = import_sp_from_entity_descriptor(
            provider=provider, entity=ent_nature, enabled=True
        )
        self.assertTrue(created1)
        self.assertEqual(sp1.provider_id, provider.pk)
        self.assertEqual(sp1.entity_id, ENTITY_NATURE)
        self.assertTrue(sp1.enabled)
        self.assertTrue(sp1.acs_url)
        self.assertIn(sp1.sp_binding, (SAMLBindings.POST, SAMLBindings.REDIRECT))

        # verification_kp may be None for some entities, but Nature usually has KeyDescriptor.
        # If you want strictness: assertIsNotNone(sp1.verification_kp)
        self._assert_cert_ref_exists(sp1, count=1 if sp1.verification_kp_id else 0)

        # --- Import #2: Atlases
        sp2, created2 = import_sp_from_entity_descriptor(
            provider=provider, entity=ent_atlases, enabled=True
        )
        self.assertTrue(created2)
        self.assertEqual(sp2.entity_id, ENTITY_ATLASES)
        self.assertTrue(sp2.acs_url)
        self._assert_cert_ref_exists(sp2, count=1 if sp2.verification_kp_id else 0)

        self.assertEqual(SAMLSP.objects.filter(provider=provider).count(), 2)

        # --- Import again should update, not create
        sp1b, created1b = import_sp_from_entity_descriptor(
            provider=provider, entity=ent_nature, enabled=False
        )
        self.assertFalse(created1b)
        sp1b.refresh_from_db()
        self.assertFalse(sp1b.enabled)  # proves update path executed

        sp2b, created2b = import_sp_from_entity_descriptor(
            provider=provider, entity=ent_atlases, enabled=False
        )
        self.assertFalse(created2b)
        sp2b.refresh_from_db()
        self.assertFalse(sp2b.enabled)
