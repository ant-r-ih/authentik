from __future__ import annotations

from io import BytesIO

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import (
    create_test_admin_user,
    create_test_flow,
    generate_id,
)
from authentik.crypto.models import CertificateKeyPair, CertificateReference
from authentik.lib.tests.utils import load_fixture
from authentik.providers.saml.models import SAMLSP, SAMLProvider
from authentik.providers.saml.utils.certrefs import REF_MODEL_SAML_SP

FIXTURE_XML = "fixtures/gakunin-metadata.xml"

# Known SP entityIDs in your existing fixture assertions
ENTITY_ID_NATURE = "https://secure.nature.com/shibboleth"
ENTITY_ID_ATLASES = "https://atlases.muni.cz/shibboleth"


class TestSAMLMetadataCatalogAndImportAPI(APITestCase):
    """API integration-ish tests: catalog(upload) -> entity -> import SP -> update SP."""

    def setUp(self) -> None:
        super().setUp()
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

        self.provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            # Keep minimal required fields aligned with your model
            acs_url="http://localhost/source/saml/provider/acs/",
        )

        self.raw = load_fixture(FIXTURE_XML).encode("utf-8")

    def _upload_file(self, name: str = "gakunin.xml") -> BytesIO:
        """Build an in-memory file-like object for multipart upload."""
        bio = BytesIO(self.raw)
        bio.name = name  # DRF uses .name for multipart
        return bio

    def _catalog_preview(self, *, kind: str = "sp"):
        """Call POST /providers/saml/catalog/preview/ with multipart upload."""
        url = reverse("authentik_api:saml-metadata-catalog-preview")
        resp = self.client.post(
            url + f"?kind={kind}",
            data={"file": self._upload_file()},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        return resp.json()

    def _catalog_entity(self, entity_id: str):
        """Call POST /providers/saml/catalog/entity/ and return entity xml."""
        url = reverse("authentik_api:saml-metadata-catalog-entity")
        resp = self.client.post(
            url,
            data={"file": self._upload_file(), "entity_id": entity_id},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        body = resp.json()
        self.assertEqual(body["entity_id"], entity_id)
        self.assertIn("xml", body)
        return body["xml"]

    def _import_sp(self, *, entity_xml: str, enabled: bool, overwrite: bool):
        """
        Call POST /providers/samlsp/import/ (or whatever your import endpoint is).
        Expected response: 201(created) or 200(updated), plus created flag in body.
        """
        url = reverse("authentik_api:samlsp-import-list")
        resp = self.client.post(
            url,
            data={
                "provider": str(self.provider.pk),
                "entity_xml": entity_xml,
                "enabled": enabled,
                "overwrite": overwrite,
            },
            format="json",
        )
        self.assertIn(resp.status_code, (200, 201), resp.content)
        return resp

    def _assert_sp_has_verification_certref(self, sp: SAMLSP):
        """Ensure CertificateReference exists and fingerprint matches the KP."""
        sp.refresh_from_db()
        if sp.verification_kp is None:
            self.fail("Expected sp.verification_kp to be set")

        kp: CertificateKeyPair = sp.verification_kp

        qs = CertificateReference.objects.filter(
            ref_model=REF_MODEL_SAML_SP,
            ref_pk=str(sp.pk),
            usage=CertificateReference.Usage.SAML_VERIFICATION,
            certificate_id=str(kp.pk),
        )
        self.assertEqual(qs.count(), 1, "Expected exactly one verification CertificateReference")

        ref = qs.first()
        self.assertIsNotNone(ref)
        self.assertEqual(ref.fingerprint_sha256.lower(), kp.fingerprint_sha256.lower())

    def test_catalog_preview_entity_import_and_update_two_sps(self):
        """
        End-to-end-ish flow:
          1) preview SP entries from uploaded metadata
          2) fetch EntityDescriptor XML for 2 known SPs
          3) import -> creates SAMLSP (201)
          4) re-import with overwrite -> updates SAMLSP (200)
          5) certref rows exist and match KP fingerprints
        """
        preview = self._catalog_preview(kind="sp")

        entity_ids = {x["entity_id"] for x in preview}
        self.assertIn(ENTITY_ID_NATURE, entity_ids)
        self.assertIn(ENTITY_ID_ATLASES, entity_ids)

        # --- Import Nature
        xml_nature = self._catalog_entity(ENTITY_ID_NATURE)

        before_kp_count = CertificateKeyPair.objects.count()
        resp1 = self._import_sp(entity_xml=xml_nature, enabled=True, overwrite=False)
        self.assertEqual(resp1.status_code, 201, resp1.content)

        # If your endpoint returns {"created": true, "sp": {...}}, assert it here:
        # self.assertTrue(body1["created"])
        # sp_pk_1 = body1["sp"]["pk"]
        # Otherwise fall back to DB lookup:
        sp1 = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_NATURE)

        self._assert_sp_has_verification_certref(sp1)
        self.assertGreaterEqual(CertificateKeyPair.objects.count(), before_kp_count)

        # Re-import Nature with overwrite -> should update, not create a new SP
        resp1b = self._import_sp(entity_xml=xml_nature, enabled=False, overwrite=True)
        self.assertEqual(resp1b.status_code, 200, resp1b.content)

        sp1.refresh_from_db()
        self.assertFalse(sp1.enabled)

        # --- Import Atlases (more complex cert set)
        xml_atlases = self._catalog_entity(ENTITY_ID_ATLASES)

        resp2 = self._import_sp(entity_xml=xml_atlases, enabled=True, overwrite=False)
        self.assertEqual(resp2.status_code, 201, resp2.content)

        sp2 = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_ATLASES)
        self._assert_sp_has_verification_certref(sp2)

        # Re-import Atlases -> update
        resp2b = self._import_sp(entity_xml=xml_atlases, enabled=True, overwrite=True)
        self.assertEqual(resp2b.status_code, 200, resp2b.content)

        # Sanity: still 2 SPs for this provider+entity_ids
        self.assertEqual(
            SAMLSP.objects.filter(
                provider=self.provider, entity_id__in=[ENTITY_ID_NATURE, ENTITY_ID_ATLASES]
            ).count(),
            2,
        )
