from __future__ import annotations

from io import BytesIO

from django.urls import reverse
from lxml import etree
from rest_framework.test import APITestCase

from authentik.admin.files.manager import get_file_manager
from authentik.admin.files.usage import FileUsage
from authentik.core.tests.utils import (
    create_test_admin_user,
    create_test_cert,
    create_test_flow,
    generate_id,
)
from authentik.crypto.models import CertificateKeyPair, CertificateReference
from authentik.lib.tests.utils import load_fixture
from authentik.providers.saml.models import SAMLSP, SAMLBindings, SAMLProvider, SAMLSPMetadataState
from authentik.providers.saml.utils.certrefs import REF_MODEL_SAML_SP
from authentik.sources.saml.processors.constants import NS_MAP

FIXTURE_XML = "fixtures/gakunin-metadata.xml"

# Known SP entityIDs in your existing fixture assertions
ENTITY_ID_NATURE = "https://secure.nature.com/shibboleth"
ENTITY_ID_ATLASES = "https://atlases.muni.cz/shibboleth"
ENTITY_ID_EDUROAM = "https://federated-id.eduroam.jp/shibboleth-sp"


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
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(
            url + f"?kind={kind}",
            data={"file": self._upload_file()},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        return resp.json()

    def _catalog_entity(self, entity_id: str):
        """Call POST /providers/saml/catalog/entity/ and return entity xml."""
        url = reverse("authentik_api:saml-catalog-entity")
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
        url = reverse("authentik_api:samlsp-import-metadata")
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

    def _assert_sp_has_encryption_certref(self, sp: SAMLSP):
        """Ensure CertificateReference exists and fingerprint matches the KP."""
        sp.refresh_from_db()
        if sp.encryption_kp is None:
            self.fail("Expected sp.encryption_kp to be set")

        kp: CertificateKeyPair = sp.encryption_kp

        qs = CertificateReference.objects.filter(
            ref_model=REF_MODEL_SAML_SP,
            ref_pk=str(sp.pk),
            usage=CertificateReference.Usage.SAML_ENCRYPTION,
            certificate_id=str(kp.pk),
        )
        self.assertEqual(qs.count(), 1, "Expected exactly one encryption CertificateReference")

        ref = qs.first()
        self.assertIsNotNone(ref)
        self.assertEqual(ref.fingerprint_sha256.lower(), kp.fingerprint_sha256.lower())
    def _strip_x509_certs(self, entity_xml: str) -> str:
        root = etree.fromstring(entity_xml.encode("utf-8"))
        for el in root.xpath("//ds:X509Certificate", namespaces=NS_MAP):
            parent = el.getparent()
            if parent is not None:
                parent.remove(el)
        return etree.tostring(root, encoding="unicode")

    def test_runtime_db_basis_unchanged_after_import(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_NATURE, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=False)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_NATURE)
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.UNCHANGED)

    def test_runtime_db_basis_diverged_when_runtime_modified(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_NATURE, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=False)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_NATURE)
        sp.acs_url = "https://evil.example.com/acs"
        sp.save(update_fields=["acs_url"])

        sp.refresh_from_db()
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.DIVERGED)

    def test_apply_metadata_resets_runtime_db_basis_diverged(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_NATURE, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=False)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_NATURE)
        sp.acs_url = "https://evil.example.com/acs"
        sp.sls_binding = SAMLBindings.REDIRECT
        sp.save(update_fields=["acs_url"])
        sp.refresh_from_db()
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.DIVERGED)

        url = reverse("authentik_api:samlsp-apply-metadata", args=[sp.uuid])
        self.client.post(url)

        sp.refresh_from_db()
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.UNCHANGED)

    def test_kp_presence_matches_snapshot_after_import(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_NATURE, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=False)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_NATURE)

        # expected presence from snapshot
        exp_ver = bool(sp.metadata_snapshot.get("has_verification_cert"))
        exp_enc = bool(sp.metadata_snapshot.get("has_encryption_cert"))

        # current presence from runtime fields
        cur_ver = sp.verification_kp_id is not None
        cur_enc = sp.encryption_kp_id is not None

        self.assertEqual(exp_ver, cur_ver)
        self.assertEqual(exp_enc, cur_enc)
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.UNCHANGED)

    def test_cert_rotation_does_not_change_state_when_presence_same(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_ATLASES, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=False)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_ATLASES)
        self.assertIsNotNone(sp.verification_kp_id)

        # create another cert KP (use existing helper create_test_cert without kwargs)
        new_kp = create_test_cert()

        sp.verification_kp = new_kp
        sp.save(update_fields=["verification_kp"])

        sp.refresh_from_db()
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.UNCHANGED)

    def test_kp_presence_change_marks_diverged(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_ATLASES, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=False)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_ATLASES)
        self.assertIsNotNone(sp.verification_kp_id)

        sp.verification_kp = None
        sp.save(update_fields=["verification_kp"])

        sp.refresh_from_db()
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.DIVERGED)

    def _save_metadata_to_files(self, name: str = "gakunin.xml") -> str:
        """
        Save fixture XML into authentik file storage under FileUsage.SAML_METADATA.
        Returns the relative path (metadata_name) to pass to API.
        """
        mgr = get_file_manager(FileUsage.SAML_METADATA)
        # simplest: single file at root
        mgr.save_file(name, self.raw)
        return name

    def _catalog_preview_by_name(self, *, kind: str = "sp", name: str = "gakunin.xml", provider: bool = False):
        url = reverse("authentik_api:saml-catalog-preview")
        qs = f"?kind={kind}"
        if provider:
            qs += f"&provider={self.provider.pk}"
        resp = self.client.post(
            url + qs,
            data={"metadata_name": name},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        return resp.json()

    def _catalog_entity_by_name(self, entity_id: str, *, name: str = "gakunin.xml", provider: bool = False) -> str:
        url = reverse("authentik_api:saml-catalog-entity")
        qs = ""
        if provider:
            qs = f"?provider={self.provider.pk}"
        resp = self.client.post(
            url + qs,
            data={"metadata_name": name, "entity_id": entity_id},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        body = resp.json()
        self.assertEqual(body["entity_id"], entity_id)
        self.assertIn("xml", body)
        return body["xml"]

    def test_catalog_preview_accepts_metadata_name(self):
        name = self._save_metadata_to_files("gakunin.xml")
        items = self._catalog_preview_by_name(kind="sp", name=name, provider=True)

        entity_ids = {it.get("entity_id") for it in items}
        self.assertIn(ENTITY_ID_NATURE, entity_ids)

        nature = next(it for it in items if it.get("entity_id") == ENTITY_ID_NATURE)
        self.assertIn("states", nature)
        self.assertIn("metadata", nature["states"])

    def test_catalog_entity_accepts_metadata_name(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_NATURE, name=name, provider=True)

        self.assertIn(ENTITY_ID_NATURE, xml)
        root = etree.fromstring(xml.encode("utf-8"))
        self.assertTrue(root.tag.endswith("EntityDescriptor"))

    def test_catalog_preview_requires_file_or_metadata_name(self):
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(url + "?kind=sp", data={}, format="json")
        self.assertEqual(resp.status_code, 400)

    def test_import_currupted_cert(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_EDUROAM, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=False)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_EDUROAM)
        self.assertEqual(sp.runtime_db_basis_state, SAMLSPMetadataState.DIVERGED)

    def test_import_sets_name_from_display_name_en(self):
        name = self._save_metadata_to_files("gakunin.xml")
        xml = self._catalog_entity_by_name(ENTITY_ID_NATURE, name=name, provider=True)
        self._import_sp(entity_xml=xml, enabled=True, overwrite=True)

        sp = SAMLSP.objects.get(provider=self.provider, entity_id=ENTITY_ID_NATURE)
        self.assertNotEqual(sp.name, sp.entity_id)
