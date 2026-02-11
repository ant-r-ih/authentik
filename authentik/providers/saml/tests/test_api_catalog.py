# authentik/providers/saml/tests/test_catalog_api.py

from __future__ import annotations

import gzip

from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_flow, generate_id
from authentik.providers.saml.models import (
    SAMLSP,
    SAMLProvider,
    compute_signature_hash,
    normalize_signature,
)
from authentik.providers.saml.processors.feed import iter_entity_descriptors
from authentik.providers.saml.processors.feed_extract import (
    extract_all_acs,
    extract_all_sls,
    extract_sp_descriptor,
    extract_x509_b64_list,
)

# Minimal SAML2 metadata aggregate with:
# - one SP-only entity
# - one IDP-only entity
METADATA_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" Name="root">
  <md:EntitiesDescriptor Name="child">
    <md:EntityDescriptor entityID="https://sp.example.com">
      <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                          AuthnRequestsSigned="false"
                          WantAssertionsSigned="false">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                     Location="https://sp.example.com/acs"
                                     index="0"
                                     isDefault="true"/>
      </md:SPSSODescriptor>
    </md:EntityDescriptor>

    <md:EntityDescriptor entityID="https://idp.example.com">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="https://idp.example.com/sso"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
  </md:EntitiesDescriptor>
</md:EntitiesDescriptor>
"""


class TestSAMLMetadataCatalogAPI(APITestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

    def _upload(self) -> SimpleUploadedFile:
        return SimpleUploadedFile(
            "metadata.xml",
            METADATA_XML,
            content_type="application/xml",
        )

    def test_preview_any(self):
        """preview should return summaries for all EntityDescriptor entries."""
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(url, data={"file": self._upload()}, format="multipart")
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 2)

        entity_ids = {x["entity_id"] for x in body}
        self.assertIn("https://sp.example.com", entity_ids)
        self.assertIn("https://idp.example.com", entity_ids)

        # container_name_chain should exist (as list)
        for item in body:
            self.assertIn("container_name_chain", item)
            self.assertIsInstance(item["container_name_chain"], list)

    def test_preview_kind_filter_sp(self):
        """preview?kind=sp should return only SP entities."""
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(url + "?kind=sp", data={"file": self._upload()}, format="multipart")
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["entity_id"], "https://sp.example.com")
        self.assertIn("sp", body[0].get("kind", []))

    def test_preview_kind_filter_idp(self):
        """preview?kind=idp should return only IdP entities."""
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(
            url + "?kind=idp", data={"file": self._upload()}, format="multipart"
        )
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["entity_id"], "https://idp.example.com")
        self.assertIn("idp", body[0].get("kind", []))

    def test_entity_ok(self):
        """entity should return raw EntityDescriptor XML for requested entity_id."""
        url = reverse("authentik_api:saml-catalog-entity")
        resp = self.client.post(
            url,
            data={"file": self._upload(), "entity_id": "https://sp.example.com"},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        self.assertEqual(body["entity_id"], "https://sp.example.com")
        self.assertIn("xml", body)
        self.assertIsInstance(body["xml"], str)
        self.assertIn("EntityDescriptor", body["xml"])
        self.assertIn('entityID="https://sp.example.com"', body["xml"])
        self.assertIn("container_name_chain", body)

    def test_entity_not_found(self):
        """entity should 400 when entity_id is not present in upload."""
        url = reverse("authentik_api:saml-catalog-entity")
        resp = self.client.post(
            url,
            data={"file": self._upload(), "entity_id": "https://missing.example.com"},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 400, resp.content)
        body = resp.json()
        self.assertIn("entity_id", body)

    def test_entity_requires_entity_id(self):
        url = reverse("authentik_api:saml-catalog-entity")
        resp = self.client.post(url, data={"file": self._upload()}, format="multipart")
        self.assertEqual(resp.status_code, 400, resp.content)
        self.assertIn("entity_id", resp.json())

    def test_preview_requires_file_or_metadata_name(self):
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(url, data={}, format="multipart")
        self.assertEqual(resp.status_code, 400, resp.content)
        body = resp.json()
        self.assertIn("metadata_name", body)

    def test_preview_accepts_file(self):
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(url + "?kind=sp", data={"file": self._upload()}, format="multipart")
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertIsInstance(resp.json(), list)

    def test_preview_states_new_when_not_in_db(self):
        provider = SAMLProvider.objects.create(
            name="p1",
            authorization_flow=create_test_flow(),
            acs_url="http://localhost/source/saml/provider/acs/",
        )

        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(
            url + f"?provider={provider.pk}",
            data={"file": self._upload()},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        sp = [x for x in body if x["entity_id"] == "https://sp.example.com"][0]
        self.assertIn("states", sp)
        self.assertEqual(sp["states"]["metadata"], "new")

    def _mk_provider(self) -> SAMLProvider:
        return SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost/source/saml/provider/acs/",
        )

    def _build_sp_snapshot_from_upload(self, entity_id: str) -> dict:
        raw = METADATA_XML
        item = next(it for it in iter_entity_descriptors(raw) if it.entity_id == entity_id)
        entity = item.xml
        sp_desc = extract_sp_descriptor(entity)

        acs_list = extract_all_acs(sp_desc)
        sls_list = extract_all_sls(sp_desc)

        verification_b64 = (
            extract_x509_b64_list(sp_desc, use="signing")
            or extract_x509_b64_list(sp_desc, use=None)
        )
        encryption_b64 = extract_x509_b64_list(sp_desc, use="encryption")

        snapshot = {
            "acs": acs_list,
            "sls": sls_list,
            "authn_requests_signed": (
                sp_desc.attrib.get("AuthnRequestsSigned", "").lower() == "true"
            ),
            "want_assertions_signed": (
                sp_desc.attrib.get("WantAssertionsSigned", "").lower() == "true"
            ),
            "has_verification_cert": bool(verification_b64),
            "has_encryption_cert": bool(encryption_b64),
        }
        return snapshot

    def test_preview_states_unknown_when_provider_not_given(self):
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(url, data={"file": self._upload()}, format="multipart")
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        sp_item = next(x for x in body if x["entity_id"] == "https://sp.example.com")

        self.assertIn("states", sp_item)
        self.assertEqual(sp_item["states"]["metadata"], "unknown")
        self.assertIn("metadata_hash", sp_item["states"])

    def test_preview_states_unchanged_or_updated_based_on_hash(self):
        provider = self._mk_provider()
        entity_id = "https://sp.example.com"

        snapshot = self._build_sp_snapshot_from_upload(entity_id)
        upload_hash = compute_signature_hash(normalize_signature(snapshot))

        # Case A: UNCHANGED
        SAMLSP.objects.create(
            provider=provider,
            entity_id=entity_id,
            name=entity_id,
            enabled=False,
            acs_url="https://sp.example.com/acs",
            sp_binding="post",
            sls_url="",
            sls_binding="post",
            authn_requests_signed=False,
            want_assertions_signed=False,
            metadata_snapshot=snapshot,
            metadata_hash=upload_hash,
            metadata_last_import=None,
        )

        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(
            url + f"?provider={provider.pk}",
            data={"file": self._upload()},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        sp_item = next(x for x in resp.json() if x["entity_id"] == entity_id)
        self.assertEqual(sp_item["states"]["metadata"], "unchanged")

        # Case B: UPDATED
        sp = SAMLSP.objects.get(provider=provider, entity_id=entity_id)
        sp.metadata_hash = "0" * 64
        sp.save(update_fields=["metadata_hash"])

        resp2 = self.client.post(
            url + f"?provider={provider.pk}",
            data={"file": self._upload()},
            format="multipart",
        )
        self.assertEqual(resp2.status_code, 200, resp2.content)
        sp_item2 = next(x for x in resp2.json() if x["entity_id"] == entity_id)
        self.assertEqual(sp_item2["states"]["metadata"], "updated")

    def test_preview_runtime_state_unchanged_when_db_runtime_matches_upload_snapshot(self):
        """
        If the SP exists in DB and its runtime config matches the runtime
        derived from the *uploaded* snapshot, preview.states.runtime == "unchanged".
        """
        provider = self._mk_provider()
        entity_id = "https://sp.example.com"

        snapshot = self._build_sp_snapshot_from_upload(entity_id)
        upload_hash = compute_signature_hash(normalize_signature(snapshot))

        # Create DB SP that matches the uploaded snapshot's expected runtime.
        # (Use same ACS/binding as the uploaded metadata; see METADATA_XML fixture.)
        SAMLSP.objects.create(
            provider=provider,
            entity_id=entity_id,
            name=entity_id,
            enabled=False,
            # Active config (runtime)
            acs_url="https://sp.example.com/acs",
            sp_binding="post",
            sls_url="",
            sls_binding="post",
            authn_requests_signed=False,
            want_assertions_signed=False,
            # Metadata bookkeeping (not strictly required for runtime state, but realistic)
            metadata_snapshot=snapshot,
            metadata_hash=upload_hash,
            metadata_last_import=None,
            # Cert KPs: catalog snapshot has no certs in this fixture, so keep null
            verification_kp=None,
            encryption_kp=None,
        )

        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(
            f"{url}?provider={provider.pk}&kind=sp",
            data={"file": self._upload()},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        sp_item = next(x for x in body if x["entity_id"] == entity_id)

        self.assertIn("states", sp_item)
        self.assertEqual(sp_item["states"]["metadata"], "unchanged")
        self.assertEqual(sp_item["states"]["runtime"], "unchanged")

    def test_preview_runtime_state_diverged_when_db_runtime_modified(self):
        """
        If the SP exists in DB but its runtime config differs from the runtime
        derived from the *uploaded* snapshot, preview.states.runtime == "diverged".
        """
        provider = self._mk_provider()
        entity_id = "https://sp.example.com"

        snapshot = self._build_sp_snapshot_from_upload(entity_id)
        upload_hash = compute_signature_hash(normalize_signature(snapshot))

        sp = SAMLSP.objects.create(
            provider=provider,
            entity_id=entity_id,
            name=entity_id,
            enabled=False,
            # Start matching...
            acs_url="https://sp.example.com/acs",
            sp_binding="post",
            sls_url="",
            sls_binding="post",
            authn_requests_signed=False,
            want_assertions_signed=False,
            metadata_snapshot=snapshot,
            metadata_hash=upload_hash,
            metadata_last_import=None,
            verification_kp=None,
            encryption_kp=None,
        )

        # Force runtime divergence (classic)
        sp.acs_url = "https://evil.example.com/acs"
        sp.save(update_fields=["acs_url"])

        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(
            f"{url}?provider={provider.pk}&kind=sp",
            data={"file": self._upload()},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        sp_item = next(x for x in body if x["entity_id"] == entity_id)

        # metadata is unchanged (hash matches), runtime must be diverged
        self.assertEqual(sp_item["states"]["metadata"], "unchanged")
        self.assertEqual(sp_item["states"]["runtime"], "diverged")

    def test_preview_accepts_gz_file(self):
        """preview should accept gzipped metadata (.xml.gz) and behave like plain XML."""
        url = reverse("authentik_api:saml-catalog-preview")

        gz = gzip.compress(METADATA_XML)
        upload = SimpleUploadedFile(
            "metadata.xml.gz",
            gz,
            content_type="application/gzip",
        )

        resp = self.client.post(url, data={"file": upload}, format="multipart")
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        self.assertIsInstance(body, list)
        self.assertEqual(len(body), 2)

        entity_ids = {x["entity_id"] for x in body}
        self.assertIn("https://sp.example.com", entity_ids)
        self.assertIn("https://idp.example.com", entity_ids)
