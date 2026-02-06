# authentik/providers/saml/tests/test_catalog_api.py

from __future__ import annotations

from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user

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
        url = reverse("authentik_api:saml-metadata-catalog-preview")
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
        url = reverse("authentik_api:saml-metadata-catalog-preview")
        resp = self.client.post(url + "?kind=sp", data={"file": self._upload()}, format="multipart")
        self.assertEqual(resp.status_code, 200, resp.content)

        body = resp.json()
        self.assertEqual(len(body), 1)
        self.assertEqual(body[0]["entity_id"], "https://sp.example.com")
        self.assertIn("sp", body[0].get("kind", []))

    def test_preview_kind_filter_idp(self):
        """preview?kind=idp should return only IdP entities."""
        url = reverse("authentik_api:saml-metadata-catalog-preview")
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
        url = reverse("authentik_api:saml-metadata-catalog-entity")
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
        url = reverse("authentik_api:saml-metadata-catalog-entity")
        resp = self.client.post(
            url,
            data={"file": self._upload(), "entity_id": "https://missing.example.com"},
            format="multipart",
        )
        self.assertEqual(resp.status_code, 400, resp.content)
        body = resp.json()
        self.assertIn("entity_id", body)

    def test_entity_requires_entity_id(self):
        url = reverse("authentik_api:saml-metadata-catalog-entity")
        resp = self.client.post(url, data={"file": self._upload()}, format="multipart")
        self.assertEqual(resp.status_code, 400, resp.content)
        self.assertIn("entity_id", resp.json())

    def test_preview_requires_file(self):
        url = reverse("authentik_api:saml-metadata-catalog-preview")
        resp = self.client.post(url, data={}, format="multipart")
        self.assertEqual(resp.status_code, 400, resp.content)
        self.assertIn("file", resp.json())
