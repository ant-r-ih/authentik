from __future__ import annotations

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.admin.files.manager import get_file_manager
from authentik.admin.files.usage import FileUsage
from authentik.core.tests.utils import create_test_admin_user
from authentik.lib.tests.utils import load_fixture

FIXTURE_XML = "fixtures/gakunin-metadata.xml"


class TestSAMLMetadataCatalogIDP(APITestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

        self.raw = load_fixture(FIXTURE_XML)  # str
        self.mgr = get_file_manager(FileUsage.SAML_METADATA)

    def _save_metadata_to_files(self, name: str = "gakunin.xml") -> str:
        self.mgr.save_file(name, self.raw.encode("utf-8"))
        return name

    def _catalog_preview_by_name(self, *, name: str) -> list[dict]:
        url = reverse("authentik_api:saml-catalog-preview")
        resp = self.client.post(
            url + "?kind=idp",
            data={"metadata_name": name},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        body = resp.json()
        self.assertIsInstance(body, list)
        return body

    def _catalog_entity_by_name(self, *, name: str, entity_id: str) -> str:
        url = reverse("authentik_api:saml-catalog-entity")
        resp = self.client.post(
            url,
            data={"metadata_name": name, "entity_id": entity_id},
            format="json",
        )
        self.assertEqual(resp.status_code, 200, resp.content)
        data = resp.json()
        self.assertEqual(data["entity_id"], entity_id)
        self.assertIn("xml", data)
        return data["xml"]

    def test_catalog_preview_kind_idp_returns_idps(self):
        name = self._save_metadata_to_files("gakunin.xml")
        items = self._catalog_preview_by_name(name=name)

        # must contain at least one idp entry
        self.assertTrue(
            any("idp" in (it.get("kind") or []) for it in items),
            "Expected at least one entry with kind includes 'idp'",
        )

        # and must not include sp-only entries if kind filter works
        self.assertFalse(
            any(("sp" in (it.get("kind") or [])) and ("idp" not in (it.get("kind") or [])) for it in items),
            "Expected kind=idp preview to exclude sp-only entries",
        )

    def test_catalog_entity_returns_entitydescriptor_for_idp(self):
        name = self._save_metadata_to_files("gakunin.xml")
        items = self._catalog_preview_by_name(name=name)

        # pick first idp entry
        idp = next(it for it in items if "idp" in (it.get("kind") or []))
        entity_id = idp["entity_id"]

        xml = self._catalog_entity_by_name(name=name, entity_id=entity_id)
        self.assertIn("EntityDescriptor", xml)
        self.assertIn(entity_id, xml)
