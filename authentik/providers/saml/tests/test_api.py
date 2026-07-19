"""SAML Provider API Tests"""

from json import loads
from tempfile import TemporaryFile

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.blueprints.tests import apply_blueprint
from authentik.core.models import Application
from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_flow
from authentik.crypto.builder import PrivateKeyAlg
from authentik.flows.models import FlowDesignation
from authentik.lib.generators import generate_id
from authentik.lib.tests.utils import load_fixture
from authentik.providers.saml.models import SAMLSP, SAMLPropertyMapping, SAMLProvider
from authentik.sources.saml.models import SAMLNameIDPolicy


class TestSAMLProviderAPI(APITestCase):
    """SAML Provider API Tests"""

    def setUp(self) -> None:
        super().setUp()
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

    def test_detail(self):
        """Test detail"""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        response = self.client.get(
            reverse("authentik_api:samlprovider-detail", kwargs={"pk": provider.pk}),
        )
        self.assertEqual(200, response.status_code)
        Application.objects.create(name=generate_id(), provider=provider, slug=generate_id())
        response = self.client.get(
            reverse("authentik_api:samlprovider-detail", kwargs={"pk": provider.pk}),
        )
        self.assertEqual(200, response.status_code)

    def test_create_validate_signing_kp(self):
        """Test create"""
        cert = create_test_cert()
        response = self.client.post(
            reverse("authentik_api:samlprovider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "acs_url": "http://localhost",
                "signing_kp": cert.pk,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertJSONEqual(
            response.content,
            {
                "non_field_errors": [
                    (
                        "With a signing keypair selected, at least one "
                        "of 'Sign assertion' and 'Sign Response' must be selected."
                    )
                ]
            },
        )
        response = self.client.post(
            reverse("authentik_api:samlprovider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "acs_url": "http://localhost",
                "signing_kp": cert.pk,
                "sign_assertion": True,
            },
        )
        self.assertEqual(response.status_code, 201)

    def test_create_validate_unsupported_key_type(self):
        """Test validation rejects unsupported key types (Ed25519)"""

        # Create an Ed25519 certificate
        ed25519_cert = create_test_cert(PrivateKeyAlg.ED25519)

        response = self.client.post(
            reverse("authentik_api:samlprovider-list"),
            data={
                "name": generate_id(),
                "authorization_flow": create_test_flow().pk,
                "invalidation_flow": create_test_flow().pk,
                "acs_url": "http://localhost",
                "signing_kp": ed25519_cert.pk,
                "sign_assertion": True,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("signing_kp", loads(response.content))
        self.assertJSONEqual(
            response.content,
            {"signing_kp": ["Only RSA, EC, and DSA key types are supported for SAML signing."]},
        )

    def test_metadata(self):
        """Test metadata export (normal)"""
        self.client.logout()
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        Application.objects.create(name=generate_id(), provider=provider, slug=generate_id())
        response = self.client.get(
            reverse("authentik_api:samlprovider-metadata", kwargs={"pk": provider.pk}),
        )
        self.assertEqual(200, response.status_code)

    def test_metadata_download(self):
        """Test metadata export (download)"""
        self.client.logout()
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        Application.objects.create(name=generate_id(), provider=provider, slug=generate_id())
        response = self.client.get(
            reverse("authentik_api:samlprovider-metadata", kwargs={"pk": provider.pk})
            + "?download",
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("Content-Disposition", response)
        # Test download with Accept: application/xml
        response = self.client.get(
            reverse("authentik_api:samlprovider-metadata", kwargs={"pk": provider.pk})
            + "?download",
            HTTP_ACCEPT="application/xml",
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("Content-Disposition", response)

        response = self.client.get(
            reverse("authentik_api:samlprovider-metadata", kwargs={"pk": provider.pk})
            + "?download",
            HTTP_ACCEPT="application/xml;charset=UTF-8",
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("Content-Disposition", response)

    def test_metadata_invalid(self):
        """Test metadata export (invalid)"""
        self.client.logout()
        # Provider without application
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        response = self.client.get(
            reverse("authentik_api:samlprovider-metadata", kwargs={"pk": provider.pk}),
        )
        self.assertEqual(404, response.status_code)
        response = self.client.get(
            reverse("authentik_api:samlprovider-metadata", kwargs={"pk": "abc"}),
        )
        self.assertEqual(404, response.status_code)
        response = self.client.get(
            reverse("authentik_api:samlprovider-metadata", kwargs={"pk": provider.pk}),
            HTTP_ACCEPT="application/invalid-mime-type",
        )
        self.assertEqual(406, response.status_code)

    def test_import_success(self):
        """Test metadata import (success case)"""
        name = generate_id()
        authorization_flow = create_test_flow(FlowDesignation.AUTHORIZATION)
        invalidation_flow = create_test_flow(FlowDesignation.INVALIDATION)
        with TemporaryFile() as metadata:
            metadata.write(load_fixture("fixtures/simple.xml").encode())
            metadata.seek(0)
            response = self.client.post(
                reverse("authentik_api:samlprovider-import-metadata"),
                {
                    "file": metadata,
                    "name": name,
                    "authorization_flow": authorization_flow.pk,
                    "invalidation_flow": invalidation_flow.pk,
                },
                format="multipart",
            )
        self.assertEqual(201, response.status_code)
        body = response.json()
        self.assertIn("pk", body)
        self.assertEqual(body["name"], name)
        self.assertEqual(body["authorization_flow"], str(authorization_flow.pk))
        self.assertEqual(body["invalidation_flow"], str(invalidation_flow.pk))

    def test_import_existing_provider_refreshes_metadata(self):
        """Test refreshing an existing provider from newer metadata."""
        authorization_flow = create_test_flow(FlowDesignation.AUTHORIZATION)
        invalidation_flow = create_test_flow(FlowDesignation.INVALIDATION)
        with TemporaryFile() as metadata:
            metadata.write(load_fixture("fixtures/simple.xml").encode())
            metadata.seek(0)
            response = self.client.post(
                reverse("authentik_api:samlprovider-import-metadata"),
                {
                    "file": metadata,
                    "name": "Initial provider",
                    "authorization_flow": authorization_flow.pk,
                    "invalidation_flow": invalidation_flow.pk,
                },
                format="multipart",
            )
        self.assertEqual(response.status_code, 201)
        provider = SAMLProvider.objects.get(pk=response.json()["pk"])

        with TemporaryFile() as metadata:
            metadata.write(load_fixture("fixtures/multi-bindings.xml").encode())
            metadata.seek(0)
            response = self.client.post(
                reverse("authentik_api:samlprovider-import-metadata"),
                {
                    "file": metadata,
                    "provider": provider.pk,
                    "name": "Refreshed provider",
                },
                format="multipart",
            )

        self.assertEqual(response.status_code, 200)
        provider.refresh_from_db()
        self.assertEqual(response.json()["pk"], provider.pk)
        self.assertEqual(provider.name, "Refreshed provider")
        self.assertEqual(
            provider.acs_url,
            "https://sp-b.example.org:10446/Shibboleth.sso/SAML2/POST",
        )
        self.assertEqual(provider.audience, "https://sp-b.example.org/shibboleth")
        self.assertIsNotNone(provider.verification_kp_ring)
        self.assertIsNotNone(provider.encryption_kp_ring)
        self.assertEqual(provider.verification_kp_ring.bindings.count(), 1)
        self.assertEqual(provider.encryption_kp_ring.bindings.count(), 1)

    def test_import_failed(self):
        """Test metadata import (invalid xml)"""
        with TemporaryFile() as metadata:
            metadata.write(b"invalid")
            metadata.seek(0)
            response = self.client.post(
                reverse("authentik_api:samlprovider-import-metadata"),
                {
                    "file": metadata,
                    "name": generate_id(),
                    "authorization_flow": create_test_flow().pk,
                },
                format="multipart",
            )
        self.assertEqual(400, response.status_code)

    def test_import_invalid(self):
        """Test metadata import (invalid input)"""
        response = self.client.post(
            reverse("authentik_api:samlprovider-import-metadata"),
            {
                "name": generate_id(),
            },
            format="multipart",
        )
        self.assertEqual(400, response.status_code)

    @apply_blueprint("system/providers-saml.yaml")
    def test_preview(self):
        """Test Preview API Endpoint"""
        provider: SAMLProvider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        provider.property_mappings.set(SAMLPropertyMapping.objects.all())
        Application.objects.create(name=generate_id(), provider=provider, slug=generate_id())
        response = self.client.get(
            reverse("authentik_api:samlprovider-preview-user", kwargs={"pk": provider.pk})
        )
        self.assertEqual(response.status_code, 200)
        body = loads(response.content.decode())["preview"]["attributes"]
        self.assertEqual(
            [x for x in body if x["Name"] == "http://schemas.goauthentik.io/2021/02/saml/username"][
                0
            ]["Value"],
            [self.user.username],
        )

    def test_service_providers_preview_entities(self):
        """Test preview endpoint for service providers with DTO payload."""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        existing = SAMLSP.objects.create(
            parent=provider,
            name=generate_id(),
            entity_id="https://sp-existing.example.org/metadata",
            enabled=True,
            acs_url="https://sp-existing.example.org/acs",
            sp_binding="post",
            sls_url="",
            sls_binding="post",
        )
        response = self.client.post(
            reverse(
                "authentik_api:samlprovider-service-providers-preview",
                kwargs={"pk": provider.pk},
            ),
            data={
                "input_mode": "entities",
                "entities": [
                    {
                        "entity_id": existing.entity_id,
                        "display_name": "Existing SP Display",
                        "acs_binding": "post",
                        "acs_location": existing.acs_url,
                        "auth_n_request_signed": False,
                        "assertion_signed": False,
                        "name_id_policy": SAMLNameIDPolicy.UNSPECIFIED,
                    }
                ],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["compare"]["entity_id"], existing.entity_id)
        self.assertEqual(
            response.json()["results"][0]["metadata"]["display_name"],
            "Existing SP Display",
        )

    def test_service_providers_apply_entities(self):
        """Test apply endpoint for service providers with DTO payload."""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        response = self.client.post(
            reverse(
                "authentik_api:samlprovider-service-providers-apply",
                kwargs={"pk": provider.pk},
            ),
            data={
                "input_mode": "entities",
                "entities": [
                    {
                        "entity_id": "https://sp-new.example.org/metadata",
                        "display_name": "New SP Display",
                        "acs_binding": "post",
                        "acs_location": "https://sp-new.example.org/acs",
                        "auth_n_request_signed": False,
                        "assertion_signed": False,
                        "name_id_policy": SAMLNameIDPolicy.UNSPECIFIED,
                    }
                ],
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["summary"]["created"], 1)
        created = provider.service_providers.get(entity_id="https://sp-new.example.org/metadata")
        self.assertEqual(created.name, "New SP Display")
        self.assertEqual(created.acs_url, "https://sp-new.example.org/acs")

    def test_service_provider_nested_crud(self):
        """Test nested list/detail/patch/delete endpoints for SAMLSP."""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
        )
        sp = SAMLSP.objects.create(
            parent=provider,
            name="before",
            entity_id="https://sp-crud.example.org/metadata",
            enabled=True,
            acs_url="https://sp-crud.example.org/acs",
            sp_binding="post",
            sls_url="",
            sls_binding="post",
        )
        list_response = self.client.get(
            reverse("authentik_api:samlprovider-service-providers", kwargs={"pk": provider.pk}),
        )
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(len(list_response.json()["results"]), 1)

        detail_url = reverse(
            "authentik_api:samlprovider-service-provider",
            kwargs={"pk": provider.pk, "sp_id": sp.pk},
        )
        detail_response = self.client.get(detail_url)
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(detail_response.json()["entity_id"], sp.entity_id)

        patch_response = self.client.patch(detail_url, data={"name": "after"}, format="json")
        self.assertEqual(patch_response.status_code, 200)
        self.assertEqual(patch_response.json()["name"], "after")

        delete_response = self.client.delete(detail_url)
        self.assertEqual(delete_response.status_code, 204)
        self.assertFalse(provider.service_providers.filter(pk=sp.pk).exists())
