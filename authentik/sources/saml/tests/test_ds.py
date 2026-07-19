"""SAML Source DS endpoint tests."""

from django.test import TestCase
from django.urls import reverse

from authentik.core.tests.utils import create_test_flow
from authentik.lib.generators import generate_id
from authentik.sources.saml.models import SAMLBindingTypes, SAMLSource


class TestSAMLSourceDSView(TestCase):
    """Test DS endpoint and entity selection flow."""

    def setUp(self):
        self.source = SAMLSource.objects.create(
            name=generate_id(),
            slug=generate_id(),
            issuer_override="authentik",
            allow_idp_initiated=True,
            pre_authentication_flow=create_test_flow(),
            sso_url="https://default.example.org/sso",
            binding_type=SAMLBindingTypes.REDIRECT,
        )

    def test_ds_view_lists_only_enabled_idps(self):
        """DS view should list enabled IdPs and hide disabled entries."""
        self.source.identity_providers.create(
            name="idp-enabled",
            entity_id="https://idp-enabled.example.org/entity",
            enabled=True,
            sso_url="https://idp-enabled.example.org/sso",
        )
        self.source.identity_providers.create(
            name="idp-disabled",
            entity_id="https://idp-disabled.example.org/entity",
            enabled=False,
            sso_url="https://idp-disabled.example.org/sso",
        )

        response = self.client.get(
            reverse("authentik_sources_saml:ds", kwargs={"source_slug": self.source.slug})
        )
        self.assertEqual(response.status_code, 200)

        body = response.content.decode()
        self.assertIn("https://idp-enabled.example.org/entity", body)
        self.assertNotIn("https://idp-disabled.example.org/entity", body)
        self.assertIn("SAMLDS=1", body)
        self.assertIn("entityID=https%3A%2F%2Fidp-enabled.example.org%2Fentity", body)

    def test_ds_view_preserves_next_query(self):
        """DS view should forward next query parameter to login links."""
        self.source.identity_providers.create(
            name="idp-enabled",
            entity_id="https://idp-enabled.example.org/entity",
            enabled=True,
            sso_url="https://idp-enabled.example.org/sso",
        )

        response = self.client.get(
            reverse("authentik_sources_saml:ds", kwargs={"source_slug": self.source.slug}),
            data={"next": "/if/flow/test/"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("next=%2Fif%2Fflow%2Ftest%2F", response.content.decode())

    def test_login_with_entity_id_selects_idp_destination(self):
        """Login endpoint should redirect to selected IdP when entityID is provided."""
        self.source.identity_providers.create(
            name="idp-selected",
            entity_id="https://idp-selected.example.org/entity",
            enabled=True,
            sso_url="https://idp-selected.example.org/sso",
            binding_type=SAMLBindingTypes.REDIRECT,
        )

        response = self.client.get(
            reverse("authentik_sources_saml:login", kwargs={"source_slug": self.source.slug}),
            data={
                "SAMLDS": "1",
                "entityID": "https://idp-selected.example.org/entity",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith("https://idp-selected.example.org/sso?"))
        self.assertIn("SAMLRequest=", response["Location"])
