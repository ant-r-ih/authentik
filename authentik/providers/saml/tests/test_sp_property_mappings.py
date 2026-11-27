"""Per-SP property mapping override: which attributes each SP receives in its assertion"""

import json

from django.test import TestCase
from django.urls import reverse

from authentik.common.saml.constants import NS_SAML_ASSERTION
from authentik.core.tests.utils import RequestFactory, create_test_admin_user, create_test_flow
from authentik.lib.generators import generate_id
from authentik.providers.saml.models import SAMLSP, SAMLPropertyMapping, SAMLProvider
from authentik.providers.saml.processors.assertion import AssertionProcessor
from authentik.providers.saml.processors.authn_request_parser import AuthNRequest
from authentik.providers.saml.resolve import build_sp_config, resolve_request_target

ACS_URL = "https://sp.example.org/acs/"
PROVIDER_ATTRIBUTE = "urn:test:provider-attribute"
SP_ATTRIBUTE = "urn:test:sp-attribute"


class TestSPPropertyMappings(TestCase):
    """SP-level property mappings replace the provider's mappings only when override is on"""

    def setUp(self):
        self.user = create_test_admin_user()
        self.provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url=ACS_URL,
        )
        provider_mapping = SAMLPropertyMapping.objects.create(
            name=generate_id(),
            saml_name=PROVIDER_ATTRIBUTE,
            expression="return 'from-provider'",
        )
        self.provider.property_mappings.add(provider_mapping)
        # Attached to the SP only, never to the provider
        self.sp_mapping = SAMLPropertyMapping.objects.create(
            name=generate_id(),
            saml_name=SP_ATTRIBUTE,
            expression="return 'from-sp'",
        )
        self.sp = SAMLSP.objects.create(
            parent=self.provider,
            entity_id="https://sp.example.org/metadata",
            acs_url=ACS_URL,
            enabled=True,
        )
        self.sp.property_mappings.add(self.sp_mapping)

    def _assertion_attributes(self, sp: SAMLSP | None) -> dict[str, list[str]]:
        """Build the SP config the way the AuthnRequest path does and return the attributes
        the assertion for that SP would carry"""
        target = resolve_request_target(self.provider, sp)
        cfg = build_sp_config(self.provider, sp, target=target)
        http_request = self._request()
        processor = AssertionProcessor(
            self.provider, http_request, AuthNRequest(cfg=cfg, sp=sp, acs_url=ACS_URL)
        )
        statement = processor.get_attributes()
        attributes: dict[str, list[str]] = {}
        for attribute in statement.iter(f"{{{NS_SAML_ASSERTION}}}Attribute"):
            values = [
                value.text for value in attribute.iter(f"{{{NS_SAML_ASSERTION}}}AttributeValue")
            ]
            attributes[attribute.attrib["Name"]] = values
        return attributes

    def _request(self):
        return RequestFactory().get("/", user=self.user)

    def test_override_off_uses_provider_mappings(self):
        """Test an SP without the override gets the provider's mappings"""
        self.sp.property_mappings_override = False
        self.sp.save()
        self.assertEqual(
            self._assertion_attributes(self.sp),
            {PROVIDER_ATTRIBUTE: ["from-provider"]},
        )

    def test_override_on_uses_sp_mappings_only(self):
        """Test an SP with the override gets only its own mappings, not the provider's"""
        self.sp.property_mappings_override = True
        self.sp.save()
        self.assertEqual(
            self._assertion_attributes(self.sp),
            {SP_ATTRIBUTE: ["from-sp"]},
        )

    def test_unknown_sp_uses_provider_mappings(self):
        """Test a request without a known SP (IdP-initiated) gets the provider's mappings"""
        self.sp.property_mappings_override = True
        self.sp.save()
        self.assertEqual(
            self._assertion_attributes(None),
            {PROVIDER_ATTRIBUTE: ["from-provider"]},
        )

    def test_override_is_per_sp(self):
        """Test two SPs of one provider each get their own mapping choice"""
        other = SAMLSP.objects.create(
            parent=self.provider,
            entity_id="https://other.example.org/metadata",
            acs_url=ACS_URL,
            enabled=True,
        )
        self.sp.property_mappings_override = True
        self.sp.save()
        other.property_mappings_override = False
        other.save()
        self.assertEqual(self._assertion_attributes(self.sp), {SP_ATTRIBUTE: ["from-sp"]})
        self.assertEqual(
            self._assertion_attributes(other),
            {PROVIDER_ATTRIBUTE: ["from-provider"]},
        )


class TestSPPropertyMappingsAPI(TestCase):
    """Saving an SP entry with the property mappings override on needs at least one mapping"""

    def setUp(self):
        self.client.force_login(create_test_admin_user())
        self.provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url=ACS_URL,
        )
        self.mapping = SAMLPropertyMapping.objects.create(
            name=generate_id(),
            saml_name=SP_ATTRIBUTE,
            expression="return 'from-sp'",
        )
        self.sp = SAMLSP.objects.create(
            parent=self.provider,
            entity_id="https://sp.example.org/metadata",
            acs_url=ACS_URL,
            enabled=True,
        )

    def _patch(self, data: dict):
        return self.client.patch(
            reverse(
                "authentik_api:samlprovider-service-provider",
                kwargs={"pk": self.provider.pk, "sp_id": self.sp.pk},
            ),
            data=json.dumps(data),
            content_type="application/json",
        )

    def test_override_on_without_mappings_rejected(self):
        """Test turning the override on with no mappings is rejected and nothing is saved"""
        response = self._patch({"property_mappings_override": True, "property_mappings": []})
        self.assertEqual(response.status_code, 400)
        self.assertIn("property_mappings", response.json())
        self.sp.refresh_from_db()
        self.assertFalse(self.sp.property_mappings_override)

    def test_override_on_without_mappings_rejected_on_flag_only(self):
        """Test turning the override on without sending mappings is rejected too"""
        response = self._patch({"property_mappings_override": True})
        self.assertEqual(response.status_code, 400)
        self.sp.refresh_from_db()
        self.assertFalse(self.sp.property_mappings_override)

    def test_override_on_with_mappings_saved(self):
        """Test turning the override on with a mapping is saved"""
        response = self._patch(
            {"property_mappings_override": True, "property_mappings": [str(self.mapping.pk)]}
        )
        self.assertEqual(response.status_code, 200)
        self.sp.refresh_from_db()
        self.assertTrue(self.sp.property_mappings_override)
        self.assertEqual(list(self.sp.property_mappings.all()), [self.mapping])

    def test_override_off_without_mappings_saved(self):
        """Test turning the override off needs no mappings"""
        response = self._patch({"property_mappings_override": False, "property_mappings": []})
        self.assertEqual(response.status_code, 200)

    def test_unrelated_edit_not_blocked_by_earlier_empty_override(self):
        """Test editing another field of an entry that already has an empty override is allowed"""
        self.sp.property_mappings_override = True
        self.sp.save()
        response = self._patch({"name": "renamed"})
        self.assertEqual(response.status_code, 200)
