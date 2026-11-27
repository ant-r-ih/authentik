"""Per-SP property mapping override: which attributes each SP receives in its assertion"""

from django.test import TestCase

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
