"""SAML Source DS compatibility tests (InitiateView)"""

from base64 import b64decode
from urllib.parse import parse_qs, urlparse

from django.test import TestCase
from lxml import etree  # nosec

from authentik.core.tests.utils import RequestFactory, create_test_flow
from authentik.lib.generators import generate_id
from authentik.sources.saml.federation import SAMLIDP
from authentik.sources.saml.models import SAMLBindingTypes, SAMLSource

# view name: authentik_sources_saml:login  (urls.py で name="login")


class TestSAMLSourceDSRedirect(TestCase):
    """Test DS-style parameters on InitiateView without adding endpoints."""

    def setUp(self):
        self.factory = RequestFactory()
        self.source = SAMLSource.objects.create(
            name=generate_id(),
            slug=generate_id(),
            issuer="authentik",
            allow_idp_initiated=True,
            pre_authentication_flow=create_test_flow(),
            sso_url="https://idp.example/sso",
            binding_type=SAMLBindingTypes.REDIRECT,
        )

    def _get_login_url(self):
        return f"/source/saml/{self.source.slug}/"

    def _decode_redirect_saml_request(self, response):
        """Return (saml_request_b64, relay_state) from redirect Location."""
        self.assertEqual(response.status_code, 302)
        loc = response["Location"]
        parsed = urlparse(loc)
        qs = parse_qs(parsed.query)
        self.assertIn("SAMLRequest", qs)
        saml_req = qs["SAMLRequest"][0]
        relay_state = qs.get("RelayState", [""])[0]
        return saml_req, relay_state

    def _assert_authn_request_xml_has_relay_state(self, saml_request_b64, expected_relay_state):
        """For redirect binding, relay_state is not in XML; it is a URL param."""
        # nothing to do here; keep helper if later you swap to POST binding.

    def test_ds_target_relative_ok(self):
        """DS target: relative URL is allowed and becomes RelayState."""
        target = "/secure/id/login.php"
        request = self.factory.get(self._get_login_url(), data={"SAMLDS": "1", "target": target})
        response = self.client.get(self._get_login_url(), data={"SAMLDS": "1", "target": target})

        saml_req, relay_state = self._decode_redirect_saml_request(response)
        self.assertEqual(relay_state, target)

    def test_ds_target_external_rejected(self):
        """DS target: external URL must be rejected (open redirect protection)."""
        target = "https://evil.example/phish"
        response = self.client.get(self._get_login_url(), data={"SAMLDS": "1", "target": target})
        self.assertEqual(response.status_code, 400)

    def test_ds_entityid_unknown_rejected(self):
        """Unknown entityID must return 400."""
        response = self.client.get(
            self._get_login_url(),
            data={"SAMLDS": "1", "entityID": "https://unknown.example/idp"},
        )
        self.assertEqual(response.status_code, 400)

    def test_ds_entityid_known_ok(self):
        """Known entityID resolves IdP and still works (no behavior change otherwise)."""
        SAMLIDP.objects.create(
            source=self.source,
            name="idp1",
            entity_id="https://idp.example/entity",
            enabled=True,
            sso_url="https://idp.example/sso",
            slo_url=None,
        )
        response = self.client.get(
            self._get_login_url(),
            data={"SAMLDS": "1", "entityID": "https://idp.example/entity"},
        )
        self.assertEqual(response.status_code, 302)
        # and it should produce a SAMLRequest
        saml_req, _ = self._decode_redirect_saml_request(response)
        self.assertTrue(saml_req)
