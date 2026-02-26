from base64 import b64encode

from django.test import TestCase
from guardian.utils import get_anonymous_user

from authentik.core.tests.utils import RequestFactory, create_test_cert, create_test_flow
from authentik.lib.generators import generate_id
from authentik.providers.saml.models import SAMLProvider
from authentik.providers.saml.processors.authn_request_parser import AuthNRequestParser
from authentik.sources.saml.federation import SAMLIDP
from authentik.sources.saml.models import SAMLSource
from authentik.sources.saml.processors.request import RequestProcessor


class TestRequestProcessorWithIdP(TestCase):
    """Minimal tests for entityID-based IdP selection in RequestProcessor"""

    def setUp(self):
        self.request_factory = RequestFactory()
        self.cert_a = create_test_cert()
        self.cert_b = create_test_cert()

        # Provider verifies signature made by Source.signing_kp (or IdP override)
        self.provider: SAMLProvider = SAMLProvider.objects.create(
            authorization_flow=create_test_flow(),
            acs_url="http://testserver/source/saml/provider/acs/",
            verification_kp=self.cert_a,  # will switch in tests
        )

        self.source = SAMLSource.objects.create(
            name=generate_id(),
            slug="provider",
            issuer="authentik",
            pre_authentication_flow=create_test_flow(),
            signing_kp=self.cert_a,  # default signing
        )

        self.entity_id = "https://accounts.google.com/o/saml2?idpid="

    def _create_enabled_idp(self, **overrides) -> SAMLIDP:
        defaults = {
            "source": self.source,
            "name": "idp1",
            "entity_id": self.entity_id,
            "enabled": True,
            "sso_url": "https://idp.example/sso",
            "slo_url": None,
            "signing_kp": None,
            "verification_kp": None,
            "encryption_kp": None,
            "signing_kp_override": True,
        }
        defaults.update(overrides)
        return SAMLIDP.objects.create(**defaults)

    def test_request_uses_idp_signing_kp_override(self):
        """If entityID matches enabled IdP, RequestProcessor should sign using idp.signing_kp."""
        # IdP override uses cert_b, not source default cert_a
        self._create_enabled_idp(signing_kp=self.cert_b)

        # Provider should accept signature created by cert_b
        self.provider.verification_kp = self.cert_b
        self.provider.save()

        http_request = self.request_factory.get(
            "/?entityID=" + self.entity_id,
            user=get_anonymous_user(),
        )

        req = RequestProcessor(self.source, http_request, "test_state")
        xml = req.build_auth_n()

        parsed = AuthNRequestParser(self.provider).parse(
            b64encode(xml.encode()).decode(),
            "test_state",
        )
        self.assertEqual(parsed.id, req.request_id)
        self.assertEqual(parsed.relay_state, "test_state")

    def test_request_unknown_entity_id_rejected(self):
        """Unknown entityID should be rejected early (no silent fallback)."""
        http_request = self.request_factory.get(
            "/?entityID=https://unknown.example/idp",
            user=get_anonymous_user(),
        )
        with self.assertRaises(ValueError):
            RequestProcessor(self.source, http_request, "test_state")

    def test_request_detached_uses_idp_signing_kp_override(self):
        """If entityID matches enabled IdP, detached signature must be made with idp.signing_kp."""
        self._create_enabled_idp(signing_kp=self.cert_b)

        # Provider must verify using cert_b (IdP override), not cert_a (source default)
        self.provider.verification_kp = self.cert_b
        self.provider.save()

        http_request = self.request_factory.get(
            "/?entityID=" + self.entity_id,
            user=get_anonymous_user(),
        )

        req = RequestProcessor(self.source, http_request, "test_state")
        params = req.build_auth_n_detached()

        parsed = AuthNRequestParser(self.provider).parse_detached(
            params["SAMLRequest"],
            params["RelayState"],
            params["Signature"],
            params["SigAlg"],
        )
        self.assertEqual(parsed.id, req.request_id)
        self.assertEqual(parsed.relay_state, "test_state")
