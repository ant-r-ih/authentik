"""Test AuthN Request generator and parser"""

from base64 import b64encode

from defusedxml.lxml import fromstring
from django.http.request import QueryDict
from django.test import TestCase
from guardian.utils import get_anonymous_user
from lxml import etree  # nosec

from authentik.blueprints.tests import apply_blueprint
from authentik.core.tests.utils import (
    RequestFactory,
    create_test_admin_user,
    create_test_cert,
    create_test_flow,
)
from authentik.crypto.models import CertificateKeyPair
from authentik.events.models import Event, EventAction
from authentik.lib.generators import generate_id
from authentik.lib.xml import lxml_from_string
from authentik.providers.saml.models import SAMLPropertyMapping, SAMLProvider, SAMLSPKeyOverrideMode
from authentik.providers.saml.processors.assertion import AssertionProcessor
from authentik.providers.saml.processors.authn_request_parser import AuthNRequestParser
from authentik.providers.saml.utils.certrefs import (
    sync_saml_provider_cert_refs,
    sync_saml_sp_cert_refs,
)
from authentik.sources.saml.exceptions import MismatchedRequestID
from authentik.sources.saml.models import SAMLSource
from authentik.sources.saml.processors.constants import (
    NS_MAP,
    SAML_BINDING_POST,
)
from authentik.sources.saml.processors.request import SESSION_KEY_REQUEST_ID, RequestProcessor
from authentik.sources.saml.processors.response import ResponseProcessor


class TestAuthNResolve(TestCase):
    """Test AuthN Request generator and parser"""

    @apply_blueprint("system/providers-saml.yaml")
    def setUp(self):
        self.request_factory = RequestFactory()
        self.cert_idp = create_test_cert()
        self.cert_sp = create_test_cert()
        self.cert_overridden_sp = create_test_cert()

        provider = "provider"
        django_host = "testserver"  # Django default

        self.acs = f"http://{django_host}/source/saml/{provider}/acs/"
        self.acs_overridden = "http://overridden_sp/source/saml/provider/acs/"

        self.issuer = "http://testserver/source/saml/provider"
        self.issuer_overridden = "http://overridden_sp/"

        self.provider: SAMLProvider = SAMLProvider.objects.create(
            issuer=self.issuer_overridden,
            authorization_flow=create_test_flow(),
            acs_url=self.acs_overridden,
            signing_kp=self.cert_idp,
            verification_kp=self.cert_overridden_sp,
        )
        self.provider.property_mappings.set(SAMLPropertyMapping.objects.all())

        sp = self.provider.service_providers.create(
            name="SP",
            entity_id=self.issuer,
            enabled=True,
            acs_url=self.acs,
            verification_kp=self.cert_sp,
            verification_kp_mode=SAMLSPKeyOverrideMode.SET,
        )
        sync_saml_sp_cert_refs(sp)
        sync_saml_provider_cert_refs(self.provider)

        self.source = SAMLSource.objects.create(
            slug=provider,
            issuer=self.issuer,
            pre_authentication_flow=create_test_flow(),
            signing_kp=self.cert_sp,
            verification_kp=self.cert_idp,
            signed_assertion=True,
        )

    def test_signed_valid(self):
        """Test generated AuthNRequest with valid signature"""
        http_request = self.request_factory.get("/")

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        auth_n = request_proc.get_auth_n()
        self.assertEqual(auth_n.attrib["ProtocolBinding"], SAML_BINDING_POST)

        request = request_proc.build_auth_n()
        # Now we check the ID and signature
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        self.assertEqual(parsed_request.id, request_proc.request_id)
        self.assertEqual(parsed_request.relay_state, "test_state")
        self.assertEqual(parsed_request.acs_url, self.acs)

        self.assertIsNotNone(parsed_request.cfg)
        self.assertEqual(parsed_request.acs_url, self.acs)
        self.assertEqual(parsed_request.sp_binding, SAML_BINDING_POST)
        self.assertEqual(parsed_request.cfg.acs_url, self.acs)
        self.assertEqual(parsed_request.cfg.sp_binding, SAML_BINDING_POST)

    def test_request_encrypt(self):
        """Test full SAML Request/Response flow, fully encrypted"""
        self.provider.encryption_kp = self.cert_idp
        self.provider.save()
        self.source.encryption_kp = self.cert_idp
        self.source.save()
        http_request = self.request_factory.get("/", user=get_anonymous_user())

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        response = response_proc.build_response()

        # Now parse the response (source)
        http_request.POST = QueryDict(mutable=True)
        http_request.POST["SAMLResponse"] = b64encode(response.encode()).decode()

        response_parser = ResponseProcessor(self.source, http_request)
        response_parser.parse()

    def test_request_encrypt_cert_only(self):
        """Test SAML encryption with certificate-only keypair (no private key).

        This tests the scenario where the IdP (provider) only has the SP's public
        certificate for encryption, without a private key. This is the expected
        real-world scenario since the SP would never share their private key.
        """
        # Create a full keypair for the source (SP) - it needs the private key to decrypt
        full_keypair = create_test_cert()

        # Create a certificate-only keypair for the provider (IdP)
        # This simulates having only the SP's public certificate
        cert_only = CertificateKeyPair.objects.create(
            name=generate_id(),
            certificate_data=full_keypair.certificate_data,
            key_data="",  # No private key
        )

        self.provider.encryption_kp = cert_only
        self.provider.save()
        self.source.encryption_kp = full_keypair
        self.source.save()
        http_request = self.request_factory.get("/", user=get_anonymous_user())

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        # This should work with only the certificate (public key) for encryption
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        response = response_proc.build_response()

        # Now parse the response (source) - decryption requires the private key
        http_request.POST = QueryDict(mutable=True)
        http_request.POST["SAMLResponse"] = b64encode(response.encode()).decode()

        response_parser = ResponseProcessor(self.source, http_request)
        response_parser.parse()

    def test_request_signed(self):
        """Test full SAML Request/Response flow, fully signed"""
        http_request = self.request_factory.get("/", user=get_anonymous_user())

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        response = response_proc.build_response()

        # Now parse the response (source)
        http_request.POST = QueryDict(mutable=True)
        http_request.POST["SAMLResponse"] = b64encode(response.encode()).decode()

        response_parser = ResponseProcessor(self.source, http_request)
        response_parser.parse()

    def test_request_signed_both(self):
        """Test full SAML Request/Response flow, fully signed"""
        self.provider.sign_assertion = True
        self.provider.sign_response = True
        self.provider.save()
        self.source.signed_response = True
        http_request = self.request_factory.get("/", user=get_anonymous_user())

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        response = response_proc.build_response()
        # Ensure both response and assertion ID are in the response twice (once as ID attribute,
        # once as ds:Reference URI)
        self.assertEqual(response.count(response_proc._assertion_id), 2)
        self.assertEqual(response.count(response_proc._response_id), 2)

        schema = etree.XMLSchema(
            etree.parse("schemas/saml-schema-protocol-2.0.xsd", parser=etree.XMLParser())  # nosec
        )
        self.assertTrue(schema.validate(lxml_from_string(response)))

        response_xml = fromstring(response)
        self.assertEqual(
            len(response_xml.xpath("//saml:Assertion/ds:Signature", namespaces=NS_MAP)), 1
        )
        self.assertEqual(
            len(response_xml.xpath("//samlp:Response/ds:Signature", namespaces=NS_MAP)), 1
        )

        # Now parse the response (source)
        http_request.POST = QueryDict(mutable=True)
        http_request.POST["SAMLResponse"] = b64encode(response.encode()).decode()

        response_parser = ResponseProcessor(self.source, http_request)
        response_parser.parse()

    def test_request_id_invalid(self):
        """Test generated AuthNRequest with invalid request ID"""
        http_request = self.request_factory.get("/", user=get_anonymous_user())

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # change the request ID
        http_request.session[SESSION_KEY_REQUEST_ID] = "test"
        http_request.session.save()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        response = response_proc.build_response()

        # Now parse the response (source)
        http_request.POST = QueryDict(mutable=True)
        http_request.POST["SAMLResponse"] = b64encode(response.encode()).decode()

        response_parser = ResponseProcessor(self.source, http_request)

        with self.assertRaises(MismatchedRequestID):
            response_parser.parse()

    def test_signed_valid_detached(self):
        """Test generated AuthNRequest with valid signature (detached)"""
        http_request = self.request_factory.get("/")

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        params = request_proc.build_auth_n_detached()
        # Now we check the ID and signature
        parsed_request = AuthNRequestParser(self.provider).parse_detached(
            params["SAMLRequest"],
            params["RelayState"],
            params["Signature"],
            params["SigAlg"],
        )
        self.assertEqual(parsed_request.id, request_proc.request_id)
        self.assertEqual(parsed_request.relay_state, "test_state")

    def test_authn_context_class_ref_mapping(self):
        """Test custom authn_context_class_ref"""
        authn_context_class_ref = generate_id()
        mapping = SAMLPropertyMapping.objects.create(
            name=generate_id(), expression=f"""return '{authn_context_class_ref}'"""
        )
        self.provider.authn_context_class_ref_mapping = mapping
        self.provider.save()
        user = create_test_admin_user()
        http_request = self.request_factory.get("/", user=user)

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        response = response_proc.build_response()
        self.assertIn(user.username, response)
        self.assertIn(authn_context_class_ref, response)

    def test_authn_context_class_ref_mapping_invalid(self):
        """Test custom authn_context_class_ref (invalid)"""
        mapping = SAMLPropertyMapping.objects.create(name=generate_id(), expression="q")
        self.provider.authn_context_class_ref_mapping = mapping
        self.provider.save()
        user = create_test_admin_user()
        http_request = self.request_factory.get("/", user=user)

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        response = response_proc.build_response()
        self.assertIn(user.username, response)

        events = Event.objects.filter(
            action=EventAction.CONFIGURATION_ERROR,
        )
        self.assertTrue(events.exists())
        self.assertEqual(
            events.first().context["message"],
            f"Failed to evaluate property-mapping: '{mapping.name}'",
        )

    def test_request_attributes(self):
        """Test full SAML Request/Response flow, fully signed"""
        user = create_test_admin_user()
        http_request = self.request_factory.get("/", user=user)

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        self.assertIn(user.username, response_proc.build_response())

    def test_request_attributes_invalid(self):
        """Test full SAML Request/Response flow, fully signed"""
        user = create_test_admin_user()
        http_request = self.request_factory.get("/", user=user)

        # First create an AuthNRequest
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # Create invalid PropertyMapping
        mapping = SAMLPropertyMapping.objects.create(
            name=generate_id(), saml_name="test", expression="q"
        )
        self.provider.property_mappings.add(mapping)

        # To get an assertion we need a parsed request (parsed by provider)
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )
        # Now create a response and convert it to string (provider)
        response_proc = AssertionProcessor(self.provider, http_request, parsed_request)
        self.assertIn(user.username, response_proc.build_response())

        events = Event.objects.filter(
            action=EventAction.CONFIGURATION_ERROR,
        )
        self.assertTrue(events.exists())
        self.assertEqual(
            events.first().context["message"],
            f"Failed to evaluate property-mapping: '{mapping.name}'",
        )
    def test_parsed_request_uses_sp_signing_kp_override(self):
        """Parsed request config should use SP signing_kp when signing_kp_mode=SET."""
        # provider default signing key (already set in setUp): self.cert_idp
        # prepare SP-local signing override
        sp = self.provider.service_providers.get(entity_id=self.issuer)
        sp.signing_kp = self.cert_overridden_sp
        sp.signing_kp_mode = SAMLSPKeyOverrideMode.SET
        sp.save()

        http_request = self.request_factory.get("/")

        # Build AuthnRequest from source side
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        # Parse on provider side
        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )

        self.assertIsNotNone(parsed_request.cfg)
        self.assertEqual(parsed_request.cfg.signing_kp, self.cert_overridden_sp)

    def test_idp_initiated(self):
        """Test IDP-initiated login"""
        self.provider.default_relay_state = generate_id()
        request = AuthNRequestParser(self.provider).idp_initiated()
        self.assertEqual(request.id, None)
        self.assertEqual(request.relay_state, self.provider.default_relay_state)

    def test_parsed_request_uses_no_signing_kp_when_sp_mode_none(self):
        """SP signing_kp_mode=NONE should suppress provider signing key."""
        sp = self.provider.service_providers.get(entity_id=self.issuer)
        sp.signing_kp = None
        sp.signing_kp_mode = SAMLSPKeyOverrideMode.NONE
        sp.save()

        http_request = self.request_factory.get("/")
        request_proc = RequestProcessor(self.source, http_request, "test_state")
        request = request_proc.build_auth_n()

        parsed_request = AuthNRequestParser(self.provider).parse(
            b64encode(request.encode()).decode(), "test_state"
        )

        self.assertIsNotNone(parsed_request.cfg)
        self.assertIsNone(parsed_request.cfg.signing_kp)
