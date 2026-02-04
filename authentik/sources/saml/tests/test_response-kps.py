"""SAML Source tests"""

from base64 import b64encode

from django.test import TestCase

from authentik.core.tests.utils import RequestFactory, create_test_cert, create_test_flow
from authentik.crypto.models import CertificateKeyPair
from authentik.lib.generators import generate_id
from authentik.lib.tests.utils import load_fixture
from authentik.sources.saml.exceptions import InvalidEncryption, InvalidSignature
from authentik.sources.saml.models import SAMLSource
from authentik.sources.saml.processors.response import ResponseProcessor

KPF1 = ("fixtures/encrypted-key.pem", "fixtures/signature_cert.pem")
KPF2 = ("fixtures/encrypted-key2.pem", "fixtures/signature_cert2.pem")
CF1 = (None, "fixtures/signature_cert.pem")
CF2 = (None, "fixtures/signature_cert2.pem")


class TestResponseProcessor(TestCase):
    """Test ResponseProcessor"""

    def setUp(self):
        self.factory = RequestFactory()
        self.source = SAMLSource.objects.create(
            name=generate_id(),
            slug=generate_id(),
            issuer="authentik",
            allow_idp_initiated=True,
            pre_authentication_flow=create_test_flow(),
        )

    def test_encrypted_correct(self):
        """Test encrypted"""
        kps = []
        for keyf, _ in [KPF1]:
            kps.append(
                CertificateKeyPair.objects.create(
                    name=generate_id(),
                    key_data=load_fixture(keyf),
                )
            )

        self.source.encryption_kps = kps
        request = self.factory.post(
            "/",
            data={
                "SAMLResponse": b64encode(
                    load_fixture("fixtures/response_encrypted.xml").encode()
                ).decode()
            },
        )

        parser = ResponseProcessor(self.source, request)
        parser.parse()

    def test_encrypted_incorrect_key(self):
        """Test encrypted"""
        kps = []
        kps.append(create_test_cert())

        self.source.encryption_kps = kps
        request = self.factory.post(
            "/",
            data={
                "SAMLResponse": b64encode(
                    load_fixture("fixtures/response_encrypted.xml").encode()
                ).decode()
            },
        )

        parser = ResponseProcessor(self.source, request)
        with self.assertRaises(InvalidEncryption):
            parser.parse()

    def test_verification_assertion(self):
        """Test verifying signature inside assertion"""
        kps = []
        for _, certf in [CF1]:
            kps.append(
                CertificateKeyPair.objects.create(
                    name=generate_id(),
                    certificate_data=load_fixture(certf),
                )
            )
        self.source.verification_kps = kps
        self.source.signed_assertion = True
        self.source.signed_response = False
        request = self.factory.post(
            "/",
            data={
                "SAMLResponse": b64encode(
                    load_fixture("fixtures/response_signed_assertion.xml").encode()
                ).decode()
            },
        )

        parser = ResponseProcessor(self.source, request)
        parser.parse()
