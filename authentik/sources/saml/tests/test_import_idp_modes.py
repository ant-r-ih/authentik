from __future__ import annotations

from base64 import b64encode
from textwrap import dedent

from django.test import TestCase
from lxml import etree  # nosec

from authentik.core.tests.utils import create_test_cert, create_test_flow
from authentik.lib.generators import generate_id
from authentik.sources.saml.federation import SAMLIDP
from authentik.sources.saml.models import SAMLSource
from authentik.sources.saml.processors.import_idp import import_idp_from_entity_descriptor


def _entity_with_signing_cert(*, entity_id: str, cert_pem: str, sso_url: str = "https://idp.example/sso"):
    """
    Build minimal EntityDescriptor with IDPSSODescriptor and signing cert.
    cert_pem: PEM string (-----BEGIN CERTIFICATE----- ...)
    """
    # Extract base64 body lines and join
    b64 = "".join(
        line.strip()
        for line in cert_pem.splitlines()
        if "BEGIN CERTIFICATE" not in line and "END CERTIFICATE" not in line
    ).strip()

    xml = dedent(f"""\
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                         xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                         entityID="{entity_id}">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
          <ds:KeyInfo>
            <ds:X509Data>
              <ds:X509Certificate>{b64}</ds:X509Certificate>
            </ds:X509Data>
          </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="{sso_url}"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
    """)
    return etree.fromstring(xml.encode())


def _entity_without_cert(*, entity_id: str, sso_url: str = "https://idp.example/sso"):
    xml = dedent(f"""\
    <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
                         entityID="{entity_id}">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                Location="{sso_url}"/>
      </md:IDPSSODescriptor>
    </md:EntityDescriptor>
    """)
    return etree.fromstring(xml.encode())


class TestImportIDPKeyFreezeAndMode(TestCase):
    def setUp(self):
        self.source = SAMLSource.objects.create(
            name=generate_id(),
            slug=generate_id(),
            issuer="authentik",
            allow_idp_initiated=False,
            sso_url="https://default.example/sso",
            pre_authentication_flow=create_test_flow(),
        )

        self.entity_id = "https://idp.example/entity"
        self.cert1 = create_test_cert()
        self.cert2 = create_test_cert()

        self.ent1 = _entity_with_signing_cert(entity_id=self.entity_id, cert_pem=self.cert1.certificate_data)
        self.ent2 = _entity_with_signing_cert(entity_id=self.entity_id, cert_pem=self.cert2.certificate_data)

    def test_inherit_allows_rotation(self):
        idp, created = import_idp_from_entity_descriptor(source=self.source, entity=self.ent1, enabled=True)
        self.assertTrue(created)
        idp.refresh_from_db()

        self.assertIsNotNone(idp.verification_kp_id)
        self.assertEqual(idp.verification_kp_override, True)

        # Make it "inherit" so importer is allowed to change it
        idp.verification_kp_override = False
        idp.verification_kp = None
        idp.save(update_fields=["verification_kp_override", "verification_kp"])

        idp2, created2 = import_idp_from_entity_descriptor(source=self.source, entity=self.ent2, enabled=True)
        self.assertFalse(created2)
        idp2.refresh_from_db()

        self.assertEqual(idp2.verification_kp_id, self.cert2.pk)
        self.assertEqual(idp2.verification_kp_override, True)

    def test_freeze_blocks_rotation(self):
        idp, _ = import_idp_from_entity_descriptor(source=self.source, entity=self.ent1, enabled=True)
        idp.freeze_verification_kp = True
        idp.save(update_fields=["freeze_verification_kp"])
        old_kp = idp.verification_kp_id

        idp2, _ = import_idp_from_entity_descriptor(source=self.source, entity=self.ent2, enabled=True)
        idp2.refresh_from_db()
        self.assertEqual(idp2.verification_kp_id, old_kp, "freeze_verification_kp should prevent rotation")

    def test_mode_set_blocks_rotation(self):
        idp, _ = import_idp_from_entity_descriptor(source=self.source, entity=self.ent1, enabled=True)
        idp.verification_kp_override = True
        idp.save(update_fields=["verification_kp_override"])
        old_kp = idp.verification_kp_id

        idp2, _ = import_idp_from_entity_descriptor(source=self.source, entity=self.ent2, enabled=True)
        idp2.refresh_from_db()
        self.assertEqual(idp2.verification_kp_id, old_kp, "mode=SET should prevent rotation")

    def test_mode_none_blocks_rotation(self):
        idp, _ = import_idp_from_entity_descriptor(source=self.source, entity=self.ent1, enabled=True)
        idp.verification_kp_override = True
        idp.save(update_fields=["verification_kp_override"])
        old_kp = idp.verification_kp_id

        idp2, _ = import_idp_from_entity_descriptor(source=self.source, entity=self.ent2, enabled=True)
        idp2.refresh_from_db()
        self.assertEqual(idp2.verification_kp_id, old_kp, "mode=NONE should prevent rotation")

    def test_no_cert_sets_in_default(self):
        ent_no = _entity_without_cert(entity_id=self.entity_id)

        idp, _ = import_idp_from_entity_descriptor(source=self.source, entity=ent_no, enabled=True)
        idp.refresh_from_db()

        self.assertIsNone(idp.verification_kp_id)
        self.assertEqual(idp.verification_kp_override, False)
