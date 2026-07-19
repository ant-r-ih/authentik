"""Test Service-Provider Metadata Parser"""

from base64 import b64encode
from dataclasses import replace

import xmlsec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from defusedxml.lxml import fromstring
from django.test import RequestFactory, TestCase
from lxml import etree  # nosec

from authentik.common.saml.constants import ECDSA_SHA256, NS_MAP, NS_SAML_METADATA
from authentik.core.models import Application
from authentik.core.tests.utils import create_test_cert, create_test_flow
from authentik.crypto.builder import PrivateKeyAlg
from authentik.lib.generators import generate_id
from authentik.lib.tests.utils import load_fixture
from authentik.lib.xml import lxml_from_string
from authentik.providers.saml.models import (
    SAMLSP,
    SAMLBindings,
    SAMLPropertyMapping,
    SAMLProvider,
)
from authentik.providers.saml.processors.metadata import MetadataProcessor
from authentik.providers.saml.processors.metadata_parser import (
    APPLY_POLICY_FORCE,
    APPLY_POLICY_IF_NOT_DEVIATED,
    ServiceProviderMetadataParser,
)
from authentik.providers.saml.utils.keyring import pick_cert_pem
from authentik.sources.saml.models import SAMLNameIDPolicy


def _pem_to_der_b64(pem: str) -> str:
    """Convert PEM cert to base64(DER) string suitable for <ds:X509Certificate>."""
    cert = load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
    der = cert.public_bytes(serialization.Encoding.DER)
    return b64encode(der).decode("ascii")


def _build_multi_cert_sp_metadata_xml(
    *, entity_id: str, acs_url: str, sls_url: str, cert_b64s: list[str], cert_b64e: list[str]
) -> str:
    """Build minimal EntityDescriptor XML with multiple signing/encryption certs."""

    def kd(use: str, b64: str) -> str:
        return f"""
        <md:KeyDescriptor use="{use}">
          <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
        </md:KeyDescriptor>
        """

    signing = "\n".join(kd("signing", b) for b in cert_b64s)
    encryption = "\n".join(kd("encryption", b) for b in cert_b64e)

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
  entityID="{entity_id}"
>
  <md:SPSSODescriptor
    protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
    AuthnRequestsSigned="true"
    WantAssertionsSigned="false"
  >
    <md:AssertionConsumerService
      index="0" isDefault="true"
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{acs_url}"
    />
    <md:SingleLogoutService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{sls_url}"
    />
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>

    {signing}
    {encryption}
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""


def _build_simple_sp_entity_descriptor(*, entity_id: str, acs_url: str) -> str:
    """Build minimal SP EntityDescriptor fragment."""
    return f"""
<md:EntityDescriptor entityID="{entity_id}">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
      index="0"
      isDefault="true"
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{acs_url}"
    />
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""


def _build_simple_idp_entity_descriptor(*, entity_id: str, sso_url: str) -> str:
    """Build minimal IdP EntityDescriptor fragment."""
    return f"""
<md:EntityDescriptor entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="{sso_url}"
    />
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
"""


class TestServiceProviderMetadataParser(TestCase):
    """Test ServiceProviderMetadataParser parsing and creation of SAML Provider"""

    def setUp(self) -> None:
        self.flow = create_test_flow()
        self.factory = RequestFactory()

    def test_consistent(self):
        """Test that metadata generation is consistent"""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        request = self.factory.get("/")
        metadata_a = MetadataProcessor(provider, request).build_entity_descriptor()
        metadata_b = MetadataProcessor(provider, request).build_entity_descriptor()
        self.assertEqual(metadata_a, metadata_b)

    def test_schema(self):
        """Test that metadata generation is consistent"""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        request = self.factory.get("/")
        metadata = lxml_from_string(MetadataProcessor(provider, request).build_entity_descriptor())

        schema = etree.XMLSchema(
            etree.parse(
                source="schemas/saml-schema-metadata-2.0.xsd", parser=etree.XMLParser()
            )  # nosec
        )
        self.assertTrue(schema.validate(metadata))

    def test_schema_want_authn_requests_signed(self):
        """Test metadata generation with WantAuthnRequestsSigned"""
        cert = create_test_cert()
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            verification_kp=cert,
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        request = self.factory.get("/")
        metadata = lxml_from_string(MetadataProcessor(provider, request).build_entity_descriptor())
        idp_sso_descriptor = metadata.findall(f"{{{NS_SAML_METADATA}}}IDPSSODescriptor")[0]
        self.assertEqual(idp_sso_descriptor.attrib["WantAuthnRequestsSigned"], "true")

    def test_simple(self):
        """Test simple metadata without Signing"""
        metadata = ServiceProviderMetadataParser().parse(load_fixture("fixtures/simple.xml"))
        provider = metadata.to_provider("test", self.flow, self.flow)
        self.assertEqual(provider.acs_url, "http://localhost:8080/saml/acs")
        self.assertEqual(provider.sp_binding, SAMLBindings.POST)
        self.assertEqual(provider.default_name_id_policy, SAMLNameIDPolicy.EMAIL)
        self.assertEqual(
            len(provider.property_mappings.all()),
            len(SAMLPropertyMapping.objects.exclude(managed__isnull=True)),
        )

    def test_with_signing_cert(self):
        """Test Metadata with signing cert"""
        create_test_cert()
        metadata = ServiceProviderMetadataParser().parse(load_fixture("fixtures/cert.xml"))
        provider = metadata.to_provider("test", self.flow, self.flow)
        self.assertEqual(provider.acs_url, "http://localhost:8080/apps/user_saml/saml/acs")
        self.assertEqual(provider.sp_binding, SAMLBindings.POST)
        self.assertEqual(
            pick_cert_pem(kp=provider.verification_kp, ring=provider.verification_kp_ring),
            load_fixture("fixtures/cert.pem"),
        )
        self.assertIsNone(provider.verification_kp)
        self.assertIsNotNone(provider.verification_kp_ring)
        self.assertEqual(provider.audience, "http://localhost:8080/apps/user_saml/saml/metadata")

    def test_with_signing_cert_invalid_signature(self):
        """Test Metadata with signing cert (invalid signature)"""
        with self.assertRaises(ValueError):
            ServiceProviderMetadataParser().parse(
                load_fixture("fixtures/cert.xml").replace("/apps/user_saml", "")
            )

    def test_signature_rsa(self):
        """Test signature validation (RSA)"""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            signing_kp=create_test_cert(PrivateKeyAlg.RSA),
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        request = self.factory.get("/")
        metadata = MetadataProcessor(provider, request).build_entity_descriptor()

        root = fromstring(metadata.encode())
        xmlsec.tree.add_ids(root, ["ID"])
        signature_nodes = root.xpath("/md:EntityDescriptor/ds:Signature", namespaces=NS_MAP)
        signature_node = signature_nodes[0]
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(
            provider.signing_kp.certificate_data,
            xmlsec.constants.KeyDataFormatCertPem,
            None,
        )
        ctx.key = key
        ctx.verify(signature_node)

    def test_signature_ecdsa(self):
        """Test signature validation (ECDSA)"""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            signing_kp=create_test_cert(PrivateKeyAlg.ECDSA),
            signature_algorithm=ECDSA_SHA256,
        )
        Application.objects.create(
            name=generate_id(),
            slug=generate_id(),
            provider=provider,
        )
        request = self.factory.get("/")
        metadata = MetadataProcessor(provider, request).build_entity_descriptor()

        root = fromstring(metadata.encode())
        xmlsec.tree.add_ids(root, ["ID"])
        signature_nodes = root.xpath("/md:EntityDescriptor/ds:Signature", namespaces=NS_MAP)
        signature_node = signature_nodes[0]
        ctx = xmlsec.SignatureContext()
        key = xmlsec.Key.from_memory(
            provider.signing_kp.certificate_data,
            xmlsec.constants.KeyDataFormatCertPem,
            None,
        )
        ctx.key = key
        ctx.verify(signature_node)

    def test_multi_bindings(self):
        """Test metadata including more than one bindings."""
        metadata = ServiceProviderMetadataParser().parse(
            load_fixture("fixtures/multi-bindings.xml")
        )
        provider = metadata.to_provider("test", self.flow, self.flow)
        self.assertEqual(
            provider.acs_url, "https://sp-b.example.org:10446/Shibboleth.sso/SAML2/POST"
        )
        self.assertEqual(provider.audience, "https://sp-b.example.org/shibboleth")
        self.assertEqual(provider.issuer_override, "https://sp-b.example.org/shibboleth")
        self.assertEqual(provider.sp_binding, SAMLBindings.POST)
        self.assertEqual(provider.default_name_id_policy, SAMLNameIDPolicy.UNSPECIFIED)
        self.assertEqual(
            len(provider.property_mappings.all()),
            len(SAMLPropertyMapping.objects.exclude(managed__isnull=True)),
        )

    def test_iter_entities_on_entities_descriptor(self):
        """Yield only SP entities from aggregate metadata."""
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  {_build_simple_idp_entity_descriptor(entity_id="https://idp.example.org/idp", sso_url="https://idp.example.org/sso")}
  {_build_simple_sp_entity_descriptor(entity_id="https://sp-a.example.org/shibboleth", acs_url="https://sp-a.example.org/acs")}
  {_build_simple_sp_entity_descriptor(entity_id="https://sp-b.example.org/shibboleth", acs_url="https://sp-b.example.org/acs")}
</md:EntitiesDescriptor>
"""
        entries = list(ServiceProviderMetadataParser().iter_entities(xml))
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].entity_id, "https://sp-a.example.org/shibboleth")
        self.assertEqual(entries[1].entity_id, "https://sp-b.example.org/shibboleth")

    def test_iter_entities_keeps_certs_scoped_per_entity(self):
        """Each SP entry keeps only its own key descriptors in aggregate metadata."""
        cert_a = create_test_cert()
        cert_b = create_test_cert()
        cert_a_b64 = _pem_to_der_b64(cert_a.certificate_data)
        cert_b_b64 = _pem_to_der_b64(cert_b.certificate_data)

        sp_a = _build_multi_cert_sp_metadata_xml(
            entity_id="https://sp-a.example.org/shibboleth",
            acs_url="https://sp-a.example.org/acs",
            sls_url="https://sp-a.example.org/sls",
            cert_b64s=[cert_a_b64],
            cert_b64e=[cert_a_b64],
        )
        sp_b = _build_multi_cert_sp_metadata_xml(
            entity_id="https://sp-b.example.org/shibboleth",
            acs_url="https://sp-b.example.org/acs",
            sls_url="https://sp-b.example.org/sls",
            cert_b64s=[cert_b_b64],
            cert_b64e=[cert_b_b64],
        )
        # Drop XML declarations before embedding into aggregate metadata.
        sp_a = "\n".join(sp_a.splitlines()[1:])
        sp_b = "\n".join(sp_b.splitlines()[1:])
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
>
  {sp_a}
  {sp_b}
</md:EntitiesDescriptor>
"""

        entries = list(ServiceProviderMetadataParser().iter_entities(xml))
        self.assertEqual(len(entries), 2)

        by_entity = {entry.entity_id: entry for entry in entries}
        self.assertEqual(
            by_entity["https://sp-a.example.org/shibboleth"].signing_cert_pems,
            [cert_a.certificate_data.strip()],
        )
        self.assertEqual(
            by_entity["https://sp-a.example.org/shibboleth"].encryption_cert_pems,
            [cert_a.certificate_data.strip()],
        )
        self.assertEqual(
            by_entity["https://sp-b.example.org/shibboleth"].signing_cert_pems,
            [cert_b.certificate_data.strip()],
        )
        self.assertEqual(
            by_entity["https://sp-b.example.org/shibboleth"].encryption_cert_pems,
            [cert_b.certificate_data.strip()],
        )

    def test_parse_display_name_prefers_en(self):
        """Parse should prefer mdui:DisplayName with xml:lang='en'."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
  entityID="https://sp-display.example.org/shibboleth"
>
  <md:Extensions>
    <mdui:UIInfo>
      <mdui:DisplayName xml:lang="ja">表示名</mdui:DisplayName>
      <mdui:DisplayName xml:lang="en">Display Name</mdui:DisplayName>
    </mdui:UIInfo>
  </md:Extensions>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
      index="0"
      isDefault="true"
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://sp-display.example.org/acs"
    />
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""
        entry = ServiceProviderMetadataParser().parse(xml)
        self.assertEqual(entry.display_name, "Display Name")
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
        )
        applied = entry.to_sp(provider)
        self.assertEqual(applied.status, "created")
        sp = SAMLSP.objects.get(pk=applied.object_pk)
        self.assertEqual(sp.name, "Display Name")

    def test_parse_display_name_from_sp_descriptor_extensions(self):
        """Parse should read mdui:DisplayName from SPSSODescriptor Extensions."""
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
  xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
  xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"
  entityID="https://secure.nature.com/shibboleth"
>
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:Extensions>
      <mdui:UIInfo>
        <mdui:DisplayName xml:lang="en">Nature Research</mdui:DisplayName>
      </mdui:UIInfo>
    </md:Extensions>
    <md:AssertionConsumerService
      index="0"
      isDefault="true"
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://secure.nature.com/shibboleth/acs"
    />
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""
        entry = ServiceProviderMetadataParser().parse(xml)
        self.assertEqual(entry.display_name, "Nature Research")

    def test_parse_on_entities_descriptor_single_sp(self):
        """Parse succeeds when aggregate metadata contains exactly one SP entity."""
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  {_build_simple_idp_entity_descriptor(entity_id="https://idp.example.org/idp", sso_url="https://idp.example.org/sso")}
  {_build_simple_sp_entity_descriptor(entity_id="https://sp-only.example.org/shibboleth", acs_url="https://sp-only.example.org/acs")}
</md:EntitiesDescriptor>
"""
        entry = ServiceProviderMetadataParser().parse(xml)
        self.assertEqual(entry.entity_id, "https://sp-only.example.org/shibboleth")
        self.assertEqual(entry.acs_location, "https://sp-only.example.org/acs")

    def test_parse_on_entities_descriptor_multiple_sp(self):
        """Parse fails when aggregate metadata contains multiple SP entities."""
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
  {_build_simple_sp_entity_descriptor(entity_id="https://sp-a.example.org/shibboleth", acs_url="https://sp-a.example.org/acs")}
  {_build_simple_sp_entity_descriptor(entity_id="https://sp-b.example.org/shibboleth", acs_url="https://sp-b.example.org/acs")}
</md:EntitiesDescriptor>
"""
        with self.assertRaises(ValueError):
            ServiceProviderMetadataParser().parse(xml)

    def test_compare_sp_new_entity(self):
        """Compare marks missing SAMLSP as creatable and non-deviated."""
        metadata = ServiceProviderMetadataParser().parse(load_fixture("fixtures/simple.xml"))
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
        )

        result = metadata.compare_sp(provider)
        self.assertFalse(result.exists)
        self.assertTrue(result.runtime_changed)
        self.assertTrue(result.cert_changed)
        self.assertFalse(result.runtime_deviated)
        self.assertFalse(result.cert_deviated)

    def test_to_sp_create_and_compare(self):
        """to_sp creates SAMLSP and subsequent compare is unchanged."""
        metadata = ServiceProviderMetadataParser().parse(load_fixture("fixtures/simple.xml"))
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
        )

        applied = metadata.to_sp(provider, create_missing_rings=True)
        self.assertEqual(applied.status, "created")
        self.assertIsNotNone(applied.object_pk)

        sp = SAMLSP.objects.get(pk=applied.object_pk)
        self.assertEqual(sp.entity_id, metadata.entity_id)
        self.assertEqual(sp.acs_url, metadata.acs_location)
        self.assertEqual(sp.sp_binding, metadata.acs_binding)
        self.assertTrue(sp.verification_kp_override)
        self.assertTrue(sp.encryption_kp_override)
        self.assertIsNone(sp.verification_kp)
        self.assertIsNone(sp.encryption_kp)
        self.assertIsNone(sp.verification_kp_ring)
        self.assertIsNone(sp.encryption_kp_ring)

        compared = metadata.compare_sp(provider, target=sp)
        self.assertTrue(compared.exists)
        self.assertFalse(compared.runtime_changed)
        self.assertFalse(compared.cert_changed)
        self.assertFalse(compared.runtime_deviated)
        self.assertFalse(compared.cert_deviated)

    def test_compare_sp_uses_stored_snapshot_for_runtime_deviation(self):
        """Compare keeps runtime non-deviated when only incoming metadata changed."""
        metadata = ServiceProviderMetadataParser().parse(load_fixture("fixtures/simple.xml"))
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
        )

        first = metadata.to_sp(provider)
        sp = SAMLSP.objects.get(pk=first.object_pk)
        incoming = replace(metadata, acs_location="https://changed.example.org/acs")

        compared = incoming.compare_sp(provider, target=sp)
        self.assertTrue(compared.exists)
        self.assertTrue(compared.runtime_changed)
        self.assertFalse(compared.cert_changed)
        self.assertFalse(compared.runtime_deviated)
        self.assertEqual(compared.runtime_diff_fields, [])

    def test_to_sp_if_not_deviated_skips_manual_change(self):
        """to_sp with if_not_deviated skips when current runtime is manually changed."""
        metadata = ServiceProviderMetadataParser().parse(load_fixture("fixtures/simple.xml"))
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
        )

        first = metadata.to_sp(provider)
        sp = SAMLSP.objects.get(pk=first.object_pk)
        sp.acs_url = "https://manually.changed.example.org/acs"
        sp.save(update_fields=["acs_url"])

        skipped = metadata.to_sp(
            provider,
            policy=APPLY_POLICY_IF_NOT_DEVIATED,
            target=sp,
        )
        self.assertEqual(skipped.status, "skipped")
        self.assertEqual(skipped.reason, "runtime_deviated")


class TestServiceProviderMetadataParserMultiCert(TestCase):
    def setUp(self) -> None:
        self.flow = create_test_flow()
        self.kp1 = create_test_cert()
        self.kp2 = create_test_cert()

        self.cert_b64s = [
            _pem_to_der_b64(self.kp1.certificate_data),
            _pem_to_der_b64(self.kp2.certificate_data),
        ]

        self.xml = _build_multi_cert_sp_metadata_xml(
            entity_id="https://sp-multi.example.org/shibboleth",
            acs_url="https://sp-multi.example.org/Shibboleth.sso/SAML2/POST",
            sls_url="https://sp-multi.example.org/Shibboleth.sso/Logout",
            cert_b64s=self.cert_b64s,
            cert_b64e=self.cert_b64s,
        )

    def test_multi_certs_metadata_creates_rings(self):
        meta = ServiceProviderMetadataParser().parse(self.xml)
        provider = meta.to_provider("test-multi", self.flow, self.flow)

        self.assertEqual(provider.audience, "https://sp-multi.example.org/shibboleth")
        self.assertEqual(provider.issuer_override, "https://sp-multi.example.org/shibboleth")
        self.assertEqual(provider.acs_url, "https://sp-multi.example.org/Shibboleth.sso/SAML2/POST")
        self.assertEqual(provider.sp_binding, SAMLBindings.POST)

        self.assertIsNone(provider.verification_kp)
        self.assertIsNotNone(provider.verification_kp_ring)
        self.assertIsNone(provider.encryption_kp)
        self.assertIsNotNone(provider.encryption_kp_ring)

        v = list(provider.verification_kp_ring.bindings.select_related("keypair").order_by("order"))
        self.assertEqual([b.order for b in v], [0, 1])
        self.assertTrue(all(b.keypair.certificate_data for b in v))

        e = list(provider.encryption_kp_ring.bindings.select_related("keypair").order_by("order"))
        self.assertEqual([b.order for b in e], [0, 1])
        self.assertTrue(all(b.keypair.certificate_data for b in e))

        sp_apply = meta.to_sp(provider, create_missing_rings=True)
        sp = SAMLSP.objects.get(pk=sp_apply.object_pk)
        self.assertTrue(sp.verification_kp_override)
        self.assertTrue(sp.encryption_kp_override)

    def test_compare_sp_detects_ring_cert_deviation(self):
        """Compare marks cert_deviated when ring membership differs from snapshot."""
        meta = ServiceProviderMetadataParser().parse(self.xml)
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
        )
        applied = meta.to_sp(provider, create_missing_rings=True)
        sp = SAMLSP.objects.get(pk=applied.object_pk)
        self.assertIsNotNone(sp.verification_kp_ring)
        sp.verification_kp_ring.sync_membership([(0, meta.signing_cert_pems[0])])

        compared = meta.compare_sp(provider, target=sp)
        self.assertFalse(compared.runtime_deviated)
        self.assertTrue(compared.cert_deviated)
        self.assertIn("verification", compared.cert_diff_fields)

        self.assertIsNotNone(pick_cert_pem(kp=sp.verification_kp, ring=sp.verification_kp_ring))

    def test_to_sp_clears_ring_when_metadata_cert_list_is_empty(self):
        """Apply clears existing rings when metadata now advertises no certs."""
        meta = ServiceProviderMetadataParser().parse(self.xml)
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
        )
        applied = meta.to_sp(provider, create_missing_rings=True)
        sp = SAMLSP.objects.get(pk=applied.object_pk)
        self.assertGreater(sp.verification_kp_ring.bindings.count(), 0)
        self.assertGreater(sp.encryption_kp_ring.bindings.count(), 0)

        no_certs = replace(meta, signing_cert_pems=[], encryption_cert_pems=[])
        no_certs.to_sp(
            provider,
            policy=APPLY_POLICY_FORCE,
            target=sp,
            create_missing_rings=True,
        )
        sp.refresh_from_db()

        self.assertEqual(sp.verification_kp_ring.bindings.count(), 0)
        self.assertEqual(sp.encryption_kp_ring.bindings.count(), 0)

        compared = no_certs.compare_sp(provider, target=sp)
        self.assertFalse(compared.cert_changed)
        self.assertFalse(compared.cert_deviated)

    def test_apply_to_provider_creates_and_syncs_keyrings(self):
        """apply_to_provider(create_missing_rings=True) creates rings and syncs certs."""
        meta = ServiceProviderMetadataParser().parse(self.xml)

        provider = SAMLProvider.objects.create(
            name="test-to-apply",
            authorization_flow=self.flow,
            invalidation_flow=self.flow,
            acs_url="https://dummy.invalid/acs",
            issuer_override="dummy",
            verification_kp=None,
            encryption_kp=None,
        )

        meta.apply_to_provider(provider, create_missing_rings=True)
        provider.refresh_from_db()

        self.assertIsNotNone(provider.verification_kp_ring)
        self.assertIsNotNone(provider.encryption_kp_ring)

        # ordering + count are the important bits (ring has what metadata had)
        v = list(provider.verification_kp_ring.bindings.order_by("order"))
        e = list(provider.encryption_kp_ring.bindings.order_by("order"))

        self.assertEqual(len(v), 2)
        self.assertEqual(len(e), 2)

        self.assertEqual([b.order for b in v], list(range(len(v))))
        self.assertEqual([b.order for b in e], list(range(len(e))))
