"""SAMLIDP API Tests"""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_flow
from authentik.crypto.models import REF_MODEL_SAML_IDP, CertificateReference
from authentik.lib.generators import generate_id
from authentik.sources.saml.models import SAMLIDP, SAMLSource


class TestSAMLIDPAPI(APITestCase):
    def setUp(self) -> None:
        super().setUp()
        super().setUp()
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

        self.source = SAMLSource.objects.create(
            name=generate_id(),
            slug=generate_id(),
            authentication_flow=create_test_flow(),
            enrollment_flow=create_test_flow(),
            pre_authentication_flow=create_test_flow(),
            issuer="https://authentik.example/source",
            sso_url="https://idp.example/sso",
            slo_url="https://idp.example/slo",
        )

        self.idp1 = SAMLIDP.objects.create(
            source=self.source,
            name="IDP1",
            entity_id="https://idp1.example",
            enabled=False,
            sso_url="https://idp1.example/sso",
            slo_url="https://idp1.example/slo",
        )
        self.idp2 = SAMLIDP.objects.create(
            source=self.source,
            name="IDP2",
            entity_id="https://idp2.example",
            enabled=True,
            sso_url="https://idp2.example/sso",
            slo_url="https://idp2.example/slo",
        )


    def _make_source(self) -> SAMLSource:
        return SAMLSource.objects.create(
            name=generate_id(),
            slug=generate_id(),
            enabled=True,
            pre_authentication_flow=create_test_flow(),
            sso_url="https://default-idp.example.org/sso",
            slo_url=None,
            issuer="https://authentik.example.org/source/issuer",
        )

    def _assert_cert_ref_exists(self, cert, idp: SAMLIDP, usage: str, *, count: int = 1):
        qs = CertificateReference.objects.filter(
            certificate=cert,
            ref_model=REF_MODEL_SAML_IDP,
            ref_pk=str(idp.pk),
            usage=usage,
        )
        self.assertEqual(
            qs.count(),
            count,
            msg=f"Expected {count} CertificateReference for usage={usage}, got {qs.count()}",
        )

    def test_create(self):
        source = self._make_source()

        resp = self.client.post(
            reverse("authentik_api:samlidp-list"),
            data={
                "source": str(source.pk),
                "name": "IdP1",
                "entity_id": "https://idp1.example.org/metadata",
                "enabled": True,
                "sso_url": "https://idp1.example.org/sso",
                "slo_url": None,
                "verification_kp": None,
                "encryption_kp": None,
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 201, resp.content)
        pk = resp.json()["pk"]
        SAMLIDP.objects.get(pk=pk)

    def test_update_creates_references(self):
        v1 = create_test_cert()
        v2 = create_test_cert()
        e1 = create_test_cert()
        e2 = create_test_cert()

        source = self._make_source()

        # Create with certs
        create_resp = self.client.post(
            reverse("authentik_api:samlidp-list"),
            data={
                "source": str(source.pk),
                "name": "IdP1",
                "entity_id": "https://idp1.example.org/metadata",
                "enabled": True,
                "sso_url": "https://idp1.example.org/sso",
                "slo_url": None,
                "verification_kp": str(v1.pk),
                "encryption_kp": str(e1.pk),
            },
            format="json",
        )
        self.assertEqual(create_resp.status_code, 201, create_resp.content)
        idp_pk = create_resp.json()["pk"]
        idp = SAMLIDP.objects.get(pk=idp_pk)

        self._assert_cert_ref_exists(v1, idp, "saml.verification", count=1)
        self._assert_cert_ref_exists(e1, idp, "saml.encryption", count=1)

        # rotate verification
        patch0 = self.client.patch(
            reverse("authentik_api:samlidp-detail", kwargs={"uuid": idp.uuid}),
            data={"verification_kp": str(v2.pk)},
            format="json",
        )
        self.assertEqual(patch0.status_code, 200, patch0.content)
        idp.refresh_from_db()

        self._assert_cert_ref_exists(v1, idp, "saml.verification", count=0)
        self._assert_cert_ref_exists(v2, idp, "saml.verification", count=1)

        # rotate encryption
        patch1 = self.client.patch(
            reverse("authentik_api:samlidp-detail", kwargs={"uuid": idp.uuid}),
            data={"encryption_kp": str(e2.pk)},
            format="json",
        )
        self.assertEqual(patch1.status_code, 200, patch1.content)
        idp.refresh_from_db()

        self._assert_cert_ref_exists(e1, idp, "saml.encryption", count=0)
        self._assert_cert_ref_exists(e2, idp, "saml.encryption", count=1)

        # unset verification
        patch2 = self.client.patch(
            reverse("authentik_api:samlidp-detail", kwargs={"uuid": idp.uuid}),
            data={"verification_kp": None},
            format="json",
        )
        self.assertEqual(patch2.status_code, 200, patch2.content)
        idp.refresh_from_db()
        self._assert_cert_ref_exists(v2, idp, "saml.verification", count=0)

        # unset encryption
        patch3 = self.client.patch(
            reverse("authentik_api:samlidp-detail", kwargs={"uuid": idp.uuid}),
            data={"encryption_kp": None},
            format="json",
        )
        self.assertEqual(patch3.status_code, 200, patch3.content)
        idp.refresh_from_db()
        self._assert_cert_ref_exists(e2, idp, "saml.encryption", count=0)

    def test_list_filtering(self):
        source = self._make_source()
        idp1 = SAMLIDP.objects.create(
            source=source,
            name="idp1",
            entity_id="https://idp1.example.org",
            enabled=True,
            sso_url="https://idp1.example.org/sso",
        )
        SAMLIDP.objects.create(
            source=source,
            name="idp2",
            entity_id="https://idp2.example.org",
            enabled=False,
            sso_url="https://idp2.example.org/sso",
        )

        resp = self.client.get(reverse("authentik_api:samlidp-list"))
        self.assertEqual(resp.status_code, 200)

        resp_enabled = self.client.get(
            reverse("authentik_api:samlidp-list"),
            data={"source": source.pk, "enabled": True},
        )
        self.assertEqual(resp_enabled.status_code, 200)
        body = resp_enabled.json()
        results = body.get("results", body)
        self.assertTrue(any(x["pk"] == idp1.pk for x in results))

    def test_import(self):
        source = self._make_source()

        xml = """<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.org/idp">
        <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>
        </md:IDPSSODescriptor>
        </md:EntityDescriptor>"""

        resp = self.client.post(
            reverse("authentik_api:samlidp-import-metadata"),
            data={"source": source.pk, "entity_xml": xml, "overwrite": True, "set_enabled": None},
            format="json",
        )
        self.assertIn(resp.status_code, (200, 201), resp.content)
        body = resp.json()
        self.assertIn("created", body)
        self.assertTrue(SAMLIDP.objects.filter(source=source, entity_id="https://idp.example.org/idp").exists())

    def test_bulk_delete(self):
        source = self._make_source()
        idp = SAMLIDP.objects.create(
            source=source,
            name="idp",
            entity_id="https://idp.example.org",
            enabled=True,
            sso_url="https://idp.example.org/sso",
        )

        resp = self.client.post(
            reverse("authentik_api:samlidp-bulk-delete"),
            data={"source": source.pk, "uuids": [str(idp.uuid)]},
            format="json",
        )
        self.assertEqual(resp.status_code, 204, resp.content)
        self.assertFalse(SAMLIDP.objects.filter(pk=idp.pk).exists())

