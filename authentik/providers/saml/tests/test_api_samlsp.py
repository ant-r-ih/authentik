"""SAML Provider API Tests"""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_flow
from authentik.crypto.models import REF_MODEL_SAML_SP, CertificateReference
from authentik.lib.generators import generate_id
from authentik.providers.saml.models import SAMLSP, SAMLProvider


class TestSAMLProviderAPI(APITestCase):
    """SAMLSP API Tests"""

    def setUp(self) -> None:
        super().setUp()
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

    def _assert_cert_ref_exists(self, cert, sp: SAMLSP, usage: str, *, count: int = 1):
        qs = CertificateReference.objects.filter(
            certificate=cert,
            ref_model=REF_MODEL_SAML_SP,
            ref_pk=str(sp.pk),
            usage=usage,
        )
        self.assertEqual(
            qs.count(),
            count,
            msg=f"Expected {count} CertificateReference for usage={usage}, got {qs.count()}",
        )

    def test_create_and_update_creates_references(self):
        """Create+Update should create/update CertificateReference rows for selected keypairs."""

        cert1 = create_test_cert()
        cert2 = create_test_cert()

        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            # whatever required in your model
            acs_url="http://localhost",
        )

        # --- Create SP with verification_kp
        create_resp = self.client.post(
            reverse("authentik_api:samlsp-list"),
            data={
                "provider": str(provider.pk),
                "name": "SP1",
                "entity_id": "https://sp.example.com/metadata",
                "enabled": True,
                "acs_url": "https://sp.example.com/acs",
                "verification_kp": str(cert1.pk),
            },
        )
        self.assertEqual(create_resp.status_code, 201, create_resp.content)
        sp_pk = create_resp.json()["pk"]
        sp = SAMLSP.objects.get(pk=sp_pk)

        # reference created on create
        self._assert_cert_ref_exists(cert1, sp, "saml.verification")

        # --- Patch: rotate verification_kp -> cert2
        patch_resp = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"pk": sp.pk}),
            data={"verification_kp": str(cert2.pk)},
            format="json",
        )
        self.assertEqual(patch_resp.status_code, 200, patch_resp.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(cert1, sp, "saml.verification", count=0)
        self._assert_cert_ref_exists(cert2, sp, "saml.verification", count=1)

        # --- Patch: unset -> reference removed
        patch_resp2 = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"pk": sp.pk}),
            data={"verification_kp": None},
            format="json",
        )
        self.assertEqual(patch_resp2.status_code, 200, patch_resp2.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(cert2, sp, "saml.verification", count=0)

    def test_list_filtering(self):
        """Basic list endpoint works and can filter by provider/enabled."""
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",
        )
        sp1 = SAMLSP.objects.create(
            provider=provider,
            name="sp1",
            entity_id="https://sp1.example.com",
            enabled=True,
            acs_url="https://sp1.example.com/acs",
        )
        SAMLSP.objects.create(
            provider=provider,
            name="sp2",
            entity_id="https://sp2.example.com",
            enabled=False,
            acs_url="https://sp2.example.com/acs",
        )

        resp = self.client.get(reverse("authentik_api:samlsp-list"))
        self.assertEqual(resp.status_code, 200)

        resp_enabled = self.client.get(
            reverse("authentik_api:samlsp-list"),
            data={"provider": provider.pk, "enabled": True},
        )
        self.assertEqual(resp_enabled.status_code, 200)
        body = resp_enabled.json()
        # depending on pagination
        results = body.get("results", body)
        self.assertTrue(any(x["pk"] == sp1.pk for x in results))
