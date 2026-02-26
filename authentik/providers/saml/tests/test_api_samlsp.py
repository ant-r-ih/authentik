"""SAML Provider API Tests"""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_flow
from authentik.crypto.models import REF_MODEL_SAML_SP, CertificateReference
from authentik.lib.generators import generate_id
from authentik.providers.saml.federation import (
    SAMLSP,
)
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
    def test_create(self):
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
                "verification_kp": None,
                "encryption_kp": None,
            },
        )
        self.assertEqual(create_resp.status_code, 201, create_resp.content)
        sp_pk = create_resp.json()["pk"]
        SAMLSP.objects.get(pk=sp_pk)

    def test_creates_references(self):
        """Create+Update should create/update CertificateReference rows for selected keypairs."""

        vcert1 = create_test_cert()

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
                "verification_kp": str(vcert1.pk),
                "encryption_kp": None,
            },
            format="json",
        )
        self.assertEqual(create_resp.status_code, 201, create_resp.content)
        sp_pk = create_resp.json()["pk"]
        SAMLSP.objects.get(pk=sp_pk)

    def test_update_creates_references(self):
        """Create+Update should create/update CertificateReference rows for selected keypairs."""

        vcert1 = create_test_cert()
        vcert2 = create_test_cert()
        ecert1 = create_test_cert()
        ecert2 = create_test_cert()
        scert1 = create_test_cert()
        scert2 = create_test_cert()

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
                "verification_kp": str(vcert1.pk),
                "encryption_kp": str(ecert1.pk),
                "signing_kp": str(scert1.pk),
            },
            format="json",
        )
        self.assertEqual(create_resp.status_code, 201, create_resp.content)
        sp_pk = create_resp.json()["pk"]
        sp = SAMLSP.objects.get(pk=sp_pk)

        # reference created on create
        self._assert_cert_ref_exists(vcert1, sp, "saml.verification")
        self._assert_cert_ref_exists(ecert1, sp, "saml.encryption")
        self._assert_cert_ref_exists(scert1, sp, "saml.signing")
        self.assertEqual(sp.verification_kp_override, True)
        self.assertEqual(sp.encryption_kp_override, True)
        self.assertEqual(sp.signing_kp_override, True)

        # --- Patch: rotate verification_kp -> cert2
        patch_resp0 = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"uuid": sp.uuid}),
            data={"verification_kp": str(vcert2.pk)},
            format="json",
        )
        self.assertEqual(patch_resp0.status_code, 200, patch_resp0.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(vcert1, sp, "saml.verification", count=0)
        self._assert_cert_ref_exists(vcert2, sp, "saml.verification", count=1)

        # --- Patch: rotate encryption_kp -> cert2
        patch_resp1 = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"uuid": sp.uuid}),
            data={"encryption_kp": str(ecert2.pk)},
            format="json",
        )
        self.assertEqual(patch_resp1.status_code, 200, patch_resp1.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(ecert1, sp, "saml.encryption", count=0)
        self._assert_cert_ref_exists(ecert2, sp, "saml.encryption", count=1)

        # --- Patch: rotate signing_kp -> cert2
        patch_resp2 = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"uuid": sp.uuid}),
            data={"signing_kp": str(scert2.pk)},
            format="json",
        )
        self.assertEqual(patch_resp2.status_code, 200, patch_resp2.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(scert1, sp, "saml.signing", count=0)
        self._assert_cert_ref_exists(scert2, sp, "saml.signing", count=1)
        self.assertEqual(sp.signing_kp_override, True)


        # --- Patch: unset -> reference removed
        patch_resp3 = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"uuid": sp.uuid}),
            data={"verification_kp": None},
            format="json",
        )
        self.assertEqual(patch_resp3.status_code, 200, patch_resp3.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(vcert2, sp, "saml.verification", count=0)
        self.assertEqual(sp.verification_kp_override, True)
        # --- Patch: unset -> reference removed
        patch_resp4 = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"uuid": sp.uuid}),
            data={"encryption_kp": None},
            format="json",
        )
        self.assertEqual(patch_resp4.status_code, 200, patch_resp4.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(ecert2, sp, "saml.encryption", count=0)
        self.assertEqual(sp.encryption_kp_override, True)

        # --- Patch: unset signing -> reference removed
        patch_resp5 = self.client.patch(
            reverse("authentik_api:samlsp-detail", kwargs={"uuid": sp.uuid}),
            data={"signing_kp": None},
            format="json",
        )
        self.assertEqual(patch_resp5.status_code, 200, patch_resp5.content)
        sp.refresh_from_db()

        self._assert_cert_ref_exists(scert2, sp, "saml.signing", count=0)
        self.assertEqual(sp.signing_kp_override, True)

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
