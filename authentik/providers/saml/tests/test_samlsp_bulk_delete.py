from __future__ import annotations

from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient

from authentik.core.tests.utils import create_test_admin_user, create_test_cert, create_test_flow
from authentik.crypto.models import CertificateReference
from authentik.lib.generators import generate_id
from authentik.providers.saml.federation import (
    SAMLSP,
    compute_signature_hash,
    normalize_signature,
)
from authentik.providers.saml.models import SAMLProvider
from authentik.providers.saml.utils.certrefs import REF_MODEL_SAML_SP, sync_saml_sp_cert_refs


class TestSAMLSPBulkDelete(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = create_test_admin_user()
        self.client.force_authenticate(user=self.user)

        self.provider1 = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",
        )
        self.provider2 = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",
        )

    def _create_sp(self, provider: SAMLProvider) -> SAMLSP:
        kp = create_test_cert()
        sp = SAMLSP.objects.create(
            provider=provider,
            name=generate_id(),
            entity_id=f"https://sp.example/{generate_id()}",
            enabled=True,
            acs_url="https://sp.example/acs",
            verification_kp=kp,
            verification_kp_override=True,
        )
        sync_saml_sp_cert_refs(sp)
        # print("sp.pk=", sp.pk, "verification_kp_id=", sp.verification_kp_id, "encryption_kp_id=", sp.encryption_kp_id)
        # print("certrefs=", list(
        #     CertificateReference.objects.filter(ref_model=REF_MODEL_SAML_SP, ref_pk=str(sp.pk))
        #     .values_list("certificate_id", "usage")
        # ))
        return sp

    def test_bulk_delete_deletes_sp_and_certrefs(self):
        sp1 = self._create_sp(self.provider1)
        sp2 = self._create_sp(self.provider1)

        # precheck: certrefs exist
        self.assertTrue(
            CertificateReference.objects.filter(ref_model=REF_MODEL_SAML_SP, ref_pk=str(sp1.pk)).exists()
        )
        self.assertTrue(
            CertificateReference.objects.filter(ref_model=REF_MODEL_SAML_SP, ref_pk=str(sp2.pk)).exists()
        )

        url = reverse("authentik_api:samlsp-bulk-delete")
        res = self.client.post(
            url,
            data={"provider": self.provider1.pk, "uuids": [str(sp1.uuid), str(sp2.uuid)]},
            format="json",
        )
        self.assertEqual(res.status_code, 204)

        self.assertFalse(SAMLSP.objects.filter(pk=sp1.pk).exists())
        self.assertFalse(SAMLSP.objects.filter(pk=sp2.pk).exists())

        self.assertFalse(
            CertificateReference.objects.filter(ref_model=REF_MODEL_SAML_SP, ref_pk=str(sp1.pk)).exists()
        )
        self.assertFalse(
            CertificateReference.objects.filter(ref_model=REF_MODEL_SAML_SP, ref_pk=str(sp2.pk)).exists()
        )

    def test_bulk_delete_ignores_foreign_provider(self):
        sp1 = self._create_sp(self.provider1)
        foreign = self._create_sp(self.provider2)

        url = reverse("authentik_api:samlsp-bulk-delete")
        res = self.client.post(
            url,
            data={"provider": self.provider1.pk, "uuids": [str(sp1.uuid), str(foreign.uuid)]},
            format="json",
        )
        self.assertEqual(res.status_code, 204)

        # deleted
        self.assertFalse(SAMLSP.objects.filter(pk=sp1.pk).exists())
        self.assertFalse(
            CertificateReference.objects.filter(ref_model=REF_MODEL_SAML_SP, ref_pk=str(sp1.pk)).exists()
        )

        # foreign remains
        self.assertTrue(SAMLSP.objects.filter(pk=foreign.pk).exists())
        self.assertTrue(
            CertificateReference.objects.filter(ref_model=REF_MODEL_SAML_SP, ref_pk=str(foreign.pk)).exists()
        )
