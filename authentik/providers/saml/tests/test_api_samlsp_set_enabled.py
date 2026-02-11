from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import (
    create_test_admin_user,
    create_test_flow,
    generate_id,
)
from authentik.providers.saml.models import SAMLSP, SAMLProvider


class TestSAMLSPSetEnabledAPI(APITestCase):
    def setUp(self):
        self.user = create_test_admin_user()
        self.client.force_login(self.user)

        self.provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",
        )

        self.sp1 = SAMLSP.objects.create(
            provider=self.provider,
            name="SP1",
            entity_id="https://sp1.example.com",
            enabled=False,
            acs_url="https://sp1.example.com/acs",
        )

        self.sp2 = SAMLSP.objects.create(
            provider=self.provider,
            name="SP2",
            entity_id="https://sp2.example.com",
            enabled=True,
            acs_url="https://sp2.example.com/acs",
        )

        self.sp3 = SAMLSP.objects.create(
            provider=self.provider,
            name="SP3",
            entity_id="https://sp3.example.com",
            enabled=True,
            acs_url="https://sp3.example.com/acs",
        )

    def test_set_enabled_replaces_set(self):
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",
        )

        sp1 = SAMLSP.objects.create(
            provider=provider,
            name="SP1",
            entity_id="a",
            acs_url="https://a",
            enabled=False,
        )
        sp2 = SAMLSP.objects.create(
            provider=provider,
            name="SP2",
            entity_id="b",
            acs_url="https://b",
            enabled=False,
        )

        url = reverse("authentik_api:samlsp-set-enabled")

        resp = self.client.post(
            url,
            data={
                "provider": str(provider.pk),
                "enabled": [str(sp1.uuid)],
            },
            format="json",
        )

        self.assertEqual(resp.status_code, 200)

        sp1.refresh_from_db()
        sp2.refresh_from_db()

        self.assertTrue(sp1.enabled)
        self.assertFalse(sp2.enabled)

        def test_set_enabled_empty_list_disables_all(self):
            """
            Sending empty enabled list should disable all SPs for provider.
            """

            url = reverse("authentik_api:samlsp-set-enabled")

            resp = self.client.post(
                url,
                data={
                    "provider": str(self.provider.pk),
                    "enabled": [],
                },
                format="json",
            )

            self.assertEqual(resp.status_code, 204, resp.content)

            for sp in (self.sp1, self.sp2, self.sp3):
                sp.refresh_from_db()
                self.assertFalse(sp.enabled)

    def test_set_enabled_is_provider_scoped(self):
        """
        Must not modify SPs belonging to other providers.
        """

        other_provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",
        )

        other_sp = SAMLSP.objects.create(
            provider=other_provider,
            name="OtherSP",
            entity_id="https://other.example.com",
            enabled=True,
            acs_url="https://other.example.com/acs",
        )

        url = reverse("authentik_api:samlsp-set-enabled")

        resp = self.client.post(
            url,
            data={
                "provider": str(self.provider.pk),
                "enabled": [str(self.sp1.uuid)],
            },
            format="json",
        )

        self.assertEqual(resp.status_code, 200, resp.content)

        other_sp.refresh_from_db()
        self.assertTrue(
            other_sp.enabled,
            "SP belonging to another provider must not be modified",
        )
    def test_set_enabled_rejects_foreign_uuid(self):
        provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost",
        )

        other_provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="http://localhost2",
        )

        foreign_sp = SAMLSP.objects.create(
            provider=other_provider,
            name="OtherSP",
            entity_id="https://other.example.com",
            enabled=True,
            acs_url="https://other.example.com/acs",
        )

        resp = self.client.post(
            reverse("authentik_api:samlsp-set-enabled"),
            data={
                "provider": str(provider.pk),
                "enabled": [str(foreign_sp.uuid)],
            },
            format="json",
        )

        self.assertEqual(resp.status_code, 400)
