# authentik/providers/saml/tests/test_resolver.py
from __future__ import annotations

import base64

from defusedxml import ElementTree
from django.test import TestCase

from authentik.core.tests.utils import create_test_cert, create_test_flow
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLPropertyMapping, SAMLProvider
from authentik.providers.saml.processors.authn_request_parser import AuthNRequestParser
from authentik.providers.saml.processors.logout_request_parser import LogoutRequestParser
from authentik.providers.saml.resolve import (
    build_samlsp_config,
    resolve_acs_url,
    resolve_verification_kp,
)

POST_REQUEST = (
    "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2FtbDJwOkF1dGhuUmVxdWVzdCB4bWxuczpzYW1sMn"
    "A9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgQXNzZXJ0aW9uQ29uc3VtZXJTZXJ2aWNlVVJMPSJo"
    "dHRwczovL2V1LWNlbnRyYWwtMS5zaWduaW4uYXdzLmFtYXpvbi5jb20vcGxhdGZvcm0vc2FtbC9hY3MvMmQ3MzdmOTYtNT"
    "VmYi00MDM1LTk1M2UtNWUyNDEzNGViNzc4IiBEZXN0aW5hdGlvbj0iaHR0cHM6Ly9pZC5iZXJ5anUub3JnL2FwcGxpY2F0"
    "aW9uL3NhbWwvYXdzLXNzby9zc28vYmluZGluZy9wb3N0LyIgSUQ9ImF3c19MRHhMR2V1YnBjNWx4MTJneENnUzZ1UGJpeD"
    "F5ZDVyZSIgSXNzdWVJbnN0YW50PSIyMDIxLTA3LTA2VDE0OjIzOjA2LjM4OFoiIFByb3RvY29sQmluZGluZz0idXJuOm9h"
    "c2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmJpbmRpbmdzOkhUVFAtUE9TVCIgVmVyc2lvbj0iMi4wIj48c2FtbDI6SXNzdWVyIH"
    "htbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj5odHRwczovL2V1LWNlbnRyYWwt"
    "MS5zaWduaW4uYXdzLmFtYXpvbi5jb20vcGxhdGZvcm0vc2FtbC9kLTk5NjcyZjgyNzg8L3NhbWwyOklzc3Vlcj48c2FtbD"
    "JwOk5hbWVJRFBvbGljeSBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjEuMTpuYW1laWQtZm9ybWF0OmVtYWls"
    "QWRkcmVzcyIvPjwvc2FtbDJwOkF1dGhuUmVxdWVzdD4="
)

REDIRECT_REQUEST = (
    "fVE9a8MwEN37K4QWT7ZlD2kQsYNpKATSUpK2QzchXRKBJbm6U0j/fY2bQDO067v3eB+3WJ5dz04Q0QbfZFUhMgZeB2P9oc"
    "kS7fN5tmzvFqhcXw+yS3T0W/hMgMRGpUc5XRqeopdBoUXplQOUpOWue9rIuhBSIUKk0YD/1gz/i4YYKOjQc7ZeNdyaPIKx"
    "ETTlyaM9eDCcvV9y81Ew8hATrD2S8jRCop7los7F7FXMZXUvhfjgrLtGeQgek4O4g3iyGt62m4YfiQaUZYlDAWflhh4KHV"
    "ypNPL2ZwE5ecT2D6YDUkaRWpQ37Ot6z2PJ9eol9FZ/sccQnaK/N6iKakLG5vuJKsEp23fGREDkrGwvLrdfab8B"
)

REDIRECT_RELAY_STATE = "ss:mem:7a054b4af44f34f89dd2d973f383c250b6b076e7f06cfa8276008a6504eaf3c7"

POST_LOGOUT_REQUEST = (
    "PHNhbWxwOkxvZ291dFJlcXVlc3QgeG1sbnM6c2FtbD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvb"
    "iIgeG1sbnM6c2FtbHA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgSUQ9ImlkLWI4ZjRmZDUxZW"
    "Q0MTA2ZjFlNzgyYjk1ZDUxZDlhZDNmMzg1ZTU4MTYiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDIyLTAyLTI"
    "xVDIyOjUwOjMzLjk5OVoiIERlc3RpbmF0aW9uPSJodHRwOi8vbG9jYWxob3N0OjkwMDAvYXBwbGljYXRpb24vc2FtbC90"
    "ZXN0L3Nsby9wb3N0LyI+PHNhbWw6SXNzdWVyIEZvcm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZ"
    "C1mb3JtYXQ6ZW50aXR5Ij5zYW1sLXRlc3Qtc3A8L3NhbWw6SXNzdWVyPjxzYW1sOk5hbWVJRCBOYW1lUXVhbGlmaWVyPS"
    "JzYW1sLXRlc3Qtc3AiIFNQTmFtZVF1YWxpZmllcj0ic2FtbC10ZXN0LXNwIiBGb3JtYXQ9InVybjpvYXNpczpuYW1lczp"
    "0YzpTQU1MOjIuMDpuYW1laWQtZm9ybWF0OnRyYW5zaWVudCIvPjwvc2FtbHA6TG9nb3V0UmVxdWVzdD4="
)


class TestSAMLResolver(TestCase):
    def test_resolve_falls_back_to_provider_values(self):
        """Without an SP-specific override, resolver returns provider values."""
        provider_cert = create_test_cert()
        provider = SAMLProvider.objects.create(
            name="p",
            authorization_flow=create_test_flow(),
            acs_url="https://provider.example/acs",
            verification_kp=provider_cert,
        )

        self.assertEqual(resolve_acs_url(provider), "https://provider.example/acs")
        self.assertEqual(resolve_verification_kp(provider), provider_cert)

    def test_parse_post_sets_samlsp(self):
        provider = SAMLProvider.objects.create(
            name="example",
            authorization_flow=create_test_flow(),
            acs_url="https://sp.example/acs",
        )

        sp = provider.service_providers.create(
            name="aws-sp",
            entity_id="https://eu-central-1.signin.aws.amazon.com/platform/saml/d-99672f8278",
            enabled=True,
            acs_url="https://eu-central-1.signin.aws.amazon.com/platform/saml/acs/2d737f96-55fb-4035-953e-5e24134eb778",
        )
        req = AuthNRequestParser(provider).parse(POST_REQUEST)

        self.assertEqual(req.issuer, sp.entity_id)
        self.assertEqual(req.sp, sp)

    def test_parse_redirect_sets_samlsp(self):
        provider = SAMLProvider.objects.create(
            name="example",
            authorization_flow=create_test_flow(),
            acs_url="https://sp.invalid.example.com/acs",
        )

        sp = provider.service_providers.create(
            name="aws-sp",
            entity_id="https://sp.example.com/metadata",
            enabled=True,
            acs_url="https://sp.example.com/acs",
        )
        req = AuthNRequestParser(provider).parse_detached(REDIRECT_REQUEST, REDIRECT_RELAY_STATE)

        self.assertEqual(req.issuer, sp.entity_id)
        self.assertEqual(req.sp, sp)

    def test_parse_logout_parses_issuer_and_nameid(self):
        """Logout parser should parse issuer and NameID without ctx assumptions."""
        provider = SAMLProvider.objects.create(
            name="example",
            authorization_flow=create_test_flow(),
            acs_url="https://sp.example/acs",
        )

        provider.service_providers.create(
            name="aws-sp",
            entity_id="saml-test-sp",
            enabled=True,
            acs_url="https://example.invalid/logout/acs",
        )

        req = LogoutRequestParser(provider).parse(POST_LOGOUT_REQUEST)

        self.assertEqual(req.issuer, "saml-test-sp")
        # self.assertEqual(req.sp, sp)  # LogoutRequest doesn't have SP, just issuer
        self.assertEqual(req.name_id_format, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
        self.assertIsNotNone(req.id)

    def test_parse_without_sp_strict_acs_ok(self):
        provider = SAMLProvider.objects.create(
            name="strict_provider",
            authorization_flow=create_test_flow(),
            acs_url="https://eu-central-1.signin.aws.amazon.com/platform/saml/acs/2d737f96-55fb-4035-953e-5e24134eb778",
        )
        req = AuthNRequestParser(provider).parse(POST_REQUEST)

        self.assertIsNotNone(req)
        self.assertEqual(
            req.issuer, "https://eu-central-1.signin.aws.amazon.com/platform/saml/d-99672f8278"
        )
        self.assertIsNone(req.sp)
        self.assertEqual(
            req.acs_url,
            "https://eu-central-1.signin.aws.amazon.com/platform/saml/acs/2d737f96-55fb-4035-953e-5e24134eb778",
        )

    def test_parse_without_sp_strict_acs_mismatch(self):
        provider = SAMLProvider.objects.create(
            name="strict_ng",
            authorization_flow=create_test_flow(),
            acs_url="https://example.com/acs",
        )
        with self.assertRaises(CannotHandleAssertion):
            AuthNRequestParser(provider).parse(POST_REQUEST)

    def test_parse_without_sp_soft_acs_mismatch(self):
        provider = SAMLProvider.objects.create(
            name="strict_ng",
            authorization_flow=create_test_flow(),
            acs_url="https://example.com/acs",
        )
        provider.strict_acs_url = False
        req = AuthNRequestParser(provider).parse(POST_REQUEST)

        self.assertIsNotNone(req)
        self.assertEqual(
            req.issuer, "https://eu-central-1.signin.aws.amazon.com/platform/saml/d-99672f8278"
        )
        self.assertIsNone(req.sp)
        self.assertEqual(
            req.acs_url,
            "https://eu-central-1.signin.aws.amazon.com/platform/saml/acs/2d737f96-55fb-4035-953e-5e24134eb778",
        )

    def test_parse_without_acs_url_attr_falls_back_to_provider_acs(self):
        provider = SAMLProvider.objects.create(
            name="strict_no_acs_attr",
            authorization_flow=create_test_flow(),
            acs_url="https://example.com/acs",
        )
        root = ElementTree.fromstring(base64.b64decode(POST_REQUEST.encode("utf-8")))
        root.attrib.pop("AssertionConsumerServiceURL", None)
        xml = ElementTree.tostring(root, encoding="unicode", xml_declaration=True)
        request = base64.b64encode(xml.encode("utf-8")).decode("utf-8")

        req = AuthNRequestParser(provider).parse(request)

        self.assertIsNotNone(req.id)
        self.assertEqual(req.acs_url, "https://example.com/acs")

    class TestSAMLSPConfigPropertyMappings(TestCase):
        def _mk_pm(self, name: str) -> SAMLPropertyMapping:
            return SAMLPropertyMapping.objects.create(
                name=name,
                expression="return {}",
            )

        def test_build_config_property_mappings_fallback_to_provider_when_no_sp(self):
            provider = SAMLProvider.objects.create(
                name="p1",
                authorization_flow=create_test_flow(),
                acs_url="https://provider.example/acs",
            )
            pm1 = self._mk_pm("pm1")
            pm2 = self._mk_pm("pm2")
            provider.property_mappings.set([pm1, pm2])

            cfg = build_samlsp_config(provider, None)

            self.assertSetEqual(
                {pm.pk for pm in cfg.property_mappings},
                {pm1.pk, pm2.pk},
            )

        def test_build_config_property_mappings_fallback_to_provider_when_sp_empty(self):
            provider = SAMLProvider.objects.create(
                name="p2",
                authorization_flow=create_test_flow(),
                acs_url="https://provider.example/acs",
            )
            pm1 = self._mk_pm("pm1")
            pm2 = self._mk_pm("pm2")
            provider.property_mappings.set([pm1, pm2])

            sp = provider.service_providers.create(
                name="sp1",
                entity_id="https://sp.example/metadata",
                enabled=True,
                acs_url="https://sp.example/acs",
            )
            # sp.property_mappings is empty

            cfg = build_samlsp_config(provider, sp)

            self.assertSetEqual(
                {pm.pk for pm in cfg.property_mappings},
                {pm1.pk, pm2.pk},
            )

        def test_build_config_property_mappings_sp_complete_override(self):
            provider = SAMLProvider.objects.create(
                name="p3",
                authorization_flow=create_test_flow(),
                acs_url="https://provider.example/acs",
            )
            ppm1 = self._mk_pm("provider-pm1")
            ppm2 = self._mk_pm("provider-pm2")
            spm1 = self._mk_pm("sp-pm1")

            provider.property_mappings.set([ppm1, ppm2])

            sp = provider.service_providers.create(
                name="sp2",
                entity_id="https://sp2.example/metadata",
                enabled=True,
                acs_url="https://sp2.example/acs",
            )
            sp.property_mappings.set([spm1])

            cfg = build_samlsp_config(provider, sp)

            self.assertSetEqual(
                {pm.pk for pm in cfg.property_mappings},
                {spm1.pk},
            )
