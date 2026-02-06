# authentik/providers/saml/tests/test_resolver.py
from __future__ import annotations

import base64
from dataclasses import dataclass

from defusedxml import ElementTree
from django.test import TestCase
from lxml import etree

from authentik.core.tests.utils import create_test_cert, create_test_flow
from authentik.providers.saml.context import (
    CURRENT_SAML_CTX,
    SAMLContext,
    get_saml_ctx,
    reset_saml_ctx,
    set_saml_ctx,
)
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLProvider
from authentik.providers.saml.processors.authn_request_parser import AuthNRequestParser
from authentik.providers.saml.resolve import resolve_acs_url, resolve_verification_kp
from authentik.providers.saml.utils.encoding import (
    decode_base64_and_inflate,
    deflate_and_base64_encode,
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

@dataclass(slots=True)
class DummySP:
    """Minimal SP stub for resolver tests."""
    acs_url: str | None = None
    verification_kp: object | None = None


class TestSAMLResolver(TestCase):
    def test_resolver_acs_url_and_verification_kp(self):
        """Resolver should prefer SP values when present, otherwise fallback to provider.
        ContextVar must be reset after use.
        """
        provider_cert = create_test_cert()
        provider = SAMLProvider.objects.create(
            name="p",
            authorization_flow=create_test_flow(),
            acs_url="https://provider.example/acs",
            verification_kp=provider_cert,
        )

        # 1) No context => provider values
        self.assertEqual(resolve_acs_url(provider), "https://provider.example/acs")
        self.assertEqual(resolve_verification_kp(provider), provider_cert)

        # 2) With SP in context => SP overrides
        sp_cert = create_test_cert()
        sp = DummySP(
            acs_url="https://sp.example/acs",
            verification_kp=sp_cert,
        )
        token = set_saml_ctx(SAMLContext(provider=provider, sp=sp, issuer="urn:test:sp"))
        try:
            self.assertEqual(resolve_acs_url(provider), "https://sp.example/acs")
            self.assertEqual(resolve_verification_kp(provider), sp_cert)
        finally:
            reset_saml_ctx(token)

        # 3) Context must be cleared after reset (no leakage)
        self.assertIsNone(get_saml_ctx())
        self.assertEqual(resolve_acs_url(provider), "https://provider.example/acs")
        self.assertEqual(resolve_verification_kp(provider), provider_cert)

        # 4) SP exists but values are None => fallback to provider
        sp2 = DummySP(acs_url=None, verification_kp=None)
        token2 = set_saml_ctx(SAMLContext(provider=provider, sp=sp2, issuer="urn:test:sp2"))
        try:
            self.assertEqual(resolve_acs_url(provider), "https://provider.example/acs")
            self.assertEqual(resolve_verification_kp(provider), provider_cert)
        finally:
            reset_saml_ctx(token2)
        self.assertIsNone(get_saml_ctx())

    def test_parse_sets_samlsp_pk_and_resets_ctx(self):
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
        self.assertEqual(req.samlsp_pk, str(sp.pk))

        self.assertIsNone(get_saml_ctx())

    def test_parse_sets_samlsp_pk_and_resets_ctx_redirect(self):
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
        self.assertEqual(req.samlsp_pk, str(sp.pk))

        self.assertIsNone(get_saml_ctx())

    def test_parse_without_sp_strict_acs_ok(self):
        provider = SAMLProvider.objects.create(
            name="strict_provider",
            authorization_flow=create_test_flow(),
            acs_url="https://eu-central-1.signin.aws.amazon.com/platform/saml/acs/2d737f96-55fb-4035-953e-5e24134eb778",
        )
        req = AuthNRequestParser(provider).parse(POST_REQUEST)

        self.assertIsNotNone(req)
        self.assertEqual(req.issuer, "https://eu-central-1.signin.aws.amazon.com/platform/saml/d-99672f8278")
        self.assertIsNone(req.samlsp_pk)

    def test_parse_without_sp_strict_acs_mismatch(self):
        provider = SAMLProvider.objects.create(
            name="strict_ng",
            authorization_flow=create_test_flow(),
            acs_url="https://example.com/acs",
        )
        with self.assertRaises(CannotHandleAssertion):
            AuthNRequestParser(provider).parse(POST_REQUEST)

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
