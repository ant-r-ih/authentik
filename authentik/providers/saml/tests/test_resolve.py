from django.test import TestCase

from authentik.core.tests.utils import create_test_cert, create_test_flow
from authentik.lib.generators import generate_id
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLPropertyMapping, SAMLProvider, SAMLSP
from authentik.providers.saml.resolve import (
    ERROR_ACS_URL_MISMATCH,
    build_samlsp_config,
    find_first_text,
    peek_issuer,
    resolve_request_target,
)
from authentik.sources.saml.processors.constants import (
    NS_SAML_ASSERTION,
    NS_SAML_PROTOCOL,
    SAML_BINDING_POST,
    SAML_BINDING_REDIRECT,
)
from defusedxml import ElementTree


# もし enum が別モジュールなら import を合わせてください
try:
    from authentik.providers.saml.models import SAMLSPKeyOverrideMode
except Exception:
    SAMLSPKeyOverrideMode = None


class TestSAMLResolveHelpers(TestCase):
    def test_find_first_text_prefers_first_nonblank(self):
        xml = f"""
        <Root xmlns:saml="{NS_SAML_ASSERTION}" xmlns:samlp="{NS_SAML_PROTOCOL}">
            <samlp:Issuer>   </samlp:Issuer>
            <saml:Issuer>https://sp.example/issuer</saml:Issuer>
        </Root>
        """
        root = ElementTree.fromstring(xml)
        value = find_first_text(
            root,
            [
                f"{{{NS_SAML_PROTOCOL}}}Issuer",
                f"{{{NS_SAML_ASSERTION}}}Issuer",
            ],
        )
        self.assertEqual(value, "https://sp.example/issuer")

    def test_peek_issuer_from_authn_request_like_root(self):
        xml = f"""
        <samlp:AuthnRequest xmlns:saml="{NS_SAML_ASSERTION}" xmlns:samlp="{NS_SAML_PROTOCOL}">
            <saml:Issuer>https://sp.example/issuer</saml:Issuer>
        </samlp:AuthnRequest>
        """
        root = ElementTree.fromstring(xml)
        self.assertEqual(peek_issuer(root), "https://sp.example/issuer")

    def test_peek_issuer_returns_none_when_missing(self):
        xml = f"""
        <samlp:AuthnRequest xmlns:samlp="{NS_SAML_PROTOCOL}"></samlp:AuthnRequest>
        """
        root = ElementTree.fromstring(xml)
        self.assertIsNone(peek_issuer(root))


class TestResolveRequestTarget(TestCase):
    def setUp(self):
        self.provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="https://provider.example/acs",
            sp_binding=SAML_BINDING_POST,
            strict_acs_url=True,
        )

    def _create_sp(self, **kwargs) -> SAMLSP:
        defaults = dict(
            provider=self.provider,
            name="sp1",
            entity_id="https://sp.example/metadata",
            enabled=True,
            acs_url="https://sp.example/acs",
            sp_binding=SAML_BINDING_POST,
        )
        defaults.update(kwargs)
        return SAMLSP.objects.create(**defaults)

    def test_resolve_request_target_uses_sp_defaults_when_no_request_overrides(self):
        sp = self._create_sp()
        target = resolve_request_target(self.provider, sp)

        self.assertEqual(target.sp, sp)
        self.assertEqual(target.acs_url, "https://sp.example/acs")
        self.assertEqual(target.sp_binding, SAML_BINDING_POST)

    def test_resolve_request_target_falls_back_to_provider_when_sp_none(self):
        target = resolve_request_target(self.provider, None)

        self.assertIsNone(target.sp)
        self.assertEqual(target.acs_url, "https://provider.example/acs")
        self.assertEqual(target.sp_binding, SAML_BINDING_POST)

    def test_resolve_request_target_strict_acs_match_accepts_same_value(self):
        sp = self._create_sp()
        target = resolve_request_target(
            self.provider,
            sp,
            request_acs_url="https://sp.example/acs",
        )
        self.assertEqual(target.acs_url, "https://sp.example/acs")

    def test_resolve_request_target_strict_acs_mismatch_rejected(self):
        sp = self._create_sp()
        with self.assertRaises(CannotHandleAssertion) as ctx:
            resolve_request_target(
                self.provider,
                sp,
                request_acs_url="https://evil.example/acs",
            )
        self.assertEqual(str(ctx.exception), ERROR_ACS_URL_MISMATCH)

    def test_resolve_request_target_soft_acs_allows_override(self):
        self.provider.strict_acs_url = False
        self.provider.save(update_fields=["strict_acs_url"])

        sp = self._create_sp()
        target = resolve_request_target(
            self.provider,
            sp,
            request_acs_url="https://runtime.example/acs",
        )
        self.assertEqual(target.acs_url, "https://runtime.example/acs")

    def test_resolve_request_target_binding_request_wins_for_compat(self):
        sp = self._create_sp(sp_binding=SAML_BINDING_POST)
        target = resolve_request_target(
            self.provider,
            sp,
            request_sp_binding=SAML_BINDING_REDIRECT,
        )
        # current compatibility behavior
        self.assertEqual(target.sp_binding, SAML_BINDING_REDIRECT)


class TestBuildSAMLSPConfig(TestCase):
    def setUp(self):
        self.provider_sign = create_test_cert()
        self.provider_verify = create_test_cert()
        self.provider_encrypt = create_test_cert()

        self.sp_sign = create_test_cert()
        self.sp_verify = create_test_cert()
        self.sp_encrypt = create_test_cert()

        self.provider = SAMLProvider.objects.create(
            name=generate_id(),
            authorization_flow=create_test_flow(),
            acs_url="https://provider.example/acs",
            sp_binding=SAML_BINDING_POST,
            sls_url="https://provider.example/sls",
            sls_binding=SAML_BINDING_POST,
            digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
            signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            signing_kp=self.provider_sign,
            verification_kp=self.provider_verify,
            encryption_kp=self.provider_encrypt,
        )

        self.pm_provider_1 = SAMLPropertyMapping.objects.create(
            name=generate_id(),
            saml_name="urn:test:provider:1",
            expression="return 'v1'",
        )
        self.pm_provider_2 = SAMLPropertyMapping.objects.create(
            name=generate_id(),
            saml_name="urn:test:provider:2",
            expression="return 'v2'",
        )
        self.provider.property_mappings.set([self.pm_provider_1, self.pm_provider_2])

    def _create_sp(self, **kwargs) -> SAMLSP:
        defaults = dict(
            provider=self.provider,
            name="sp1",
            entity_id="https://sp.example/metadata",
            enabled=True,
            acs_url="https://sp.example/acs",
            sp_binding=SAML_BINDING_REDIRECT,
            sls_url="https://sp.example/sls",
            sls_binding=SAML_BINDING_REDIRECT,
            verification_kp=self.sp_verify,
            encryption_kp=self.sp_encrypt,
        )
        # signing_kp may not exist on your SAMLSP model in some revisions; set conditionally below
        defaults.update(kwargs)
        sp = SAMLSP.objects.create(**defaults)

        # Optional fields by generation (only if present)
        if hasattr(sp, "signing_kp_id") and "signing_kp" not in kwargs:
            sp.signing_kp = self.sp_sign
            sp.save(update_fields=["signing_kp"])

        return sp

    def _mapping_pks(self, mappings_obj):
        if hasattr(mappings_obj, "all"):
            return set(mappings_obj.all().values_list("pk", flat=True))
        return {m.pk for m in mappings_obj}

    def test_build_samlsp_config_uses_target_values_when_given(self):
        sp = self._create_sp()

        class DummyTarget:
            def __init__(self, sp):
                self.sp = sp
                self.acs_url = "https://request.example/acs"
                self.sp_binding = SAML_BINDING_POST

        cfg = build_samlsp_config(self.provider, sp, target=DummyTarget(sp))

        self.assertEqual(cfg.sp, sp)
        self.assertEqual(cfg.acs_url, "https://request.example/acs")
        self.assertEqual(cfg.sp_binding, SAML_BINDING_POST)
        # non-target values still come from SP/provider resolution
        self.assertEqual(cfg.sls_url, "https://sp.example/sls")
        self.assertEqual(cfg.sls_binding, SAML_BINDING_REDIRECT)

    def test_build_samlsp_config_without_target_uses_sp_then_provider(self):
        sp = self._create_sp()
        cfg = build_samlsp_config(self.provider, sp)

        self.assertEqual(cfg.sp, sp)
        self.assertEqual(cfg.acs_url, "https://sp.example/acs")
        self.assertEqual(cfg.sp_binding, SAML_BINDING_REDIRECT)
        self.assertEqual(cfg.sls_url, "https://sp.example/sls")
        self.assertEqual(cfg.sls_binding, SAML_BINDING_REDIRECT)

    def test_build_samlsp_config_without_sp_uses_provider_defaults(self):
        cfg = build_samlsp_config(self.provider, None)

        self.assertIsNone(cfg.sp)
        self.assertEqual(cfg.acs_url, "https://provider.example/acs")
        self.assertEqual(cfg.sp_binding, SAML_BINDING_POST)
        self.assertEqual(cfg.sls_url, "https://provider.example/sls")
        self.assertEqual(cfg.sls_binding, SAML_BINDING_POST)
        self.assertEqual(cfg.verification_kp, self.provider_verify)
        self.assertEqual(cfg.signing_kp, self.provider_sign)
        self.assertEqual(cfg.encryption_kp, self.provider_encrypt)

    def test_build_samlsp_config_property_mappings_fallback_to_provider_when_no_sp_override(self):
        sp = self._create_sp()

        if hasattr(sp, "property_mappings_override"):
            sp.property_mappings_override = False
            sp.save(update_fields=["property_mappings_override"])

        cfg = build_samlsp_config(self.provider, sp)
        self.assertEqual(
            self._mapping_pks(cfg.property_mappings),
            {self.pm_provider_1.pk, self.pm_provider_2.pk},
        )

    def test_build_samlsp_config_property_mappings_use_sp_when_override_on_and_nonempty(self):
        sp = self._create_sp()

        pm_sp = SAMLPropertyMapping.objects.create(
            name=generate_id(),
            saml_name="urn:test:sp:1",
            expression="return 'sp'",
        )
        sp.property_mappings.set([pm_sp])

        if hasattr(sp, "property_mappings_override"):
            sp.property_mappings_override = True
            sp.save(update_fields=["property_mappings_override"])

        cfg = build_samlsp_config(self.provider, sp)
        self.assertEqual(self._mapping_pks(cfg.property_mappings), {pm_sp.pk})

    def test_build_samlsp_config_property_mappings_empty_when_override_on_and_sp_empty(self):
        sp = self._create_sp()
        sp.property_mappings.clear()

        if hasattr(sp, "property_mappings_override"):
            sp.property_mappings_override = True
            sp.save(update_fields=["property_mappings_override"])

        cfg = build_samlsp_config(self.provider, sp)
        # override=True + empty => empty (NO provider fallback)
        self.assertEqual(self._mapping_pks(cfg.property_mappings), set())

    def test_build_samlsp_config_target_sp_replaces_explicit_sp_argument(self):
        sp1 = self._create_sp(entity_id="https://sp1.example/metadata", acs_url="https://sp1.example/acs")
        sp2 = self._create_sp(
            entity_id="https://sp2.example/metadata",
            acs_url="https://sp2.example/acs",
            sls_url="https://sp2.example/sls",
        )

        class DummyTarget:
            def __init__(self, sp):
                self.sp = sp
                self.acs_url = "https://request.example/acs"
                self.sp_binding = SAML_BINDING_REDIRECT

        cfg = build_samlsp_config(self.provider, sp1, target=DummyTarget(sp2))
        self.assertEqual(cfg.sp, sp2)
        self.assertEqual(cfg.acs_url, "https://request.example/acs")
        self.assertEqual(cfg.sls_url, "https://sp2.example/sls")
