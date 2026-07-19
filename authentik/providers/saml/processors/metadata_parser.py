"""SAML metadata parser (policy + snapshot/runtime + compatibility DTOs)."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import xmlsec
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import InvalidVersion, load_pem_x509_certificate
from lxml import etree  # nosec
from structlog.stdlib import get_logger

from authentik.common.saml.constants import (
    NS_MAP,
)
from authentik.crypto.models import (
    CertificateKeyPair,
    CertificateKeyPairRing,
    format_cert,
)
from authentik.flows.models import Flow
from authentik.providers.saml.models import (
    SAMLIDP,
    SAMLSP,
    SAMLBindings,
    SAMLPropertyMapping,
    SAMLProvider,
)
from authentik.providers.saml.processors import metadata_extract as mx
from authentik.providers.saml.processors.entities import (
    APPLY_POLICY_FORCE,
    APPLY_POLICY_IF_NOT_DEVIATED,
    MetadataApplyResult,
    MetadataCompareResult,
    SAMLIDPEntityApplier,
    SAMLSPEntityApplier,
    compare_idp,
    compare_sp,
)
from authentik.sources.saml.models import (
    SAMLBindingTypes,
    SAMLNameIDPolicy,
    SAMLSource,
)

LOGGER = get_logger()

__all__ = [
    "ServiceProviderMetadata",
    "IdentityProviderMetadata",
    "ServiceProviderMetadataParser",
    "IdentityProviderMetadataParser",
    "APPLY_POLICY_FORCE",
    "APPLY_POLICY_IF_NOT_DEVIATED",
    "MetadataCompareResult",
    "MetadataApplyResult",
    "compare_sp",
    "compare_idp",
    "build_sp_snapshot",
    "build_sp_runtime_from_snapshot",
    "build_idp_snapshot",
    "build_idp_runtime_from_snapshot",
]

"""Allowed binding tokens for SP ACS/SLS selection."""
_ALLOWED_ACS = {SAMLBindings.POST}  # keep strict for now
_ALLOWED_SLS = {SAMLBindings.POST, SAMLBindings.REDIRECT}
_ALLOWED_SSO = {SAMLBindings.POST, SAMLBindings.REDIRECT}
_ALLOWED_SLO = {SAMLBindings.POST, SAMLBindings.REDIRECT}

"""Preferred order for selection."""
_PREFER_BINDINGS = (SAMLBindings.POST, SAMLBindings.REDIRECT)
_PREFER_NAME_IDS = (
    SAMLNameIDPolicy.PERSISTENT,
    SAMLNameIDPolicy.TRANSIENT,
    SAMLNameIDPolicy.EMAIL,
    SAMLNameIDPolicy.UNSPECIFIED,
)


def build_sp_snapshot(entity: etree._Element) -> dict[str, Any]:
    """Build SP snapshot with stable keys."""
    sp_desc = mx.extract_sp_descriptor(entity)

    acs_list = mx.extract_all_acs(sp_desc)
    sls_list = mx.extract_all_sls(sp_desc)
    name_id_list = mx.extract_nameid_formats(sp_desc)

    verification_b64 = mx.extract_x509_b64_list(sp_desc, use="signing") or mx.extract_x509_b64_list(
        sp_desc, use=None
    )
    encryption_b64 = mx.extract_x509_b64_list(sp_desc, use="encryption")

    return {
        "acs": acs_list,
        "sls": sls_list,
        "name_id_formats": name_id_list,
        "authn_requests_signed": (sp_desc.attrib.get("AuthnRequestsSigned", "").lower() == "true"),
        "want_assertions_signed": (
            sp_desc.attrib.get("WantAssertionsSigned", "").lower() == "true"
        ),
        "has_verification_cert": bool(verification_b64),
        "has_encryption_cert": bool(encryption_b64),
    }


def build_sp_runtime_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Deterministically derive SP runtime defaults from snapshot using policy."""
    snap = snapshot or {}

    acs = (
        mx.pick_preferred_service(
            snap.get("acs"),
            allowed_bindings=_ALLOWED_ACS,
            prefer_order=(SAMLBindings.POST,),
        )
        or {}
    )
    sls = (
        mx.pick_preferred_service(
            snap.get("sls"),
            allowed_bindings=_ALLOWED_SLS,
            prefer_order=_PREFER_BINDINGS,
        )
        or {}
    )

    name_id_policy = mx.pick_preferred_name_id_policy(
        snap.get("name_id_formats"), prefer_order=_PREFER_NAME_IDS
    )

    return {
        "acs_url": (acs.get("url") or "").strip(),
        "sp_binding": (acs.get("binding") or "").strip(),
        "sls_url": (sls.get("url") or "").strip(),
        "sls_binding": (sls.get("binding") or "").strip(),
        "authn_requests_signed": bool(snap.get("authn_requests_signed", False)),
        "want_assertions_signed": bool(snap.get("want_assertions_signed", False)),
        "name_id_policy": (name_id_policy or "").strip(),
    }


def _pick_display_name(display_names: list[dict[str, str]], preferred_lang: str = "en") -> str:
    """Pick display name preferring exact language match, then same language family."""
    if not display_names:
        return ""

    preferred_lang = (preferred_lang or "").strip().lower()
    for entry in display_names:
        if entry.get("lang") == preferred_lang:
            return entry.get("text", "")

    for entry in display_names:
        lang = entry.get("lang", "")
        if lang.startswith(f"{preferred_lang}-"):
            return entry.get("text", "")

    for entry in display_names:
        if not entry.get("lang"):
            return entry.get("text", "")

    return display_names[0].get("text", "")


def build_idp_snapshot(entity: etree._Element) -> dict[str, Any]:
    """Build IdP snapshot with stable keys."""
    idp_desc = mx.extract_idp_descriptor(entity)

    sso_list = mx.extract_all_sso(idp_desc)
    slo_list = mx.extract_all_slo(idp_desc)
    name_id_list = mx.extract_nameid_formats(idp_desc)

    verification_b64 = mx.extract_x509_b64_list(
        idp_desc, use="signing"
    ) or mx.extract_x509_b64_list(idp_desc, use=None)
    encryption_b64 = mx.extract_x509_b64_list(idp_desc, use="encryption")

    return {
        "sso": sso_list,
        "slo": slo_list,
        "name_id_formats": name_id_list,
        "want_authn_requests_signed": (
            idp_desc.attrib.get("WantAuthnRequestsSigned", "").lower() == "true"
        ),
        "has_verification_cert": bool(verification_b64),
        "has_encryption_cert": bool(encryption_b64),
    }


def build_idp_runtime_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Derive IdP runtime defaults from snapshot using policy."""
    snap = snapshot or {}

    sso = (
        mx.pick_preferred_service(
            snap.get("sso"),
            allowed_bindings=_ALLOWED_SSO,
            prefer_order=_PREFER_BINDINGS,
        )
        or {}
    )
    slo = (
        mx.pick_preferred_service(
            snap.get("slo"),
            allowed_bindings=_ALLOWED_SLO,
            prefer_order=_PREFER_BINDINGS,
        )
        or {}
    )

    name_id_policy = mx.pick_preferred_name_id_policy(
        snap.get("name_id_formats"),
        prefer_order=_PREFER_NAME_IDS,
    )

    return {
        "sso_url": (sso.get("url") or "").strip(),
        "sso_binding": (sso.get("binding") or "").strip(),
        "slo_url": (slo.get("url") or "").strip(),
        "slo_binding": (slo.get("binding") or "").strip(),
        "want_authn_requests_signed": bool(snap.get("want_authn_requests_signed", False)),
        "name_id_policy": (name_id_policy or "").strip(),
    }


@dataclass(slots=True)
class ServiceProviderMetadata:
    """SP Metadata Dataclass"""

    entity_id: str

    acs_binding: str
    acs_location: str

    auth_n_request_signed: bool
    assertion_signed: bool
    name_id_policy: SAMLNameIDPolicy
    display_name: str | None = None

    """Keys extracted from metadata."""
    signing_cert_pems: list[str] | None = None
    encryption_cert_pems: list[str] | None = None

    # Single Logout Service (optional)
    sls_binding: str | None = None
    sls_location: str | None = None

    def to_provider(
        self, name: str, authorization_flow: Flow, invalidation_flow: Flow
    ) -> SAMLProvider:
        """Create a new SAMLProvider and apply metadata-derived fields."""
        provider = SAMLProvider.objects.create(
            name=name,
            authorization_flow=authorization_flow,
            invalidation_flow=invalidation_flow,
        )
        self.apply_to_provider(provider, create_missing_rings=True)
        return provider

    def apply_to_provider(
        self, provider: SAMLProvider, *, create_missing_rings: bool = False
    ) -> None:
        """Apply metadata-derived fields to an existing SAMLProvider."""
        provider.issuer_override = self.entity_id
        provider.sp_binding = self.acs_binding
        provider.acs_url = self.acs_location
        provider.audience = self.entity_id
        provider.default_name_id_policy = self.name_id_policy

        if self.sls_location:
            provider.sls_url = self.sls_location
        if self.sls_binding:
            provider.sls_binding = self.sls_binding

        # --- verification (remote SP signing certs) ---
        if self.signing_cert_pems and not provider.verification_kp:
            if provider.verification_kp_ring is None and create_missing_rings:
                provider.verification_kp_ring = CertificateKeyPairRing.objects.create(
                    name=f"Provider {provider.name} - SAML Verification Ring",
                )
            if provider.verification_kp_ring is not None:
                provider.verification_kp_ring.sync_membership(
                    [(i, pem) for i, pem in enumerate(self.signing_cert_pems)]
                )

        # --- encryption (remote SP encryption certs) ---
        if self.encryption_cert_pems and not provider.encryption_kp:
            if provider.encryption_kp_ring is None and create_missing_rings:
                provider.encryption_kp_ring = CertificateKeyPairRing.objects.create(
                    name=f"Provider {provider.name} - SAML Encryption Ring",
                )
            if provider.encryption_kp_ring is not None:
                provider.encryption_kp_ring.sync_membership(
                    [(i, pem) for i, pem in enumerate(self.encryption_cert_pems)]
                )

        if (
            self.assertion_signed
            and provider.signing_kp is None
            and provider.signing_kp_ring is None
        ):
            provider.signing_kp = CertificateKeyPair.objects.exclude(key_data__iexact="").first()

        if provider.property_mappings.count() == 0:
            provider.property_mappings.set(
                SAMLPropertyMapping.objects.exclude(managed__isnull=True)
            )

        provider.save()

    def compare_sp(
        self,
        parent: SAMLProvider,
        *,
        target: SAMLSP | None = None,
    ) -> MetadataCompareResult:
        """Compare DTO against current SAMLSP state."""
        return compare_sp(self, parent=parent, target=target)

    def to_sp(
        self,
        parent: SAMLProvider,
        *,
        policy: str = APPLY_POLICY_IF_NOT_DEVIATED,
        target: SAMLSP | None = None,
        create_missing_rings: bool = True,
    ) -> MetadataApplyResult:
        """Create or update SAMLSP under parent using apply policy."""
        return SAMLSPEntityApplier.apply(
            self,
            parent=parent,
            policy=policy,
            target=target,
            create_missing_rings=create_missing_rings,
        )


@dataclass(slots=True)
class IdentityProviderMetadata:
    """IdP Metadata Dataclass"""

    entity_id: str

    sso_binding: str
    sso_location: str

    want_authn_requests_signed: bool
    name_id_policy: SAMLNameIDPolicy
    display_name: str | None = None

    signing_cert_pems: list[str] | None = None
    encryption_cert_pems: list[str] | None = None

    slo_binding: str | None = None
    slo_location: str | None = None

    def to_source(
        self,
        name: str,
        *,
        pre_authentication_flow: Flow,
        issuer: str = "",
    ) -> SAMLSource:
        """Create a new SAMLSource and apply metadata-derived fields."""
        if name is None:
            raise ValueError("Name is required to create SAMLSource from metadata")
        slug = name.lower().replace(" ", "_")[:50]
        source = SAMLSource.objects.create(
            name=name,
            slug=slug,
            pre_authentication_flow=pre_authentication_flow,
            issuer_override=issuer,
        )
        self.apply_to_source(source, create_missing_rings=True)
        return source

    def apply_to_source(self, source: SAMLSource, *, create_missing_rings: bool = False) -> None:
        """Apply metadata-derived fields to an existing SAMLSource."""
        if self.sso_binding == "post":
            source.binding_type = SAMLBindingTypes.POST
        elif self.sso_binding == "redirect":
            source.binding_type = SAMLBindingTypes.REDIRECT

        source.sso_url = self.sso_location
        source.name_id_policy = self.name_id_policy

        if self.slo_location:
            source.slo_url = self.slo_location

        if self.signing_cert_pems and not source.verification_kp:
            if source.verification_kp_ring is None and create_missing_rings:
                source.verification_kp_ring = CertificateKeyPairRing.objects.create(
                    name=f"Source {source.name} - SAML Verification Ring",
                )
            if source.verification_kp_ring is not None:
                source.verification_kp_ring.sync_membership(
                    [(i, pem) for i, pem in enumerate(self.signing_cert_pems)]
                )

        source.save()

    def compare_idp(
        self,
        parent: SAMLSource,
        *,
        target: SAMLIDP | None = None,
    ) -> MetadataCompareResult:
        """Compare DTO against current SAMLIDP state."""
        return compare_idp(self, parent=parent, target=target)

    def to_idp(
        self,
        parent: SAMLSource,
        *,
        policy: str = APPLY_POLICY_IF_NOT_DEVIATED,
        target: SAMLIDP | None = None,
        create_missing_rings: bool = True,
    ) -> MetadataApplyResult:
        """Create or update SAMLIDP under parent using apply policy."""
        return SAMLIDPEntityApplier.apply(
            self,
            parent=parent,
            policy=policy,
            target=target,
            create_missing_rings=create_missing_rings,
        )


class ServiceProviderMetadataParser:
    """Service-Provider Metadata Parser"""

    def __init__(self, signing_certificate: CertificateKeyPair | None = None):
        """Optionally use an external certificate to verify metadata signatures."""
        self.signing_certificate = signing_certificate

    def get_signing_cert(self, root: etree.Element) -> CertificateKeyPair | None:
        """Extract signing X509Certificate from metadata, when given."""
        signing_certs = root.xpath(
            '//md:SPSSODescriptor/md:KeyDescriptor[@use="signing"]//ds:X509Certificate/text()',
            namespaces=NS_MAP,
        )
        if len(signing_certs) < 1:
            return None
        raw_cert = format_cert(signing_certs[0])
        # sanity check, make sure the certificate is valid.
        try:
            load_pem_x509_certificate(raw_cert.encode("utf-8"), default_backend())
        except InvalidVersion as exc:
            raise ValueError("Certificate in metadata is not a valid X.509 version") from exc
        return CertificateKeyPair(
            certificate_data=raw_cert,
        )

    def get_encryption_cert(self, root: etree.Element) -> CertificateKeyPair | None:
        """Extract encryption X509Certificate from metadata, when given."""
        encryption_certs = root.xpath(
            '//md:SPSSODescriptor/md:KeyDescriptor[@use="encryption"]//ds:X509Certificate/text()',
            namespaces=NS_MAP,
        )
        if len(encryption_certs) < 1:
            return None
        raw_cert = format_cert(encryption_certs[0])
        # sanity check, make sure the certificate is valid.
        try:
            load_pem_x509_certificate(raw_cert.encode("utf-8"), default_backend())
        except InvalidVersion as exc:
            raise ValueError("Certificate in metadata is not a valid X.509 version") from exc
        return CertificateKeyPair(
            certificate_data=raw_cert,
        )

    def get_keydescriptor_cert_pems(
        self,
        root: etree.Element,
        *,
        use: str | None,
    ) -> list[str]:
        """Extract certificate PEMs for one SP EntityDescriptor only."""
        if use == "signing":
            xp = ".//md:SPSSODescriptor/md:KeyDescriptor[@use='signing']//ds:X509Certificate/text()"
        elif use == "encryption":
            xp = (
                ".//md:SPSSODescriptor/md:KeyDescriptor[@use='encryption']"
                "//ds:X509Certificate/text()"
            )
        elif use is None:
            xp = ".//md:SPSSODescriptor/md:KeyDescriptor[not(@use)]//ds:X509Certificate/text()"
        else:
            raise ValueError("Invalid use")

        out: list[str] = []
        for b64 in root.xpath(xp, namespaces=NS_MAP):
            pem = format_cert(b64).strip()
            load_pem_x509_certificate(pem.encode("utf-8"), default_backend())  # sanity check
            out.append(pem)
        return out

    def check_signature(self, root: etree.Element, keypair: CertificateKeyPair):
        """If Metadata is signed, check validity of signature"""
        xmlsec.tree.add_ids(root, ["ID"])
        signature_nodes = root.xpath("./ds:Signature", namespaces=NS_MAP)
        if len(signature_nodes) != 1:
            return

        signature_node = signature_nodes[0]
        if signature_node is not None:
            try:
                ctx = xmlsec.SignatureContext()
                key = xmlsec.Key.from_memory(
                    keypair.certificate_data,
                    xmlsec.constants.KeyDataFormatCertPem,
                    None,
                )
                ctx.key = key
                ctx.verify(signature_node)
            except Exception as exc:
                raise ValueError("Failed to verify Metadata signature") from exc

    def _dedupe_keep_order(self, items: list[str]) -> list[str]:
        """Dedupe strings while preserving input order."""
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    def _parse_entity(self, entity: etree._Element) -> ServiceProviderMetadata:
        """Parse one EntityDescriptor node into ServiceProviderMetadata."""
        snap = build_sp_snapshot(entity)
        runtime = build_sp_runtime_from_snapshot(snap)

        signing_pems = self.get_keydescriptor_cert_pems(entity, use="signing")
        unspecified_pems = self.get_keydescriptor_cert_pems(entity, use=None)
        encryption_pems = self.get_keydescriptor_cert_pems(entity, use="encryption")

        signing_pems = self._dedupe_keep_order(signing_pems + unspecified_pems)
        encryption_pems = self._dedupe_keep_order(encryption_pems)
        display_name = _pick_display_name(
            mx.extract_entity_display_names(entity),
            preferred_lang="en",
        )

        sig_nodes = entity.xpath("./ds:Signature", namespaces=NS_MAP)
        if len(sig_nodes) == 1:
            if self.signing_certificate is not None:
                self.check_signature(entity, self.signing_certificate)  # external anchor
            else:
                """WARNING (TOFU): Verifying with an embedded certificate is not a trust anchor."""
                if not signing_pems:
                    raise ValueError("Metadata is signed but no signing certificate is present")
                last_exc: Exception | None = None
                for pem in signing_pems:
                    try:
                        self.check_signature(entity, CertificateKeyPair(certificate_data=pem))
                        break
                    except ValueError as exc:
                        last_exc = exc
                else:
                    raise last_exc or ValueError("Failed to verify Metadata signature")

        return ServiceProviderMetadata(
            entity_id=entity.attrib["entityID"],
            display_name=display_name or None,
            acs_binding=runtime.get("sp_binding") or SAMLBindings.POST,
            acs_location=runtime.get("acs_url") or "",
            auth_n_request_signed=bool(runtime.get("authn_requests_signed", False)),
            assertion_signed=bool(runtime.get("want_assertions_signed", False)),
            name_id_policy=runtime.get("name_id_policy") or SAMLNameIDPolicy.UNSPECIFIED,
            sls_binding=runtime.get("sls_binding") or None,
            sls_location=runtime.get("sls_url") or None,
            signing_cert_pems=signing_pems,
            encryption_cert_pems=encryption_pems,
        )

    def iter_entities(self, raw_xml: str) -> Iterator[ServiceProviderMetadata]:
        """Yield SP metadata entries from a metadata XML document."""
        for entity in mx.iter_sp_entity_descriptors(raw_xml):
            yield self._parse_entity(entity)

    def parse(self, raw_xml: str) -> ServiceProviderMetadata:
        """Parse metadata XML and return exactly one SP metadata entry."""
        entities = self.iter_entities(raw_xml)
        first = next(entities, None)
        if first is None:
            raise ValueError("Metadata has no SP EntityDescriptor")
        if next(entities, None) is not None:
            raise ValueError("Metadata has multiple SP entities; use iter_entities")
        return first


class IdentityProviderMetadataParser:
    """Identity-Provider Metadata Parser"""

    def __init__(self, signing_certificate: CertificateKeyPair | None = None):
        """Optionally use external certificate for ds:Signature verification."""
        self.signing_certificate = signing_certificate

    def get_keydescriptor_cert_pems(
        self,
        root: etree.Element,
        *,
        use: str | None,
    ) -> list[str]:
        """Extract and validate cert PEM values from IdP KeyDescriptor nodes."""
        if use == "signing":
            xp = (
                ".//md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']//ds:X509Certificate/text()"
            )
        elif use == "encryption":
            xp = (
                ".//md:IDPSSODescriptor/md:KeyDescriptor[@use='encryption']"
                "//ds:X509Certificate/text()"
            )
        elif use is None:
            xp = ".//md:IDPSSODescriptor/md:KeyDescriptor[not(@use)]//ds:X509Certificate/text()"
        else:
            raise ValueError("Invalid use")

        out: list[str] = []
        for b64 in root.xpath(xp, namespaces=NS_MAP):
            pem = format_cert(b64).strip()
            load_pem_x509_certificate(pem.encode("utf-8"), default_backend())  # sanity check
            out.append(pem)
        return out

    def check_signature(self, root: etree.Element, keypair: CertificateKeyPair):
        """Verify signature if the metadata contains one ds:Signature node."""
        xmlsec.tree.add_ids(root, ["ID"])
        signature_nodes = root.xpath("./ds:Signature", namespaces=NS_MAP)
        if len(signature_nodes) != 1:
            return

        signature_node = signature_nodes[0]
        if signature_node is not None:
            try:
                ctx = xmlsec.SignatureContext()
                key = xmlsec.Key.from_memory(
                    keypair.certificate_data,
                    xmlsec.constants.KeyDataFormatCertPem,
                    None,
                )
                ctx.key = key
                ctx.verify(signature_node)
            except Exception as exc:
                raise ValueError("Failed to verify Metadata signature") from exc

    def _dedupe_keep_order(self, items: list[str]) -> list[str]:
        """Dedupe strings while preserving input order."""
        seen: set[str] = set()
        out: list[str] = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
        return out

    def _parse_entity(self, entity: etree._Element) -> IdentityProviderMetadata:
        """Parse one EntityDescriptor node into IdentityProviderMetadata."""
        snap = build_idp_snapshot(entity)
        runtime = build_idp_runtime_from_snapshot(snap)
        display_name = _pick_display_name(
            mx.extract_entity_display_names(entity),
            preferred_lang="en",
        )

        signing_pems = self.get_keydescriptor_cert_pems(entity, use="signing")
        unspecified_pems = self.get_keydescriptor_cert_pems(entity, use=None)
        encryption_pems = self.get_keydescriptor_cert_pems(entity, use="encryption")

        signing_pems = self._dedupe_keep_order(signing_pems + unspecified_pems)
        encryption_pems = self._dedupe_keep_order(encryption_pems)

        sig_nodes = entity.xpath("./ds:Signature", namespaces=NS_MAP)
        if len(sig_nodes) == 1:
            if self.signing_certificate is not None:
                self.check_signature(entity, self.signing_certificate)
            else:
                if not signing_pems:
                    raise ValueError("Metadata is signed but no signing certificate is present")
                last_exc: Exception | None = None
                for pem in signing_pems:
                    try:
                        self.check_signature(entity, CertificateKeyPair(certificate_data=pem))
                        break
                    except ValueError as exc:
                        last_exc = exc
                else:
                    raise last_exc or ValueError("Failed to verify Metadata signature")

        return IdentityProviderMetadata(
            entity_id=entity.attrib["entityID"],
            sso_binding=runtime.get("sso_binding") or SAMLBindings.REDIRECT,
            sso_location=runtime.get("sso_url") or "",
            want_authn_requests_signed=bool(runtime.get("want_authn_requests_signed", False)),
            name_id_policy=runtime.get("name_id_policy") or SAMLNameIDPolicy.UNSPECIFIED,
            display_name=display_name or None,
            slo_binding=runtime.get("slo_binding") or None,
            slo_location=runtime.get("slo_url") or None,
            signing_cert_pems=signing_pems,
            encryption_cert_pems=encryption_pems,
        )

    def iter_entities(self, raw_xml: str) -> Iterator[IdentityProviderMetadata]:
        """Yield IdP metadata entries from a metadata XML document."""
        for entity in mx.iter_idp_entity_descriptors(raw_xml):
            yield self._parse_entity(entity)

    def parse(self, raw_xml: str) -> IdentityProviderMetadata:
        """Parse metadata XML and return exactly one IdP metadata entry."""
        entities = self.iter_entities(raw_xml)
        first = next(entities, None)
        if first is None:
            raise ValueError("Metadata has no IdP EntityDescriptor")
        if next(entities, None) is not None:
            raise ValueError("Metadata has multiple IdP entities; use iter_entities")
        return first
