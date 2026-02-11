"""saml sp models"""

import hashlib
import json
from typing import Any, Optional
from uuid import uuid4

from django.db import models
from django.http import HttpRequest
from django.templatetags.static import static
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer

from authentik.core.models import (
    GroupSourceConnection,
    PropertyMapping,
    Source,
    UserSourceConnection,
)
from authentik.core.types import UILoginButton, UserSettingSerializer
from authentik.crypto.models import CertificateKeyPair
from authentik.flows.challenge import RedirectChallenge
from authentik.flows.models import Flow
from authentik.lib.expression.evaluator import BaseEvaluator
from authentik.lib.models import DomainlessURLValidator
from authentik.lib.utils.time import timedelta_string_validator
from authentik.sources.saml.processors.constants import (
    DSA_SHA1,
    ECDSA_SHA1,
    ECDSA_SHA256,
    ECDSA_SHA384,
    ECDSA_SHA512,
    NS_SAML_ASSERTION,
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
    SAML_ATTRIBUTES_GROUP,
    SAML_BINDING_POST,
    SAML_BINDING_REDIRECT,
    SAML_NAME_ID_FORMAT_EMAIL,
    SAML_NAME_ID_FORMAT_PERSISTENT,
    SAML_NAME_ID_FORMAT_TRANSIENT,
    SAML_NAME_ID_FORMAT_UNSPECIFIED,
    SAML_NAME_ID_FORMAT_WINDOWS,
    SAML_NAME_ID_FORMAT_X509,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
)


class SAMLBindingTypes(models.TextChoices):
    """SAML Binding types"""

    REDIRECT = "REDIRECT", _("Redirect Binding")
    POST = "POST", _("POST Binding")
    POST_AUTO = "POST_AUTO", _("POST Binding with auto-confirmation")

    @property
    def uri(self) -> str:
        """Convert database field to URI"""
        return {
            SAMLBindingTypes.POST: SAML_BINDING_POST,
            SAMLBindingTypes.POST_AUTO: SAML_BINDING_POST,
            SAMLBindingTypes.REDIRECT: SAML_BINDING_REDIRECT,
        }[self]


class SAMLNameIDPolicy(models.TextChoices):
    """SAML NameID Policies"""

    EMAIL = SAML_NAME_ID_FORMAT_EMAIL
    PERSISTENT = SAML_NAME_ID_FORMAT_PERSISTENT
    X509 = SAML_NAME_ID_FORMAT_X509
    WINDOWS = SAML_NAME_ID_FORMAT_WINDOWS
    TRANSIENT = SAML_NAME_ID_FORMAT_TRANSIENT
    UNSPECIFIED = SAML_NAME_ID_FORMAT_UNSPECIFIED


class SAMLSource(Source):
    """Authenticate using an external SAML Identity Provider."""

    pre_authentication_flow = models.ForeignKey(
        Flow,
        on_delete=models.CASCADE,
        help_text=_("Flow used before authentication."),
        related_name="source_pre_authentication",
    )

    issuer = models.TextField(
        blank=True,
        default=None,
        verbose_name=_("Issuer"),
        help_text=_("Also known as Entity ID. Defaults the Metadata URL."),
    )

    sso_url = models.TextField(
        validators=[DomainlessURLValidator(schemes=("http", "https"))],
        verbose_name=_("SSO URL"),
        help_text=_("URL that the initial Login request is sent to."),
    )
    slo_url = models.TextField(
        validators=[DomainlessURLValidator(schemes=("http", "https"))],
        default=None,
        blank=True,
        null=True,
        verbose_name=_("SLO URL"),
        help_text=_("Optional URL if your IDP supports Single-Logout."),
    )

    allow_idp_initiated = models.BooleanField(
        default=False,
        help_text=_(
            "Allows authentication flows initiated by the IdP. This can be a security risk, "
            "as no validation of the request ID is done."
        ),
    )
    name_id_policy = models.TextField(
        choices=SAMLNameIDPolicy.choices,
        default=SAMLNameIDPolicy.PERSISTENT,
        help_text=_(
            "NameID Policy sent to the IdP. Can be unset, in which case no Policy is sent."
        ),
    )
    binding_type = models.CharField(
        max_length=100,
        choices=SAMLBindingTypes.choices,
        default=SAMLBindingTypes.REDIRECT,
    )

    temporary_user_delete_after = models.TextField(
        default="days=1",
        verbose_name=_("Delete temporary users after"),
        validators=[timedelta_string_validator],
        help_text=_(
            "Time offset when temporary users should be deleted. This only applies if your IDP "
            "uses the NameID Format 'transient', and the user doesn't log out manually. "
            "(Format: hours=1;minutes=2;seconds=3)."
        ),
    )

    verification_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        help_text=_(
            "When selected, incoming assertion's Signatures will be validated against this "
            "certificate. To allow unsigned Requests, leave on default."
        ),
        on_delete=models.SET_NULL,
        verbose_name=_("Verification Certificate"),
        related_name="+",
    )
    signing_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        help_text=_("Keypair used to sign outgoing Responses going to the Identity Provider."),
        on_delete=models.SET_NULL,
        verbose_name=_("Signing Keypair"),
    )
    encryption_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        help_text=_(
            "When selected, incoming assertions are encrypted by the IdP using the public "
            "key of the encryption keypair. The assertion is decrypted by the SP using the "
            "the private key."
        ),
        on_delete=models.SET_NULL,
        verbose_name=_("Encryption Keypair"),
        related_name="+",
    )

    digest_algorithm = models.TextField(
        choices=(
            (SHA1, _("SHA1")),
            (SHA256, _("SHA256")),
            (SHA384, _("SHA384")),
            (SHA512, _("SHA512")),
        ),
        default=SHA256,
    )
    signature_algorithm = models.TextField(
        choices=(
            (RSA_SHA1, _("RSA-SHA1")),
            (RSA_SHA256, _("RSA-SHA256")),
            (RSA_SHA384, _("RSA-SHA384")),
            (RSA_SHA512, _("RSA-SHA512")),
            (ECDSA_SHA1, _("ECDSA-SHA1")),
            (ECDSA_SHA256, _("ECDSA-SHA256")),
            (ECDSA_SHA384, _("ECDSA-SHA384")),
            (ECDSA_SHA512, _("ECDSA-SHA512")),
            (DSA_SHA1, _("DSA-SHA1")),
        ),
        default=RSA_SHA256,
    )

    signed_assertion = models.BooleanField(default=True)
    signed_response = models.BooleanField(default=False)

    @property
    def component(self) -> str:
        return "ak-source-saml-form"

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.sources.saml.api.source import SAMLSourceSerializer

        return SAMLSourceSerializer

    @property
    def property_mapping_type(self) -> type[PropertyMapping]:
        return SAMLSourcePropertyMapping

    def get_base_user_properties(self, root: Any, name_id: Any, **kwargs):
        attributes = {}
        assertion = root.find(f"{{{NS_SAML_ASSERTION}}}Assertion")
        if assertion is None:
            raise ValueError("Assertion element not found")
        attribute_statement = assertion.find(f"{{{NS_SAML_ASSERTION}}}AttributeStatement")
        if attribute_statement is None:
            raise ValueError("Attribute statement element not found")
        # Get all attributes and their values into a dict
        for attribute in attribute_statement.iterchildren():
            key = attribute.attrib["Name"]
            attributes.setdefault(key, [])
            for value in attribute.iterchildren():
                attributes[key].append(value.text)
        if SAML_ATTRIBUTES_GROUP in attributes:
            attributes["groups"] = attributes[SAML_ATTRIBUTES_GROUP]
            del attributes[SAML_ATTRIBUTES_GROUP]
        # Flatten all lists in the dict
        for key, value in attributes.items():
            if key == "groups":
                continue
            attributes[key] = BaseEvaluator.expr_flatten(value)
        attributes["username"] = name_id.text

        return attributes

    def get_base_group_properties(self, group_id: str, **kwargs):
        return {
            "name": group_id,
        }

    def get_issuer(self, request: HttpRequest) -> str:
        """Get Source's Issuer, falling back to our Metadata URL if none is set"""
        if self.issuer is None:
            return self.build_full_url(request, view="metadata")
        return self.issuer

    def build_full_url(self, request: HttpRequest, view: str = "acs") -> str:
        """Build Full ACS URL to be used in IDP"""
        return request.build_absolute_uri(
            reverse(f"authentik_sources_saml:{view}", kwargs={"source_slug": self.slug})
        )

    @property
    def icon_url(self) -> str:
        icon = super().icon_url
        if not icon:
            return static("authentik/sources/saml.png")
        return icon

    def ui_login_button(self, request: HttpRequest) -> UILoginButton:
        return UILoginButton(
            challenge=RedirectChallenge(
                data={
                    "to": reverse(
                        "authentik_sources_saml:login",
                        kwargs={"source_slug": self.slug},
                    ),
                }
            ),
            name=self.name,
            icon_url=self.icon_url,
            promoted=self.promoted,
        )

    def ui_user_settings(self) -> UserSettingSerializer | None:
        return UserSettingSerializer(
            data={
                "title": self.name,
                "component": "ak-user-settings-source-saml",
                "configure_url": reverse(
                    "authentik_sources_saml:login",
                    kwargs={"source_slug": self.slug},
                ),
                "icon_url": self.icon_url,
            }
        )

    def get_idp(self, entity_id: str | None) -> "SAMLIDP | None":
        """Resolve enabled additional IdP by entityID (issuer). Returns None if not found."""
        if not entity_id:
            return None
        return self.identity_providers.filter(entity_id=entity_id, enabled=True).first()

    def __str__(self):
        return f"SAML Source {self.name}"

    class Meta:
        verbose_name = _("SAML Source")
        verbose_name_plural = _("SAML Sources")

class SAMLIDPMetadataState(models.TextChoices):
    MANUAL = "manual", "Manual"
    UNCHANGED = "unchanged", "Unchanged"
    DIVERGED = "diverged", "Diverged"
    # いまは SP 側と同じく “lifecycle” までは使わないが、将来の UI/運用に備えて持つ
    OUTDATED = "outdated", "Outdated"
    ORPHANED = "orphaned", "Orphaned"


class SAMLIDPKeyOverrideMode(models.TextChoices):
    """How SAMLIDP resolves keypair settings relative to SAMLSource defaults."""

    INHERIT = "inherit", "Inherit source setting"
    SET = "set", "Use local key"
    NONE = "none", "Disable key (no key)"


def compute_signature_hash(data: dict[str, Any]) -> str:
    """Caller must pass already-normalized dict."""
    normalized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode()).hexdigest()


def _norm_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v.strip()
    return str(v).strip()


def normalize_idp_signature(data: dict[str, Any]) -> dict[str, Any]:
    """
    Canonical normalization for SAMLIDP snapshot/runtime structures.

    Canonical form is intentionally coarse:
      - endpoints/flags + key *presence* (not key identity)

    Accepts both:
      A) snapshot-ish dict (metadata_snapshot)
      B) runtime-ish dict (fields from SAMLIDP + computed presence flags)
    """
    return {
        "sso_url": _norm_str(data.get("sso_url")),
        "slo_url": _norm_str(data.get("slo_url")),
        "binding_type": _norm_str(data.get("binding_type")),
        "allow_idp_initiated": bool(data.get("allow_idp_initiated", False)),
        "name_id_policy": _norm_str(data.get("name_id_policy")),
        "signed_assertion": bool(data.get("signed_assertion", True)),
        "signed_response": bool(data.get("signed_response", False)),
        "has_verification_cert": bool(data.get("has_verification_cert", False)),
        "has_encryption_cert": bool(data.get("has_encryption_cert", False)),
        "has_signing_cert": bool(data.get("has_signing_cert", False)),
    }


def _mode_value(obj: Any, attr: str) -> str | None:
    if obj is None:
        return None
    v = getattr(obj, attr, None)
    if isinstance(v, str):
        v = v.strip().lower()
    return v or None


def _resolve_kp_with_mode(
    local_obj: Any,
    *,
    mode_attr: str,
    kp_attr: str,
    fallback_kp: Optional[CertificateKeyPair],
) -> Optional[CertificateKeyPair]:
    """
    Tri-state resolver:
      - none    => None
      - set     => local key
      - inherit => fallback key (SAMLSource default)
    """
    mode = _mode_value(local_obj, mode_attr)
    local_kp = getattr(local_obj, kp_attr, None) if local_obj is not None else None

    if mode == "none":
        return None
    if mode == "set":
        return local_kp
    if mode == "inherit":
        return fallback_kp

    # legacy fallback (mode missing)
    return local_kp or fallback_kp


def current_runtime_signature_idp(idp: "SAMLIDP") -> dict[str, Any]:
    """
    Current runtime signature for IDP:
      - fields come from SAMLIDP row
      - key presence is computed using mode + fallback (SAMLSource)
    """
    source = getattr(idp, "source", None)

    verification_kp = _resolve_kp_with_mode(
        idp,
        mode_attr="verification_kp_mode",
        kp_attr="verification_kp",
        fallback_kp=getattr(source, "verification_kp", None),
    )
    encryption_kp = _resolve_kp_with_mode(
        idp,
        mode_attr="encryption_kp_mode",
        kp_attr="encryption_kp",
        fallback_kp=getattr(source, "encryption_kp", None),
    )
    signing_kp = _resolve_kp_with_mode(
        idp,
        mode_attr="signing_kp_mode",
        kp_attr="signing_kp",
        fallback_kp=getattr(source, "signing_kp", None),
    )

    return {
        "sso_url": idp.sso_url,
        "slo_url": idp.slo_url,
        "binding_type": idp.binding_type,
        "allow_idp_initiated": bool(idp.allow_idp_initiated),
        "name_id_policy": idp.name_id_policy,
        "signed_assertion": bool(idp.signed_assertion),
        "signed_response": bool(idp.signed_response),
        "has_verification_cert": verification_kp is not None,
        "has_encryption_cert": encryption_kp is not None,
        "has_signing_cert": signing_kp is not None,
    }


def expected_runtime_signature_idp_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """
    Expected signature derived from metadata_snapshot.
    """
    snap = snapshot or {}
    return {
        "sso_url": snap.get("sso_url", ""),
        "slo_url": snap.get("slo_url", ""),
        "binding_type": snap.get("binding_type", ""),
        "allow_idp_initiated": bool(snap.get("allow_idp_initiated", False)),
        "name_id_policy": snap.get("name_id_policy", ""),
        "signed_assertion": bool(snap.get("signed_assertion", True)),
        "signed_response": bool(snap.get("signed_response", False)),
        "has_verification_cert": bool(snap.get("has_verification_cert", False)),
        "has_encryption_cert": bool(snap.get("has_encryption_cert", False)),
        "has_signing_cert": bool(snap.get("has_signing_cert", False)),
    }


def idp_runtime_diverged(idp: "SAMLIDP") -> bool:
    """
    DB snapshot basis diverged check for SAMLIDP.

    Important design note (SPと同じ):
      - coarse compare: endpoints/flags + key *presence*
      - does NOT compare exact key identity (fingerprint/kp id)
    """
    if not idp.metadata_snapshot:
        return False

    expected = expected_runtime_signature_idp_from_snapshot(idp.metadata_snapshot or {})
    current = current_runtime_signature_idp(idp)

    return normalize_idp_signature(expected) != normalize_idp_signature(current)

class SAMLIDP(models.Model):
    """Additional SAML Identity Provider configuration under a SAMLSource.

    The existing SAMLSource fields remain the 'default IdP'. This model is only for additional IdPs.
    """

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True)

    source = models.ForeignKey(
        "SAMLSource",
        on_delete=models.CASCADE,
        related_name="identity_providers",
    )

    name = models.TextField(blank=True, default="")
    entity_id = models.TextField(help_text=_("IdP EntityID (Issuer)"))
    enabled = models.BooleanField(default=False)

    created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    # IdP endpoints
    sso_url = models.TextField(
        validators=[DomainlessURLValidator(schemes=("http", "https"))],
        verbose_name=_("SSO URL"),
        help_text=_("URL that the initial Login request is sent to."),
    )
    slo_url = models.TextField(
        validators=[DomainlessURLValidator(schemes=("http", "https"))],
        default=None,
        blank=True,
        null=True,
        verbose_name=_("SLO URL"),
        help_text=_("Optional URL if your IDP supports Single-Logout."),
    )

    # Per-IdP behavior knobs (copied from SAMLSource for symmetry)
    allow_idp_initiated = models.BooleanField(
        default=False,
        help_text=_(
            "Allows authentication flows initiated by the IdP. This can be a security risk, "
            "as no validation of the request ID is done."
        ),
    )
    name_id_policy = models.TextField(
        choices=SAMLNameIDPolicy.choices,
        default=SAMLNameIDPolicy.PERSISTENT,
        help_text=_(
            "NameID Policy sent to the IdP. Can be unset, in which case no Policy is sent."
        ),
    )
    binding_type = models.CharField(
        max_length=100,
        choices=SAMLBindingTypes.choices,
        default=SAMLBindingTypes.REDIRECT,
    )

    verification_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        help_text=_(
            "When selected, incoming assertion's Signatures will be validated against this "
            "certificate. To allow unsigned Requests, leave on default."
        ),
        on_delete=models.SET_NULL,
        verbose_name=_("Verification Certificate"),
        related_name="+",
    )
    signing_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        help_text=_("Keypair used to sign outgoing Responses going to the Identity Provider."),
        on_delete=models.SET_NULL,
        verbose_name=_("Signing Keypair"),
    )
    encryption_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        help_text=_(
            "When selected, incoming assertions are encrypted by the IdP using the public "
            "key of the encryption keypair. The assertion is decrypted by the SP using the "
            "the private key."
        ),
        on_delete=models.SET_NULL,
        verbose_name=_("Encryption Keypair"),
        related_name="+",
    )
    metadata_last_import = models.DateTimeField(
        default=None,
        null=True,
        blank=True,
        verbose_name=_("Metadata last import"),
        help_text=_("Timestamp of the last successful metadata import."),
    )
    metadata_snapshot = models.JSONField(
        default=None,
        null=True,
        blank=True,
        verbose_name=_("Metadata snapshot"),
        help_text=_("Canonical snapshot built from SAML metadata (JSON)."),
    )
    metadata_hash = models.CharField(
        max_length=64,
        default=None,
        null=True,
        blank=True,
        verbose_name=_("Metadata hash"),
        help_text=_("sha256 hex digest of normalized metadata snapshot."),
    )
    digest_algorithm = models.TextField(
        choices=(
            (SHA1, _("SHA1")),
            (SHA256, _("SHA256")),
            (SHA384, _("SHA384")),
            (SHA512, _("SHA512")),
        ),
        default=SHA256,
    )
    signature_algorithm = models.TextField(
        choices=(
            (RSA_SHA1, _("RSA-SHA1")),
            (RSA_SHA256, _("RSA-SHA256")),
            (RSA_SHA384, _("RSA-SHA384")),
            (RSA_SHA512, _("RSA-SHA512")),
            (ECDSA_SHA1, _("ECDSA-SHA1")),
            (ECDSA_SHA256, _("ECDSA-SHA256")),
            (ECDSA_SHA384, _("ECDSA-SHA384")),
            (ECDSA_SHA512, _("ECDSA-SHA512")),
            (DSA_SHA1, _("DSA-SHA1")),
        ),
        default=RSA_SHA256,
    )

    signed_assertion = models.BooleanField(default=True)
    signed_response = models.BooleanField(default=False)

    # -------------------------
    # Key resolution policy (source fallback / local / explicit none)
    # -------------------------
    verification_kp_mode = models.CharField(
        max_length=16,
        choices=SAMLIDPKeyOverrideMode.choices,
        default=SAMLIDPKeyOverrideMode.INHERIT,
        help_text=(
            "How verification_kp is resolved: inherit source, use local key, "
            "or explicitly disable verification key."
        ),
    )
    encryption_kp_mode = models.CharField(
        max_length=16,
        choices=SAMLIDPKeyOverrideMode.choices,
        default=SAMLIDPKeyOverrideMode.INHERIT,
        help_text=(
            "How encryption_kp is resolved: inherit source, use local key, "
            "or explicitly disable encryption key."
        ),
    )
    signing_kp_mode = models.CharField(
        max_length=16,
        choices=SAMLIDPKeyOverrideMode.choices,
        default=SAMLIDPKeyOverrideMode.INHERIT,
        help_text=(
            "How signing_kp is resolved: inherit source, use local key, "
            "or explicitly disable signing key."
        ),
    )

    # -------------------------
    # UI/diagnostic + metadata-apply behavior
    # -------------------------
    has_local_override = models.BooleanField(
        default=False,
        help_text=(
            "UI/diagnostic flag indicating local changes may exist relative to "
            "metadata-derived defaults. Protocol processing does not read this flag."
        ),
    )

    freeze_verification_kp = models.BooleanField(
        default=False,
        help_text=(
            "Do not overwrite verification_kp during metadata apply/import. "
            "Useful for certificate rollover handling or local pinning."
        ),
    )
    freeze_encryption_kp = models.BooleanField(
        default=False,
        help_text=(
            "Do not overwrite encryption_kp during metadata apply/import. "
            "Useful for certificate rollover handling or local pinning."
        ),
    )
    freeze_signing_kp = models.BooleanField(
        default=False,
        help_text=(
            "Do not overwrite signing_kp during metadata apply/import. "
            "Useful for certificate rollover handling or local pinning."
        ),
    )
    class Meta:
        verbose_name = _("SAML Identity Provider")
        verbose_name_plural = _("SAML Identity Providers")
        unique_together = [("source", "entity_id")]
        indexes = [
            models.Index(fields=["source", "entity_id"]),
            models.Index(fields=["source", "enabled"]),
        ]
    def __str__(self):
        return f"SAML IdP {self.name or self.entity_id}"

    @property
    def snapshot_hash_normalized(self) -> str | None:
        """Hash of *current* metadata_snapshot after canonical normalization."""
        if not self.metadata_snapshot:
            return None
        return compute_signature_hash(normalize_idp_signature(self.metadata_snapshot))

    @property
    def runtime_db_basis_state(self) -> SAMLIDPMetadataState:
        """
        Compare runtime config against what would be generated from stored DB snapshot.

        Same philosophy as SAMLSP:
          - coarse drift detection (endpoints/flags + key presence)
          - key rotation/rollback should not flip this state if presence stays the same
        """
        if not self.metadata_snapshot:
            return SAMLIDPMetadataState.MANUAL
        return (
            SAMLIDPMetadataState.DIVERGED
            if idp_runtime_diverged(self)
            else SAMLIDPMetadataState.UNCHANGED
        )

    def clean(self):
        """
        Keep *_kp_mode and local key fields consistent.

        Rule:
          - mode == SET   -> local FK must be present
          - mode != SET   -> local FK may be empty
        """
        super().clean()

        def _validate(mode_field: str, kp_field: str):
            mode = getattr(self, mode_field)
            kp = getattr(self, kp_field)
            if mode == SAMLIDPKeyOverrideMode.SET and kp is None:
                from django.core.exceptions import ValidationError

                raise ValidationError(
                    {kp_field: f"{kp_field} is required when {mode_field}=SET."}
                )

        _validate("verification_kp_mode", "verification_kp")
        _validate("encryption_kp_mode", "encryption_kp")
        _validate("signing_kp_mode", "signing_kp")

class SAMLSourcePropertyMapping(PropertyMapping):
    """Map SAML properties to User or Group object attributes"""

    @property
    def component(self) -> str:
        return "ak-property-mapping-source-saml-form"

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.sources.saml.api.property_mappings import SAMLSourcePropertyMappingSerializer

        return SAMLSourcePropertyMappingSerializer

    class Meta:
        verbose_name = _("SAML Source Property Mapping")
        verbose_name_plural = _("SAML Source Property Mappings")


class UserSAMLSourceConnection(UserSourceConnection):
    """Connection to configured SAML Sources."""

    @property
    def serializer(self) -> Serializer:
        from authentik.sources.saml.api.source_connection import UserSAMLSourceConnectionSerializer

        return UserSAMLSourceConnectionSerializer

    class Meta:
        verbose_name = _("User SAML Source Connection")
        verbose_name_plural = _("User SAML Source Connections")


class GroupSAMLSourceConnection(GroupSourceConnection):
    """Group-source connection"""

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.sources.saml.api.source_connection import (
            GroupSAMLSourceConnectionSerializer,
        )

        return GroupSAMLSourceConnectionSerializer

    class Meta:
        verbose_name = _("Group SAML Source Connection")
        verbose_name_plural = _("Group SAML Source Connections")
