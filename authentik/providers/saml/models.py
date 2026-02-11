"""authentik SAML Provider Models"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import uuid4

from defusedxml import ElementTree
from django.db import models
from django.templatetags.static import static
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import Serializer
from structlog.stdlib import get_logger

from authentik.core.api.object_types import CreatableType
from authentik.core.models import (
    AuthenticatedSession,
    ExpiringModel,
    PropertyMapping,
    Provider,
    User,
)
from authentik.crypto.models import CertificateKeyPair
from authentik.lib.models import DomainlessURLValidator, SerializerModel
from authentik.lib.utils.time import timedelta_string_validator
from authentik.sources.saml.models import SAMLNameIDPolicy
from authentik.sources.saml.processors.constants import (
    DSA_SHA1,
    ECDSA_SHA1,
    ECDSA_SHA256,
    ECDSA_SHA384,
    ECDSA_SHA512,
    NS_SAML_ASSERTION,
    NS_SAML_PROTOCOL,
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
)

SAMLSP_KEY_SLOTS: tuple[tuple[str, str, str], ...] = (
    ("verification", "verification_kp_mode", "verification_kp"),
    ("signing", "signing_kp_mode", "signing_kp"),
    ("encryption", "encryption_kp_mode", "encryption_kp"),
)

LOGGER = get_logger()

def _runtime_key_presence(sp: "SAMLSP") -> dict[str, bool]:
    return {
        "has_verification_cert": sp.verification_kp_id is not None,
        "has_signing_cert": sp.signing_kp_id is not None,
        "has_encryption_cert": sp.encryption_kp_id is not None,
    }

def _snapshot_key_presence(snapshot: dict[str, Any]) -> dict[str, bool]:
    snap = snapshot or {}
    return {
        "has_verification_cert": bool(snap.get("has_verification_cert", False)),
        "has_signing_cert": bool(snap.get("has_signing_cert", False)),
        "has_encryption_cert": bool(snap.get("has_encryption_cert", False)),
    }

class SAMLBindings(models.TextChoices):
    """SAML Bindings supported by authentik"""

    REDIRECT = "redirect"
    POST = "post"


class SAMLLogoutMethods(models.TextChoices):
    """SAML Logout methods supported by authentik"""

    FRONTCHANNEL_IFRAME = "frontchannel_iframe"
    FRONTCHANNEL_NATIVE = "frontchannel_native"
    BACKCHANNEL = "backchannel"


class SAMLProvider(Provider):
    """SAML 2.0 Endpoint for applications which support SAML."""

    acs_url = models.TextField(
        validators=[DomainlessURLValidator(schemes=("http", "https"))], verbose_name=_("ACS URL")
    )
    sp_binding = models.TextField(
        choices=SAMLBindings.choices,
        default=SAMLBindings.REDIRECT,
        verbose_name=_("Service Provider Binding"),
        help_text=_("This determines how authentik sends the response back to the Service Provider."),
    )
    audience = models.TextField(
        default="",
        blank=True,
        help_text=_(
            "Value of the audience restriction field of the assertion. When left empty, "
            "no audience restriction will be added."
        ),
    )
    issuer = models.TextField(help_text=_("Also known as EntityID"), default="authentik")
    sls_url = models.TextField(
        blank=True,
        validators=[DomainlessURLValidator(schemes=("http", "https"))],
        verbose_name=_("SLS URL"),
        help_text=_("Single Logout Service URL where the logout response should be sent."),
    )
    sls_binding = models.TextField(
        choices=SAMLBindings.choices,
        default=SAMLBindings.REDIRECT,
        verbose_name=_("SLS Binding"),
        help_text=_("This determines how authentik sends the logout response back to the Service Provider."),
    )
    logout_method = models.TextField(
        choices=SAMLLogoutMethods.choices,
        default=SAMLLogoutMethods.FRONTCHANNEL_IFRAME,
        help_text=_(
            "Method to use for logout. Front-channel iframe loads all logout URLs simultaneously "
            "in hidden iframes. Front-channel native uses your active browser tab to send post "
            "requests and redirect to providers. "
            "Back-channel sends logout requests directly from the server without "
            "user interaction (requires POST SLS binding)."
        ),
    )
    name_id_mapping = models.ForeignKey(
        "SAMLPropertyMapping",
        default=None,
        blank=True,
        null=True,
        on_delete=models.SET_DEFAULT,
        verbose_name=_("NameID Property Mapping"),
        help_text=_(
            "Configure how the NameID value will be created. When left empty, "
            "the NameIDPolicy of the incoming request will be considered"
        ),
    )
    authn_context_class_ref_mapping = models.ForeignKey(
        "SAMLPropertyMapping",
        default=None,
        blank=True,
        null=True,
        on_delete=models.SET_DEFAULT,
        verbose_name=_("AuthnContextClassRef Property Mapping"),
        related_name="+",
        help_text=_(
            "Configure how the AuthnContextClassRef value will be created. When left empty, "
            "the AuthnContextClassRef will be set based on which authentication methods the user "
            "used to authenticate."
        ),
    )

    assertion_valid_not_before = models.TextField(
        default="minutes=-5",
        validators=[timedelta_string_validator],
        help_text=_(
            "Assertion valid not before current time + this value "
            "(Format: hours=-1;minutes=-2;seconds=-3)."
        ),
    )
    assertion_valid_not_on_or_after = models.TextField(
        default="minutes=5",
        validators=[timedelta_string_validator],
        help_text=_(
            "Assertion not valid on or after current time + this value "
            "(Format: hours=1;minutes=2;seconds=3)."
        ),
    )

    session_valid_not_on_or_after = models.TextField(
        default="minutes=86400",
        validators=[timedelta_string_validator],
        help_text=_(
            "Session not valid on or after current time + this value "
            "(Format: hours=1;minutes=2;seconds=3)."
        ),
    )

    digest_algorithm = models.TextField(
        choices=((SHA1, _("SHA1")), (SHA256, _("SHA256")), (SHA384, _("SHA384")), (SHA512, _("SHA512"))),
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
        help_text=_("Keypair used to sign outgoing Responses going to the Service Provider."),
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

    default_relay_state = models.TextField(
        default="", blank=True, help_text=_("Default relay_state value for IDP-initiated logins")
    )
    default_name_id_policy = models.TextField(
        choices=SAMLNameIDPolicy.choices, default=SAMLNameIDPolicy.UNSPECIFIED
    )

    sign_assertion = models.BooleanField(default=True)
    sign_response = models.BooleanField(default=False)
    sign_logout_request = models.BooleanField(default=False)
    strict_acs_url = models.BooleanField(
        default=True,
        help_text=_(
            "When disabled, the ACS URL from the SAML request is used"
            "instead of the provider's configured ACS URL."
        ),
    )

    @property
    def launch_url(self) -> str | None:
        """Use IDP-Initiated SAML flow as launch URL"""
        try:
            return reverse(
                "authentik_providers_saml:sso-init",
                kwargs={"application_slug": self.application.slug},
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return None

    @property
    def icon_url(self) -> str | None:
        return static("authentik/sources/saml.png")

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.providers.saml.api.providers import SAMLProviderSerializer

        return SAMLProviderSerializer

    @property
    def component(self) -> str:
        return "ak-provider-saml-form"

    def get_sp(self, entity_id: str | None) -> "SAMLSP | None":
        if not entity_id:
            return None
        return self.service_providers.filter(entity_id=entity_id, enabled=True).first()

    def __str__(self):
        return f"SAML Provider {self.name}"

    class Meta:
        verbose_name = _("SAML Provider")
        verbose_name_plural = _("SAML Providers")

class SAMLSPMetadataState(models.TextChoices):
    MANUAL = "manual", "Manual"
    UNCHANGED = "unchanged", "Unchanged"
    DIVERGED = "diverged", "Diverged"
    # NOTE: OUTDATED/ORPHANED are lifecycle concerns; currently not used in DB-basis runtime compare
    OUTDATED = "outdated", "Outdated"
    ORPHANED = "orphaned", "Orphaned"

class SAMLSPKeyOverrideMode(models.TextChoices):
    """How SAMLSP resolves keypair settings relative to provider defaults."""

    INHERIT = "inherit", "Inherit provider setting"
    SET = "set", "Use local key"
    NONE = "none", "Disable key (no key)"

class SAMLSP(models.Model):
    uuid = models.UUIDField(default=uuid4, editable=False, unique=True)

    provider = models.ForeignKey(
        "SAMLProvider",
        on_delete=models.CASCADE,
        related_name="service_providers",
    )

    name = models.TextField(blank=True, default="")
    entity_id = models.TextField()
    enabled = models.BooleanField(default=False)

    created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    # -------------------------
    # Active configuration (runtime values)
    # -------------------------
    acs_url = models.TextField(validators=[DomainlessURLValidator(schemes=("http", "https"))])
    sp_binding = models.TextField(choices=SAMLBindings.choices, default=SAMLBindings.POST)

    sls_url = models.TextField(blank=True, default="")
    sls_binding = models.TextField(choices=SAMLBindings.choices, default=SAMLBindings.POST)

    authn_requests_signed = models.BooleanField(default=False)
    want_assertions_signed = models.BooleanField(default=False)

    name_id_policy = models.TextField(
        choices=SAMLNameIDPolicy.choices,
        default=SAMLNameIDPolicy.UNSPECIFIED,
    )

    # verification cert (used to verify incoming AuthnRequests from this SP)
    verification_kp = models.ForeignKey(
        CertificateKeyPair,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    # encryption cert/key (provider-side encryption behavior for this SP, if used)
    encryption_kp = models.ForeignKey(
        CertificateKeyPair,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    # local signing key for this SP (optional override; can also be explicitly disabled)
    signing_kp = models.ForeignKey(
        CertificateKeyPair,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    # -------------------------
    # Key resolution policy (provider fallback / local / explicit none)
    # -------------------------
    verification_kp_mode = models.CharField(
        max_length=16,
        choices=SAMLSPKeyOverrideMode.choices,
        default=SAMLSPKeyOverrideMode.INHERIT,
        help_text=(
            "How verification_kp is resolved: inherit provider, use local key, "
            "or explicitly disable verification key."
        ),
    )

    encryption_kp_mode = models.CharField(
        max_length=16,
        choices=SAMLSPKeyOverrideMode.choices,
        default=SAMLSPKeyOverrideMode.INHERIT,
        help_text=(
            "How encryption_kp is resolved: inherit provider, use local key, "
            "or explicitly disable encryption key."
        ),
    )

    signing_kp_mode = models.CharField(
        max_length=16,
        choices=SAMLSPKeyOverrideMode.choices,
        default=SAMLSPKeyOverrideMode.INHERIT,
        help_text=(
            "How signing_kp is resolved: inherit provider, use local key, "
            "or explicitly disable signing key."
        ),
    )

    property_mappings_override = models.BooleanField(
        default=False,
        help_text=(
            "If enabled, use this SAMLSP's property mappings instead of provider mappings. "
            "An empty set is treated as an explicit override (no attributes)."
        ),
    )

    property_mappings = models.ManyToManyField(
        "authentik_providers_saml.SAMLPropertyMapping",
        blank=True,
        related_name="samlsp_overrides",
        help_text=_("Per-SP property mappings. If empty, provider property mappings are used."),
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


    freeze_encryption_kp = models.BooleanField(
        default=False,
        help_text=(
            "Do not overwrite encryption_kp during metadata apply/import. "
            "Useful for certificate rollover handling or local pinning."
        ),
    )

    freeze_verification_kp = models.BooleanField(
        default=False,
        help_text=(
            "Do not overwrite verification_kp during metadata apply/import. "
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

    # -------------------------
    # Metadata snapshot / import tracking
    # -------------------------
    metadata_last_import = models.DateTimeField(null=True, blank=True)

    metadata_snapshot = models.JSONField(
        default=dict,
        null=True,
        blank=True,
        help_text="Extracted metadata structure for comparison and selection.",
    )

    metadata_hash = models.CharField(
        max_length=64,
        blank=True,
        null=True,
        default="",
        help_text="Normalized metadata hash for change detection.",
    )
    class Meta:
        unique_together = [("provider", "entity_id")]
        indexes = [
            models.Index(fields=["provider", "entity_id"]),
            models.Index(fields=["provider", "enabled"]),
        ]

    def __str__(self):
        return f"SAML SP {self.name or self.entity_id}"

    @property
    def snapshot_hash_normalized(self) -> str | None:
        """Hash of *current* metadata_snapshot after canonical normalization."""
        if not self.metadata_snapshot:
            return None
        return compute_signature_hash(normalize_signature(self.metadata_snapshot))

    @property
    def runtime_db_basis_state(self) -> SAMLSPMetadataState:
        """
        Compare runtime config against what would be generated from stored DB snapshot.
        This is the basis for 'apply' decisions.

        Note:
        - This remains a result-state comparison (runtime vs metadata-derived expected).
        - Local flags like has_local_override / freeze_*_kp are explanatory
          and should not replace the divergence check itself.
        """
        if not self.metadata_snapshot:
            return SAMLSPMetadataState.MANUAL
        return (
            SAMLSPMetadataState.DIVERGED
            if runtime_diverged(self)
            else SAMLSPMetadataState.UNCHANGED
        )

    def clean(self):
        """
        Keep *_kp_mode and local key fields consistent.

        Rule:
        - mode == SET   -> local FK must be present
        - mode != SET   -> local FK may be empty (and can be ignored by resolver)
        """
        super().clean()

        def _validate(mode_field: str, kp_field: str):
            mode = getattr(self, mode_field)
            kp = getattr(self, kp_field)
            if mode == SAMLSPKeyOverrideMode.SET and kp is None:
                from django.core.exceptions import ValidationError

                raise ValidationError(
                    {kp_field: f"{kp_field} is required when {mode_field}=SET."}
                )

            for _name, mode_field, kp_field in SAMLSP_KEY_SLOTS:
                _validate(mode_field, kp_field)

# ============================================================
# Canonical signature helpers (single source of truth)
# ============================================================

def compute_signature_hash(data: dict[str, Any]) -> str:
    """Caller must pass already-normalized dict."""
    normalized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode()).hexdigest()


def _to_list_endpoints(*, url: Any, binding: Any) -> list[dict[str, str]]:
    u = (url or "").strip() if isinstance(url, str) else (str(url) if url else "")
    b = (binding or "").strip() if isinstance(binding, str) else (str(binding) if binding else "")
    if not u:
        return []
    return [{"url": u, "binding": b}]


def normalize_signature(data: dict[str, Any]) -> dict[str, Any]:
    """
    Canonical normalization for snapshot and runtime structures.

    Accepts either:
      A) snapshot-ish: {"acs":[{"url","binding",...}], "sls":[...], ...}
      B) runtime-ish : {"acs_url","sp_binding","sls_url","sls_binding", ...}

    Returns canonical:
      {"acs":[{"url","binding"}], "sls":[{"url","binding"}],
       "authn_requests_signed": bool, "want_assertions_signed": bool,
       "has_verification_cert": bool, "has_encryption_cert": bool}
    Note:
      This canonical form is intentionally scoped for metadata/runtime drift
      checks and uses coarse key presence flags instead of exact key identity
      (no key fingerprint/keypair ID comparison here).
    """

    # 1) endpoints: prefer list-form if present, otherwise derive from flat form
    acs = data.get("acs", None)
    if isinstance(acs, list):
        acs_list = [
            {"url": str(x.get("url") or ""), "binding": str(x.get("binding") or "")}
            for x in acs
            if isinstance(x, dict) and (x.get("url") or "")
        ]
    else:
        acs_list = _to_list_endpoints(url=data.get("acs_url"), binding=data.get("sp_binding"))

    sls = data.get("sls", None)
    if isinstance(sls, list):
        sls_list = [
            {"url": str(x.get("url") or ""), "binding": str(x.get("binding") or "")}
            for x in sls
            if isinstance(x, dict) and (x.get("url") or "")
        ]
    else:
        sls_list = _to_list_endpoints(url=data.get("sls_url"), binding=data.get("sls_binding"))

    # 2) canonical sort
    acs_list = sorted(acs_list, key=lambda x: (x.get("binding") or "", x.get("url") or ""))
    sls_list = sorted(sls_list, key=lambda x: (x.get("binding") or "", x.get("url") or ""))

    # 3) canonical booleans
    return {
        "acs": acs_list,
        "sls": sls_list,
        "authn_requests_signed": bool(data.get("authn_requests_signed", False)),
        "want_assertions_signed": bool(data.get("want_assertions_signed", False)),
        "has_encryption_cert": bool(data.get("has_encryption_cert", False)),
        "has_signing_cert": bool(data.get("has_signing_cert", False)),
        "has_verification_cert": bool(data.get("has_verification_cert", False)),
    }


# ============================================================
# Runtime-vs-DB-snapshot compare helpers
# ============================================================

def current_runtime_signature(sp: "SAMLSP") -> dict[str, Any]:
    """Current runtime signature in flat form (normalize_signature handles it)."""
    return {
        "acs_url": sp.acs_url or "",
        "sp_binding": str(sp.sp_binding or ""),
        "sls_url": sp.sls_url or "",
        "sls_binding": str(sp.sls_binding or ""),
        "authn_requests_signed": bool(sp.authn_requests_signed),
        "want_assertions_signed": bool(sp.want_assertions_signed),
        **_runtime_key_presence(sp),
    }


def _pick_default_acs_from_snapshot(acs_list: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not acs_list:
        return None

    def idx(x: dict[str, Any]) -> int:
        try:
            return int(x.get("index", 0))
        except Exception:
            return 0

    post = [a for a in acs_list if a.get("binding") == SAMLBindings.POST]
    if post:
        return sorted(post, key=lambda x: (idx(x), x.get("url") or ""))[0]

    return sorted(acs_list, key=lambda x: (idx(x), x.get("url") or ""))[0]


def _pick_default_sls_from_snapshot(sls_list: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not sls_list:
        return None
    return sorted(sls_list, key=lambda x: (x.get("binding") or "", x.get("url") or ""))[0]


def _binding_value(v: Any) -> str:
    """Ensure enum/TextChoices become plain strings."""
    if v is None:
        return ""
    return str(v)


def build_runtime_from_snapshot(snapshot: dict[str, Any], **_kwargs) -> dict[str, Any]:
    """
    Returns the runtime *flat* fields that are derived from snapshot.
    (No cert fingerprints; only endpoints + flags.)
    """
    snap = snapshot or {}
    acs = _pick_default_acs_from_snapshot(snap.get("acs", []) or [])
    sls = _pick_default_sls_from_snapshot(snap.get("sls", []) or [])

    return {
        "acs_url": (acs or {}).get("url") or "",
        "sp_binding": _binding_value((acs or {}).get("binding")),
        "sls_url": (sls or {}).get("url") or "",
        "sls_binding": _binding_value((sls or {}).get("binding")),
        "authn_requests_signed": bool(snap.get("authn_requests_signed", False)),
        "want_assertions_signed": bool(snap.get("want_assertions_signed", False)),
    }


def expected_runtime_signature_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Expected runtime signature derived from snapshot (flat form)."""
    base = build_runtime_from_snapshot(snapshot)
    snap = snapshot or {}
    return {
        **base,
        **_snapshot_key_presence(snapshot),
    }


def runtime_diverged(sp: "SAMLSP") -> bool:
    """
    DB snapshot basis diverged check.
    - expected: derived from stored DB snapshot
    - current : current SAMLSP runtime fields (+ coarse key presence)
    - compare via same normalize_signature()

    Important design note:
    This comparison is intentionally coarse for metadata-apply decisions.
    It detects drift in metadata-derived runtime behavior (endpoints/flags and
    key *presence*), but does NOT compare which exact keypair/certificate is set
    (e.g. rollover from old key to new key, or temporary rollback).

    Rationale:
    - operational key rollover/rollback may be intentional local state
    - local key behavior is governed by *_kp_mode and freeze_* flags
    - metadata apply should not treat every key rotation as generic runtime drift
      in this check

    If exact key identity drift needs to be diagnosed, use a separate check
    (e.g. compare certificate references / fingerprints) instead of changing
    this function's semantics.
    """
    if not sp.metadata_snapshot:
        return False

    expected = expected_runtime_signature_from_snapshot(sp.metadata_snapshot)
    current = current_runtime_signature(sp)

    return normalize_signature(expected) != normalize_signature(current)


# ============================================================
# Other models
# ============================================================

class SAMLPropertyMapping(PropertyMapping):
    """Map User/Group attribute to SAML Attribute, which can be used by the Service Provider"""

    saml_name = models.TextField(verbose_name="SAML Name")
    friendly_name = models.TextField(default=None, blank=True, null=True)

    @property
    def component(self) -> str:
        return "ak-property-mapping-provider-saml-form"

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.providers.saml.api.property_mappings import SAMLPropertyMappingSerializer

        return SAMLPropertyMappingSerializer

    def __str__(self):
        name = self.friendly_name if self.friendly_name != "" else self.saml_name
        return f"{self.name} ({name})"

    class Meta:
        verbose_name = _("SAML Provider Property Mapping")
        verbose_name_plural = _("SAML Provider Property Mappings")


class SAMLProviderImportModel(CreatableType, Provider):
    """Create a SAML Provider by importing its Metadata."""

    @property
    def component(self):
        return "ak-provider-saml-import-form"

    @property
    def icon_url(self) -> str | None:
        return static("authentik/sources/saml.png")

    class Meta:
        abstract = True
        verbose_name = _("SAML Provider from Metadata")
        verbose_name_plural = _("SAML Providers from Metadata")


class SAMLSession(SerializerModel, ExpiringModel):
    """Track active SAML sessions for Single Logout support"""

    saml_session_id = models.UUIDField(default=uuid4, primary_key=True)
    provider = models.ForeignKey(SAMLProvider, on_delete=models.CASCADE)
    user = models.ForeignKey(User, verbose_name=_("User"), on_delete=models.CASCADE)
    session = models.ForeignKey(
        AuthenticatedSession,
        on_delete=models.CASCADE,
        help_text=_("Link to the user's authenticated session"),
    )
    session_index = models.TextField(help_text=_("SAML SessionIndex for this session"))
    name_id = models.TextField(help_text=_("SAML NameID value for this session"))
    name_id_format = models.TextField(default="", blank=True, help_text=_("SAML NameID format"))
    created = models.DateTimeField(auto_now_add=True)
    samlsp = models.ForeignKey(
        "authentik_providers_saml.SAMLSP",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="sessions",
    )

    @property
    def serializer(self) -> type[Serializer]:
        from authentik.providers.saml.api.sessions import SAMLSessionSerializer

        return SAMLSessionSerializer

    def __str__(self):
        return f"SAML Session for provider {self.provider_id} and user {self.user_id}"

    class Meta:
        verbose_name = _("SAML Session")
        verbose_name_plural = _("SAML Sessions")
        unique_together = [("session_index", "provider")]
        indexes = [
            models.Index(fields=["session_index"]),
            models.Index(fields=["provider", "user"]),
            models.Index(fields=["session"]),
        ]


def peek_issuer(root: ElementTree) -> str | None:
    issuers = root.findall(f"{{{NS_SAML_PROTOCOL}}}Issuer")
    if not issuers:
        issuers = root.findall(f"{{{NS_SAML_ASSERTION}}}Issuer")
    return issuers[0].text if issuers else None
