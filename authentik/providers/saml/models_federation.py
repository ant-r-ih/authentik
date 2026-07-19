"""Federation models for SAML metadata feeds and bound entities."""

from __future__ import annotations

from uuid import uuid4

from django.db import models
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

from authentik.admin.files.fields import FileField
from authentik.common.saml.constants import (
    DSA_SHA1,
    ECDSA_SHA1,
    ECDSA_SHA256,
    ECDSA_SHA384,
    ECDSA_SHA512,
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
    SHA1,
    SHA256,
    SHA384,
    SHA512,
)
from authentik.crypto.models import CertificateKeyPair
from authentik.lib.models import DomainlessURLValidator
from authentik.sources.saml.models import SAMLBindingTypes, SAMLNameIDPolicy

# Keep SP binding tokens local to avoid importing SAMLBindings from models.py.
SP_BINDING_REDIRECT = "redirect"
SP_BINDING_POST = "post"
SP_BINDING_CHOICES = (
    (SP_BINDING_REDIRECT, _("Redirect")),
    (SP_BINDING_POST, _("Post")),
)


class SAMLMetadataBindKind(models.TextChoices):
    """Bind target kind."""

    SP = "sp", _("Service Provider")
    IDP = "idp", _("Identity Provider")


class SAMLMetadataFeed(models.Model):
    """Metadata feed definition backed by admin/files."""

    name = models.TextField()
    metadata_name = FileField(help_text=_("Path in admin/files (usage=saml_metadata)."))
    signing_certificate = models.ForeignKey(
        CertificateKeyPair,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    enabled = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("SAML Metadata Feed")
        verbose_name_plural = _("SAML Metadata Feeds")

    def __str__(self) -> str:
        """Return display name."""
        return self.name


class SAMLMetadataBind(models.Model):
    """Bind a metadata feed to either a provider or source."""

    feed = models.ForeignKey(
        SAMLMetadataFeed,
        on_delete=models.CASCADE,
        related_name="binds",
    )
    kind = models.TextField(choices=SAMLMetadataBindKind.choices)

    provider = models.ForeignKey(
        "authentik_providers_saml.SAMLProvider",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="metadata_binds",
    )
    source = models.ForeignKey(
        "authentik_sources_saml.SAMLSource",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="metadata_binds",
    )

    enabled = models.BooleanField(default=True)
    created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = _("SAML Metadata Bind")
        verbose_name_plural = _("SAML Metadata Binds")
        constraints = [
            models.CheckConstraint(
                name="ak_saml_metadata_bind_owner_matches_kind",
                condition=(
                    (
                        Q(kind=SAMLMetadataBindKind.SP)
                        & Q(provider__isnull=False)
                        & Q(source__isnull=True)
                    )
                    | (
                        Q(kind=SAMLMetadataBindKind.IDP)
                        & Q(source__isnull=False)
                        & Q(provider__isnull=True)
                    )
                ),
            ),
            models.UniqueConstraint(
                fields=["feed", "provider"],
                condition=Q(provider__isnull=False),
                name="ak_saml_metadata_bind_feed_provider_unique",
            ),
            models.UniqueConstraint(
                fields=["feed", "source"],
                condition=Q(source__isnull=False),
                name="ak_saml_metadata_bind_feed_source_unique",
            ),
        ]
        indexes = [
            models.Index(fields=["feed", "kind"]),
            models.Index(fields=["provider"]),
            models.Index(fields=["source"]),
        ]

    def __str__(self) -> str:
        """Return bind label."""
        return f"{self.feed_id}:{self.kind}:{self.provider_id or self.source_id}"


class SAMLMetadataEntityBase(models.Model):
    """Common fields for metadata-managed SAML entities."""

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True)

    name = models.TextField(blank=True, default="")
    entity_id = models.TextField(help_text=_("SAML EntityID (Issuer)"))
    enabled = models.BooleanField(default=False)

    created = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    verification_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name=_("Verification Certificate"),
    )
    signing_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name=_("Signing Keypair"),
    )
    encryption_kp = models.ForeignKey(
        CertificateKeyPair,
        default=None,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
        verbose_name=_("Encryption Keypair"),
    )

    verification_kp_ring = models.OneToOneField(
        "authentik_crypto.CertificateKeyPairRing",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    signing_kp_ring = models.OneToOneField(
        "authentik_crypto.CertificateKeyPairRing",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    encryption_kp_ring = models.OneToOneField(
        "authentik_crypto.CertificateKeyPairRing",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    verification_kp_override = models.BooleanField(
        default=False,
        help_text=_("Use local key; otherwise inherit from owner."),
    )
    signing_kp_override = models.BooleanField(
        default=False,
        help_text=_("Use local key; otherwise inherit from owner."),
    )
    encryption_kp_override = models.BooleanField(
        default=False,
        help_text=_("Use local key; otherwise inherit from owner."),
    )

    freeze_verification_kp = models.BooleanField(default=False)
    freeze_signing_kp = models.BooleanField(default=False)
    freeze_encryption_kp = models.BooleanField(default=False)

    local_override_set = models.BooleanField(default=False)

    metadata_snapshot = models.JSONField(default=dict, blank=True)
    metadata_last_import = models.DateTimeField(default=None, null=True, blank=True)
    metadata_hash = models.CharField(max_length=64, default="", blank=True)

    class Meta:
        abstract = True


class SAMLSP(SAMLMetadataEntityBase):
    """Metadata-managed SP entity attached to a SAMLProvider."""

    parent = models.ForeignKey(
        "authentik_providers_saml.SAMLProvider",
        on_delete=models.CASCADE,
        related_name="service_providers",
    )

    acs_url = models.TextField(validators=[DomainlessURLValidator(schemes=("http", "https"))])
    sp_binding = models.TextField(choices=SP_BINDING_CHOICES, default=SP_BINDING_POST)

    sls_url = models.TextField(blank=True, default="")
    sls_binding = models.TextField(choices=SP_BINDING_CHOICES, default=SP_BINDING_POST)

    authn_requests_signed = models.BooleanField(default=False)
    want_assertions_signed = models.BooleanField(default=False)

    name_id_policy = models.TextField(
        choices=SAMLNameIDPolicy.choices,
        default=SAMLNameIDPolicy.UNSPECIFIED,
    )

    property_mappings_override = models.BooleanField(
        default=False,
        help_text=_(
            "If enabled, use this SAMLSP's property mappings instead of provider mappings."
        ),
    )
    property_mappings = models.ManyToManyField(
        "authentik_providers_saml.SAMLPropertyMapping",
        blank=True,
        related_name="samlsp_overrides",
        help_text=_("Per-SP property mappings."),
    )

    class Meta:
        verbose_name = _("SAML Service Provider")
        verbose_name_plural = _("SAML Service Providers")
        unique_together = [("parent", "entity_id")]
        indexes = [
            models.Index(fields=["parent", "entity_id"]),
            models.Index(fields=["parent", "enabled"]),
        ]

    def __str__(self) -> str:
        """Return display name."""
        return f"SAML SP {self.name or self.entity_id}"


class SAMLIDP(SAMLMetadataEntityBase):
    """Metadata-managed IdP entity attached to a SAMLSource."""

    parent = models.ForeignKey(
        "authentik_sources_saml.SAMLSource",
        on_delete=models.CASCADE,
        related_name="identity_providers",
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

    allow_idp_initiated = models.BooleanField(default=False)
    name_id_policy = models.TextField(
        choices=SAMLNameIDPolicy.choices,
        default=SAMLNameIDPolicy.PERSISTENT,
    )
    binding_type = models.CharField(
        max_length=100,
        choices=SAMLBindingTypes.choices,
        default=SAMLBindingTypes.REDIRECT,
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

    class Meta:
        verbose_name = _("SAML Identity Provider")
        verbose_name_plural = _("SAML Identity Providers")
        unique_together = [("parent", "entity_id")]
        indexes = [
            models.Index(fields=["parent", "entity_id"]),
            models.Index(fields=["parent", "enabled"]),
        ]

    def __str__(self) -> str:
        """Return display name."""
        return f"SAML IdP {self.name or self.entity_id}"
