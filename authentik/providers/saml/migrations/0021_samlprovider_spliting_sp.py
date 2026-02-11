from django.db import migrations, models
import uuid

from authentik.lib.models import DomainlessURLValidator
from authentik.sources.saml.models import SAMLNameIDPolicy
from authentik.providers.saml.models import SAMLBindings, PropertyMapping

class Migration(migrations.Migration):

    dependencies = [
        ("authentik_providers_saml", "0020_samlprovider_logout_method_and_more"),
        ("authentik_crypto", "0006_create_certificate_reference"),
    ]

    operations = [
        migrations.AddField(
            model_name="samlprovider",
            name="strict_acs_url",
            field=models.BooleanField(
                default=True,
                help_text="When disabled, the ACS URL from the SAML request is used instead of the provider's configured ACS URL.",
            ),
        ),

        migrations.CreateModel(
            name="SAMLSP",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "uuid",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        unique=True,
                    ),
                ),
                (
                    "name",
                    models.TextField(
                        blank=True,
                        default="",
                        help_text="Optional display name for this Service Provider entry.",
                    ),
                ),
                (
                    "entity_id",
                    models.TextField(
                        help_text="Service Provider EntityID (Issuer in AuthnRequest).",
                    ),
                ),
                (
                    "enabled",
                    models.BooleanField(
                        default=False,
                        help_text="If enabled, this SP can be selected during request processing.",
                    ),
                ),

                # -------------------------
                # Metadata snapshot
                # -------------------------
                (
                    "metadata_last_import",
                    models.DateTimeField(
                        null=True,
                        blank=True,
                    ),
                ),
                (
                    "metadata_snapshot",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Extracted metadata structure for comparison and selection.",
                        null=True,
                    ),
                ),
                (
                    "metadata_hash",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="Normalized metadata hash for change detection.",
                        max_length=64,
                        null=True,
                    ),
                ),

                # -------------------------
                # Selected runtime values
                # -------------------------
                (
                    "acs_url",
                    models.TextField(
                        validators=[DomainlessURLValidator(schemes=("http", "https"))],
                        help_text="Selected Assertion Consumer Service URL.",
                    ),
                ),
                (
                    "sp_binding",
                    models.TextField(
                        choices=SAMLBindings.choices,
                        default=SAMLBindings.POST,
                        help_text="Selected binding for ACS.",
                    ),
                ),
                (
                    "sls_url",
                    models.TextField(
                        blank=True,
                        default="",
                        validators=[DomainlessURLValidator(schemes=("http", "https"))],
                        help_text="Selected Single Logout Service URL.",
                    ),
                ),
                (
                    "sls_binding",
                    models.TextField(
                        choices=SAMLBindings.choices,
                        default=SAMLBindings.POST,
                        help_text="Selected binding for SLS.",
                    ),
                ),
                (
                    "authn_requests_signed",
                    models.BooleanField(default=False),
                ),
                (
                    "want_assertions_signed",
                    models.BooleanField(default=False),
                ),
                (
                    "name_id_policy",
                    models.TextField(
                        choices=SAMLNameIDPolicy.choices,
                        default=SAMLNameIDPolicy.UNSPECIFIED,
                    ),
                ),
                (
                    "created",
                    models.DateTimeField(auto_now_add=True),
                ),
                (
                    "last_updated",
                    models.DateTimeField(auto_now=True),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="service_providers",
                        to="authentik_providers_saml.samlprovider",
                        verbose_name="SAML Provider",
                    ),
                ),
                (
                    "verification_kp",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=models.deletion.SET_NULL,
                        related_name="+",
                        to="authentik_crypto.certificatekeypair",
                        help_text="Selected verification certificate.",
                    ),
                ),
                (
                    "encryption_kp",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=models.deletion.SET_NULL,
                        related_name="+",
                        to="authentik_crypto.certificatekeypair",
                        help_text="Selected encryption certificate.",
                    ),
                ),
            ],
            options={
                "verbose_name": "SAML Service Provider",
                "verbose_name_plural": "SAML Service Providers",
                "ordering": ["provider", "name", "entity_id"],
            },
        ),

        migrations.AddConstraint(
            model_name="samlsp",
            constraint=models.UniqueConstraint(
                fields=("provider", "entity_id"),
                name="uniq_samlsp_provider_entity_id",
            ),
        ),

        migrations.AddIndex(
            model_name="samlsp",
            index=models.Index(
                fields=["provider", "enabled"],
                name="samlsp_provider_enabled_idx",
            ),
        ),

        migrations.AddIndex(
            model_name="samlsp",
            index=models.Index(
                fields=["entity_id"],
                name="samlsp_entity_id_idx",
            ),
        ),
    ]
