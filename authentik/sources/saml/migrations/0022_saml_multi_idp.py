from django.db import migrations, models
import uuid
import django.db.models.deletion

import authentik.lib.models


class Migration(migrations.Migration):
    dependencies = [
        ("authentik_sources_saml", "0021_samlsource_signed_assertion_and_more",),
        ("authentik_crypto", "0006_create_certificate_reference"),
    ]

    operations = [
        migrations.CreateModel(
            name="SAMLIDP",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("uuid", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ("name", models.TextField(blank=True, default="")),
                ("entity_id", models.TextField(help_text="IdP EntityID (Issuer)")),
                ("enabled", models.BooleanField(default=False)),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),
                (
                    "sso_url",
                    models.TextField(
                        help_text="URL that the initial Login request is sent to.",
                        validators=[authentik.lib.models.DomainlessURLValidator(schemes=("http", "https"))],
                        verbose_name="SSO URL",
                    ),
                ),
                (
                    "slo_url",
                    models.TextField(
                        blank=True,
                        default=None,
                        help_text="Optional URL if your IDP supports Single-Logout.",
                        null=True,
                        validators=[authentik.lib.models.DomainlessURLValidator(schemes=("http", "https"))],
                        verbose_name="SLO URL",
                    ),
                ),
                (
                    "allow_idp_initiated",
                    models.BooleanField(
                        default=False,
                        help_text=(
                            "Allows authentication flows initiated by the IdP. This can be a security risk, "
                            "as no validation of the request ID is done."
                        ),
                    ),
                ),
                (
                    "name_id_policy",
                    models.TextField(
                        choices=[
                            ("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "EMAIL"),
                            ("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", "PERSISTENT"),
                            ("urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName", "X509"),
                            ("urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName", "WINDOWS"),
                            ("urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "TRANSIENT"),
                            ("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", "UNSPECIFIED"),
                        ],
                        default="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                        help_text="NameID Policy sent to the IdP. Can be unset, in which case no Policy is sent.",
                    ),
                ),
                (
                    "binding_type",
                    models.CharField(
                        choices=[("REDIRECT", "Redirect Binding"), ("POST", "POST Binding"), ("POST_AUTO", "POST Binding with auto-confirmation")],
                        default="REDIRECT",
                        max_length=100,
                    ),
                ),
                (
                    "digest_algorithm",
                    models.TextField(
                        choices=[("sha1", "SHA1"), ("sha256", "SHA256"), ("sha384", "SHA384"), ("sha512", "SHA512")],
                        default="sha256",
                    ),
                ),
                (
                    "signature_algorithm",
                    models.TextField(
                        choices=[
                            ("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "RSA-SHA1"),
                            ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RSA-SHA256"),
                            ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "RSA-SHA384"),
                            ("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "RSA-SHA512"),
                            ("http://www.w3.org/2000/09/xmldsig#ecdsa-sha1", "ECDSA-SHA1"),
                            ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "ECDSA-SHA256"),
                            ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "ECDSA-SHA384"),
                            ("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "ECDSA-SHA512"),
                            ("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "DSA-SHA1"),
                        ],
                        default="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                    ),
                ),
                ("signed_assertion", models.BooleanField(default=True)),
                ("signed_response", models.BooleanField(default=False)),
                (
                    "encryption_kp",
                    models.ForeignKey(
                        blank=True,
                        default=None,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="authentik_crypto.certificatekeypair",
                        verbose_name="Encryption Keypair",
                    ),
                ),
                (
                    "signing_kp",
                    models.ForeignKey(
                        blank=True,
                        default=None,
                        help_text="Keypair used to sign outgoing Responses going to the Identity Provider.",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="authentik_crypto.certificatekeypair",
                        verbose_name="Signing Keypair",
                    ),
                ),
                (
                    "verification_kp",
                    models.ForeignKey(
                        blank=True,
                        default=None,
                        help_text=(
                            "When selected, incoming assertion's Signatures will be validated against this "
                            "certificate. To allow unsigned Requests, leave on default."
                        ),
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="authentik_crypto.certificatekeypair",
                        verbose_name="Verification Certificate",
                    ),
                ),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="identity_providers",
                        to="authentik_sources_saml.samlsource",
                    ),
                ),
            ],
            options={
                "verbose_name": "SAML Identity Provider",
                "verbose_name_plural": "SAML Identity Providers",
                "unique_together": {("source", "entity_id")},
            },
        ),
        migrations.AddIndex(
            model_name="samlidp",
            index=models.Index(fields=["source", "entity_id"], name="authentik_s_source_i_2d0c4b_idx"),
        ),
        migrations.AddIndex(
            model_name="samlidp",
            index=models.Index(fields=["source", "enabled"], name="authentik_s_source_e_2f0e90_idx"),
        ),
        migrations.AddField(
            model_name="samlidp",
            name="metadata_last_import",
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name="samlidp",
            name="metadata_snapshot",
            field=models.JSONField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name="samlidp",
            name="metadata_hash",
            field=models.CharField(blank=True, default=None, max_length=64, null=True),
        ),
    ]
