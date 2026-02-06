# authentik/crypto/migrations/000X_create_certificatereference.py
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("authentik_crypto", "0005_alter_certificatekeypair_options"),
    ]

    operations = [
        migrations.CreateModel(
            name="CertificateReference",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                    ),
                ),
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),
                ("ref_model", models.CharField(max_length=200)),
                ("ref_pk", models.CharField(max_length=64)),
                (
                    "usage",
                    models.CharField(
                        max_length=64,
                        choices=[
                            ("saml.signing", "SAML signing"),
                            ("saml.encryption", "SAML encryption"),
                            ("saml.verification", "SAML verification"),
                        ],
                    ),
                ),
                (
                    "fingerprint_sha256",
                    models.CharField(
                        max_length=95,  # "AA:BB:..." (SHA256) = 95 chars with colons
                        db_index=True,
                        help_text="SHA256 fingerprint of referenced certificate at time of linking.",
                    ),
                ),
                (
                    "certificate",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="references",
                        to="authentik_crypto.certificatekeypair",
                    ),
                ),
            ],
            options={
                "verbose_name": "Certificate reference",
                "verbose_name_plural": "Certificate references",
            },
        ),
        migrations.AddConstraint(
            model_name="certificatereference",
            constraint=models.UniqueConstraint(
                fields=("certificate", "ref_model", "ref_pk", "usage"),
                name="uniq_certificate_reference",
            ),
        ),
        migrations.AddIndex(
            model_name="certificatereference",
            index=models.Index(fields=["certificate"], name="crypto_certref_cert_idx"),
        ),
        migrations.AddIndex(
            model_name="certificatereference",
            index=models.Index(fields=["ref_model", "ref_pk"], name="crypto_certref_ref_idx"),
        ),
        migrations.AddIndex(
            model_name="certificatereference",
            index=models.Index(fields=["usage"], name="crypto_certref_usage_idx"),
        ),
    ]
