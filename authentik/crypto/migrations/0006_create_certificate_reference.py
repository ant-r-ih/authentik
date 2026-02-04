# authentik/crypto/migrations/000X_create_certificatereference.py
from django.db import migrations, models
import django.db.models.deletion

class Migration(migrations.Migration):
    dependencies = [
        ("authentik_crypto", "0005_alter_certificatekeypair_options"),  # 直前に合わせて調整
    ]

    operations = [
        migrations.CreateModel(
            name="CertificateReference",
            fields=[
                # ✅ Django のデフォルトPK（これが無いと今回みたいに壊れる）
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),

                # ✅ CreatedUpdatedModel のフィールド（抽象基底ならここに展開される）
                ("created", models.DateTimeField(auto_now_add=True)),
                ("last_updated", models.DateTimeField(auto_now=True)),

                ("ref_model", models.CharField(max_length=200)),
                ("ref_pk", models.CharField(max_length=64)),
                ("usage", models.CharField(max_length=64, choices=[
                    ("saml.signing", "SAML signing"),
                    ("saml.encryption", "SAML encryption"),
                    ("saml.verification", "SAML verification"),
                ])),
                ("certificate", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="references",
                    to="authentik_crypto.certificatekeypair",
                )),
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
