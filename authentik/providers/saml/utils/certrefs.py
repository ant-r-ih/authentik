from django.db.models import Q
from structlog.stdlib import get_logger

from authentik.crypto.models import (
    REF_MODEL_SAML_PROVIDER,
    REF_MODEL_SAML_SP,
    CertificateKeyPair,
    CertificateReference,
)
from authentik.providers.saml.models import SAMLSP, SAMLProvider

LOGGER = get_logger()


def sync_saml_provider_cert_refs(provider: SAMLProvider) -> None:
    """Ensure CertificateReference rows reflect provider.{signing,verification,encryption}_kp."""
    desired: set[tuple[str, str]] = set()
    if provider.signing_kp_id:
        desired.add((str(provider.signing_kp_id), CertificateReference.Usage.SAML_SIGNING))
    if provider.encryption_kp_id:
        desired.add((str(provider.encryption_kp_id), CertificateReference.Usage.SAML_ENCRYPTION))
    if provider.verification_kp_id:
        desired.add(
            (str(provider.verification_kp_id), CertificateReference.Usage.SAML_VERIFICATION)
        )

    existing = CertificateReference.objects.filter(
        ref_model=REF_MODEL_SAML_PROVIDER,
        ref_pk=str(provider.pk),
    )

    existing_set = set(existing.values_list("certificate_id", "usage"))

    to_add = desired - existing_set
    to_del = existing_set - desired

    if to_del:
        for cert_id, usage in to_del:
            existing.filter(certificate_id=cert_id, usage=usage).delete()

    if not to_add:
        return

    kps = CertificateKeyPair.objects.filter(pk__in=[cid for cid, _ in to_add])
    fp_map = {str(kp.pk): kp.fingerprint_sha256 for kp in kps}

    CertificateReference.objects.bulk_create(
        [
            CertificateReference(
                certificate_id=cert_id,
                fingerprint_sha256=fp_map[str(cert_id)],
                ref_model=REF_MODEL_SAML_PROVIDER,
                ref_pk=str(provider.pk),
                usage=usage,
            )
            for cert_id, usage in to_add
        ],
        ignore_conflicts=True,
    )


def sync_saml_sp_cert_refs(sp: "SAMLSP") -> None:
    """Ensure CertificateReference rows for SAMLSP match current config."""
    if not sp.pk:
        return

    desired: set[tuple[str, str]] = set()  # (cert_pk, usage)

    # example: SP signature verification cert
    if getattr(sp, "verification_kp_id", None):
        desired.add((str(sp.verification_kp_id), CertificateReference.Usage.SAML_VERIFICATION))

    existing = CertificateReference.objects.filter(
        ref_model=REF_MODEL_SAML_SP,
        ref_pk=str(sp.pk),
    ).values_list("certificate_id", "usage")

    existing_set = {(str(cid), usage) for cid, usage in existing}

    to_add = desired - existing_set
    to_del = existing_set - desired

    if to_del:
        q = Q()
        for cid, usage in to_del:
            q |= Q(certificate_id=cid, usage=usage)
        CertificateReference.objects.filter(
            ref_model=REF_MODEL_SAML_SP,
            ref_pk=str(sp.pk),
        ).filter(q).delete()

    if not to_add:
        return

    kps = CertificateKeyPair.objects.filter(pk__in=[cid for cid, _ in to_add])
    fp_map = {str(kp.pk): kp.fingerprint_sha256 for kp in kps}

    CertificateReference.objects.bulk_create(
        [
            CertificateReference(
                certificate_id=cert_id,
                fingerprint_sha256=fp_map[str(cert_id)],
                ref_model=REF_MODEL_SAML_SP,
                ref_pk=str(sp.pk),
                usage=usage,
            )
            for cert_id, usage in to_add
            if str(cert_id) in fp_map
        ],
        ignore_conflicts=True,
    )
