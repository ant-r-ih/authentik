import hashlib
import json
from typing import Any
from uuid import uuid4

from defusedxml import ElementTree
from django.db import models
from django.utils.translation import gettext_lazy as _

from authentik.crypto.models import CertificateKeyPair
from authentik.lib.models import DomainlessURLValidator
from authentik.providers.saml.processors.constants import (
    SAMLBindings,
    SAMLBindingTypes,
    SAMLNameIDPolicy,
)
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

SAMLIDP_KEY_SLOTS = (
    ("verification", "verification_kp_override", "verification_kp"),
    ("signing", "signing_kp_override", "signing_kp"),
    ("encryption", "encryption_kp_override", "encryption_kp"),
)

def _snapshot_key_presence(snapshot: dict[str, Any]) -> dict[str, bool]:
    snap = snapshot or {}
    return {
        "has_verification_cert": bool(snap.get("has_verification_cert", False)),
        "has_signing_cert": bool(snap.get("has_signing_cert", False)),
        "has_encryption_cert": bool(snap.get("has_encryption_cert", False)),
    }

def peek_issuer(root: ElementTree) -> str | None:
    issuers = root.findall(f"{{{NS_SAML_PROTOCOL}}}Issuer")
    if not issuers:
        issuers = root.findall(f"{{{NS_SAML_ASSERTION}}}Issuer")
    return issuers[0].text if issuers else None

class SAMLIDPMetadataState(models.TextChoices):
    MANUAL = "manual", "Manual"
    UNCHANGED = "unchanged", "Unchanged"
    DIVERGED = "diverged", "Diverged"
    OUTDATED = "outdated", "Outdated"
    ORPHANED = "orphaned", "Orphaned"


def compute_signature_hash(data: dict[str, Any]) -> str:
    """Caller must pass already-normalized dict."""
    normalized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode()).hexdigest()

def _resolve_kp_with_override(
    local_obj: Any,
    *,
    override_attr: str,
    kp_attr: str,
    fallback_kp: CertificateKeyPair | None,
) -> CertificateKeyPair | None:
    if local_obj is None:
        return fallback_kp
    if getattr(local_obj, override_attr, False):
        return getattr(local_obj, kp_attr, None)  # may be None => disabled
    return fallback_kp

def _runtime_key_presence(idp: "SAMLIDP") -> dict[str, bool]:
    source = getattr(idp, "source", None)
    return {
        "has_verification_cert": _resolve_kp_with_override(
            idp,
            override_attr="verification_kp_override",
            kp_attr="verification_kp",
            fallback_kp=getattr(source, "verification_kp", None),
        )
        is not None,
        "has_signing_cert": _resolve_kp_with_override(
            idp,
            override_attr="signing_kp_override",
            kp_attr="signing_kp",
            fallback_kp=getattr(source, "signing_kp", None),
        )
        is not None,
        "has_encryption_cert": _resolve_kp_with_override(
            idp,
            override_attr="encryption_kp_override",
            kp_attr="encryption_kp",
            fallback_kp=getattr(source, "encryption_kp", None),
        )
        is not None,
    }

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

def current_runtime_signature_idp(idp: "SAMLIDP") -> dict[str, Any]:
    """
    Current runtime signature for IDP:
      - fields come from SAMLIDP row
      - key presence is computed using mode + fallback (SAMLSource)
    """

    return {
        "sso_url": idp.sso_url,
        "slo_url": idp.slo_url,
        "binding_type": idp.binding_type,
        "allow_idp_initiated": bool(idp.allow_idp_initiated),
        "name_id_policy": idp.name_id_policy,
        "signed_assertion": bool(idp.signed_assertion),
        "signed_response": bool(idp.signed_response),
        **_runtime_key_presence(idp),
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
class SAMLSPMetadataState(models.TextChoices):
    MANUAL = "manual", "Manual"
    UNCHANGED = "unchanged", "Unchanged"
    DIVERGED = "diverged", "Diverged"
    # NOTE: OUTDATED/ORPHANED are lifecycle concerns; currently not used in DB-basis runtime compare
    OUTDATED = "outdated", "Outdated"
    ORPHANED = "orphaned", "Orphaned"

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

class SAMLIDP(models.Model):
    """Additional SAML Identity Provider configuration under a SAMLSource.

    The existing SAMLSource fields remain the 'default IdP'. This model is only for additional IdPs.
    """

    uuid = models.UUIDField(default=uuid4, editable=False, unique=True)

    source = models.ForeignKey(
        "authentik_sources_saml.SAMLSource",
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

    encryption_kp_override = models.BooleanField(
        default=False,
        help_text="If enabled, use this IdP's local encryption_kp (may be null to disable). "
                "If disabled, inherit source setting."
    )

    signing_kp_override = models.BooleanField(
        default=False,
        help_text="If enabled, use this IdP's local signing_kp (may be null to disable). "
                "If disabled, inherit source setting."
    )

    verification_kp_override = models.BooleanField(
        default=False,
        help_text="If enabled, use this IdP's local verification_kp (may be null to disable). "
                "If disabled, inherit source setting."
    )

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
        # app_label = "authentik_sources_saml"
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
