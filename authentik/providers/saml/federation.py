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

SAMLSP_KEY_SLOTS = (
    ("verification", "verification_kp_override", "verification_kp"),
    ("signing", "signing_kp_override", "signing_kp"),
    ("encryption", "encryption_kp_override", "encryption_kp"),
)

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

def _runtime_key_presence(sp: "SAMLSP") -> dict[str, bool]:
    provider = getattr(sp, "provider", None)
    return {
        "has_verification_cert": _resolve_kp_with_override(
            sp, override_attr="verification_kp_override", kp_attr="verification_kp",
            fallback_kp=getattr(provider, "verification_kp", None),
        )
        is not None,
        "has_signing_cert": _resolve_kp_with_override(
            sp, override_attr="signing_kp_override", kp_attr="signing_kp",
            fallback_kp=getattr(provider, "signing_kp", None),
        )
        is not None,
        "has_encryption_cert": _resolve_kp_with_override(
            sp, override_attr="encryption_kp_override", kp_attr="encryption_kp",
            fallback_kp=getattr(provider, "encryption_kp", None),
        )
        is not None,
    }

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
    fallback_kp: CertificateKeyPair | None,
) -> CertificateKeyPair | None:
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

class SAMLSPMetadataState(models.TextChoices):
    MANUAL = "manual", "Manual"
    UNCHANGED = "unchanged", "Unchanged"
    DIVERGED = "diverged", "Diverged"
    # NOTE: OUTDATED/ORPHANED are lifecycle concerns; currently not used in DB-basis runtime compare
    OUTDATED = "outdated", "Outdated"
    ORPHANED = "orphaned", "Orphaned"

class SAMLSP(models.Model):
    uuid = models.UUIDField(default=uuid4, editable=False, unique=True)

    provider = models.ForeignKey(
        "authentik_providers_saml.SAMLProvider",
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

    encryption_kp_override = models.BooleanField(
        default=False,
        help_text="If enabled, use this SP's local encryption_kp (may be null to disable). "
                "If disabled, inherit provider setting."
    )

    signing_kp_override = models.BooleanField(
        default=False,
        help_text="If enabled, use this SP's local signing_kp (may be null to disable). "
                "If disabled, inherit provider setting."
    )

    verification_kp_override = models.BooleanField(
        default=False,
        help_text="If enabled, use this SP's local verification_kp (may be null to disable). "
                "If disabled, inherit provider setting."
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
        # app_label = "authentik_providers_saml"
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
