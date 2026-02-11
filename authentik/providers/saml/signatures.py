# authentik/providers/saml/signature.py
from __future__ import annotations

import hashlib
import json
from typing import Any

from authentik.providers.saml.models import SAMLBindings  # TextChoices


def _to_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    # TextChoices values, enums, etc.
    return str(v)


def _to_list_endpoints(url: Any, binding: Any) -> list[dict[str, str]]:
    u = _to_str(url).strip()
    b = _to_str(binding).strip()
    if not u:
        return []
    return [{"url": u, "binding": b}]


def normalize_signature(data: dict[str, Any]) -> dict[str, Any]:
    """
    Canonical normalization for snapshot and runtime signature structures.

    Accepts either:
      A) snapshot-ish: {"acs":[{"url","binding",...}], "sls":[...], ...}
      B) runtime-ish : {"acs_url","sp_binding","sls_url","sls_binding", ...}

    Returns canonical:
      {"acs":[{"url","binding"}], "sls":[{"url","binding"}],
       "authn_requests_signed": bool, "want_assertions_signed": bool,
       "has_verification_cert": bool, "has_encryption_cert": bool}
    """

    acs = data.get("acs")
    if isinstance(acs, list):
        acs_list = [
            {"url": _to_str(x.get("url")), "binding": _to_str(x.get("binding"))}
            for x in acs
            if isinstance(x, dict) and _to_str(x.get("url")).strip()
        ]
    else:
        acs_list = _to_list_endpoints(data.get("acs_url"), data.get("sp_binding"))

    sls = data.get("sls")
    if isinstance(sls, list):
        sls_list = [
            {"url": _to_str(x.get("url")), "binding": _to_str(x.get("binding"))}
            for x in sls
            if isinstance(x, dict) and _to_str(x.get("url")).strip()
        ]
    else:
        sls_list = _to_list_endpoints(data.get("sls_url"), data.get("sls_binding"))

    # Canonical sort
    acs_list = sorted(acs_list, key=lambda x: (x.get("binding") or "", x.get("url") or ""))
    sls_list = sorted(sls_list, key=lambda x: (x.get("binding") or "", x.get("url") or ""))

    return {
        "acs": acs_list,
        "sls": sls_list,
        "authn_requests_signed": bool(data.get("authn_requests_signed", False)),
        "want_assertions_signed": bool(data.get("want_assertions_signed", False)),
        "has_verification_cert": bool(data.get("has_verification_cert", False)),
        "has_encryption_cert": bool(data.get("has_encryption_cert", False)),
    }


def hash_signature(data: dict[str, Any]) -> str:
    """Always normalize before hashing."""
    normalized = normalize_signature(data)
    s = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode()).hexdigest()


def current_runtime_signature(sp) -> dict[str, Any]:
    """Runtime signature in *flat* form (normalize_signature handles it)."""
    return {
        "acs_url": sp.acs_url or "",
        "sp_binding": _to_str(sp.sp_binding),
        "sls_url": sp.sls_url or "",
        "sls_binding": _to_str(sp.sls_binding),
        "authn_requests_signed": bool(sp.authn_requests_signed),
        "want_assertions_signed": bool(sp.want_assertions_signed),
        "has_verification_cert": sp.verification_kp_id is not None,
        "has_encryption_cert": sp.encryption_kp_id is not None,
    }


def build_runtime_signature_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Expected runtime signature derived from snapshot, in flat form."""
    snap = snapshot or {}

    # pick default acs/sls from snapshot list
    acs_list = snap.get("acs") or []
    sls_list = snap.get("sls") or []

    def _idx(x):
        try:
            return int(x.get("index", 0))
        except Exception:
            return 0

    def _pick_acs(items):
        if not items:
            return None
        post = [a for a in items if a.get("binding") == SAMLBindings.POST]
        if post:
            return sorted(post, key=lambda x: (_idx(x), _to_str(x.get("url"))))[0]
        return sorted(items, key=lambda x: (_idx(x), _to_str(x.get("url"))))[0]

    def _pick_sls(items):
        if not items:
            return None
        return sorted(items, key=lambda x: (_to_str(x.get("binding")), _to_str(x.get("url"))))[0]

    acs = _pick_acs(acs_list)
    sls = _pick_sls(sls_list)

    return {
        "acs_url": _to_str((acs or {}).get("url")),
        "sp_binding": _to_str((acs or {}).get("binding")),
        "sls_url": _to_str((sls or {}).get("url")),
        "sls_binding": _to_str((sls or {}).get("binding")),
        "authn_requests_signed": bool(snap.get("authn_requests_signed", False)),
        "want_assertions_signed": bool(snap.get("want_assertions_signed", False)),
        "has_verification_cert": bool(snap.get("has_verification_cert", False)),
        "has_encryption_cert": bool(snap.get("has_encryption_cert", False)),
    }


def runtime_diverged_db_basis(sp) -> bool:
    if not sp.metadata_snapshot:
        return False
    expected = build_runtime_signature_from_snapshot(sp.metadata_snapshot)
    current = current_runtime_signature(sp)
    return normalize_signature(expected) != normalize_signature(current)
