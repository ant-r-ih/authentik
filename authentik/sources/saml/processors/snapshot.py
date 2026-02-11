# authentik/sources/saml/processors/snapshot.py
from __future__ import annotations

import hashlib
import json
from typing import Any


def normalize_snapshot(snapshot: dict[str, Any]) -> str:
    """Return canonical JSON string for hashing.

    - sort_keys=True
    - separators=(',', ':') to remove whitespace
    - ensure_ascii=False keeps unicode stable (still deterministic)
    """
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_snapshot_hash(normalized_json: str) -> str:
    """sha256 hex digest of normalized snapshot JSON."""
    return hashlib.sha256(normalized_json.encode("utf-8")).hexdigest()
