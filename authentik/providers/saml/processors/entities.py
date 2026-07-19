"""SAML SP/IdP entity compare and apply helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_pem_x509_certificate
from django.db import transaction
from django.utils.timezone import now

from authentik.crypto.models import CertificateKeyPair, CertificateKeyPairRing
from authentik.providers.saml.models import SAMLIDP, SAMLSP, SAMLBindings, SAMLProvider
from authentik.sources.saml.models import SAMLBindingTypes, SAMLNameIDPolicy, SAMLSource

APPLY_POLICY_FORCE = "force"
APPLY_POLICY_IF_NOT_DEVIATED = "if_not_deviated"
APPLY_POLICIES = {APPLY_POLICY_FORCE, APPLY_POLICY_IF_NOT_DEVIATED}


class ServiceProviderMetadataLike(Protocol):
    """Protocol for SP metadata DTO consumed by entity applier."""

    entity_id: str
    display_name: str | None
    acs_binding: str
    acs_location: str
    auth_n_request_signed: bool
    assertion_signed: bool
    name_id_policy: SAMLNameIDPolicy
    signing_cert_pems: list[str] | None
    encryption_cert_pems: list[str] | None
    sls_binding: str | None
    sls_location: str | None


class IdentityProviderMetadataLike(Protocol):
    """Protocol for IdP metadata DTO consumed by entity applier."""

    entity_id: str
    display_name: str | None
    sso_binding: str
    sso_location: str
    want_authn_requests_signed: bool
    name_id_policy: SAMLNameIDPolicy
    signing_cert_pems: list[str] | None
    encryption_cert_pems: list[str] | None
    slo_binding: str | None
    slo_location: str | None


@dataclass(slots=True)
class MetadataCompareResult:
    """Comparison result for one metadata entity."""

    entity_id: str
    exists: bool
    runtime_changed: bool
    cert_changed: bool
    runtime_deviated: bool
    cert_deviated: bool
    runtime_diff_fields: list[str]
    cert_diff_fields: list[str]
    runtime_locked: bool
    cert_locked: bool
    target_pk: int | None = None


@dataclass(slots=True)
class MetadataApplyResult:
    """Apply result for one metadata entity."""

    entity_id: str
    status: str
    reason: str = ""
    object_pk: int | None = None
    compare: MetadataCompareResult | None = None


def _snapshot_hash(payload: dict[str, Any]) -> str:
    """Return deterministic hash for JSON-serializable snapshot payload."""
    normalized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return sha256(normalized.encode("utf-8")).hexdigest()


def _cert_fingerprints(pems: list[str] | None) -> list[str]:
    """Return stable SHA-256 fingerprints for PEM list."""
    out: list[str] = []
    for pem in pems or []:
        cert = load_pem_x509_certificate(pem.encode("utf-8"), default_backend())
        out.append(cert.fingerprint(hashes.SHA256()).hex())
    return out


def _runtime_diff_fields(expected: dict[str, Any], current: dict[str, Any]) -> list[str]:
    """Return sorted runtime field keys that differ."""
    keys = sorted(set(expected) | set(current))
    return [key for key in keys if expected.get(key) != current.get(key)]


def _cert_diff_fields(
    expected: dict[str, list[str]],
    current: dict[str, list[str]],
) -> list[str]:
    """Return cert field keys whose fingerprint lists differ."""
    keys = ("verification", "encryption")
    return [key for key in keys if expected.get(key, []) != current.get(key, [])]


def _ring_fingerprints(ring: CertificateKeyPairRing | None) -> list[str]:
    """Return ordered certificate fingerprints from ring membership."""
    if ring is None:
        return []
    out: list[str] = []
    for keypair in ring.ordered_keypairs():
        if keypair.fingerprint_sha256:
            out.append(keypair.fingerprint_sha256.replace(":", "").lower())
            continue
        cert = load_pem_x509_certificate(
            keypair.certificate_data.encode("utf-8"),
            default_backend(),
        )
        out.append(cert.fingerprint(hashes.SHA256()).hex())
    return out


def _keypair_fingerprints(keypair: CertificateKeyPair | None) -> list[str]:
    """Return single-item fingerprint list from legacy keypair field."""
    if keypair is None:
        return []
    if keypair.fingerprint_sha256:
        return [keypair.fingerprint_sha256.replace(":", "").lower()]
    cert = load_pem_x509_certificate(keypair.certificate_data.encode("utf-8"), default_backend())
    return [cert.fingerprint(hashes.SHA256()).hex()]


def _cert_state_from_snapshot(snapshot: dict[str, Any]) -> dict[str, list[str]] | None:
    """Extract cert fingerprint state from snapshot."""
    if not snapshot:
        return None
    has_keys = (
        "verification_cert_fingerprints" in snapshot and "encryption_cert_fingerprints" in snapshot
    )
    if not has_keys:
        return None
    verification = snapshot.get("verification_cert_fingerprints")
    encryption = snapshot.get("encryption_cert_fingerprints")
    if not isinstance(verification, list) or not isinstance(encryption, list):
        return None
    return {
        "verification": [str(item) for item in verification],
        "encryption": [str(item) for item in encryption],
    }


def _sp_cert_state_from_metadata(metadata: ServiceProviderMetadataLike) -> dict[str, list[str]]:
    """Build SP cert state from incoming metadata DTO."""
    return {
        "verification": _cert_fingerprints(metadata.signing_cert_pems),
        "encryption": _cert_fingerprints(metadata.encryption_cert_pems),
    }


def _idp_cert_state_from_metadata(metadata: IdentityProviderMetadataLike) -> dict[str, list[str]]:
    """Build IdP cert state from incoming metadata DTO."""
    return {
        "verification": _cert_fingerprints(metadata.signing_cert_pems),
        # Source-side IdP metadata manages verification certs only.
        # Decryption keys are local/private material and stay parent-managed by default.
        "encryption": [],
    }


def _sp_cert_state_from_model(sp: SAMLSP) -> dict[str, list[str]]:
    """Build effective SP cert state with ring-first semantics."""
    verification = _ring_fingerprints(sp.verification_kp_ring)
    if not verification:
        verification = _keypair_fingerprints(sp.verification_kp)
    encryption = _ring_fingerprints(sp.encryption_kp_ring)
    if not encryption:
        encryption = _keypair_fingerprints(sp.encryption_kp)
    return {"verification": verification, "encryption": encryption}


def _idp_cert_state_from_model(idp: SAMLIDP) -> dict[str, list[str]]:
    """Build effective IdP cert state with ring-first semantics."""
    verification = _ring_fingerprints(idp.verification_kp_ring)
    if not verification:
        verification = _keypair_fingerprints(idp.verification_kp)
    # Source-side IdP metadata compare tracks verification certs only.
    return {"verification": verification, "encryption": []}


def _sp_runtime_from_metadata(metadata: ServiceProviderMetadataLike) -> dict[str, Any]:
    """Build comparable SP runtime defaults from parsed metadata DTO."""
    return {
        "display_name": (metadata.display_name or metadata.entity_id or "").strip(),
        "acs_url": metadata.acs_location or "",
        "sp_binding": metadata.acs_binding or SAMLBindings.POST,
        "sls_url": metadata.sls_location or "",
        "sls_binding": metadata.sls_binding or SAMLBindings.POST,
        "authn_requests_signed": bool(metadata.auth_n_request_signed),
        "want_assertions_signed": bool(metadata.assertion_signed),
        "name_id_policy": metadata.name_id_policy or SAMLNameIDPolicy.UNSPECIFIED,
    }


def _sp_runtime_from_model(sp: SAMLSP) -> dict[str, Any]:
    """Build comparable SP runtime defaults from existing DB model."""
    return {
        "display_name": (sp.name or sp.entity_id or "").strip(),
        "acs_url": sp.acs_url or "",
        "sp_binding": sp.sp_binding or SAMLBindings.POST,
        "sls_url": sp.sls_url or "",
        "sls_binding": sp.sls_binding or SAMLBindings.POST,
        "authn_requests_signed": bool(sp.authn_requests_signed),
        "want_assertions_signed": bool(sp.want_assertions_signed),
        "name_id_policy": sp.name_id_policy or SAMLNameIDPolicy.UNSPECIFIED,
    }


def _idp_binding_token_to_enum(binding: str) -> str:
    """Map parser binding token to SAMLSource/SAMLIDP binding enum."""
    if binding == SAMLBindings.POST:
        return SAMLBindingTypes.POST
    return SAMLBindingTypes.REDIRECT


def _idp_runtime_from_metadata(metadata: IdentityProviderMetadataLike) -> dict[str, Any]:
    """Build comparable IdP runtime defaults from parsed metadata DTO."""
    return {
        "display_name": (metadata.display_name or metadata.entity_id or "").strip(),
        "sso_url": metadata.sso_location or "",
        "binding_type": _idp_binding_token_to_enum(metadata.sso_binding or SAMLBindings.REDIRECT),
        "slo_url": metadata.slo_location or "",
        "name_id_policy": metadata.name_id_policy or SAMLNameIDPolicy.UNSPECIFIED,
    }


def _idp_runtime_from_model(idp: SAMLIDP) -> dict[str, Any]:
    """Build comparable IdP runtime defaults from existing DB model."""
    return {
        "display_name": (idp.name or idp.entity_id or "").strip(),
        "sso_url": idp.sso_url or "",
        "binding_type": idp.binding_type or SAMLBindingTypes.REDIRECT,
        "slo_url": idp.slo_url or "",
        "name_id_policy": idp.name_id_policy or SAMLNameIDPolicy.UNSPECIFIED,
    }


def _sp_runtime_from_stored_snapshot(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """Extract comparable SP runtime baseline from stored snapshot payload."""
    if not snapshot:
        return None
    runtime = snapshot.get("runtime")
    if isinstance(runtime, dict):
        return {
            "display_name": (
                runtime.get("display_name") or snapshot.get("entity_id") or ""
            ).strip(),
            "acs_url": runtime.get("acs_url") or "",
            "sp_binding": runtime.get("sp_binding") or SAMLBindings.POST,
            "sls_url": runtime.get("sls_url") or "",
            "sls_binding": runtime.get("sls_binding") or SAMLBindings.POST,
            "authn_requests_signed": bool(runtime.get("authn_requests_signed", False)),
            "want_assertions_signed": bool(runtime.get("want_assertions_signed", False)),
            "name_id_policy": runtime.get("name_id_policy") or SAMLNameIDPolicy.UNSPECIFIED,
        }
    if {
        "acs",
        "sls",
        "name_id_formats",
        "authn_requests_signed",
        "want_assertions_signed",
    }.intersection(snapshot):
        from authentik.providers.saml.processors import metadata_parser as mp

        legacy_runtime = mp.build_sp_runtime_from_snapshot(snapshot)
        return {
            "display_name": (snapshot.get("entity_id") or "").strip(),
            "acs_url": legacy_runtime.get("acs_url") or "",
            "sp_binding": legacy_runtime.get("sp_binding") or SAMLBindings.POST,
            "sls_url": legacy_runtime.get("sls_url") or "",
            "sls_binding": legacy_runtime.get("sls_binding") or SAMLBindings.POST,
            "authn_requests_signed": bool(legacy_runtime.get("authn_requests_signed", False)),
            "want_assertions_signed": bool(legacy_runtime.get("want_assertions_signed", False)),
            "name_id_policy": legacy_runtime.get("name_id_policy") or SAMLNameIDPolicy.UNSPECIFIED,
        }
    return None


def _idp_runtime_from_stored_snapshot(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """Extract comparable IdP runtime baseline from stored snapshot payload."""
    if not snapshot:
        return None
    runtime = snapshot.get("runtime")
    if isinstance(runtime, dict):
        binding = runtime.get("binding_type") or _idp_binding_token_to_enum(
            runtime.get("sso_binding") or SAMLBindings.REDIRECT
        )
        return {
            "display_name": (
                runtime.get("display_name") or snapshot.get("entity_id") or ""
            ).strip(),
            "sso_url": runtime.get("sso_url") or "",
            "binding_type": binding,
            "slo_url": runtime.get("slo_url") or "",
            "name_id_policy": runtime.get("name_id_policy") or SAMLNameIDPolicy.UNSPECIFIED,
        }
    if {"sso", "slo", "name_id_formats", "want_authn_requests_signed"}.intersection(snapshot):
        from authentik.providers.saml.processors import metadata_parser as mp

        legacy_runtime = mp.build_idp_runtime_from_snapshot(snapshot)
        return {
            "display_name": (snapshot.get("entity_id") or "").strip(),
            "sso_url": legacy_runtime.get("sso_url") or "",
            "binding_type": _idp_binding_token_to_enum(
                legacy_runtime.get("sso_binding") or SAMLBindings.REDIRECT
            ),
            "slo_url": legacy_runtime.get("slo_url") or "",
            "name_id_policy": legacy_runtime.get("name_id_policy") or SAMLNameIDPolicy.UNSPECIFIED,
        }
    return None


def _sp_snapshot_from_metadata(metadata: ServiceProviderMetadataLike) -> dict[str, Any]:
    """Build stable SP snapshot payload used for change detection."""
    return {
        "entity_id": metadata.entity_id,
        "runtime": _sp_runtime_from_metadata(metadata),
        "verification_cert_fingerprints": _cert_fingerprints(metadata.signing_cert_pems),
        "encryption_cert_fingerprints": _cert_fingerprints(metadata.encryption_cert_pems),
    }


def _idp_snapshot_from_metadata(metadata: IdentityProviderMetadataLike) -> dict[str, Any]:
    """Build stable IdP snapshot payload used for change detection."""
    return {
        "entity_id": metadata.entity_id,
        "runtime": _idp_runtime_from_metadata(metadata),
        "verification_cert_fingerprints": _cert_fingerprints(metadata.signing_cert_pems),
        # Source-side IdP snapshot stores only metadata-managed cert axis.
        "encryption_cert_fingerprints": [],
    }


def _sync_ring_from_pems(
    obj: SAMLSP | SAMLIDP | SAMLProvider | SAMLSource,
    *,
    ring_attr: str,
    kp_attr: str,
    pems: list[str] | None,
    create_missing_rings: bool,
    ring_name: str,
) -> None:
    """Sync a keypair ring from PEM values unless local keypair is pinned."""
    if pems is None or getattr(obj, kp_attr):
        return
    ring = getattr(obj, ring_attr)
    if ring is None and create_missing_rings and pems:
        ring = CertificateKeyPairRing.objects.create(name=ring_name)
        setattr(obj, ring_attr, ring)
    if ring is not None:
        ring.sync_membership([(i, pem) for i, pem in enumerate(pems)])


class SAMLSPEntityApplier:
    """Compare and apply one SP entity to SAMLSP model."""

    @staticmethod
    def compare(
        metadata: ServiceProviderMetadataLike,
        *,
        parent: SAMLProvider,
        target: SAMLSP | None = None,
    ) -> MetadataCompareResult:
        """Compare incoming SP metadata DTO against current SAMLSP state."""
        if target is not None and (
            target.parent_id != parent.pk or target.entity_id != metadata.entity_id
        ):
            raise ValueError("Provided SAMLSP target does not match parent/entity_id")
        target_obj = (
            target
            or SAMLSP.objects.filter(
                parent=parent,
                entity_id=metadata.entity_id,
            ).first()
        )
        if target_obj is None:
            return MetadataCompareResult(
                entity_id=metadata.entity_id,
                exists=False,
                runtime_changed=True,
                cert_changed=True,
                runtime_deviated=False,
                cert_deviated=False,
                runtime_diff_fields=[],
                cert_diff_fields=[],
                runtime_locked=False,
                cert_locked=False,
                target_pk=None,
            )
        incoming_runtime = _sp_runtime_from_metadata(metadata)
        incoming_cert_state = _sp_cert_state_from_metadata(metadata)

        stored_runtime = _sp_runtime_from_stored_snapshot(target_obj.metadata_snapshot)
        if stored_runtime is None:
            runtime_changed = True
            runtime_diff_fields = ["metadata_snapshot.runtime"]
        else:
            runtime_changed = bool(_runtime_diff_fields(incoming_runtime, stored_runtime))
            runtime_diff_fields = _runtime_diff_fields(
                stored_runtime,
                _sp_runtime_from_model(target_obj),
            )

        stored_cert_state = _cert_state_from_snapshot(target_obj.metadata_snapshot)
        if stored_cert_state is None:
            cert_changed = True
            cert_diff_fields = ["metadata_snapshot.certs"]
        else:
            cert_changed = bool(_cert_diff_fields(incoming_cert_state, stored_cert_state))
            cert_diff_fields = _cert_diff_fields(
                stored_cert_state,
                _sp_cert_state_from_model(target_obj),
            )

        runtime_locked = bool(target_obj.local_override_set)
        cert_locked = bool(
            target_obj.freeze_verification_kp
            or target_obj.freeze_signing_kp
            or target_obj.freeze_encryption_kp
            or target_obj.verification_kp_id
            or target_obj.signing_kp_id
            or target_obj.encryption_kp_id
        )

        return MetadataCompareResult(
            entity_id=metadata.entity_id,
            exists=True,
            runtime_changed=runtime_changed,
            cert_changed=cert_changed,
            runtime_deviated=bool(runtime_diff_fields),
            cert_deviated=bool(cert_diff_fields),
            runtime_diff_fields=runtime_diff_fields,
            cert_diff_fields=cert_diff_fields,
            runtime_locked=runtime_locked,
            cert_locked=cert_locked,
            target_pk=target_obj.pk,
        )

    @staticmethod
    def apply(
        metadata: ServiceProviderMetadataLike,
        *,
        parent: SAMLProvider,
        policy: str = APPLY_POLICY_IF_NOT_DEVIATED,
        target: SAMLSP | None = None,
        create_missing_rings: bool = True,
    ) -> MetadataApplyResult:
        """Create or update SAMLSP under parent using apply policy."""
        if policy not in APPLY_POLICIES:
            raise ValueError(f"Unsupported apply policy: {policy}")

        compare_result = SAMLSPEntityApplier.compare(metadata, parent=parent, target=target)
        target_obj = target
        if target_obj is None and compare_result.target_pk is not None:
            target_obj = SAMLSP.objects.filter(pk=compare_result.target_pk).first()

        if (
            policy == APPLY_POLICY_IF_NOT_DEVIATED
            and compare_result.exists
            and (compare_result.runtime_deviated or compare_result.runtime_locked)
        ):
            return MetadataApplyResult(
                entity_id=metadata.entity_id,
                status="skipped",
                reason="runtime_locked" if compare_result.runtime_locked else "runtime_deviated",
                object_pk=compare_result.target_pk,
                compare=compare_result,
            )

        with transaction.atomic():
            obj = target_obj
            created = False
            if obj is None:
                obj, created = SAMLSP.objects.get_or_create(
                    parent=parent,
                    entity_id=metadata.entity_id,
                )

            runtime = _sp_runtime_from_metadata(metadata)
            obj.name = runtime["display_name"]
            obj.acs_url = runtime["acs_url"]
            obj.sp_binding = runtime["sp_binding"]
            obj.sls_url = runtime["sls_url"]
            obj.sls_binding = runtime["sls_binding"]
            obj.authn_requests_signed = runtime["authn_requests_signed"]
            obj.want_assertions_signed = runtime["want_assertions_signed"]
            obj.name_id_policy = runtime["name_id_policy"]

            incoming_snapshot = _sp_snapshot_from_metadata(metadata)
            snapshot = dict(obj.metadata_snapshot or {})
            snapshot["entity_id"] = incoming_snapshot["entity_id"]
            snapshot["runtime"] = incoming_snapshot["runtime"]

            if not compare_result.cert_locked:
                # Metadata-managed entities must not inherit parent verification/encryption keys.
                obj.verification_kp_override = True
                obj.encryption_kp_override = True
                _sync_ring_from_pems(
                    obj,
                    ring_attr="verification_kp_ring",
                    kp_attr="verification_kp",
                    pems=metadata.signing_cert_pems,
                    create_missing_rings=create_missing_rings,
                    ring_name=f"SAMLSP {metadata.entity_id} - Verification Ring",
                )
                _sync_ring_from_pems(
                    obj,
                    ring_attr="encryption_kp_ring",
                    kp_attr="encryption_kp",
                    pems=metadata.encryption_cert_pems,
                    create_missing_rings=create_missing_rings,
                    ring_name=f"SAMLSP {metadata.entity_id} - Encryption Ring",
                )
                snapshot["verification_cert_fingerprints"] = incoming_snapshot[
                    "verification_cert_fingerprints"
                ]
                snapshot["encryption_cert_fingerprints"] = incoming_snapshot[
                    "encryption_cert_fingerprints"
                ]

            obj.metadata_snapshot = snapshot
            obj.metadata_hash = _snapshot_hash(snapshot)
            obj.metadata_last_import = now()
            obj.save()

        return MetadataApplyResult(
            entity_id=metadata.entity_id,
            status="created" if created else "updated",
            reason="",
            object_pk=obj.pk,
            compare=compare_result,
        )


class SAMLIDPEntityApplier:
    """Compare and apply one IdP entity to SAMLIDP model."""

    @staticmethod
    def compare(
        metadata: IdentityProviderMetadataLike,
        *,
        parent: SAMLSource,
        target: SAMLIDP | None = None,
    ) -> MetadataCompareResult:
        """Compare incoming IdP metadata DTO against current SAMLIDP state."""
        if target is not None and (
            target.parent_id != parent.pk or target.entity_id != metadata.entity_id
        ):
            raise ValueError("Provided SAMLIDP target does not match parent/entity_id")
        target_obj = (
            target
            or SAMLIDP.objects.filter(
                parent=parent,
                entity_id=metadata.entity_id,
            ).first()
        )
        if target_obj is None:
            return MetadataCompareResult(
                entity_id=metadata.entity_id,
                exists=False,
                runtime_changed=True,
                cert_changed=True,
                runtime_deviated=False,
                cert_deviated=False,
                runtime_diff_fields=[],
                cert_diff_fields=[],
                runtime_locked=False,
                cert_locked=False,
                target_pk=None,
            )
        incoming_runtime = _idp_runtime_from_metadata(metadata)
        incoming_cert_state = _idp_cert_state_from_metadata(metadata)

        stored_runtime = _idp_runtime_from_stored_snapshot(target_obj.metadata_snapshot)
        if stored_runtime is None:
            runtime_changed = True
            runtime_diff_fields = ["metadata_snapshot.runtime"]
        else:
            runtime_changed = bool(_runtime_diff_fields(incoming_runtime, stored_runtime))
            runtime_diff_fields = _runtime_diff_fields(
                stored_runtime,
                _idp_runtime_from_model(target_obj),
            )

        stored_cert_state = _cert_state_from_snapshot(target_obj.metadata_snapshot)
        if stored_cert_state is None:
            cert_changed = True
            cert_diff_fields = ["metadata_snapshot.certs"]
        else:
            cert_changed = bool(_cert_diff_fields(incoming_cert_state, stored_cert_state))
            cert_diff_fields = _cert_diff_fields(
                stored_cert_state,
                _idp_cert_state_from_model(target_obj),
            )

        runtime_locked = bool(target_obj.local_override_set)
        cert_locked = bool(target_obj.freeze_verification_kp or target_obj.verification_kp_id)

        return MetadataCompareResult(
            entity_id=metadata.entity_id,
            exists=True,
            runtime_changed=runtime_changed,
            cert_changed=cert_changed,
            runtime_deviated=bool(runtime_diff_fields),
            cert_deviated=bool(cert_diff_fields),
            runtime_diff_fields=runtime_diff_fields,
            cert_diff_fields=cert_diff_fields,
            runtime_locked=runtime_locked,
            cert_locked=cert_locked,
            target_pk=target_obj.pk,
        )

    @staticmethod
    def apply(
        metadata: IdentityProviderMetadataLike,
        *,
        parent: SAMLSource,
        policy: str = APPLY_POLICY_IF_NOT_DEVIATED,
        target: SAMLIDP | None = None,
        create_missing_rings: bool = True,
    ) -> MetadataApplyResult:
        """Create or update SAMLIDP under parent using apply policy."""
        if policy not in APPLY_POLICIES:
            raise ValueError(f"Unsupported apply policy: {policy}")

        compare_result = SAMLIDPEntityApplier.compare(metadata, parent=parent, target=target)
        target_obj = target
        if target_obj is None and compare_result.target_pk is not None:
            target_obj = SAMLIDP.objects.filter(pk=compare_result.target_pk).first()

        if (
            policy == APPLY_POLICY_IF_NOT_DEVIATED
            and compare_result.exists
            and (compare_result.runtime_deviated or compare_result.runtime_locked)
        ):
            return MetadataApplyResult(
                entity_id=metadata.entity_id,
                status="skipped",
                reason="runtime_locked" if compare_result.runtime_locked else "runtime_deviated",
                object_pk=compare_result.target_pk,
                compare=compare_result,
            )

        with transaction.atomic():
            obj = target_obj
            created = False
            if obj is None:
                obj, created = SAMLIDP.objects.get_or_create(
                    parent=parent,
                    entity_id=metadata.entity_id,
                )

            runtime = _idp_runtime_from_metadata(metadata)
            obj.name = runtime["display_name"]
            obj.sso_url = runtime["sso_url"]
            obj.binding_type = runtime["binding_type"]
            obj.slo_url = runtime["slo_url"] or None
            obj.name_id_policy = runtime["name_id_policy"]

            incoming_snapshot = _idp_snapshot_from_metadata(metadata)
            snapshot = dict(obj.metadata_snapshot or {})
            snapshot["entity_id"] = incoming_snapshot["entity_id"]
            snapshot["runtime"] = incoming_snapshot["runtime"]

            if not compare_result.cert_locked:
                # Source-side IdP metadata manages verification certs.
                obj.verification_kp_override = True
                _sync_ring_from_pems(
                    obj,
                    ring_attr="verification_kp_ring",
                    kp_attr="verification_kp",
                    pems=metadata.signing_cert_pems,
                    create_missing_rings=create_missing_rings,
                    ring_name=f"SAMLIDP {metadata.entity_id} - Verification Ring",
                )
                snapshot["verification_cert_fingerprints"] = incoming_snapshot[
                    "verification_cert_fingerprints"
                ]
                snapshot["encryption_cert_fingerprints"] = []

            obj.metadata_snapshot = snapshot
            obj.metadata_hash = _snapshot_hash(snapshot)
            obj.metadata_last_import = now()
            obj.save()

        return MetadataApplyResult(
            entity_id=metadata.entity_id,
            status="created" if created else "updated",
            reason="",
            object_pk=obj.pk,
            compare=compare_result,
        )


def compare_sp(
    metadata: ServiceProviderMetadataLike,
    *,
    parent: SAMLProvider,
    target: SAMLSP | None = None,
) -> MetadataCompareResult:
    """Compare incoming SP metadata DTO against current SAMLSP state."""
    return SAMLSPEntityApplier.compare(metadata, parent=parent, target=target)


def compare_idp(
    metadata: IdentityProviderMetadataLike,
    *,
    parent: SAMLSource,
    target: SAMLIDP | None = None,
) -> MetadataCompareResult:
    """Compare incoming IdP metadata DTO against current SAMLIDP state."""
    return SAMLIDPEntityApplier.compare(metadata, parent=parent, target=target)
