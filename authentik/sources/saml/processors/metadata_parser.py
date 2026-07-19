"""Compatibility shim for IdP metadata parser now implemented in providers.saml."""

from authentik.providers.saml.processors.metadata_parser import (
    APPLY_POLICY_FORCE,
    APPLY_POLICY_IF_NOT_DEVIATED,
    IdentityProviderMetadata,
    IdentityProviderMetadataParser,
    MetadataApplyResult,
    MetadataCompareResult,
    build_idp_runtime_from_snapshot,
    build_idp_snapshot,
    compare_idp,
)

__all__ = [
    "IdentityProviderMetadata",
    "IdentityProviderMetadataParser",
    "APPLY_POLICY_FORCE",
    "APPLY_POLICY_IF_NOT_DEVIATED",
    "MetadataCompareResult",
    "MetadataApplyResult",
    "compare_idp",
    "build_idp_snapshot",
    "build_idp_runtime_from_snapshot",
]
