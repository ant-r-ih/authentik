from __future__ import annotations

from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from django.db import transaction
from django.utils import timezone
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import mixins, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.fields import CharField, FileField, ListField, SerializerMethodField, UUIDField
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import PrimaryKeyRelatedField, ValidationError
from rest_framework.viewsets import ModelViewSet
from structlog.stdlib import get_logger

from authentik.api.validation import validate
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import (
    ModelSerializer,
    PassiveSerializer,
    PropertyMappingPreviewSerializer,
)
from authentik.crypto.models import CertificateReference
from authentik.providers.saml.federation import (
    build_runtime_from_snapshot,
)
from authentik.providers.saml.models import (
    SAMLSP,
    SAMLBindings,
    SAMLProvider,
)
from authentik.providers.saml.processors.feed_extract import parse_entity_descriptor_xml
from authentik.providers.saml.processors.import_sp import import_sp_from_entity_descriptor
from authentik.providers.saml.utils.certrefs import (
    REF_MODEL_SAML_SP,
    sync_saml_sp_cert_refs,
)
from authentik.rbac.decorators import permission_required
from authentik.sources.saml.processors.constants import (
    NS_SAML_METADATA,
    NS_SIGNATURE,
)

NS_MAP = {
    "md": NS_SAML_METADATA,
    "ds": NS_SIGNATURE,
}

LOGGER = get_logger()
class SAMLSPSerializer(ModelSerializer):

    has_verification_kp = serializers.SerializerMethodField()
    has_encryption_kp = serializers.SerializerMethodField()
    has_signing_kp = serializers.SerializerMethodField()
    runtime_db_basis_state = serializers.CharField(read_only=True)

    def get_has_encryption_kp(self, obj: SAMLSP) -> bool:
        return obj.encryption_kp_id is not None

    def get_has_signing_kp(self, obj: SAMLSP) -> bool:
        return obj.signing_kp_id is not None

    def get_has_verification_kp(self, obj: SAMLSP) -> bool:
        return obj.verification_kp_id is not None

    def create(self, validated_data):
        property_mappings = validated_data.pop("property_mappings", None)

        _normalize_kp_overrides(None, validated_data)
        instance: SAMLSP = super().create(validated_data)

        if property_mappings is not None:
            instance.property_mappings.set(property_mappings)

        if validated_data.get("property_mappings_override") is False:
            instance.property_mappings.clear()

        update_fields = _apply_kp_overrides(instance, validated_data)
        if update_fields:
            instance.save(update_fields=update_fields)

        sync_saml_sp_cert_refs(instance)
        return instance


    def update(self, instance, validated_data):
        property_mappings = validated_data.pop("property_mappings", None)

        _normalize_kp_overrides(instance, validated_data)
        instance: SAMLSP = super().update(instance, validated_data)

        if property_mappings is not None:
            instance.property_mappings.set(property_mappings)

        if validated_data.get("property_mappings_override") is False:
            instance.property_mappings.clear()

        update_fields = _apply_kp_overrides(instance, validated_data)
        if update_fields:
            instance.save(update_fields=update_fields)

        sync_saml_sp_cert_refs(instance)
        return instance
    class Meta:
        model = SAMLSP
        fields = [
            "pk",
            "uuid",
            "name",
            "provider",
            "entity_id",
            "enabled",
            "acs_url",
            "sp_binding",
            "sls_url",
            "sls_binding",
            "authn_requests_signed",
            "want_assertions_signed",
            "name_id_policy",
            "encryption_kp",
            "encryption_kp_override",
            "freeze_encryption_kp",
            "signing_kp",
            "signing_kp_override",
            "freeze_signing_kp",
            "verification_kp",
            "verification_kp_override",
            "freeze_verification_kp",
            "has_local_override",
            "created",
            "last_updated",
            "has_encryption_kp",
            "has_signing_kp",
            "has_verification_kp",
            "runtime_db_basis_state",
            "property_mappings",
            "property_mappings_override",
        ]
        read_only_fields = [
            "pk",
            "uuid",
            "created",
            "last_updated",
            "metadata_snapshot",
            "metadata_hash",
            "runtime_db_basis_state",
            "has_local_override",
            "has_encryption_kp",
            "has_signing_kp",
            "has_verification_kp",
        ]
        extra_kwargs = {
            "sp_binding": {"required": False},
            "sls_binding": {"required": False},
        }

class SetEnabledSerializer(serializers.Serializer):
    provider = serializers.PrimaryKeyRelatedField(
        queryset=SAMLProvider.objects.all()
    )
    enabled = serializers.ListField(
        child=serializers.UUIDField(),
        required=True,
    )

class SAMLSPBulkDeleteRequest(PassiveSerializer):
    provider = PrimaryKeyRelatedField(queryset=SAMLProvider.objects.all())
    uuids = ListField(child=UUIDField(), allow_empty=False)

class SAMLSPViewSet(UsedByMixin, ModelViewSet):
    queryset = SAMLSP.objects.all()
    serializer_class = SAMLSPSerializer
    lookup_field = "uuid"
    lookup_url_kwarg = "uuid"

    # --- Filtering / search / ordering ---
    filter_backends = [
        DjangoFilterBackend,
        SearchFilter,
        OrderingFilter,
    ]

    filterset_fields = [
        "provider",
        "enabled",
        "entity_id",
        "name",]
    search_fields = ["name", "entity_id"]
    ordering_fields = ["provider","name", "entity_id", "enabled", "created"]
    ordering = ["provider", "name"]

    @action(detail=True, methods=["post"])
    def apply_metadata(self, request, uuid=None):
        sp: SAMLSP = self.get_object()

        if not sp.metadata_snapshot:
            return Response({"detail": "No metadata snapshot"}, status=400)

        skipped = []
        if sp.freeze_verification_kp:
            skipped.append("verification_kp (frozen)")

        if sp.freeze_signing_kp:
            skipped.append("signing_kp (frozen)")

        if sp.freeze_encryption_kp:
            skipped.append("encryption_kp (frozen)")

        apply_snapshot_to_runtime(sp)

        sp.metadata_last_import = timezone.now()
        sp.metadata_hash = sp.snapshot_hash_normalized
        if not (sp.sls_url or "").strip():
            sp.sls_binding = sp.sls_binding or SAMLBindings.POST
        sp.full_clean()
        sp.save()

        data = SAMLSPSerializer(sp).data
        if skipped:
            data["_apply_info"] = {"skipped_fields": skipped}
        return Response(data)

    # -------------------------------------------------
    # Bulk enable setter (DualSelect backend endpoint)
    # -------------------------------------------------

    @transaction.atomic
    @action(methods=["POST"], detail=False, url_path="set-enabled")
    def set_enabled(self, request):
        """
        Replace the enabled SAMLSP set for a provider.

        Expected body:
        {
            "provider": "<provider_pk>",
            "enabled": ["uuid1", "uuid2", ...]
        }

        Behavior:
          - Fully replaces enabled set (not incremental).
          - Validates UUIDs belong to provider.
          - Atomic.
        """

        provider_pk = request.data.get("provider")
        enabled_uuids = request.data.get("enabled", [])

        if not provider_pk:
            raise ValidationError({"provider": ["This field is required."]})

        if not isinstance(enabled_uuids, list):
            raise ValidationError({"enabled": ["Must be a list of UUIDs."]})

        # Fetch provider
        try:
            provider = SAMLProvider.objects.get(pk=provider_pk)
        except SAMLProvider.DoesNotExist:
            raise ValidationError({"provider": ["Invalid provider."]})  # noqa: B904

        # Fetch all SPs for this provider
        sps = SAMLSP.objects.filter(provider=provider)

        # Validate UUIDs belong to provider
        valid_uuids = set(sps.values_list("uuid", flat=True))
        unknown = set(enabled_uuids) - {str(u) for u in valid_uuids}

        if unknown:
            raise ValidationError(
                {"enabled": [f"Unknown or foreign UUID(s): {', '.join(unknown)}"]}
            )

        # Disable all
        sps.update(enabled=False)

        # Enable selected
        SAMLSP.objects.filter(provider=provider, uuid__in=enabled_uuids).update(
            enabled=True
        )

        return Response(
            {
                "provider": provider_pk,
                "enabled": enabled_uuids,
            },
            status=status.HTTP_200_OK,
        )

    @extend_schema(
        request=SAMLSPSerializer,
        responses={
            200: SAMLSPSerializer,
            201: SAMLSPSerializer,
            400: OpenApiResponse(description="Invalid import"),
        },
    )
    @action(detail=False, methods=["post"], url_path="import")
    def import_metadata(self, request):
        """
        Create/update a SAMLSP from an uploaded EntityDescriptor XML string.
        """
        serializer = SAMLSPImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        provider = serializer.validated_data["provider"]
        entity_xml: str = serializer.validated_data["entity_xml"]
#        enabled: bool = serializer.validated_data["enabled"]
        overwrite: bool = serializer.validated_data["overwrite"]
        set_enabled = serializer.validated_data["set_enabled"]
        if set_enabled is None:
            enabled_arg = None
        else:
            enabled_arg = bool(set_enabled)

        try:
            entity_el = parse_entity_descriptor_xml(entity_xml)
            sp, created = import_sp_from_entity_descriptor(
                provider=provider,
                entity=entity_el,
                enabled=enabled_arg,
                overwrite=overwrite,
            )
        except ValueError as exc:
            raise _normalize_import_error(exc) from None

        body = SAMLSPSerializer(sp).data
        body["created"] = created

        return Response(
            body,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

#    @permission_required("authentik_providers_saml.change_samlprovider")
    @extend_schema(
        request=SAMLSPBulkDeleteRequest,
        responses={204: OpenApiResponse(description="Deleted")},
    )
    @action(detail=False, methods=["post"], url_path="bulk-delete")
    @transaction.atomic
    def bulk_delete(self, request: Request) -> Response:
        ser = SAMLSPBulkDeleteRequest(data=request.data)
        ser.is_valid(raise_exception=True)

        provider: SAMLProvider = ser.validated_data["provider"]
        uuids: list[str] = [str(u) for u in ser.validated_data["uuids"]]

        qs = SAMLSP.objects.select_for_update().filter(provider=provider, uuid__in=uuids)

        # CertificateReference.ref_pk is the *stringified pk* of SAMLSP
        pks = list(qs.values_list("pk", flat=True))
        if pks:
            CertificateReference.objects.filter(
                ref_model=REF_MODEL_SAML_SP,
                ref_pk__in=[str(pk) for pk in pks],
            ).delete()

        qs.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
class SAMLSPImportSerializer(serializers.Serializer):
    """
    Import payload for creating/updating SAMLSP from a single EntityDescriptor XML.

    We keep the import payload explicit to avoid hidden coupling with the catalog API.
    """

    provider = serializers.PrimaryKeyRelatedField(queryset=SAMLProvider.objects.all())
    entity_xml = serializers.CharField()
#    enabled = serializers.BooleanField(required=False, default=False)
    set_enabled = serializers.BooleanField(required=False, allow_null=True, default=None)
    overwrite = serializers.BooleanField(
        required=False,
        default=True,
        help_text="If true, metadata-derived fields overwrite existing SP fields.",
    )

def _normalize_import_error(exc: ValueError) -> ValidationError:
    """Convert importer ValueError into a DRF ValidationError with stable shape."""
    msg = str(exc)

    # Keep this simple and predictable for UI/tests.
    # If you later introduce custom exception classes, switch to isinstance checks.
    if "EntityDescriptor" in msg or "SPSSODescriptor" in msg or "AssertionConsumerService" in msg:
        return ValidationError({"entity_xml": [msg]})

    if "certificate" in msg.lower() or "x509" in msg.lower() or "KeyDescriptor" in msg:
        return ValidationError({"certificate": [msg]})

    return ValidationError({"non_field_errors": [msg]})

def apply_snapshot_to_runtime(sp: SAMLSP) -> list[str]:
    """Apply metadata-derived runtime fields to SAMLSP, respecting key freeze/mode controls.

    Returns:
        list[str]: human-readable skipped fields info
    """
    expected = build_runtime_from_snapshot(sp.metadata_snapshot or {})
    skipped: list[str] = []

    sp.acs_url = expected["acs_url"]
    sp.sp_binding = expected["sp_binding"] or sp.sp_binding

    sls_url = (expected.get("sls_url") or "").strip()
    sp.sls_url = sls_url
    if sls_url:
        sp.sls_binding = expected.get("sls_binding") or sp.sls_binding

    sp.authn_requests_signed = expected["authn_requests_signed"]
    sp.want_assertions_signed = expected["want_assertions_signed"]

    # Key application policy:
    # metadata apply may update runtime key refs only when mode=INHERIT and not frozen.
    # (Actual key values should come from your metadata snapshot/import pipeline logic.)
    #
    # If apply_snapshot_to_runtime currently does not assign keys directly, keep this as
    # bookkeeping for response transparency.
    for key_name in ("verification", "signing", "encryption"):
        ok, reason = _can_apply_kp_from_metadata(sp, key_name)
        if not ok and reason:
            skipped.append(reason)

    sync_saml_sp_cert_refs(sp)
    return skipped

def _can_apply_kp_from_metadata(sp: SAMLSP, key_name: str) -> tuple[bool, str | None]:
    freeze_attr = f"freeze_{key_name}_kp"
    if getattr(sp, freeze_attr, False):
        return False, f"{key_name}_kp (frozen)"
    return True, None

def _normalize_kp_overrides(instance: SAMLSP, validated_data: dict) -> None:
    """
    Keep *_kp_override and *_kp consistent.

    Rules (simple & deterministic):
      - If override flag is present in request:
          override == False => force *_kp = None  (inherit)
          override == True  => keep provided *_kp as-is (may be None => disable)
      - If *_kp is present but override flag is NOT present:
          (optional policy) do nothing OR auto-set override=True.
          Recommend: auto-set override=True to match user intent.
    """
    # auto-enable override if user explicitly sent a kp field (even None)
    for slot in ("verification", "signing", "encryption"):
        kp_field = f"{slot}_kp"
        ov_field = f"{slot}_kp_override"
        if kp_field in validated_data and ov_field not in validated_data:
            validated_data[ov_field] = True

def _apply_kp_overrides(instance: SAMLSP, validated_data: dict) -> list[str]:
    update_fields: list[str] = []

    for slot in ("verification", "signing", "encryption"):
        kp_field = f"{slot}_kp"
        ov_field = f"{slot}_kp_override"

        if ov_field in validated_data:
            ov = bool(validated_data[ov_field])
            setattr(instance, ov_field, ov)
            update_fields.append(ov_field)

            if not ov:
                # inherit => clear local kp to avoid confusion
                if getattr(instance, kp_field + "_id", None) is not None:
                    setattr(instance, kp_field, None)
                    update_fields.append(kp_field)

    return update_fields
