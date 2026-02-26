from __future__ import annotations

from django.db import transaction
from django.utils import timezone
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.fields import ListField, UUIDField
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import ModelSerializer, PassiveSerializer
from authentik.crypto.models import CertificateReference
from authentik.providers.saml.processors.feed_extract import parse_entity_descriptor_xml
from authentik.providers.saml.utils.certrefs import REF_MODEL_SAML_IDP, sync_saml_idp_cert_refs
from authentik.sources.saml.federation import SAMLIDP
from authentik.sources.saml.models import (
    SAMLSource,
)
from authentik.sources.saml.processors.import_idp import import_idp_from_entity_descriptor


class SAMLIDPSetEnabledSerializer(serializers.Serializer):
    source = serializers.PrimaryKeyRelatedField(queryset=SAMLSource.objects.all())
    enabled = serializers.ListField(
        child=serializers.UUIDField(),
        required=True,
    )

class SAMLIDPSerializer(ModelSerializer):
    has_verification_kp = serializers.SerializerMethodField()
    has_encryption_kp = serializers.SerializerMethodField()
    has_signing_kp = serializers.SerializerMethodField()

    # model property (read-only)
    runtime_db_basis_state = serializers.CharField(read_only=True)

    def get_has_verification_kp(self, obj: SAMLIDP) -> bool:
        return obj.verification_kp_id is not None

    def get_has_encryption_kp(self, obj: SAMLIDP) -> bool:
        return obj.encryption_kp_id is not None

    def get_has_signing_kp(self, obj: SAMLIDP) -> bool:
        return obj.signing_kp_id is not None

    def create(self, validated_data):
        _normalize_kp_overrides(validated_data)
        instance: SAMLIDP = super().create(validated_data)

        update_fields = _apply_kp_overrides(instance, validated_data)
        if update_fields:
            instance.save(update_fields=update_fields)

        sync_saml_idp_cert_refs(instance)
        return instance

    def update(self, instance, validated_data):
        _normalize_kp_overrides(validated_data)
        instance: SAMLIDP = super().update(instance, validated_data)

        update_fields = _apply_kp_overrides(instance, validated_data)
        if update_fields:
            instance.save(update_fields=update_fields)

        sync_saml_idp_cert_refs(instance)
        return instance

    class Meta:
        model = SAMLIDP
        fields = [
            "pk",
            "uuid",
            "source",
            "name",
            "entity_id",
            "enabled",
            "sso_url",
            "slo_url",
            "allow_idp_initiated",
            "name_id_policy",
            "binding_type",
            "signed_assertion",
            "signed_response",
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
            "runtime_db_basis_state",
            "metadata_last_import",
            "metadata_snapshot",
            "metadata_hash",
            "created",
            "last_updated",
            "has_verification_kp",
            "has_encryption_kp",
            "has_signing_kp",
        ]
        read_only_fields = [
            "pk",
            "uuid",
            "created",
            "last_updated",
            "metadata_last_import",
            "metadata_snapshot",
            "metadata_hash",
            "runtime_db_basis_state",
            "has_local_override",
            "has_verification_kp",
            "has_encryption_kp",
            "has_signing_kp",
        ]

class SAMLIDPImportSerializer(serializers.Serializer):
    source = serializers.PrimaryKeyRelatedField(queryset=SAMLSource.objects.all())
    entity_xml = serializers.CharField()
    set_enabled = serializers.BooleanField(required=False, allow_null=True, default=None)
    overwrite = serializers.BooleanField(required=False, default=True)

class SAMLIDPBulkDeleteRequest(PassiveSerializer):
    source = serializers.PrimaryKeyRelatedField(queryset=SAMLSource.objects.all())
    uuids = ListField(child=UUIDField(), allow_empty=False)

def _normalize_import_error(exc: ValueError) -> ValidationError:
    msg = str(exc)

    if "EntityDescriptor" in msg or "IDPSSODescriptor" in msg or "SingleSignOnService" in msg:
        return ValidationError({"entity_xml": [msg]})

    if "certificate" in msg.lower() or "x509" in msg.lower() or "KeyDescriptor" in msg:
        return ValidationError({"certificate": [msg]})

    return ValidationError({"non_field_errors": [msg]})

class SAMLIDPViewSet(UsedByMixin, ModelViewSet):
    queryset = SAMLIDP.objects.all()
    serializer_class = SAMLIDPSerializer

    lookup_field = "uuid"
    lookup_url_kwarg = "uuid"

    filterset_fields = ["source", "enabled", "entity_id", "name"]
    search_fields = ["name", "entity_id"]
    ordering_fields = ["source", "name", "entity_id", "enabled", "created"]
    ordering = ["source", "name"]

    @extend_schema(
        request=SAMLIDPImportSerializer,
        responses={
            200: SAMLIDPSerializer,
            201: SAMLIDPSerializer,
            400: OpenApiResponse(description="Invalid import"),
        },
    )
    @action(detail=False, methods=["post"], url_path="import")
    @transaction.atomic
    def import_metadata(self, request: Request) -> Response:
        """
        Create/update a SAMLIDP from an uploaded EntityDescriptor XML string.
        """
        ser = SAMLIDPImportSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        source: SAMLSource = ser.validated_data["source"]
        entity_xml: str = ser.validated_data["entity_xml"]
        overwrite: bool = ser.validated_data["overwrite"]
        set_enabled = ser.validated_data["set_enabled"]
        enabled_arg = None if set_enabled is None else bool(set_enabled)

        try:
            entity_el = parse_entity_descriptor_xml(entity_xml)
            idp, created = import_idp_from_entity_descriptor(
                source=source,
                entity=entity_el,
                enabled=enabled_arg,
                overwrite=overwrite,
            )
        except ValueError as exc:
            raise _normalize_import_error(exc) from None

        body = SAMLIDPSerializer(idp).data
        body["created"] = created
        return Response(body, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    @extend_schema(
        request=SAMLIDPBulkDeleteRequest,
        responses={204: OpenApiResponse(description="Deleted")},
    )
    @action(detail=False, methods=["post"], url_path="bulk-delete")
    @transaction.atomic
    def bulk_delete(self, request: Request) -> Response:
        ser = SAMLIDPBulkDeleteRequest(data=request.data)
        ser.is_valid(raise_exception=True)

        source: SAMLSource = ser.validated_data["source"]
        uuids: list[str] = [str(u) for u in ser.validated_data["uuids"]]

        qs = SAMLIDP.objects.select_for_update().filter(source=source, uuid__in=uuids)

        # CertificateReference.ref_pk is pk(string)
        pks = list(qs.values_list("pk", flat=True))
        if pks:
            CertificateReference.objects.filter(
                ref_model=REF_MODEL_SAML_IDP,
                ref_pk__in=[str(pk) for pk in pks],
            ).delete()

        qs.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    @action(methods=["POST"], detail=False, url_path="set-enabled")
    def set_enabled(self, request):
        ser = SAMLIDPSetEnabledSerializer(data=request.data)
        ser.is_valid(raise_exception=True)

        source: SAMLSource = ser.validated_data["source"]
        enabled_uuids = [str(u) for u in ser.validated_data["enabled"]]

        qs = SAMLIDP.objects.filter(source=source)

        valid_uuids = set(str(u) for u in qs.values_list("uuid", flat=True))
        unknown = set(enabled_uuids) - valid_uuids
        if unknown:
            raise ValidationError({"enabled": [f"Unknown or foreign UUID(s): {', '.join(sorted(unknown))}"]})

        qs.update(enabled=False)
        if enabled_uuids:
            SAMLIDP.objects.filter(source=source, uuid__in=enabled_uuids).update(enabled=True)

        return Response(
            {"source": source.pk, "enabled": enabled_uuids},
            status=status.HTTP_200_OK,
        )
def _normalize_kp_overrides(validated_data: dict) -> None:
    for slot in ("verification", "signing", "encryption"):
        kp_field = f"{slot}_kp"
        ov_field = f"{slot}_kp_override"
        if kp_field in validated_data and ov_field not in validated_data:
            validated_data[ov_field] = True

def _apply_kp_overrides(instance: SAMLIDP, validated_data: dict) -> list[str]:
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
