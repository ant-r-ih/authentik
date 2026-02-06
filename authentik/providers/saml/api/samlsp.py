from __future__ import annotations

from typing import Any

from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import mixins, serializers, viewsets
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from structlog.stdlib import get_logger

from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import (
    ModelSerializer,
)
from authentik.providers.saml.models import SAMLSP, SAMLProvider
from authentik.providers.saml.processors.feed_extract import parse_entity_descriptor_xml
from authentik.providers.saml.processors.import_sp import import_sp_from_entity_descriptor
from authentik.providers.saml.utils.certrefs import (
    sync_saml_sp_cert_refs,
)
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

    def create(self, validated_data):
        instance: SAMLSP = super().create(validated_data)
        sync_saml_sp_cert_refs(instance)
        return instance

    def update(self, instance, validated_data):
        instance: SAMLSP = super().update(instance, validated_data)
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
            "verification_kp",
            "created",
            "last_updated",
        ]
        read_only_fields = ["pk", "uuid", "created", "last_updated"]


class SAMLSPViewSet(UsedByMixin, ModelViewSet):
    queryset = SAMLSP.objects.all()
    serializer_class = SAMLSPSerializer
    filterset_fields = [
        "provider",
        "enabled",
        "entity_id",
        "name",
    ]

    ordering = ["provider", "name", "entity_id"]
    search_fields = ["name", "entity_id"]


class SAMLSPImportSerializer(serializers.Serializer):
    """
    Import payload for creating/updating SAMLSP from a single EntityDescriptor XML.

    We keep the import payload explicit to avoid hidden coupling with the catalog API.
    """

    provider = serializers.PrimaryKeyRelatedField(queryset=SAMLProvider.objects.all())
    entity_xml = serializers.CharField()
    enabled = serializers.BooleanField(required=False, default=True)
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


class SAMLSPImportViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """Import a single EntityDescriptor into a SAMLSP row (stateful)."""

    permission_classes = [IsAuthenticated]
    serializer_class = SAMLSPImportSerializer
    queryset = SAMLSP.objects.none()

    @extend_schema(
        request=SAMLSPImportSerializer,
        responses={
            200: SAMLSPSerializer,
            201: SAMLSPSerializer,
            400: OpenApiResponse(description="Invalid import"),
        },
    )
    def create(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Create/update a SAMLSP from an uploaded EntityDescriptor XML string."""
        set = self.get_serializer(data=request.data)
        set.is_valid(raise_exception=True)

        provider = set.validated_data["provider"]
        entity_xml: str = set.validated_data["entity_xml"]
        enabled: bool = set.validated_data["enabled"]
        overwrite: bool = set.validated_data["overwrite"]

        try:
            entity_el = parse_entity_descriptor_xml(entity_xml)
            sp, created = import_sp_from_entity_descriptor(
                provider=provider,
                entity=entity_el,
                enabled=enabled,
                overwrite=overwrite,
            )
        except ValueError as exc:
            raise _normalize_import_error(exc) from None

        body = SAMLSPSerializer(sp).data
        body["created"] = created
        return Response(body, status=201 if created else 200)
