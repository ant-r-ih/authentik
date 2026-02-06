# authentik/providers/saml/api/catalog.py

from __future__ import annotations

from typing import Any

from django.utils.translation import gettext_lazy as _
from drf_spectacular.utils import OpenApiResponse, extend_schema
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet

from authentik.providers.saml.processors.feed import (
    is_idp_entity,
    is_sp_entity,
    iter_entity_descriptors,
)
from authentik.providers.saml.processors.feed_summarize import summarize_entity_descriptor


class CatalogPreviewSerializer(serializers.Serializer):
    file = serializers.FileField()


class CatalogEntitySerializer(serializers.Serializer):
    file = serializers.FileField()
    entity_id = serializers.CharField()


class SAMLMetadataCatalogViewSet(ViewSet):
    """
    Stateless metadata catalog endpoints.

    This ViewSet is intentionally state-less:
      - The uploaded metadata file is processed in-memory only.
      - No persistence is performed.
    """

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    # Optional: set queryset to satisfy routers that try to infer basename
    queryset = []  # type: ignore

    def _read_upload(self, request: Request) -> bytes:
        # NOTE: The API is multipart/form-data with a single uploaded file.
        if "file" not in request.FILES:
            raise ValidationError({"file": [_("This field is required.")]})
        f = request.FILES["file"]
        data = f.read()
        if not data:
            raise ValidationError({"file": [_("Empty upload.")]})
        return data

    @extend_schema(
        responses={200: OpenApiResponse(description="List of entity summaries")},
    )
    @action(methods=["POST"], detail=False, url_path="preview")
    def preview(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        POST multipart/form-data:
          - file: metadata XML (EntitiesDescriptor or EntityDescriptor)

        Query params:
          - kind: "sp" | "idp" | "any" (default "any")
        """
        raw = self._read_upload(request)
        kind = request.query_params.get("kind", "any").lower()

        out: list[dict[str, Any]] = []
        for item in iter_entity_descriptors(raw):
            ent = item.xml

            if kind == "sp" and not is_sp_entity(ent):
                continue
            if kind == "idp" and not is_idp_entity(ent):
                continue

            summary = summarize_entity_descriptor(ent)
            summary["container_name_chain"] = list(item.container_name_chain)
            out.append(summary)

        return Response(out, status=200)

    @extend_schema(
        responses={200: OpenApiResponse(description="EntityDescriptor XML string")},
    )
    @action(methods=["POST"], detail=False, url_path="entity")
    def entity(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """
        POST multipart/form-data:
          - file: metadata XML
          - entity_id: exact match key

        Returns:
          - entity_id
          - xml: serialized <md:EntityDescriptor> element
          - container_name_chain
        """
        raw = self._read_upload(request)
        entity_id = request.data.get("entity_id")
        if not entity_id:
            raise ValidationError({"entity_id": [_("This field is required.")]})

        from lxml import etree  # nosec

        for item in iter_entity_descriptors(raw):
            if item.entity_id == entity_id:
                return Response(
                    {
                        "entity_id": item.entity_id,
                        "xml": etree.tostring(item.xml, encoding="unicode"),
                        "container_name_chain": list(item.container_name_chain),
                    },
                    status=200,
                )

        raise ValidationError({"entity_id": [_("entity_id not found in uploaded metadata.")]})
