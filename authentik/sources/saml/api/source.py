"""SAMLSource API Views"""

import gzip
from uuid import UUID
from xml.etree.ElementTree import ParseError  # nosec

from defusedxml.ElementTree import fromstring
from django.http.response import Http404
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.fields import SerializerMethodField
from rest_framework.parsers import MultiPartParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import (
    BooleanField,
    CharField,
    ChoiceField,
    FileField,
    IntegerField,
    ListField,
    PrimaryKeyRelatedField,
    ValidationError,
)
from rest_framework.viewsets import ModelViewSet

from authentik.admin.files.manager import get_file_manager
from authentik.admin.files.usage import FileApiUsage
from authentik.api.validation import validate
from authentik.core.api.sources import SourceSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import ModelSerializer, PassiveSerializer
from authentik.crypto.models import CertificateKeyPair
from authentik.flows.models import Flow
from authentik.providers.saml.api.providers import SAMLMetadataSerializer
from authentik.providers.saml.models import SAMLIDP, SAMLBindings
from authentik.rbac.decorators import permission_required
from authentik.sources.saml.models import SAMLNameIDPolicy, SAMLSource
from authentik.sources.saml.processors.metadata import MetadataProcessor
from authentik.sources.saml.processors.metadata_parser import (
    APPLY_POLICY_FORCE,
    APPLY_POLICY_IF_NOT_DEVIATED,
    IdentityProviderMetadata,
    IdentityProviderMetadataParser,
)


class SAMLSourceSerializer(SourceSerializer):
    """SAMLSource Serializer"""

    url_issuer = SerializerMethodField()

    def get_url_issuer(self, instance: SAMLSource) -> str:
        """Get the resolved Issuer, falling back to the metadata URL when unset"""
        if "request" not in self._context:
            return instance.issuer_override or ""
        return instance.get_issuer(self._context["request"]._request)

    def validate(self, attrs: dict):
        if attrs.get("verification_kp"):
            if not attrs.get("signed_assertion") and not attrs.get("signed_response"):
                raise ValidationError(
                    _(
                        "With a Verification Certificate selected, at least one of"
                        " 'Verify Assertion Signature' or 'Verify Response Signature' "
                        "must be selected."
                    )
                )
        return super().validate(attrs)

    class Meta:
        model = SAMLSource
        fields = SourceSerializer.Meta.fields + [
            "group_matching_mode",
            "pre_authentication_flow",
            "issuer_override",
            "url_issuer",
            "sso_url",
            "slo_url",
            "allow_idp_initiated",
            "force_authn",
            "name_id_policy",
            "binding_type",
            "verification_kp",
            "signing_kp",
            "verification_kp_ring",
            "signing_kp_ring",
            "encryption_kp",
            "encryption_kp_ring",
            "digest_algorithm",
            "signature_algorithm",
            "temporary_user_delete_after",
            "signed_assertion",
            "signed_response",
        ]


class SAMLSourceImportSerializer(PassiveSerializer):
    """Import SAML source from IdP XML Metadata"""

    source = PrimaryKeyRelatedField(
        queryset=SAMLSource.objects.all(),
        required=False,
        allow_null=True,
    )
    name = CharField(required=True, allow_blank=False)
    pre_authentication_flow = PrimaryKeyRelatedField(
        queryset=Flow.objects.all(),
        required=False,
        allow_null=True,
    )
    file = FileField(required=True)

    signing_certificate = PrimaryKeyRelatedField(
        queryset=CertificateKeyPair.objects.all(),
        required=False,
        allow_null=True,
    )

    create_missing_rings = BooleanField(required=False, default=True)

    def validate(self, attrs: dict):
        target = attrs.get("source")
        if target:
            return attrs

        missing = {}
        if not attrs.get("name"):
            missing["name"] = "This field is required when source is not set."
        if not attrs.get("pre_authentication_flow"):
            missing["pre_authentication_flow"] = "This field is required when source is not set."
        if missing:
            raise ValidationError(missing)
        return attrs


class SAMLIDPSerializer(ModelSerializer):
    """Serializer for nested SAML identity provider entities."""

    class Meta:
        model = SAMLIDP
        fields = [
            "pk",
            "uuid",
            "name",
            "entity_id",
            "enabled",
            "sso_url",
            "slo_url",
            "allow_idp_initiated",
            "name_id_policy",
            "binding_type",
            "digest_algorithm",
            "signature_algorithm",
            "signed_assertion",
            "signed_response",
            "verification_kp",
            "signing_kp",
            "encryption_kp",
            "verification_kp_ring",
            "signing_kp_ring",
            "encryption_kp_ring",
            "verification_kp_override",
            "signing_kp_override",
            "encryption_kp_override",
            "freeze_verification_kp",
            "freeze_signing_kp",
            "freeze_encryption_kp",
            "local_override_set",
            "metadata_snapshot",
            "metadata_last_import",
            "metadata_hash",
            "created",
            "last_updated",
        ]
        read_only_fields = [
            "pk",
            "uuid",
            "metadata_snapshot",
            "metadata_last_import",
            "metadata_hash",
            "created",
            "last_updated",
        ]


class SAMLIDPDTOSerializer(PassiveSerializer):
    """Serializer for IdP DTO payloads used by preview/apply."""

    entity_id = CharField(required=True, allow_blank=False)
    display_name = CharField(required=False, allow_blank=True, allow_null=True)
    sso_binding = ChoiceField(
        choices=[SAMLBindings.POST, SAMLBindings.REDIRECT],
        required=True,
    )
    sso_location = CharField(required=True, allow_blank=False)
    want_authn_requests_signed = BooleanField(required=False, default=False)
    name_id_policy = ChoiceField(
        choices=[choice for choice, _ in SAMLNameIDPolicy.choices],
        required=False,
        default=SAMLNameIDPolicy.UNSPECIFIED,
    )
    signing_cert_pems = ListField(child=CharField(), required=False, allow_empty=True)
    encryption_cert_pems = ListField(child=CharField(), required=False, allow_empty=True)
    slo_binding = ChoiceField(
        choices=[SAMLBindings.POST, SAMLBindings.REDIRECT],
        required=False,
        allow_null=True,
    )
    slo_location = CharField(required=False, allow_blank=True, allow_null=True)


class SAMLIDPPreviewSerializer(PassiveSerializer):
    """Preview request for source identity-providers."""

    input_mode = ChoiceField(choices=["file", "entities"], required=False, default="file")
    file_ref = CharField(required=False, allow_blank=False)
    signing_certificate = PrimaryKeyRelatedField(
        queryset=CertificateKeyPair.objects.all(),
        required=False,
        allow_null=True,
    )
    entity_ids = ListField(child=CharField(), required=False, allow_empty=False)
    entities = SAMLIDPDTOSerializer(many=True, required=False)

    def validate(self, attrs: dict):
        mode = attrs.get("input_mode", "file")
        if mode == "file" and not attrs.get("file_ref"):
            raise ValidationError({"file_ref": "This field is required when input_mode='file'."})
        if mode == "entities" and not attrs.get("entities"):
            raise ValidationError(
                {"entities": "This field is required when input_mode='entities'."}
            )
        return attrs


class SAMLIDPApplySerializer(SAMLIDPPreviewSerializer):
    """Apply request for source identity-providers."""

    apply_policy = ChoiceField(
        choices=[APPLY_POLICY_FORCE, APPLY_POLICY_IF_NOT_DEVIATED],
        required=False,
        default=APPLY_POLICY_IF_NOT_DEVIATED,
    )
    create_missing_rings = BooleanField(required=False, default=True)


class SAMLIDPCompareSerializer(PassiveSerializer):
    """Compare result for one IdP entity."""

    entity_id = CharField(required=True, allow_blank=False)
    exists = BooleanField(required=True)
    runtime_changed = BooleanField(required=True)
    cert_changed = BooleanField(required=True)
    runtime_deviated = BooleanField(required=True)
    cert_deviated = BooleanField(required=True)
    runtime_diff_fields = ListField(child=CharField(), required=False, allow_empty=True)
    cert_diff_fields = ListField(child=CharField(), required=False, allow_empty=True)
    runtime_locked = BooleanField(required=True)
    cert_locked = BooleanField(required=True)
    target_pk = IntegerField(required=False, allow_null=True)


class SAMLIDPPreviewItemSerializer(PassiveSerializer):
    """Preview payload item for one IdP entity."""

    metadata = SAMLIDPDTOSerializer(required=True)
    compare = SAMLIDPCompareSerializer(required=True)


class SAMLIDPPreviewResponseSerializer(PassiveSerializer):
    """Preview response payload for IdP entities."""

    count = IntegerField(required=True)
    results = SAMLIDPPreviewItemSerializer(many=True, required=True)


class SAMLIDPApplyResultSerializer(PassiveSerializer):
    """Apply result payload for one IdP entity."""

    entity_id = CharField(required=True, allow_blank=False)
    status = CharField(required=True, allow_blank=False)
    reason = CharField(required=False, allow_blank=True, allow_null=True)
    object_pk = IntegerField(required=False, allow_null=True)
    compare = SAMLIDPCompareSerializer(required=False, allow_null=True)


class SAMLIDPApplySummarySerializer(PassiveSerializer):
    """Apply summary payload for IdP entities."""

    created = IntegerField(required=True)
    updated = IntegerField(required=True)
    skipped = IntegerField(required=True)


class SAMLIDPApplyResponseSerializer(PassiveSerializer):
    """Apply response payload for IdP entities."""

    count = IntegerField(required=True)
    summary = SAMLIDPApplySummarySerializer(required=True)
    results = SAMLIDPApplyResultSerializer(many=True, required=True)


class SAMLSourceViewSet(UsedByMixin, ModelViewSet):
    """SAMLSource Viewset"""

    queryset = SAMLSource.objects.all()
    serializer_class = SAMLSourceSerializer
    lookup_field = "slug"
    filterset_fields = [
        "pbm_uuid",
        "name",
        "slug",
        "enabled",
        "authentication_flow",
        "enrollment_flow",
        "managed",
        "policy_engine_mode",
        "user_matching_mode",
        "pre_authentication_flow",
        "issuer_override",
        "sso_url",
        "slo_url",
        "allow_idp_initiated",
        "force_authn",
        "name_id_policy",
        "binding_type",
        "verification_kp",
        "verification_kp_ring",
        "signing_kp",
        "signing_kp_ring",
        "encryption_kp",
        "encryption_kp_ring",
        "digest_algorithm",
        "signature_algorithm",
        "temporary_user_delete_after",
        "signed_assertion",
        "signed_response",
    ]
    search_fields = ["name", "slug"]
    ordering = ["name"]

    @extend_schema(responses={200: SAMLMetadataSerializer(many=False)})
    @action(methods=["GET"], detail=True)
    def metadata(self, request: Request, slug: str) -> Response:
        """Return metadata as XML string"""
        source = self.get_object()
        metadata = MetadataProcessor(source, request).build_entity_descriptor()
        return Response(
            {
                "metadata": metadata,
                "download_url": reverse(
                    "authentik_sources_saml:metadata",
                    kwargs={
                        "source_slug": source.slug,
                    },
                ),
            }
        )

    @permission_required(
        None,
        [
            "authentik_sources_saml.add_samlsource",
            "authentik_crypto.add_certificatekeypair",
        ],
    )
    @extend_schema(
        request={
            "multipart/form-data": SAMLSourceImportSerializer,
        },
        responses={
            201: SAMLSourceSerializer,
            400: None,
        },
    )
    @action(detail=False, methods=["POST"], parser_classes=(MultiPartParser,))
    @validate(SAMLSourceImportSerializer)
    def import_metadata(self, request: Request, body: SAMLSourceImportSerializer) -> Response:
        """Create source from IdP SAML metadata, or apply to an existing source."""
        file = body.validated_data["file"]

        try:
            fromstring(file.read())
        except ParseError:
            raise ValidationError(_("Invalid XML Syntax")) from None
        file.seek(0)

        try:
            sig_cert = body.validated_data.get("signing_certificate")
            metadata = IdentityProviderMetadataParser(signing_certificate=sig_cert).parse(
                file.read().decode()
            )

            target: SAMLSource | None = body.validated_data.get("source")
            name: str = body.validated_data["name"]
            create_missing_rings: bool = body.validated_data.get("create_missing_rings", True)

            if target is not None:
                if not (
                    request.user.has_perm("authentik_sources_saml.change_samlsource")
                    or request.user.has_perm("authentik_sources_saml.change_samlsource", target)
                ):
                    raise PermissionDenied()
                if target.name != name:
                    target.name = name
                    target.save(update_fields=["name"])

                metadata.apply_to_source(
                    target,
                    create_missing_rings=create_missing_rings,
                )
                return Response(
                    SAMLSourceSerializer(target, context={"request": request}).data,
                    status=200,
                )
            source = metadata.to_source(
                name=name,
                pre_authentication_flow=body.validated_data["pre_authentication_flow"],
            )
            return Response(
                SAMLSourceSerializer(source, context={"request": request}).data,
                status=201,
            )
        except ValueError as exc:
            raise ValidationError(
                _("Failed to import Metadata: {messages}".format_map({"messages": str(exc)}))
            ) from None

    def _read_file_ref(self, file_ref: str) -> str:
        """Read XML text from admin/files, transparently handling gzip."""
        manager = get_file_manager(FileApiUsage.SAML_METADATA)
        try:
            with manager.open_file_stream(file_ref, "rb") as stream:
                raw = stream.read()
        except FileNotFoundError:
            raise ValidationError({"file_ref": "File not found."}) from None

        if raw.startswith(b"\x1f\x8b") or file_ref.endswith(".gz"):
            try:
                raw = gzip.decompress(raw)
            except OSError:
                raise ValidationError({"file_ref": "Invalid gzip payload."}) from None

        for encoding in ("utf-8", "utf-8-sig"):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError:
                continue
        raise ValidationError({"file_ref": "Metadata file is not valid UTF-8 XML text."})

    def _dto_to_metadata(self, dto: dict) -> IdentityProviderMetadata:
        """Convert validated DTO dictionary to IdentityProviderMetadata."""
        return IdentityProviderMetadata(
            entity_id=dto["entity_id"],
            display_name=dto.get("display_name"),
            sso_binding=dto["sso_binding"],
            sso_location=dto["sso_location"],
            want_authn_requests_signed=bool(dto.get("want_authn_requests_signed", False)),
            name_id_policy=dto.get("name_id_policy", SAMLNameIDPolicy.UNSPECIFIED),
            signing_cert_pems=dto.get("signing_cert_pems") or [],
            encryption_cert_pems=dto.get("encryption_cert_pems") or [],
            slo_binding=dto.get("slo_binding"),
            slo_location=dto.get("slo_location"),
        )

    def _metadata_to_dict(self, metadata: IdentityProviderMetadata) -> dict:
        """Serialize metadata DTO for preview responses."""
        return {
            "entity_id": metadata.entity_id,
            "display_name": metadata.display_name,
            "sso_binding": metadata.sso_binding,
            "sso_location": metadata.sso_location,
            "want_authn_requests_signed": metadata.want_authn_requests_signed,
            "name_id_policy": metadata.name_id_policy,
            "slo_binding": metadata.slo_binding,
            "slo_location": metadata.slo_location,
            "signing_cert_pems": metadata.signing_cert_pems or [],
            "encryption_cert_pems": metadata.encryption_cert_pems or [],
        }

    def _compare_to_dict(self, compare) -> dict:
        """Serialize compare result for API responses."""
        return {
            "entity_id": compare.entity_id,
            "exists": compare.exists,
            "runtime_changed": compare.runtime_changed,
            "cert_changed": compare.cert_changed,
            "runtime_deviated": compare.runtime_deviated,
            "cert_deviated": compare.cert_deviated,
            "runtime_diff_fields": compare.runtime_diff_fields,
            "cert_diff_fields": compare.cert_diff_fields,
            "runtime_locked": compare.runtime_locked,
            "cert_locked": compare.cert_locked,
            "target_pk": compare.target_pk,
        }

    def _apply_to_dict(self, result) -> dict:
        """Serialize apply result for API responses."""
        return {
            "entity_id": result.entity_id,
            "status": result.status,
            "reason": result.reason,
            "object_pk": result.object_pk,
            "compare": (
                self._compare_to_dict(result.compare) if result.compare is not None else None
            ),
        }

    def _iter_idp_metadata(self, body: dict) -> list[IdentityProviderMetadata]:
        """Resolve IdP metadata DTOs from request body."""
        mode = body.get("input_mode", "file")
        if mode == "entities":
            return [self._dto_to_metadata(entry) for entry in body.get("entities", [])]

        parser = IdentityProviderMetadataParser(signing_certificate=body.get("signing_certificate"))
        xml = self._read_file_ref(body["file_ref"])
        return list(parser.iter_entities(xml))

    def _get_idp(self, source: SAMLSource, idp_id: str) -> SAMLIDP:
        """Resolve nested SAMLIDP by pk or uuid."""
        qs = source.identity_providers.all()
        if idp_id.isdigit():
            return get_object_or_404(qs, pk=int(idp_id))
        try:
            return get_object_or_404(qs, uuid=UUID(idp_id))
        except ValueError:
            raise Http404 from None

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="entity_id",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.STR,
                required=False,
            )
        ],
        responses={200: SAMLIDPSerializer(many=True)},
    )
    @action(detail=True, methods=["GET"], url_path="identity-providers")
    def identity_providers(self, request: Request, slug: str) -> Response:
        """List nested identity providers for this SAML source."""
        source = self.get_object()
        qs = source.identity_providers.all().order_by("entity_id")
        entity_id = request.query_params.get("entity_id")
        if entity_id:
            qs = qs.filter(entity_id=entity_id)
        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = SAMLIDPSerializer(page, many=True, context={"request": request})
            return self.get_paginated_response(serializer.data)
        serializer = SAMLIDPSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    @extend_schema(
        methods=["GET"],
        responses={200: SAMLIDPSerializer(many=False)},
    )
    @extend_schema(
        methods=["PATCH"],
        request=SAMLIDPSerializer(partial=True),
        responses={200: SAMLIDPSerializer(many=False)},
    )
    @extend_schema(
        methods=["DELETE"],
        responses={204: OpenApiResponse(description="No response body")},
    )
    @action(
        detail=True,
        methods=["GET", "PATCH", "DELETE"],
        url_path=r"identity-providers/(?P<idp_id>\d+|[0-9a-fA-F-]{36})",
    )
    def identity_provider(self, request: Request, slug: str, idp_id: str) -> Response:
        """Retrieve, update, or delete one nested identity provider."""
        source = self.get_object()
        idp = self._get_idp(source, idp_id)
        if request.method == "GET":
            return Response(SAMLIDPSerializer(idp, context={"request": request}).data)
        if request.method == "PATCH":
            serializer = SAMLIDPSerializer(
                idp,
                data=request.data,
                partial=True,
                context={"request": request},
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

        idp.delete()
        return Response(status=204)

    @extend_schema(
        request=SAMLIDPPreviewSerializer,
        responses={200: SAMLIDPPreviewResponseSerializer},
    )
    @action(detail=True, methods=["POST"], url_path="identity-providers/preview")
    @validate(SAMLIDPPreviewSerializer)
    def identity_providers_preview(
        self,
        request: Request,
        slug: str,
        body: SAMLIDPPreviewSerializer,
    ) -> Response:
        """Preview IdP metadata reconciliation results."""
        source = self.get_object()
        entities = self._iter_idp_metadata(body.validated_data)
        entity_ids = set(body.validated_data.get("entity_ids") or [])
        if entity_ids:
            entities = [entry for entry in entities if entry.entity_id in entity_ids]

        results = []
        for metadata in entities:
            compare = metadata.compare_idp(source)
            results.append(
                {
                    "metadata": self._metadata_to_dict(metadata),
                    "compare": self._compare_to_dict(compare),
                }
            )
        return Response({"count": len(results), "results": results})

    @extend_schema(
        request=SAMLIDPApplySerializer,
        responses={200: SAMLIDPApplyResponseSerializer},
    )
    @action(detail=True, methods=["POST"], url_path="identity-providers/apply")
    @validate(SAMLIDPApplySerializer)
    def identity_providers_apply(
        self,
        request: Request,
        slug: str,
        body: SAMLIDPApplySerializer,
    ) -> Response:
        """Apply IdP metadata reconciliation results."""
        source = self.get_object()
        entities = self._iter_idp_metadata(body.validated_data)
        entity_ids = set(body.validated_data.get("entity_ids") or [])
        if entity_ids:
            entities = [entry for entry in entities if entry.entity_id in entity_ids]

        policy = body.validated_data.get("apply_policy", APPLY_POLICY_IF_NOT_DEVIATED)
        create_missing_rings = body.validated_data.get("create_missing_rings", True)
        results = []
        summary = {"created": 0, "updated": 0, "skipped": 0}
        for metadata in entities:
            applied = metadata.to_idp(
                source,
                policy=policy,
                create_missing_rings=create_missing_rings,
            )
            if applied.status in summary:
                summary[applied.status] += 1
            results.append(self._apply_to_dict(applied))
        return Response({"count": len(results), "summary": summary, "results": results})
