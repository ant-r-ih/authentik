"""SAMLProvider API Views"""

import gzip
from copy import copy  # noqa: I001
from uuid import UUID
from xml.etree.ElementTree import ParseError  # nosec

from defusedxml.ElementTree import fromstring
from django.http import HttpRequest
from django.http.response import Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from guardian.shortcuts import get_objects_for_user
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.fields import (
    BooleanField,
    CharField,
    ChoiceField,
    FileField,
    IntegerField,
    ListField,
    SerializerMethodField,
)
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import PrimaryKeyRelatedField, ValidationError
from rest_framework.viewsets import ModelViewSet
from structlog.stdlib import get_logger

from authentik.admin.files.manager import get_file_manager
from authentik.admin.files.usage import FileApiUsage
from authentik.api.validation import validate
from authentik.common.saml.constants import (
    DEFAULT_ISSUER,
    SAML_BINDING_POST,
    SAML_BINDING_REDIRECT,
)
from authentik.core.api.providers import ProviderSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import (
    ModelSerializer,
    PassiveSerializer,
    PropertyMappingPreviewSerializer,
)
from authentik.core.models import Provider
from authentik.crypto.models import CertificateKeyPair, KeyType
from authentik.flows.models import Flow, FlowDesignation
from authentik.providers.saml.models import SAMLSP, SAMLBindings, SAMLLogoutMethods, SAMLProvider
from authentik.providers.saml.processors.assertion import AssertionProcessor
from authentik.providers.saml.processors.authn_request_parser import AuthNRequest
from authentik.providers.saml.processors.metadata import MetadataProcessor
from authentik.providers.saml.processors.metadata_parser import (
    APPLY_POLICY_FORCE,
    APPLY_POLICY_IF_NOT_DEVIATED,
    ServiceProviderMetadata,
    ServiceProviderMetadataParser,
)
from authentik.rbac.decorators import permission_required
from authentik.sources.saml.models import SAMLNameIDPolicy

LOGGER = get_logger()


class RawXMLDataRenderer(BaseRenderer):
    """Renderer to allow application/xml as value for 'Accept' in the metadata endpoint."""

    media_type = "application/xml"
    format = "xml"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data


class SAMLProviderSerializer(ProviderSerializer):
    """SAMLProvider Serializer"""

    url_download_metadata = SerializerMethodField()
    url_issuer = SerializerMethodField()

    # Unified SAML endpoint (primary)
    url_unified = SerializerMethodField()
    url_unified_init = SerializerMethodField()

    # Legacy endpoints (for backward compatibility)
    url_sso_post = SerializerMethodField()
    url_sso_redirect = SerializerMethodField()
    url_sso_init = SerializerMethodField()
    url_slo_post = SerializerMethodField()
    url_slo_redirect = SerializerMethodField()

    def get_url_download_metadata(self, instance: SAMLProvider) -> str:
        """Get metadata download URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:metadata-download",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return request.build_absolute_uri(
                reverse(
                    "authentik_api:samlprovider-metadata",
                    kwargs={
                        "pk": instance.pk,
                    },
                )
                + "?download"
            )

    def get_url_issuer(self, instance: SAMLProvider) -> str:
        """Get Issuer/EntityID URL"""
        if instance.issuer_override:
            return instance.issuer_override
        if "request" not in self._context:
            return DEFAULT_ISSUER
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:metadata-download",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return DEFAULT_ISSUER

    def get_url_unified(self, instance: SAMLProvider) -> str:
        """Get unified SAML endpoint URL (handles SSO and SLO)"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:base",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_unified_init(self, instance: SAMLProvider) -> str:
        """Get IdP-initiated SAML URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:init",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_sso_post(self, instance: SAMLProvider) -> str:
        """Get SSO Post URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:sso-post",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_sso_redirect(self, instance: SAMLProvider) -> str:
        """Get SSO Redirect URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:sso-redirect",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_sso_init(self, instance: SAMLProvider) -> str:
        """Get SSO IDP-Initiated URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:sso-init",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_slo_post(self, instance: SAMLProvider) -> str:
        """Get SLO POST URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:slo-post",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def get_url_slo_redirect(self, instance: SAMLProvider) -> str:
        """Get SLO redirect URL"""
        if "request" not in self._context:
            return ""
        request: HttpRequest = self._context["request"]._request
        try:
            return request.build_absolute_uri(
                reverse(
                    "authentik_providers_saml:slo-redirect",
                    kwargs={"application_slug": instance.application.slug},
                )
            )
        except Provider.application.RelatedObjectDoesNotExist:
            return "-"

    def validate(self, attrs: dict):
        signing_kp = attrs.get("signing_kp")
        if signing_kp:
            if not attrs.get("sign_assertion") and not attrs.get("sign_response"):
                raise ValidationError(
                    _(
                        "With a signing keypair selected, at least one of 'Sign assertion' "
                        "and 'Sign Response' must be selected."
                    )
                )

            key_type = signing_kp.key_type

            if key_type and key_type not in [KeyType.RSA, KeyType.EC, KeyType.DSA]:
                raise ValidationError(
                    {
                        "signing_kp": _(
                            "Only RSA, EC, and DSA key types are supported for SAML signing."
                        )
                    }
                )

        # Validate logout_method - backchannel is only available with POST SLS binding
        if (
            attrs.get("logout_method") == SAMLLogoutMethods.BACKCHANNEL
            and attrs.get("sls_binding") == SAML_BINDING_REDIRECT
        ):
            # Auto-correct to frontchannel_iframe
            attrs["logout_method"] = SAMLLogoutMethods.FRONTCHANNEL_IFRAME

        return super().validate(attrs)

    class Meta:
        model = SAMLProvider
        fields = ProviderSerializer.Meta.fields + [
            "acs_url",
            "sls_url",
            "audience",
            "issuer_override",
            "assertion_valid_not_before",
            "assertion_valid_not_on_or_after",
            "session_valid_not_on_or_after",
            "property_mappings",
            "name_id_mapping",
            "authn_context_class_ref_mapping",
            "digest_algorithm",
            "signature_algorithm",
            "signing_kp",
            "verification_kp",
            "encryption_kp",
            "signing_kp_ring",
            "verification_kp_ring",
            "encryption_kp_ring",
            "sign_assertion",
            "sign_response",
            "sign_logout_request",
            "sign_logout_response",
            "sp_binding",
            "sls_binding",
            "logout_method",
            "default_relay_state",
            "default_name_id_policy",
            "url_download_metadata",
            "url_issuer",
            "url_unified",
            "url_unified_init",
            "url_sso_post",
            "url_sso_redirect",
            "url_sso_init",
            "url_slo_post",
            "url_slo_redirect",
        ]
        extra_kwargs = ProviderSerializer.Meta.extra_kwargs


class SAMLMetadataSerializer(PassiveSerializer):
    """SAML Provider Metadata serializer"""

    metadata = CharField()
    download_url = CharField(required=False, allow_null=True)


class SAMLProviderImportSerializer(PassiveSerializer):
    """Import saml provider from XML Metadata"""

    provider = PrimaryKeyRelatedField(
        queryset=SAMLProvider.objects.all(),
        required=False,
        allow_null=True,
    )
    name = CharField(required=True, allow_blank=False)
    authorization_flow = PrimaryKeyRelatedField(
        queryset=Flow.objects.filter(designation=FlowDesignation.AUTHORIZATION),
        required=False,
        allow_null=True,
    )
    invalidation_flow = PrimaryKeyRelatedField(
        queryset=Flow.objects.filter(designation=FlowDesignation.INVALIDATION),
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
        target = attrs.get("provider")
        # Apply to existing SAMLProvider.
        if target:
            return attrs

        # Create new SAMLProvider.
        missing = {}
        if not attrs.get("name"):
            missing["name"] = "This field is required when provider is not set."
        if not attrs.get("authorization_flow"):
            missing["authorization_flow"] = "This field is required when provider is not set."
        if not attrs.get("invalidation_flow"):
            missing["invalidation_flow"] = "This field is required when provider is not set."
        if missing:
            raise ValidationError(missing)
        return attrs


class SAMLSPSerializer(ModelSerializer):
    """Serializer for nested SAML service provider entities."""

    class Meta:
        model = SAMLSP
        fields = [
            "pk",
            "uuid",
            "name",
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
            "property_mappings_override",
            "property_mappings",
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


class SAMLSPDTOSerializer(PassiveSerializer):
    """Serializer for SP DTO payloads used by preview/apply."""

    entity_id = CharField(required=True, allow_blank=False)
    display_name = CharField(required=False, allow_blank=True, allow_null=True)
    acs_binding = ChoiceField(choices=[SAMLBindings.POST, SAMLBindings.REDIRECT], required=True)
    acs_location = CharField(required=True, allow_blank=False)
    auth_n_request_signed = BooleanField(required=False, default=False)
    assertion_signed = BooleanField(required=False, default=False)
    name_id_policy = ChoiceField(
        choices=[choice for choice, _ in SAMLNameIDPolicy.choices],
        required=False,
        default=SAMLNameIDPolicy.UNSPECIFIED,
    )
    sls_binding = ChoiceField(
        choices=[SAMLBindings.POST, SAMLBindings.REDIRECT],
        required=False,
        allow_null=True,
    )
    sls_location = CharField(required=False, allow_blank=True, allow_null=True)
    signing_cert_pems = ListField(child=CharField(), required=False, allow_empty=True)
    encryption_cert_pems = ListField(child=CharField(), required=False, allow_empty=True)


class SAMLSPPreviewSerializer(PassiveSerializer):
    """Preview request for provider service-providers."""

    input_mode = ChoiceField(choices=["file", "entities"], required=False, default="file")
    file_ref = CharField(required=False, allow_blank=False)
    signing_certificate = PrimaryKeyRelatedField(
        queryset=CertificateKeyPair.objects.all(),
        required=False,
        allow_null=True,
    )
    entity_ids = ListField(child=CharField(), required=False, allow_empty=False)
    entities = SAMLSPDTOSerializer(many=True, required=False)

    def validate(self, attrs: dict):
        mode = attrs.get("input_mode", "file")
        if mode == "file" and not attrs.get("file_ref"):
            raise ValidationError({"file_ref": "This field is required when input_mode='file'."})
        if mode == "entities" and not attrs.get("entities"):
            raise ValidationError(
                {"entities": "This field is required when input_mode='entities'."}
            )
        return attrs


class SAMLSPApplySerializer(SAMLSPPreviewSerializer):
    """Apply request for provider service-providers."""

    apply_policy = ChoiceField(
        choices=[APPLY_POLICY_FORCE, APPLY_POLICY_IF_NOT_DEVIATED],
        required=False,
        default=APPLY_POLICY_IF_NOT_DEVIATED,
    )
    create_missing_rings = BooleanField(required=False, default=True)


class SAMLSPCompareSerializer(PassiveSerializer):
    """Compare result for one SP entity."""

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


class SAMLSPPreviewItemSerializer(PassiveSerializer):
    """Preview payload item for one SP entity."""

    metadata = SAMLSPDTOSerializer(required=True)
    compare = SAMLSPCompareSerializer(required=True)


class SAMLSPPreviewResponseSerializer(PassiveSerializer):
    """Preview response payload for SP entities."""

    count = IntegerField(required=True)
    results = SAMLSPPreviewItemSerializer(many=True, required=True)


class SAMLSPApplyResultSerializer(PassiveSerializer):
    """Apply result payload for one SP entity."""

    entity_id = CharField(required=True, allow_blank=False)
    status = CharField(required=True, allow_blank=False)
    reason = CharField(required=False, allow_blank=True, allow_null=True)
    object_pk = IntegerField(required=False, allow_null=True)
    compare = SAMLSPCompareSerializer(required=False, allow_null=True)


class SAMLSPApplySummarySerializer(PassiveSerializer):
    """Apply summary payload for SP entities."""

    created = IntegerField(required=True)
    updated = IntegerField(required=True)
    skipped = IntegerField(required=True)


class SAMLSPApplyResponseSerializer(PassiveSerializer):
    """Apply response payload for SP entities."""

    count = IntegerField(required=True)
    summary = SAMLSPApplySummarySerializer(required=True)
    results = SAMLSPApplyResultSerializer(many=True, required=True)


class SAMLProviderViewSet(UsedByMixin, ModelViewSet):
    """SAMLProvider Viewset"""

    queryset = SAMLProvider.objects.all()
    serializer_class = SAMLProviderSerializer
    filterset_fields = "__all__"
    ordering = ["name"]
    search_fields = ["name"]

    metadata_generator_class = MetadataProcessor

    @extend_schema(
        responses={
            200: SAMLMetadataSerializer(many=False),
            404: OpenApiResponse(description="Provider has no application assigned"),
        },
        parameters=[
            OpenApiParameter(
                name="download",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                name="force_binding",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.STR,
                enum=[
                    SAML_BINDING_REDIRECT,
                    SAML_BINDING_POST,
                ],
                description="Optionally force the metadata to only include one binding.",
            ),
            # Explicitly excluded, because otherwise spectacular automatically
            # add it when using multiple renderer_classes
            OpenApiParameter(
                name="format",
                exclude=True,
                required=False,
            ),
        ],
    )
    @action(
        methods=["GET"],
        detail=True,
        permission_classes=[AllowAny],
        renderer_classes=[JSONRenderer, RawXMLDataRenderer],
    )
    def metadata(self, request: Request, pk: int) -> Response:
        """Return metadata as XML string"""
        # We don't use self.get_object() on purpose as this view is un-authenticated
        try:
            provider = get_object_or_404(SAMLProvider, pk=pk)
        except ValueError:
            raise Http404 from None
        try:
            proc = self.metadata_generator_class(provider, request)
            proc.force_binding = request.query_params.get("force_binding", None)
            metadata = proc.build_entity_descriptor()
            if "download" in request.query_params:
                response = HttpResponse(metadata, content_type="application/xml")
                response["Content-Disposition"] = (
                    f'attachment; filename="{provider.name}_authentik_meta.xml"'
                )
                return response
            return Response({"metadata": metadata}, content_type="application/json")
        except Provider.application.RelatedObjectDoesNotExist:
            raise Http404 from None

    @permission_required(
        None,
        [
            "authentik_providers_saml.add_samlprovider",
            "authentik_crypto.add_certificatekeypair",
        ],
    )
    @extend_schema(
        request={
            "multipart/form-data": SAMLProviderImportSerializer,
        },
        responses={
            201: SAMLProviderSerializer,
            400: OpenApiResponse(description="Bad request"),
        },
    )
    @action(detail=False, methods=["POST"], parser_classes=(MultiPartParser,))
    @validate(SAMLProviderImportSerializer)
    def import_metadata(self, request: Request, body: SAMLProviderImportSerializer) -> Response:
        """Create provider from SAML Metadata, or apply to an existing provider."""
        file = body.validated_data["file"]
        # Validate syntax first
        try:
            fromstring(file.read())
        except ParseError:
            raise ValidationError(_("Invalid XML Syntax")) from None
        file.seek(0)
        try:
            sig_cert = body.validated_data.get("signing_certificate")
            metadata = ServiceProviderMetadataParser(signing_certificate=sig_cert).parse(
                file.read().decode()
            )

            target: SAMLProvider | None = body.validated_data.get("provider")
            name: str = body.validated_data["name"]
            create_missing_rings: bool = body.validated_data.get("create_missing_rings", True)

            if target is not None:
                if not (
                    request.user.has_perm("authentik_providers_saml.change_samlprovider")
                    or request.user.has_perm("authentik_providers_saml.change_samlprovider", target)
                ):
                    raise PermissionDenied()
                if target.name != name:
                    target.name = name
                    target.save(update_fields=["name"])

                metadata.apply_to_provider(target, create_missing_rings=create_missing_rings)
                return Response(SAMLProviderSerializer(target).data, status=200)

            provider = metadata.to_provider(
                body.validated_data["name"],
                body.validated_data["authorization_flow"],
                body.validated_data["invalidation_flow"],
            )
            return Response(SAMLProviderSerializer(provider).data, status=201)
        except ValueError as exc:  # pragma: no cover
            LOGGER.warning(str(exc))
            raise ValidationError(
                _("Failed to import Metadata: {messages}".format_map({"messages": str(exc)})),
            ) from None

    @permission_required(
        "authentik_providers_saml.view_samlprovider",
    )
    @extend_schema(
        responses={
            200: PropertyMappingPreviewSerializer(),
            400: OpenApiResponse(description="Bad request"),
        },
        parameters=[
            OpenApiParameter(
                name="for_user",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.INT,
            )
        ],
    )
    @action(detail=True, methods=["GET"])
    def preview_user(self, request: Request, pk: int) -> Response:
        """Preview user data for provider"""
        provider: SAMLProvider = self.get_object()
        for_user = request.user
        if "for_user" in request.query_params:
            try:
                for_user = (
                    get_objects_for_user(request.user, "authentik_core.preview_user")
                    .filter(pk=request.query_params.get("for_user"))
                    .first()
                )
                if not for_user:
                    raise ValidationError({"for_user": "User not found"})
            except ValueError:
                raise ValidationError({"for_user": "input must be numerical"}) from None

        new_request = copy(request._request)
        new_request.user = for_user

        processor = AssertionProcessor(provider, new_request, AuthNRequest())
        attributes = processor.get_attributes()
        name_id = processor.get_name_id()
        data = []
        for attribute in attributes:
            item = {"Value": []}
            item.update(attribute.attrib)
            for value in attribute:
                item["Value"].append(value.text)
            data.append(item)
        serializer = PropertyMappingPreviewSerializer(
            instance={"preview": {"attributes": data, "nameID": name_id.text}}
        )
        return Response(serializer.data)

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

    def _dto_to_metadata(self, dto: dict) -> ServiceProviderMetadata:
        """Convert validated DTO dictionary to ServiceProviderMetadata."""
        return ServiceProviderMetadata(
            entity_id=dto["entity_id"],
            display_name=dto.get("display_name"),
            acs_binding=dto["acs_binding"],
            acs_location=dto["acs_location"],
            auth_n_request_signed=bool(dto.get("auth_n_request_signed", False)),
            assertion_signed=bool(dto.get("assertion_signed", False)),
            name_id_policy=dto.get("name_id_policy", SAMLNameIDPolicy.UNSPECIFIED),
            signing_cert_pems=dto.get("signing_cert_pems") or [],
            encryption_cert_pems=dto.get("encryption_cert_pems") or [],
            sls_binding=dto.get("sls_binding"),
            sls_location=dto.get("sls_location"),
        )

    def _metadata_to_dict(self, metadata: ServiceProviderMetadata) -> dict:
        """Serialize metadata DTO for preview responses."""
        return {
            "entity_id": metadata.entity_id,
            "display_name": metadata.display_name,
            "acs_binding": metadata.acs_binding,
            "acs_location": metadata.acs_location,
            "auth_n_request_signed": metadata.auth_n_request_signed,
            "assertion_signed": metadata.assertion_signed,
            "name_id_policy": metadata.name_id_policy,
            "sls_binding": metadata.sls_binding,
            "sls_location": metadata.sls_location,
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

    def _iter_sp_metadata(self, body: dict) -> list[ServiceProviderMetadata]:
        """Resolve SP metadata DTOs from request body."""
        mode = body.get("input_mode", "file")
        if mode == "entities":
            return [self._dto_to_metadata(entry) for entry in body.get("entities", [])]

        parser = ServiceProviderMetadataParser(signing_certificate=body.get("signing_certificate"))
        xml = self._read_file_ref(body["file_ref"])
        return list(parser.iter_entities(xml))

    def _get_sp(self, provider: SAMLProvider, sp_id: str) -> SAMLSP:
        """Resolve nested SAMLSP by pk or uuid."""
        qs = provider.service_providers.all()
        if sp_id.isdigit():
            return get_object_or_404(qs, pk=int(sp_id))
        try:
            return get_object_or_404(qs, uuid=UUID(sp_id))
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
        responses={200: SAMLSPSerializer(many=True)},
    )
    @action(detail=True, methods=["GET"], url_path="service-providers")
    def service_providers(self, request: Request, pk: int) -> Response:
        """List nested service providers for this SAML provider."""
        provider = self.get_object()
        qs = provider.service_providers.all().order_by("entity_id")
        entity_id = request.query_params.get("entity_id")
        if entity_id:
            qs = qs.filter(entity_id=entity_id)
        page = self.paginate_queryset(qs)
        if page is not None:
            serializer = SAMLSPSerializer(page, many=True, context={"request": request})
            return self.get_paginated_response(serializer.data)
        serializer = SAMLSPSerializer(qs, many=True, context={"request": request})
        return Response(serializer.data)

    @extend_schema(
        methods=["GET"],
        responses={200: SAMLSPSerializer(many=False)},
    )
    @extend_schema(
        methods=["PATCH"],
        request=SAMLSPSerializer(partial=True),
        responses={200: SAMLSPSerializer(many=False)},
    )
    @extend_schema(
        methods=["DELETE"],
        responses={204: OpenApiResponse(description="No response body")},
    )
    @action(
        detail=True,
        methods=["GET", "PATCH", "DELETE"],
        url_path=r"service-providers/(?P<sp_id>\d+|[0-9a-fA-F-]{36})",
    )
    def service_provider(self, request: Request, pk: int, sp_id: str) -> Response:
        """Retrieve, update, or delete one nested service provider."""
        provider = self.get_object()
        sp = self._get_sp(provider, sp_id)
        if request.method == "GET":
            return Response(SAMLSPSerializer(sp, context={"request": request}).data)
        if request.method == "PATCH":
            serializer = SAMLSPSerializer(
                sp,
                data=request.data,
                partial=True,
                context={"request": request},
            )
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)

        sp.delete()
        return Response(status=204)

    @extend_schema(
        request=SAMLSPPreviewSerializer,
        responses={200: SAMLSPPreviewResponseSerializer},
    )
    @action(detail=True, methods=["POST"], url_path="service-providers/preview")
    @validate(SAMLSPPreviewSerializer)
    def service_providers_preview(
        self,
        request: Request,
        pk: int,
        body: SAMLSPPreviewSerializer,
    ) -> Response:
        """Preview SP metadata reconciliation results."""
        provider = self.get_object()
        entities = self._iter_sp_metadata(body.validated_data)
        entity_ids = set(body.validated_data.get("entity_ids") or [])
        if entity_ids:
            entities = [entry for entry in entities if entry.entity_id in entity_ids]

        results = []
        for metadata in entities:
            compare = metadata.compare_sp(provider)
            results.append(
                {
                    "metadata": self._metadata_to_dict(metadata),
                    "compare": self._compare_to_dict(compare),
                }
            )
        return Response({"count": len(results), "results": results})

    @extend_schema(
        request=SAMLSPApplySerializer,
        responses={200: SAMLSPApplyResponseSerializer},
    )
    @action(detail=True, methods=["POST"], url_path="service-providers/apply")
    @validate(SAMLSPApplySerializer)
    def service_providers_apply(
        self,
        request: Request,
        pk: int,
        body: SAMLSPApplySerializer,
    ) -> Response:
        """Apply SP metadata reconciliation results."""
        provider = self.get_object()
        entities = self._iter_sp_metadata(body.validated_data)
        entity_ids = set(body.validated_data.get("entity_ids") or [])
        if entity_ids:
            entities = [entry for entry in entities if entry.entity_id in entity_ids]

        policy = body.validated_data.get("apply_policy", APPLY_POLICY_IF_NOT_DEVIATED)
        create_missing_rings = body.validated_data.get("create_missing_rings", True)
        results = []
        summary = {"created": 0, "updated": 0, "skipped": 0}
        for metadata in entities:
            applied = metadata.to_sp(
                provider,
                policy=policy,
                create_missing_rings=create_missing_rings,
            )
            if applied.status in summary:
                summary[applied.status] += 1
            results.append(self._apply_to_dict(applied))
        return Response({"count": len(results), "summary": summary, "results": results})
