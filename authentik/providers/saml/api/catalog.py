from __future__ import annotations

import gzip
from io import BytesIO
from typing import Any, Optional

from django.shortcuts import get_object_or_404
from lxml import etree  # nosec
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.request import Request
from rest_framework.response import Response

from authentik.admin.files.manager import FileManager
from authentik.admin.files.usage import FileUsage
from authentik.providers.saml.models import (
    SAMLSP,
    SAMLProvider,
    compute_signature_hash,
    current_runtime_signature,
    expected_runtime_signature_from_snapshot,
    normalize_signature,
)
from authentik.providers.saml.processors.feed import (
    is_idp_entity,
    is_sp_entity,
    iter_entity_descriptors,
)

# Reuse existing extractors (same as import)
from authentik.providers.saml.processors.feed_extract import (
    extract_sp_descriptor,
    extract_x509_b64_list,
)
from authentik.providers.saml.processors.feed_summarize import summarize_entity_descriptor
from authentik.providers.saml.processors.import_sp import extract_all_acs, extract_all_sls

MAX_EXPANDED_BYTES = 200 * 1024 * 1024 # 200MB for eduGAIN metadata feed (expanded)
GZIP_MAGIC = b"\x1f\x8b"

def _read_metadata_bytes_from_request(request) -> bytes:
    upload = request.data.get("file")
    name = (request.data.get("metadata_name") or "").strip()

    if upload and name:
        raise ValidationError({"metadata_name": ["Provide either file or metadata_name, not both."]})
    if not upload and not name:
        raise ValidationError({"metadata_name": ["This field is required if file is not provided."]})

    if upload:
        raw = upload.read()
        up_name = getattr(upload, "name", "") or name
        return _maybe_decompress_metadata(raw, name=up_name)

    manager = FileManager(FileUsage.SAML_METADATA)
    with manager.open_file_stream(name, "rb") as f:
        raw = f.read()
        return _maybe_decompress_metadata(raw, name=name)

def _build_sp_snapshot_for_catalog(entity: etree._Element) -> dict[str, Any]:
    """
    Build a minimal snapshot used ONLY for catalog state comparison.

    NOTE:
      - Keep it consistent with import snapshot keys.
      - Do not embed certificate bodies; only presence booleans.
    """
    sp_desc = extract_sp_descriptor(entity)

    acs_list = extract_all_acs(sp_desc)
    sls_list = extract_all_sls(sp_desc)

    verification_b64 = (
        extract_x509_b64_list(sp_desc, use="signing")
        or extract_x509_b64_list(sp_desc, use=None)
    )
    encryption_b64 = extract_x509_b64_list(sp_desc, use="encryption")

    return {
        "acs": acs_list,
        "sls": sls_list,
        "authn_requests_signed": (sp_desc.attrib.get("AuthnRequestsSigned", "").lower() == "true"),
        "want_assertions_signed": (sp_desc.attrib.get("WantAssertionsSigned", "").lower() == "true"),
        "has_verification_cert": bool(verification_b64),
        "has_encryption_cert": bool(encryption_b64),
    }


def _catalog_metadata_state_for_sp(*, provider_id: str | None, entity_id: str, upload_hash: str) -> str:
    """
    Return catalog-level metadata state.

    - unknown: provider_id is missing
    - new: SAMLSP(provider, entity_id) is missing
    - unchanged: db.metadata_hash == upload_hash
    - updated: otherwise
    """
    if not provider_id:
        return "unknown"

    sp = (
        SAMLSP.objects.filter(provider_id=provider_id, entity_id=entity_id)
        .only("metadata_hash")
        .first()
    )
    if not sp:
        return "new"

    db_hash = (sp.metadata_hash or "").strip()
    if db_hash and db_hash == upload_hash:
        return "unchanged"
    return "updated"

def _maybe_decompress_metadata(raw: bytes, *, name: str = "") -> bytes:
    """If raw looks like gzip (by magic or .gz suffix), decompress with a safety cap."""
    if not raw:
        return raw

    looks_gz = raw.startswith(GZIP_MAGIC) or name.lower().endswith(".gz")
    if not looks_gz:
        return raw

    # Stream decompress with an upper bound (basic zip-bomb mitigation)
    out = bytearray()
    with gzip.GzipFile(fileobj=BytesIO(raw)) as gz:
        while True:
            chunk = gz.read(1024 * 1024)  # 1MB
            if not chunk:
                break
            out.extend(chunk)
            if len(out) > MAX_EXPANDED_BYTES:
                raise ValidationError(
                    {"metadata_name": [f"Decompressed metadata exceeds limit ({MAX_EXPANDED_BYTES} bytes)."]}
                )
    return bytes(out)
class SAMLMetadataCatalogUploadSerializer(serializers.Serializer):
    file = serializers.FileField(required=False)
    metadata_name = serializers.CharField(required=False)

class SAMLMetadataCatalogViewSet(viewsets.ViewSet):
    queryset = SAMLSP.objects.none()
    parser_classes = (MultiPartParser, FormParser, JSONParser)
    serializer_class = SAMLMetadataCatalogUploadSerializer

    def get_serializer_class(self):
        return self.serializer_class

    def get_queryset(self):
        # Permissions framework expects this to exist.
        return SAMLSP.objects.none()

    @action(detail=False, methods=["POST"], url_path="preview")
    def preview(self, request):
        """
        Preview catalog entries from an uploaded metadata XML file.

        Contract:
          - Always returns list
          - Always includes 'states'
          - provider is OPTIONAL; without it -> states.metadata == "unknown" for SP entries
        """
        ser = self.serializer_class(data=request.data)
        ser.is_valid(raise_exception=True)

        try:
            raw = _read_metadata_bytes_from_request(request)
        except FileNotFoundError:
            raise ValidationError({"metadata_name": ["File not found."]})

        try:
            provider = _get_provider_from_request(request, kwargs=getattr(self, "kwargs", None))
        except ValidationError:
            provider = None
        provider_id = str(provider.pk) if provider else None

        kind = (request.query_params.get("kind") or "").lower().strip()  # "", "sp", "idp"

        out: list[dict[str, Any]] = []
        for item in iter_entity_descriptors(raw):
            if kind == "sp" and not is_sp_entity(item.xml):
                continue
            if kind == "idp" and not is_idp_entity(item.xml):
                continue

            summary = summarize_entity_descriptor(item.xml)
            summary["from_aggregate"] = item.from_aggregate
            summary["container_name_chain"] = list(item.container_name_chain)

            states: dict[str, Any] = {}

            if is_sp_entity(item.xml):
                snap = _build_sp_snapshot_for_catalog(item.xml)
                upload_hash = compute_signature_hash(normalize_signature(snap))

                states["metadata"] = _catalog_metadata_state_for_sp(
                    provider_id=provider_id,
                    entity_id=summary["entity_id"],
                    upload_hash=upload_hash,
                )
                states["metadata_hash"] = upload_hash

                if states["metadata"] not in ("new", "unknown"):
                    states["runtime"] = _catalog_runtime_state_for_sp(
                        provider_id=provider_id,
                        entity_id=summary["entity_id"],
                        upload_snapshot=snap,
                    )
                else:
                    states["runtime"] = "unknown"

            # IMPORTANT: always set and always append (so IdP is included)
            summary["states"] = states
            out.append(summary)

        return Response(out, status=status.HTTP_200_OK)

    @action(detail=False, methods=["POST"], url_path="entity")
    def entity(self, request):
        """
        Return raw EntityDescriptor XML for requested entity_id from uploaded metadata.
        """
        entity_id = request.data.get("entity_id")

        # Validate request (file or metadata_name)
        ser = self.serializer_class(data=request.data)
        ser.is_valid(raise_exception=True)
        if not entity_id:
            return Response({"entity_id": ["This field is required."]}, status=status.HTTP_400_BAD_REQUEST)

        try:
            raw = _read_metadata_bytes_from_request(request)
        except FileNotFoundError:
            raise ValidationError({"metadata_name": ["File not found."]})
        for item in iter_entity_descriptors(raw):
            if item.entity_id != entity_id:
                continue

            xml_str = etree.tostring(item.xml, encoding="utf-8", xml_declaration=False).decode("utf-8")
            return Response(
                {
                    "entity_id": entity_id,
                    "xml": xml_str,
                    "container_name_chain": list(item.container_name_chain),
                },
                status=status.HTTP_200_OK,
            )

        return Response(
            {"entity_id": ["Entity not found in uploaded metadata."]},
            status=status.HTTP_400_BAD_REQUEST,
        )

def _get_provider_from_request(request, *, kwargs=None) -> SAMLProvider:
    """
    Resolve provider from request.

    Priority:
      1) path kwargs (future-proof)
      2) query param ?provider=
      3) request.data["provider"] (optional fallback)

    Notes:
      - Do NOT assume UUID. PK may be int or UUID depending on deployment/migrations.
      - Return a SAMLProvider instance or raise ValidationError (400).
    """
    kwargs = kwargs or {}

    provider_pk = (
        kwargs.get("provider_pk")
        or kwargs.get("provider")
        or request.query_params.get("provider")
        or request.data.get("provider")
    )

    if not provider_pk:
        raise ValidationError({"provider": ["This field is required."]})

    # Let Django ORM handle PK type coercion (int/uuid).
    try:
        provider = SAMLProvider.objects.filter(pk=provider_pk).first()
    except Exception:
        # e.g. totally invalid pk format
        raise ValidationError({"provider": ["Invalid provider."]})

    if not provider:
        raise ValidationError({"provider": ["Invalid provider."]})

    return provider

def _catalog_runtime_state_for_sp(
    *,
    provider_id: str | None,
    entity_id: str,
    upload_snapshot: dict[str, Any],
) -> str:
    """
    Return runtime state comparing:
      - current DB runtime config
      - expected runtime derived from *uploaded* snapshot

    Returns:
      - "unknown": provider_id missing OR SP not found
      - "unchanged": runtime matches expected
      - "diverged": runtime differs
    """
    if not provider_id:
        return "unknown"

    sp = (
        SAMLSP.objects.filter(provider_id=provider_id, entity_id=entity_id)
        .select_related("verification_kp", "encryption_kp")
        .first()
    )
    if not sp:
        return "unknown"

    expected = expected_runtime_signature_from_snapshot(upload_snapshot)
    current = current_runtime_signature(sp)

    if normalize_signature(expected) == normalize_signature(current):
        return "unchanged"
    return "diverged"
