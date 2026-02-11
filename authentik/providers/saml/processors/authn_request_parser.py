"""SAML AuthNRequest Parser and dataclass"""

from base64 import b64decode
from dataclasses import dataclass
from urllib.parse import quote_plus
from xml.etree.ElementTree import ParseError  # nosec

import xmlsec
from defusedxml import ElementTree
from structlog.stdlib import get_logger

from authentik.lib.xml import lxml_from_string
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLProvider
from authentik.providers.saml.resolve import (
    build_samlsp_config,
    peek_issuer,
    resolve_request_target,
)
from authentik.providers.saml.utils.encoding import decode_base64_and_inflate
from authentik.sources.saml.models import SAMLNameIDPolicy
from authentik.sources.saml.processors.constants import (
    DSA_SHA1,
    NS_MAP,
    NS_SAML_PROTOCOL,
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
    SAML_NAME_ID_FORMAT_UNSPECIFIED,
)

ERROR_CANNOT_DECODE_REQUEST = "Cannot decode SAML request."
ERROR_SIGNATURE_REQUIRED_BUT_ABSENT = (
    "Verification Certificate configured, but request is not signed."
)
ERROR_FAILED_TO_VERIFY = "Failed to verify signature"


@dataclass(slots=True)
class AuthNRequest:
    """AuthNRequest Dataclass"""

    id: str | None = None
    relay_state: str | None = None
    name_id_policy: str = SAML_NAME_ID_FORMAT_UNSPECIFIED

    # parsed/derived
    issuer: str | None = None
    sp: object | None = None  # later: SAMLSP | None
    acs_url: str | None = None
    sp_binding: str | None = None

    # resolved config (request-scope)
    cfg: object | None = None  # later: SAMLConfig | None

class AuthNRequestParser:
    """AuthNRequest Parser"""

    provider: SAMLProvider

    def __init__(self, provider: SAMLProvider):
        self.provider = provider
        self.logger = get_logger().bind(provider=self.provider)

    def _parse_xml(self, decoded_xml: str | bytes, relay_state: str | None) -> AuthNRequest:
        root = ElementTree.fromstring(decoded_xml)

        issuer = peek_issuer(root)
        sp = self.provider.get_sp(issuer)

        request_acs_url = root.attrib.get("AssertionConsumerServiceURL")
        request_sp_binding = root.attrib.get("ProtocolBinding")

        # Resolve the final target (ACS/binding) from provider+sp defaults and request overrides
        target = resolve_request_target(
            self.provider,
            sp,
            request_acs_url=request_acs_url,
            request_sp_binding=request_sp_binding,
        )

        auth_n_request = AuthNRequest(id=root.attrib.get("ID"), relay_state=relay_state)
        auth_n_request.issuer = issuer
        auth_n_request.sp = sp
        auth_n_request.acs_url = target.acs_url
        auth_n_request.sp_binding = target.sp_binding

        # NameIDPolicy
        name_id_policies = root.findall(f"{{{NS_SAML_PROTOCOL}}}NameIDPolicy")
        if name_id_policies:
            name_id_policy = name_id_policies[0]
            auth_n_request.name_id_policy = name_id_policy.attrib.get(
                "Format", SAML_NAME_ID_FORMAT_UNSPECIFIED
            )

        # Build request-scoped config (includes target)
        auth_n_request.cfg = build_samlsp_config(self.provider, sp, target=target)
        return auth_n_request

    def parse(self, saml_request: str, relay_state: str | None = None) -> AuthNRequest:
        """Validate and parse raw request with enveloped signature."""
        try:
            decoded_xml = b64decode(saml_request.encode())
        except UnicodeDecodeError:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None

        # Determine issuer/sp early for verification policy & key selection
        try:
            et_root = ElementTree.fromstring(decoded_xml)
        except Exception as exc:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from exc

        issuer = peek_issuer(et_root)
        sp = self.provider.get_sp(issuer)

        cfg = build_samlsp_config(
            self.provider,
            sp,
            target=resolve_request_target(
                self.provider,
                sp,
                request_acs_url=et_root.attrib.get("AssertionConsumerServiceURL"),
                request_sp_binding=et_root.attrib.get("ProtocolBinding"),
            ),
        )

        verifier = cfg.verification_kp
        # If no verifier, accept unsigned requests and just parse
        if not verifier:
            return self._parse_xml(decoded_xml, relay_state)

        # Enveloped signature verification
        root = lxml_from_string(decoded_xml)
        xmlsec.tree.add_ids(root, ["ID"])
        signature_nodes = root.xpath("/samlp:AuthnRequest/ds:Signature", namespaces=NS_MAP)
        if len(signature_nodes) < 1:
            raise CannotHandleAssertion(ERROR_SIGNATURE_REQUIRED_BUT_ABSENT)

        signature_node = signature_nodes[0]
        if signature_node is not None:
            try:
                ctx = xmlsec.SignatureContext()
                key = xmlsec.Key.from_memory(
                    verifier.certificate_data,
                    xmlsec.constants.KeyDataFormatCertPem,
                    None,
                )
                ctx.key = key
                ctx.verify(signature_node)
            except xmlsec.Error as exc:
                raise CannotHandleAssertion(ERROR_FAILED_TO_VERIFY) from exc

        # Parse fully (will also attach cfg)
        return self._parse_xml(decoded_xml, relay_state)

    def parse_detached(
        self,
        saml_request: str,
        relay_state: str | None,
        signature: str | None = None,
        sig_alg: str | None = None,
    ) -> AuthNRequest:
        """Validate and parse raw request with detached signature."""
        try:
            decoded_xml = decode_base64_and_inflate(saml_request)
        except UnicodeDecodeError:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None

        # Determine issuer/sp early for verification key selection
        try:
            et_root = ElementTree.fromstring(decoded_xml)
        except Exception as exc:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from exc

        issuer = peek_issuer(et_root)
        sp = self.provider.get_sp(issuer)

        cfg = build_samlsp_config(
            self.provider,
            sp,
            target=resolve_request_target(
                self.provider,
                sp,
                request_acs_url=et_root.attrib.get("AssertionConsumerServiceURL"),
                request_sp_binding=et_root.attrib.get("ProtocolBinding"),
            ),
        )

        verifier = cfg.verification_kp
        if not verifier:
            return self._parse_xml(decoded_xml, relay_state)

        if verifier and not (signature and sig_alg):
            raise CannotHandleAssertion(ERROR_SIGNATURE_REQUIRED_BUT_ABSENT)

        if signature and sig_alg:
            querystring = f"SAMLRequest={quote_plus(saml_request)}&"
            if relay_state is not None:
                querystring += f"RelayState={quote_plus(relay_state)}&"
            querystring += f"SigAlg={quote_plus(sig_alg)}"

            dsig_ctx = xmlsec.SignatureContext()
            key = xmlsec.Key.from_memory(
                verifier.certificate_data, xmlsec.constants.KeyDataFormatCertPem, None
            )
            dsig_ctx.key = key

            sign_algorithm_transform_map = {
                DSA_SHA1: xmlsec.constants.TransformDsaSha1,
                RSA_SHA1: xmlsec.constants.TransformRsaSha1,
                RSA_SHA256: xmlsec.constants.TransformRsaSha256,
                RSA_SHA384: xmlsec.constants.TransformRsaSha384,
                RSA_SHA512: xmlsec.constants.TransformRsaSha512,
            }
            sign_algorithm_transform = sign_algorithm_transform_map.get(
                sig_alg, xmlsec.constants.TransformRsaSha1
            )

            try:
                dsig_ctx.verify_binary(
                    querystring.encode("utf-8"),
                    sign_algorithm_transform,
                    b64decode(signature),
                )
            except xmlsec.Error as exc:
                raise CannotHandleAssertion(ERROR_FAILED_TO_VERIFY) from exc
        try:
            return self._parse_xml(decoded_xml, relay_state)
        except ParseError as exc:
            raise CannotHandleAssertion(ERROR_FAILED_TO_VERIFY) from exc

    def idp_initiated(self) -> AuthNRequest:
        """Create IdP Initiated AuthNRequest."""
        request = AuthNRequest(relay_state=None)
        if self.provider.default_relay_state != "":
            request.relay_state = self.provider.default_relay_state
        if self.provider.default_name_id_policy != SAMLNameIDPolicy.UNSPECIFIED:
            request.name_id_policy = self.provider.default_name_id_policy

        # No issuer/sp in IdP-initiated; still attach cfg for downstream
        target = resolve_request_target(
            self.provider,
            None,
            request_acs_url=None,
            request_sp_binding=None,
        )
        request.cfg = build_samlsp_config(self.provider, None, target=target)
        return request
