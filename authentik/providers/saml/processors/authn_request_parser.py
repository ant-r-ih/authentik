"""SAML AuthNRequest Parser and dataclass"""

from base64 import b64decode
from binascii import Error as BinasciiError
from dataclasses import dataclass
from urllib.parse import quote_plus
from xml.etree.ElementTree import ParseError  # nosec

import xmlsec
from defusedxml import ElementTree
from structlog.stdlib import get_logger

from authentik.common.saml.constants import (
    DSA_SHA1,
    NS_MAP,
    NS_SAML_PROTOCOL,
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,
    SAML_BINDING_POST,
    SAML_BINDING_REDIRECT,
    SAML_NAME_ID_FORMAT_UNSPECIFIED,
)
from authentik.lib.xml import lxml_from_string
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLBindings, SAMLProvider
from authentik.providers.saml.resolve import build_sp_config, peek_issuer, resolve_request_target
from authentik.providers.saml.utils.encoding import decode_base64_and_inflate
from authentik.providers.saml.utils.keyring import candidate_cert_pems
from authentik.sources.saml.models import SAMLNameIDPolicy

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

    force_authn: bool = False
    issuer: str | None = None
    sp: object | None = None
    acs_url: str | None = None
    sp_binding: str | None = None
    cfg: object | None = None


class AuthNRequestParser:
    """AuthNRequest Parser"""

    provider: SAMLProvider

    def __init__(self, provider: SAMLProvider):
        self.provider = provider
        self.logger = get_logger().bind(provider=self.provider)

    def _normalize_binding(self, value: str | None) -> str | None:
        """Normalize a request ProtocolBinding URI into provider binding token."""
        if value == SAML_BINDING_POST:
            return SAMLBindings.POST
        if value == SAML_BINDING_REDIRECT:
            return SAMLBindings.REDIRECT
        if value in (SAMLBindings.POST, SAMLBindings.REDIRECT):
            return value
        return None

    def _resolve_request(self, root) -> tuple[str | None, object | None, object, object]:
        """Resolve issuer, target SP, and effective runtime config for one request."""
        issuer = peek_issuer(root)
        sp = self.provider.get_sp(issuer)
        request_acs_url = root.attrib.get("AssertionConsumerServiceURL")
        request_sp_binding = self._normalize_binding(root.attrib.get("ProtocolBinding"))
        target = resolve_request_target(
            self.provider,
            sp,
            request_acs_url=request_acs_url,
            request_sp_binding=request_sp_binding or SAMLBindings.POST,
        )
        cfg = build_sp_config(self.provider, sp, target=target)
        return issuer, sp, target, cfg

    def _build_request(self, root, relay_state: str | None, *, resolved: tuple) -> AuthNRequest:
        """Build AuthNRequest DTO from parsed XML and pre-resolved runtime config."""
        issuer, sp, target, cfg = resolved
        auth_n_request = AuthNRequest(
            id=root.attrib.get("ID"),
            relay_state=relay_state,
            force_authn=root.attrib.get("ForceAuthn", "false").lower() == "true",
            issuer=issuer,
            sp=sp,
            acs_url=target.acs_url,
            sp_binding=target.sp_binding,
            cfg=cfg,
        )
        name_id_policies = root.findall(f"{{{NS_SAML_PROTOCOL}}}NameIDPolicy")
        if name_id_policies:
            name_id_policy = name_id_policies[0]
            auth_n_request.name_id_policy = name_id_policy.attrib.get(
                "Format", SAML_NAME_ID_FORMAT_UNSPECIFIED
            )
        return auth_n_request

    def parse(self, saml_request: str, relay_state: str | None = None) -> AuthNRequest:
        """Validate and parse raw request with enveloped signautre."""
        try:
            decoded_xml = b64decode(saml_request.encode())
            root = ElementTree.fromstring(decoded_xml)
        except BinasciiError, ParseError, ValueError:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None

        resolved = self._resolve_request(root)
        _issuer, _sp, _target, cfg = resolved
        verifier_pems = candidate_cert_pems(
            kp=cfg.keys.verification_kp,
            ring=cfg.keys.verification_kp_ring,
        )
        if not verifier_pems:
            return self._build_request(root, relay_state, resolved=resolved)

        root_lxml = lxml_from_string(decoded_xml)
        xmlsec.tree.add_ids(root_lxml, ["ID"])
        signature_nodes = root_lxml.xpath("/samlp:AuthnRequest/ds:Signature", namespaces=NS_MAP)
        # No signatures, no verifier configured -> decode xml directly
        if len(signature_nodes) < 1:
            raise CannotHandleAssertion(ERROR_SIGNATURE_REQUIRED_BUT_ABSENT)

        signature_node = signature_nodes[0]
        last_exc: Exception | None = None

        if signature_node is not None:
            for pem in verifier_pems:
                try:
                    ctx = xmlsec.SignatureContext()
                    key = xmlsec.Key.from_memory(
                        pem,
                        xmlsec.constants.KeyDataFormatCertPem,
                        None,
                    )
                    ctx.key = key
                    ctx.verify(signature_node)
                    break
                except xmlsec.Error as exc:
                    last_exc = exc
                    continue
            else:
                self.logger.warning("Failed to verify AuthnRequest signature", exc=last_exc)
                raise CannotHandleAssertion(ERROR_FAILED_TO_VERIFY)
        return self._build_request(root, relay_state, resolved=resolved)

    def parse_detached(
        self,
        saml_request: str,
        relay_state: str | None,
        signature: str | None = None,
        sig_alg: str | None = None,
    ) -> AuthNRequest:
        """Validate and parse raw request with detached signature"""
        try:
            decoded_xml = decode_base64_and_inflate(saml_request)
            root = ElementTree.fromstring(decoded_xml)
        except BinasciiError, ParseError, UnicodeDecodeError, ValueError:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None

        resolved = self._resolve_request(root)
        _issuer, _sp, _target, cfg = resolved
        verifier_pems = candidate_cert_pems(
            kp=cfg.keys.verification_kp,
            ring=cfg.keys.verification_kp_ring,
        )
        if not verifier_pems:
            return self._build_request(root, relay_state, resolved=resolved)

        if verifier_pems and not (signature and sig_alg):
            raise CannotHandleAssertion(ERROR_SIGNATURE_REQUIRED_BUT_ABSENT)

        if signature and sig_alg:
            querystring = f"SAMLRequest={quote_plus(saml_request)}&"
            if relay_state is not None:
                querystring += f"RelayState={quote_plus(relay_state)}&"
            querystring += f"SigAlg={quote_plus(sig_alg)}"

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
            dsig_ctx = xmlsec.SignatureContext()
            last_exc: Exception | None = None
            for pem in verifier_pems:
                key = xmlsec.Key.from_memory(pem, xmlsec.constants.KeyDataFormatCertPem, None)
                dsig_ctx.key = key
                try:
                    dsig_ctx.verify_binary(
                        querystring.encode("utf-8"),
                        sign_algorithm_transform,
                        b64decode(signature),
                    )
                    break
                except xmlsec.Error as exc:
                    last_exc = exc
                    continue
            else:
                self.logger.warning("Failed to verify AuthnRequest signature", exc=last_exc)
                raise CannotHandleAssertion(ERROR_FAILED_TO_VERIFY)
        try:
            return self._build_request(root, relay_state, resolved=resolved)
        except ParseError as exc:
            raise CannotHandleAssertion(ERROR_FAILED_TO_VERIFY) from exc

    def idp_initiated(self) -> AuthNRequest:
        """Create IdP Initiated AuthNRequest"""
        target = resolve_request_target(
            self.provider,
            None,
            request_acs_url=None,
            request_sp_binding=None,
        )
        cfg = build_sp_config(self.provider, None, target=target)
        request = AuthNRequest(
            relay_state=None,
            acs_url=target.acs_url,
            sp_binding=target.sp_binding,
            cfg=cfg,
        )
        if self.provider.default_relay_state != "":
            request.relay_state = self.provider.default_relay_state
        if self.provider.default_name_id_policy != SAMLNameIDPolicy.UNSPECIFIED:
            request.name_id_policy = self.provider.default_name_id_policy
        return request
