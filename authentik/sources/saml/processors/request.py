"""SAML AuthnRequest Processor"""

from base64 import b64encode
from urllib.parse import quote_plus

import xmlsec
from django.http import HttpRequest
from lxml import etree  # nosec
from lxml.etree import Element  # nosec
from structlog.stdlib import get_logger

from authentik.common.saml.constants import (
    DIGEST_ALGORITHM_TRANSLATION_MAP,
    NS_MAP,
    NS_SAML_ASSERTION,
    NS_SAML_PROTOCOL,
    SAML_BINDING_POST,
    SIGN_ALGORITHM_TRANSFORM_MAP,
)
from authentik.lib.xml import remove_xml_newlines
from authentik.providers.saml.resolve import build_idp_config
from authentik.providers.saml.utils import get_random_id
from authentik.providers.saml.utils.encoding import deflate_and_base64_encode
from authentik.providers.saml.utils.keyring import pick_private_key_pem
from authentik.providers.saml.utils.time import get_time_string
from authentik.sources.saml.models import SAMLBindingTypes, SAMLSource

SESSION_KEY_REQUEST_ID = "authentik/sources/saml/request_id"
REQUEST_KEY_ENTITY_ID = "entityID"
LOGGER = get_logger()


class RequestProcessor:
    """SAML AuthnRequest Processor"""

    source: SAMLSource
    http_request: HttpRequest

    relay_state: str

    request_id: str
    issue_instant: str

    def __init__(self, source: SAMLSource, request: HttpRequest, relay_state: str):
        self.source = source
        self.http_request = request
        self.relay_state = relay_state
        self.request_id = get_random_id()
        self.http_request.session[SESSION_KEY_REQUEST_ID] = self.request_id
        self.issue_instant = get_time_string()
        self.entity_id = self.http_request.GET.get(REQUEST_KEY_ENTITY_ID) or None
        self.idp = self.source.get_idp(self.entity_id) if self.entity_id else None
        if self.entity_id and self.idp is None:
            LOGGER.warning(
                "Unknown entityID requested, falling back to source defaults",
                source_slug=self.source.slug,
                entity_id=self.entity_id,
            )
        self.cfg = build_idp_config(self.source, self.idp)

    def get_issuer(self) -> Element:
        """Get Issuer Element"""
        issuer = Element(f"{{{NS_SAML_ASSERTION}}}Issuer")
        issuer.text = self.source.get_issuer(self.http_request)
        return issuer

    def get_name_id_policy(self) -> Element:
        """Get NameID Policy Element"""
        name_id_policy = Element(f"{{{NS_SAML_PROTOCOL}}}NameIDPolicy")
        name_id_policy.attrib["Format"] = self.cfg.name_id_policy
        return name_id_policy

    def get_auth_n(self) -> Element:
        """Get full AuthnRequest"""
        auth_n_request = Element(f"{{{NS_SAML_PROTOCOL}}}AuthnRequest", nsmap=NS_MAP)
        auth_n_request.attrib["AssertionConsumerServiceURL"] = self.source.build_full_url(
            self.http_request
        )
        auth_n_request.attrib["Destination"] = self.cfg.sso_url
        auth_n_request.attrib["ID"] = self.request_id
        auth_n_request.attrib["IssueInstant"] = self.issue_instant
        auth_n_request.attrib["ProtocolBinding"] = SAML_BINDING_POST
        auth_n_request.attrib["Version"] = "2.0"
        if self.source.force_authn:
            auth_n_request.attrib["ForceAuthn"] = "true"
        # Create issuer object
        auth_n_request.append(self.get_issuer())

        key_pem, _ = pick_private_key_pem(
            kp=self.cfg.keys.signing_kp,
            ring=self.cfg.keys.signing_kp_ring,
        )
        if key_pem and self.cfg.binding_type != SAMLBindingTypes.REDIRECT:
            sign_algorithm_transform = SIGN_ALGORITHM_TRANSFORM_MAP.get(
                self.cfg.keys.signature_algorithm,
                xmlsec.constants.TransformRsaSha1,
            )
            signature = xmlsec.template.create(
                auth_n_request,
                xmlsec.constants.TransformExclC14N,
                sign_algorithm_transform,
                ns=xmlsec.constants.DSigNs,
            )
            auth_n_request.append(signature)

        # Create NameID Policy Object
        auth_n_request.append(self.get_name_id_policy())
        return auth_n_request

    def build_auth_n(self) -> str:
        """Get Signed string representation of AuthN Request
        (used for POST Bindings)"""
        auth_n_request = self.get_auth_n()

        key_pem, cert_pem = pick_private_key_pem(
            kp=self.cfg.keys.signing_kp,
            ring=self.cfg.keys.signing_kp_ring,
        )
        if key_pem and self.cfg.binding_type != SAMLBindingTypes.REDIRECT:
            xmlsec.tree.add_ids(auth_n_request, ["ID"])

            ctx = xmlsec.SignatureContext()

            key = xmlsec.Key.from_memory(key_pem, xmlsec.constants.KeyDataFormatPem, None)
            if cert_pem:
                key.load_cert_from_memory(cert_pem, xmlsec.constants.KeyDataFormatCertPem)
            ctx.key = key

            digest_algorithm_transform = DIGEST_ALGORITHM_TRANSLATION_MAP.get(
                self.cfg.keys.digest_algorithm, xmlsec.constants.TransformSha1
            )

            signature_node = xmlsec.tree.find_node(auth_n_request, xmlsec.constants.NodeSignature)

            ref = xmlsec.template.add_reference(
                signature_node,
                digest_algorithm_transform,
                uri="#" + auth_n_request.attrib["ID"],
            )
            xmlsec.template.add_transform(ref, xmlsec.constants.TransformEnveloped)
            xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)
            key_info = xmlsec.template.ensure_key_info(signature_node)
            xmlsec.template.add_x509_data(key_info)

            ctx.sign(remove_xml_newlines(auth_n_request, signature_node))

        return etree.tostring(auth_n_request).decode()

    def build_auth_n_detached(self) -> dict[str, str]:
        """Get Dict AuthN Request for Redirect bindings, with detached
        Signature. See https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf"""
        auth_n_request = self.get_auth_n()

        saml_request = deflate_and_base64_encode(etree.tostring(auth_n_request).decode())

        response_dict = {
            "SAMLRequest": saml_request,
        }

        if self.relay_state != "":
            response_dict["RelayState"] = self.relay_state

        key_pem, cert_pem = pick_private_key_pem(
            kp=self.cfg.keys.signing_kp,
            ring=self.cfg.keys.signing_kp_ring,
        )
        if key_pem:
            sign_algorithm_transform = SIGN_ALGORITHM_TRANSFORM_MAP.get(
                self.cfg.keys.signature_algorithm,
                xmlsec.constants.TransformRsaSha1,
            )

            # Create the full querystring in the correct order to be signed
            querystring = f"SAMLRequest={quote_plus(saml_request)}&"
            if "RelayState" in response_dict:
                querystring += f"RelayState={quote_plus(response_dict['RelayState'])}&"
            querystring += f"SigAlg={quote_plus(self.cfg.keys.signature_algorithm)}"

            ctx = xmlsec.SignatureContext()

            key = xmlsec.Key.from_memory(key_pem, xmlsec.constants.KeyDataFormatPem, None)
            if cert_pem:
                key.load_cert_from_memory(cert_pem, xmlsec.constants.KeyDataFormatCertPem)
            ctx.key = key

            signature = ctx.sign_binary(querystring.encode("utf-8"), sign_algorithm_transform)
            response_dict["Signature"] = b64encode(signature).decode()
            response_dict["SigAlg"] = self.cfg.keys.signature_algorithm

        return response_dict
