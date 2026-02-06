"""LogoutRequest parser"""

from base64 import b64decode
from dataclasses import dataclass

from defusedxml import ElementTree

from authentik.providers.saml.context import (
    CURRENT_SAML_CTX,
    SAMLContext,
    reset_saml_ctx,
    set_saml_ctx,
)
from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLProvider, peek_issuer
from authentik.providers.saml.processors.authn_request_parser import ERROR_CANNOT_DECODE_REQUEST
from authentik.providers.saml.utils.encoding import decode_base64_and_inflate
from authentik.sources.saml.processors.constants import NS_SAML_ASSERTION, NS_SAML_PROTOCOL


@dataclass(slots=True)
class LogoutRequest:
    """Logout Request"""

    id: str | None = None

    issuer: str | None = None

    name_id: str | None = None

    name_id_format: str | None = None

    session_index: str | None = None

    relay_state: str | None = None

    samlsp_pk: str | None = None


class LogoutRequestParser:
    """LogoutRequest Parser"""

    provider: SAMLProvider

    def __init__(self, provider: SAMLProvider):
        self.provider = provider

    def _parse_xml(self, decoded_xml: str | bytes, relay_state: str | None = None) -> LogoutRequest:
        root = ElementTree.fromstring(decoded_xml)
        request = LogoutRequest(
            id=root.attrib["ID"],
        )
        ctx = CURRENT_SAML_CTX.get()
        if ctx:
            request.issuer = ctx.issuer
            if ctx.sp:
                request.samlsp_pk = str(ctx.sp.pk)
        else:
            request.issuer = peek_issuer(root)

        # Extract NameID
        name_ids = root.findall(f"{{{NS_SAML_ASSERTION}}}NameID")
        if not name_ids:
            name_ids = root.findall(f"{{{NS_SAML_PROTOCOL}}}NameID")
        if len(name_ids) > 0:
            request.name_id = name_ids[0].text
            # Extract NameID Format if present
            if "Format" in name_ids[0].attrib:
                request.name_id_format = name_ids[0].attrib["Format"]

        # Extract SessionIndex
        session_indexes = root.findall(f"{{{NS_SAML_PROTOCOL}}}SessionIndex")
        if not session_indexes:
            session_indexes = root.findall(f"{{{NS_SAML_ASSERTION}}}SessionIndex")
        if len(session_indexes) > 0:
            request.session_index = session_indexes[0].text

        request.relay_state = relay_state
        return request

    def parse(self, saml_request: str, relay_state: str | None = None) -> LogoutRequest:
        """Validate and parse raw request with enveloped signautre."""
        try:
            decoded_xml = b64decode(saml_request.encode())
        except UnicodeDecodeError:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None

        root = ElementTree.fromstring(decoded_xml)
        issuer = peek_issuer(root)
        sp = self.provider.get_sp(issuer)

        token = set_saml_ctx(SAMLContext(provider=self.provider, sp=sp, issuer=issuer))
        try:
            return self._parse_xml(decoded_xml, relay_state)
        finally:
            reset_saml_ctx(token)

    def parse_detached(
        self,
        saml_request: str,
        relay_state: str | None = None,
    ) -> LogoutRequest:
        """Validate and parse raw request with detached signature"""
        try:
            decoded_xml = decode_base64_and_inflate(saml_request)
        except UnicodeDecodeError:
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None

        root = ElementTree.fromstring(decoded_xml)
        issuer = peek_issuer(root)
        sp = self.provider.get_sp(issuer)

        token = set_saml_ctx(SAMLContext(provider=self.provider, sp=sp, issuer=issuer))
        try:
            return self._parse_xml(decoded_xml, relay_state)
        finally:
            reset_saml_ctx(token)
