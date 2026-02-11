"""LogoutRequest parser"""

from base64 import b64decode
from dataclasses import dataclass

from defusedxml import ElementTree

from authentik.providers.saml.exceptions import CannotHandleAssertion
from authentik.providers.saml.models import SAMLProvider
from authentik.providers.saml.processors.authn_request_parser import ERROR_CANNOT_DECODE_REQUEST
from authentik.providers.saml.resolve import (
    find_first_element,
    find_first_text,
    peek_issuer,
)
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


class LogoutRequestParser:
    """LogoutRequest Parser"""

    provider: SAMLProvider

    def __init__(self, provider: SAMLProvider):
        self.provider = provider

    def _parse_xml(self, decoded_xml: str | bytes, relay_state: str | None = None) -> LogoutRequest:
        root = ElementTree.fromstring(decoded_xml)

        request = LogoutRequest(
            id=root.attrib.get("ID"),
            relay_state=relay_state,
        )

        request.issuer = peek_issuer(root)

        name_id_el = find_first_element(
            root,
            [
                f"{{{NS_SAML_ASSERTION}}}NameID",
                f"{{{NS_SAML_PROTOCOL}}}NameID",
            ],
        )
        if name_id_el is not None:
            request.name_id = name_id_el.text
            request.name_id_format = name_id_el.attrib.get("Format")

        # SessionIndex も両 namespace を許容
        request.session_index = find_first_text(
            root,
            [
                f"{{{NS_SAML_PROTOCOL}}}SessionIndex",
                f"{{{NS_SAML_ASSERTION}}}SessionIndex",
            ],
        )

        return request

    def parse(self, saml_request: str, relay_state: str | None = None) -> LogoutRequest:
        """Validate and parse raw request with enveloped signature."""
        try:
            decoded_xml = b64decode(saml_request.encode())
        except (UnicodeDecodeError, ValueError):
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None
        return self._parse_xml(decoded_xml, relay_state)

    def parse_detached(
        self,
        saml_request: str,
        relay_state: str | None = None,
    ) -> LogoutRequest:
        """Validate and parse raw request with detached signature."""
        try:
            decoded_xml = decode_base64_and_inflate(saml_request)
        except (UnicodeDecodeError, ValueError):
            raise CannotHandleAssertion(ERROR_CANNOT_DECODE_REQUEST) from None

        return self._parse_xml(decoded_xml, relay_state)
