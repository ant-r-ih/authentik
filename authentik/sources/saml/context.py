# authentik/sources/saml/context.py
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

from authentik.sources.saml.models import SAMLSource

if TYPE_CHECKING:
    from authentik.sources.saml.models import SAMLIDP


@dataclass(slots=True)
class SAMLSourceContext:
    """Request-scoped SAML Source context.

    Holds resolved IdP (additional SAMLIDP) or None for default (SAMLSource itself).
    """

    source: SAMLSource
    idp: "SAMLIDP | None" = None
    entity_id: str | None = None


CURRENT_SAML_SOURCE_CTX: ContextVar[SAMLSourceContext | None] = ContextVar(
    "CURRENT_SAML_SOURCE_CTX",
    default=None,
)


def set_saml_source_ctx(ctx: SAMLSourceContext):
    """Set current SAML source context. Returns token for reset()."""
    return CURRENT_SAML_SOURCE_CTX.set(ctx)


def reset_saml_source_ctx(token) -> None:
    """Reset current SAML source context to previous value."""
    CURRENT_SAML_SOURCE_CTX.reset(token)


def get_saml_source_ctx() -> SAMLSourceContext | None:
    return CURRENT_SAML_SOURCE_CTX.get()


def get_current_idp() -> "SAMLIDP | None":
    """Return currently-resolved IdP (SAMLIDP) or None (meaning default SAMLSource)."""
    ctx = CURRENT_SAML_SOURCE_CTX.get()
    return ctx.idp if ctx else None


def get_current_entity_id() -> str | None:
    """Return request-scoped entityID (issuer) if present."""
    ctx = CURRENT_SAML_SOURCE_CTX.get()
    return ctx.entity_id if ctx else None
