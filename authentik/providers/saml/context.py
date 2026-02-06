# authentik/providers/saml/context.py
from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass

from authentik.providers.saml.models import SAMLProvider


@dataclass(slots=True)
class SAMLContext:
    """Request-scoped SAML context.

    Holds resolved SP (or any other per-request derived info) without mutating Django models.
    """
    provider: SAMLProvider
    sp: object | None = None  # later: "SAMLSP | None"
    issuer: str | None = None

CURRENT_SAML_CTX: ContextVar[SAMLContext | None] = ContextVar("CURRENT_SAML_CTX", default=None)

def set_saml_ctx(ctx: SAMLContext):
    """Set current SAML context. Returns token for reset()."""
    return CURRENT_SAML_CTX.set(ctx)


def reset_saml_ctx(token) -> None:
    """Reset current SAML context to previous value."""
    CURRENT_SAML_CTX.reset(token)


def get_saml_ctx() -> SAMLContext | None:
    return CURRENT_SAML_CTX.get()


def get_current_sp():
    ctx = CURRENT_SAML_CTX.get()
    return ctx.sp if ctx else None
