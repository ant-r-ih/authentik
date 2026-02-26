# authentik/saml/constants.py

from django.db import models
from django.utils.translation import gettext_lazy as _

from authentik.sources.saml.processors.constants import (
    SAML_BINDING_POST,
    SAML_BINDING_REDIRECT,
    SAML_NAME_ID_FORMAT_EMAIL,
    SAML_NAME_ID_FORMAT_PERSISTENT,
    SAML_NAME_ID_FORMAT_TRANSIENT,
    SAML_NAME_ID_FORMAT_UNSPECIFIED,
    SAML_NAME_ID_FORMAT_WINDOWS,
    SAML_NAME_ID_FORMAT_X509,
)


class SAMLBindings(models.TextChoices):
    """SAML Bindings supported by authentik"""

    REDIRECT = "redirect"
    POST = "post"

class SAMLBindingTypes(models.TextChoices):
    POST = "post", "POST"
    REDIRECT = "redirect", "Redirect"

class SAMLNameIDPolicy(models.TextChoices):
    UNSPECIFIED = "unspecified", "Unspecified"
    PERSISTENT = "persistent", "Persistent"
    TRANSIENT = "transient", "Transient"
    EMAIL = "email", "Email"

class SAMLBindingTypes(models.TextChoices):
    """SAML Binding types"""

    REDIRECT = "REDIRECT", _("Redirect Binding")
    POST = "POST", _("POST Binding")
    POST_AUTO = "POST_AUTO", _("POST Binding with auto-confirmation")

    @property
    def uri(self) -> str:
        """Convert database field to URI"""
        return {
            SAMLBindingTypes.POST: SAML_BINDING_POST,
            SAMLBindingTypes.POST_AUTO: SAML_BINDING_POST,
            SAMLBindingTypes.REDIRECT: SAML_BINDING_REDIRECT,
        }[self]

class SAMLNameIDPolicy(models.TextChoices):
    """SAML NameID Policies"""

    EMAIL = SAML_NAME_ID_FORMAT_EMAIL
    PERSISTENT = SAML_NAME_ID_FORMAT_PERSISTENT
    X509 = SAML_NAME_ID_FORMAT_X509
    WINDOWS = SAML_NAME_ID_FORMAT_WINDOWS
    TRANSIENT = SAML_NAME_ID_FORMAT_TRANSIENT
    UNSPECIFIED = SAML_NAME_ID_FORMAT_UNSPECIFIED
