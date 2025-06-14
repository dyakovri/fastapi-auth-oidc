from datetime import datetime, timedelta
from typing import Any

import requests

from .settings import OIDC_CONFIGURATION_URI, OIDC_JWKS_URI, OIDC_USERINFO_URI, OIDC_ISSUER
from .provider import OIDCAuthProvider


class OIDCAuthFactory:
    """Creates preconfigured classes for using :class:`fastapi.security.base.SecurityBase`
    as dependencies in FastAPI
    """

    def __init__(
        self,
        configuration_uri: str | None = None,
        jwks_uri: str | None = None,
        userinfo_uri: str | None = None,
        issuer: str | None = None,
        *,
        scheme_name: str = "OIDC token",
    ):
        """Creates a new instance of OIDC auth factory

        :param configuration_uri: OIDC Configuration URI, typically
            `yourdoman.tld/.well-known/openid-configuration`, defaults to `OIDC_CONFIGURATION_URI`
            environment variable
        :type configuration_uri: str | None, optional
        :param jwks_uri: JWKS endpoint wuth public key data of the signing key, defaults
            `OIDC_JWKS_URI` environment variable or `jwks_uri` value from configuration
        :type jwks_uri: str | None, optional
        :param userinfo_uri: _description_, defaults to None
        :type userinfo_uri: str | None, optional
        :param issuer: _description_, defaults to None
        :type issuer: str | None, optional
        :param scheme_name: _description_, defaults to "OIDC token"
        :type scheme_name: str, optional
        """
        self.scheme_name = scheme_name
        self._configuration_uri = configuration_uri
        self._jwks_uri = jwks_uri
        self._userinfo_uri = userinfo_uri
        self._issuer = issuer

    @property
    def configuration_uri(self):
        return self._configuration_uri or OIDC_CONFIGURATION_URI

    @property
    def jwks_uri(self):
        return self._jwks_uri or OIDC_JWKS_URI or self.configuration()["jwks_uri"]

    @property
    def userinfo_url(self):
        return self._jwks_uri or OIDC_USERINFO_URI or self.configuration()["jwks_uri"]

    @property
    def issuer(self):
        return self._jwks_uri or OIDC_ISSUER or self.configuration()["jwks_uri"]

    def jwks(self) -> dict | list | str | bytes:
        if self._jwks_update_ts is None or datetime.now() > self._jwks_update_ts + timedelta(minutes=5):
            self._jwks = requests.get(self.jwks_uri).json()
            self._jwks_update_ts = datetime.now()
        return self._jwks

    def configuration(self) -> dict[str, Any]:
        if self._configuration_update_ts is None or datetime.now() > self._configuration_update_ts + timedelta(
            minutes=5
        ):
            self._configuration = requests.get(self.configuration_uri).json()
            self._configuration_update_ts = datetime.now()
        return self._configuration

    def __call__(self, *args, **kwds) -> OIDCAuthProvider:
        return OIDCAuthProvider(self, *args, **kwds, factory=self)
