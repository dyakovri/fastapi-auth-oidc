from datetime import datetime, timedelta
from typing import Any

import requests

from .provider import OIDCAuthProvider
from .settings import Settings


class OIDCAuthFactory:
    def __init__(
        self,
        configuration_uri: str | None = None,
        jwks_uri: str | None = None,
        userinfo_uri: str | None = None,
        issuer: str | None = None,
        *,
        scheme_name: str = "OIDC token",
    ):
        self.scheme_name = scheme_name

        self._settings = Settings()
        self._configuration_uri = configuration_uri
        self._jwks_uri = jwks_uri
        self._userinfo_uri = userinfo_uri
        self._issuer = issuer

    @property
    def configuration_uri(self):
        return self._configuration_uri or self._settings.OIDC_CONFIGURATION_URI

    @property
    def jwks_uri(self):
        return self._jwks_uri or self._settings.OIDC_JWKS_URI or self.configuration()["jwks_uri"]

    @property
    def userinfo_url(self):
        return self._jwks_uri or self._settings.OIDC_JWKS_URI or self.configuration()["jwks_uri"]

    @property
    def issuer(self):
        return self._jwks_uri or self._settings.OIDC_JWKS_URI or self.configuration()["jwks_uri"]

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
