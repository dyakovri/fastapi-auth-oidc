import logging

import requests
from cachetools.func import ttl_cache

logger = logging.getLogger(__name__)


class OidcSettingsProvider:
    def __init__(
        self,
        *,
        configuration_uri: str,
        client_id: str,
        jwks_uri: str | None = None,
        audience: str | None = None,
        issuer: str | None = None,
    ):
        self._configuration_uri = configuration_uri
        self._client_id = client_id
        self._jwks_uri = jwks_uri
        self._audience = audience or client_id
        self._issuer = issuer

    @property
    def configuration_uri(self):
        return self._configuration_uri

    @property
    def client_id(self):
        return self._client_id

    @property
    def jwks_uri(self):
        jwks_uri = self._jwks_uri or self.configuration.get("jwks_uri")
        if not jwks_uri:
            raise ValueError("jwks_uri should be set")
        return jwks_uri

    @property
    def userinfo_endpoint(self):
        return self.configuration.get("userinfo_endpoint")

    @property
    def authorization_endpoint(self):
        return self.configuration.get("authorization_endpoint")

    @property
    def token_endpoint(self):
        return self.configuration.get("token_endpoint")

    @property
    def audience(self):
        return self._audience or self._client_id

    @property
    def issuer(self):
        return self._issuer or self.configuration.get("issuer")

    @property
    def signing_algorithms(self):
        return self.configuration.get("id_token_signing_alg_values_supported", ["RS256"])

    @property
    @ttl_cache(maxsize=1, ttl=600)
    def configuration(self) -> dict:
        logger.info("Fetching oidc condiguration from %s", self.configuration_uri)
        result = requests.get(self.configuration_uri).json()
        if not isinstance(result, dict):
            raise ValueError("oidc_configuration should be dict")
        return result

    @property
    @ttl_cache(maxsize=1, ttl=600)
    def jwks(self):
        logger.info("Fetching jwks from %s", self.jwks_uri)
        result = requests.get(self.jwks_uri).json()
        if not isinstance(result, dict):
            raise ValueError("oidc_configuration should be dict")
        return result
