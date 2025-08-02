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
        userinfo_uri: str | None = None,
        audience: str | None = None,
        issuer: str | None = None,
    ):
        self.configuration_uri = configuration_uri
        self.client_id = client_id
        self.jwks_uri = jwks_uri or self.configuration.get("jwks_uri")
        self.userinfo_uri = userinfo_uri or self.configuration.get("userinfo_endpoint")
        self.audience = audience or client_id
        self.issuer = issuer or self.configuration.get("issuer")
        self.signing_algorithms = self.configuration.get("id_token_signing_alg_values_supported", ["RS256"])

    @property
    @ttl_cache(maxsize=1, ttl=600)
    def configuration(self) -> dict:
        logger.info("Fetching oidc condiguration from %s", self.configuration_uri)
        result = requests.get(self.configuration_uri).json()
        if not isinstance(result, dict):
            raise ValueError("oidc_configuration should be dict")
        return result

    def _get_jwks_uri(self):
        jwks_uri = self.jwks_uri
        if not jwks_uri:
            raise ValueError("jwks_uri should be set")
        return jwks_uri

    @property
    @ttl_cache(maxsize=1, ttl=600)
    def jwks(self):
        logger.info("Fetching jwks from %s", self._get_jwks_uri())
        result = requests.get(self._get_jwks_uri()).json()
        if not isinstance(result, dict):
            raise ValueError("oidc_configuration should be dict")
        return result

    def _get_userinfo_uri(self):
        userinfo_uri = self.userinfo_uri
        if not userinfo_uri:
            raise ValueError("userinfo_uri should be set")
        return userinfo_uri
