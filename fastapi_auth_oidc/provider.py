"""OIDC Authentication utilities."""

import logging
from typing import Any

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security.http import HTTPBearer
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from typing_extensions import Annotated

from fastapi_auth_oidc.exceptions import InvalidCredentialsException, UnauthenticatedException
from fastapi_auth_oidc.settings import OidcSettingsProvider
from fastapi_auth_oidc.types import IDToken

logger = logging.getLogger(__name__)


security = HTTPBearer(
    bearerFormat="jwt",
    scheme_name="JWT Token",
    description="Token from OIDC provider",
    auto_error=False,
)
Credentials = Annotated[HTTPAuthorizationCredentials | None, Depends(security)]


class OIDCProvider:
    """Data provider and OIDC authentication utilities.

    Used for:
    - obtaining data about OIDC provider,
    - user authentication in FastAPI,
    - manual validation and decoding of tokens.
    """

    def __init__(
        self,
        *,
        configuration_uri: str,
        client_id: str,
        jwks_uri: str | None = None,
        audience: str | None = None,
        issuer: str | None = None,
        token_type: type[IDToken] = IDToken,
    ):
        """Создание провайдера учетных данных.

        Args:
            configuration_uri (str): OIDC configuration URI.
            client_id (str): Provider Client ID.
            jwks_uri (str | None, optional): URI for publik keys provider. If `None` will be taken from configuration.
            audience (str | None, optional): OIDC audience claim value. Defaults to `client_id`.
            issuer (str | None, optional): OIDC token issuer claim value. If `None` will be taken from configuration.
            token_type (type[IDToken], optional): _description_. Defaults to `IDToken`.
        """
        self._settings = OidcSettingsProvider(
            configuration_uri=configuration_uri,
            client_id=client_id,
            jwks_uri=jwks_uri,
            audience=audience,
            issuer=issuer,
        )
        self._token_type = token_type

    configuration_uri = property(lambda self: self._settings.configuration_uri)
    jwks_uri = property(lambda self: self._settings.jwks_uri)
    userinfo_endpoint = property(lambda self: self._settings.userinfo_endpoint)
    authorization_endpoint = property(lambda self: self._settings.authorization_endpoint)
    token_endpoint = property(lambda self: self._settings.token_endpoint)

    configuration = property(lambda self: self._settings.configuration)
    jwks = property(lambda self: self._settings.jwks)

    def decode_token(self, token: str) -> dict[str, Any]:
        """Returns decoded token with claims validation.

        Args:
            token (str): token to be validated and decoded.

        Returns:
            dict[str, Any]: decoded token
        """
        return jwt.decode(
            token=token,
            key=self._settings.jwks,
            algorithms=self._settings.signing_algorithms,
            audience=self._settings.audience,
            issuer=self._settings.issuer,
            options={"verify_at_hash": False},
        )

    def __call__(self, creds: Credentials):
        """FastAPI authentication dependency.

        Takes bearer token, decodes it as JWT and returns IDToken model. Bearer token should be in `Authorization`
        header with `Bearer` scheme.

        **If no Authorization header is present, returns `None`!**
        """
        logger.debug("OIDCProvider called")
        if creds is None:
            return None
        if creds.scheme != "Bearer" or not creds.credentials:
            raise InvalidCredentialsException(creds)

        try:
            token = self.decode_token(creds.credentials)
        except (ExpiredSignatureError, JWTClaimsError, JWTError) as exc:
            raise UnauthenticatedException(exc)

        return self._token_type.model_validate(token)
