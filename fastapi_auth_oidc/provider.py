import logging

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.security.http import HTTPBearer
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError
from typing_extensions import Annotated

from fastapi_auth_oidc.exceptions import UnauthenticatedException, InvalidCredentialsException
from fastapi_auth_oidc.settings import OidcSettingsProvider
from fastapi_auth_oidc.types import IDToken

logger = logging.getLogger(__name__)


security = HTTPBearer(
    bearerFormat="jwt",
    scheme_name="JWT Token",
    description="Token from OIDC provider",
    auto_error=False,
)


class OIDCProvider:
    def __init__(
        self,
        *,
        configuration_uri: str,
        client_id: str,
        jwks_uri: str | None = None,
        userinfo_uri: str | None = None,
        audience: str | None = None,
        issuer: str | None = None,
        token_type: type[IDToken] = IDToken,
    ):
        self._settings = OidcSettingsProvider(
            configuration_uri=configuration_uri,
            jwks_uri=jwks_uri,
            userinfo_uri=userinfo_uri,
            client_id=client_id,
            audience=audience,
            issuer=issuer,
        )
        self._token_type = token_type

    def __call__(self, creds: Annotated[HTTPAuthorizationCredentials | None, Depends(security)]):
        logger.debug("OIDCProvider called")
        if creds is None:
            return None
        if creds.scheme != "Bearer" or not creds.credentials:
            raise InvalidCredentialsException(creds)

        try:
            token = jwt.decode(
                token=creds.credentials,
                key=self._settings.jwks,
                algorithms=self._settings.signing_algorithms,
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                options={"verify_at_hash": False},
            )
        except (ExpiredSignatureError, JWTClaimsError, JWTError) as exc:
            raise UnauthenticatedException(exc)

        return self._token_type.model_validate(token)
