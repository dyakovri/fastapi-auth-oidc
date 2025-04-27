import logging
from typing import TYPE_CHECKING, Any

from fastapi import Request
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.http import HTTPBearer
from jose import ExpiredSignatureError, JWTError, jwt
from typing_extensions import Annotated, Doc

from .exceptions import UnauthenticatedException


if TYPE_CHECKING:
    from .factory import OIDCAuthFactory


logger = logging.getLogger(__name__)


class OIDCAuthProvider(HTTPBearer):
    def __init__(
        self,
        auto_error: Annotated[
            bool,
            Doc(
                """
                By default, if the HTTP Bearer token is not provided (in an
                `Authorization` header), `HTTPBearer` will automatically cancel the
                request and send the client an error.

                If `auto_error` is set to `False`, when the HTTP Bearer token
                is not available, instead of erroring out, the dependency result will
                be `None`.

                This is useful when you want to have optional authentication.

                It is also useful when you want to have authentication that can be
                provided in one of multiple optional ways (for example, in an HTTP
                Bearer token or in a cookie).
                """
            ),
        ] = True,
        *,
        factory: "OIDCAuthFactory" = None,
    ):
        self.model = APIKey.model_construct(in_=APIKeyIn.header, name="Authorization")
        self.scheme_name = factory.scheme_name
        super().__init__(
            bearerFormat="jwt",
            scheme_name=self.scheme_name,
            description="OpenID JWT token auth",
            auto_error=auto_error,
        )
        self._factory = factory

    @staticmethod
    def _get_authorization_scheme_param(
        authorization_header_value: str | None,
    ) -> tuple[str, str]:
        if not authorization_header_value:
            return "", ""
        scheme, _, param = authorization_header_value.partition(" ")
        return scheme, param

    def _extract_creds(self, authorization: str | None) -> tuple[str | None, str | None]:
        scheme, credentials = self._get_authorization_scheme_param(authorization)
        if not (authorization and scheme and credentials):
            if self.auto_error:
                raise UnauthenticatedException()
            else:
                return None, None
        if scheme.lower() != "bearer":
            if self.auto_error:
                raise UnauthenticatedException("Invalid authentication credentials")
            else:
                return None, None
        return scheme, credentials

    def _decode_jwt(self, token: str) -> dict[str, Any]:
        try:
            decoded_token = jwt.decode(
                token,
                key=self._factory.jwks(),
                algorithms="RS256",
            )
            return decoded_token
        except ExpiredSignatureError as exc:
            if self.auto_error:
                raise UnauthenticatedException("Signature has expired") from exc
            else:
                return None
        except JWTError as exc:
            if self.auto_error:
                raise UnauthenticatedException("Can't verify key") from exc
            else:
                return None
        except Exception as exc:
            if self.auto_error:
                raise UnauthenticatedException("Unexpected exception: " + str(exc)) from exc
            else:
                return None

    async def __call__(self, request: Request) -> dict[str, Any] | None:
        _, token = self._extract_creds(request.headers.get("Authorization"))
        if token is None:
            logger.debug("token in None")
            return None
        user_jwt_info = self._decode_jwt(token)
        return user_jwt_info
