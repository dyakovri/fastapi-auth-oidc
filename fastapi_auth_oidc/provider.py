import json
import logging
from typing import TYPE_CHECKING, Any

from fastapi import Request
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.http import HTTPBearer
from jose import ExpiredSignatureError, JWTError, jwt
import requests
from typing_extensions import Annotated, Doc

from .exceptions import UnauthenticatedException


if TYPE_CHECKING:
    from .factory import OIDCAuthFactory


logger = logging.getLogger(__name__)


class OIDCAuthProvider(HTTPBearer):
    def __init__(
        self,
        auto_error: bool = True,
        force_check: bool = False,
        fetch_userdata: bool = False,
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
        self._force_check = force_check
        self._fetch_userdata = fetch_userdata
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
            return None
        except JWTError as exc:
            if self.auto_error:
                raise UnauthenticatedException("Can't verify key") from exc
            return None
        except Exception as exc:
            if self.auto_error:
                raise UnauthenticatedException("Unexpected exception: " + str(exc)) from exc
            return None

    def _get_userdata(self, token: str) -> str | None:
        userdata_response = requests.get(self._factory.userinfo_url, headers={"Authorization": f"Bearer {token}"})
        if not userdata_response.ok():
            if self.auto_error:
                raise UnauthenticatedException("Can't verify key")
            return None
        return userdata_response.text

    def _decode_userdata(self, userdata_response: str) -> dict[str, Any]:
        userdata_response_dict = None
        try:
            userdata_response_dict = json.loads(userdata_response)
        except json.JSONDecodeError:
            logger.debug("userdata response not json formatter")
        try:
            userdata_response_dict = self._decode_jwt(userdata_response)
        except Exception:
            logger.debug("userdata response not jwt formatter")
        if not userdata_response_dict:
            if self.auto_error:
                raise UnauthenticatedException("No userdata response")
            return None
        return userdata_response_dict

    def __call__(self, request: Request) -> dict[str, Any] | None:
        # Check token
        _, token = self._extract_creds(request.headers.get("Authorization"))
        if token is None:
            logger.debug("token in None")
            return None
        user_jwt_info = self._decode_jwt(token)

        # Force check and userdata
        if self._force_check or self._fetch_userdata:
            userdata_response = self._get_userdata(token)
            if userdata_response is None:
                return None

            # Decode userdata
            if self._fetch_userdata:
                user_jwt_info = self._decode_userdata(userdata_response)

        return user_jwt_info
