from typing import Any

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from typing_extensions import Annotated

from fastapi_auth_oidc import OIDCAuthFactory, OIDCAuth
from fastapi_auth_oidc.exceptions import UnauthenticatedException


app = FastAPI()
OIDCAuth2 = OIDCAuthFactory(configuration_uri="https://example.com/.well-known/openid-configuration")


@app.get("/get_default")
def read_root(user: Annotated[dict[str, Any], Depends(OIDCAuth())]):
    return user


@app.get("/get_user")
def user(user: Annotated[dict[str, Any], Depends(OIDCAuth2())]):
    return user


@app.get("/get_userdata")
def userdata(user: Annotated[dict[str, Any], Depends(OIDCAuth2(fetch_userdata=True))]):
    return user


@app.exception_handler(UnauthenticatedException)
def unauthenticated_exception_handler(request, exc):
    return JSONResponse({"detail": "Unauthenticated"}, status_code=401)
