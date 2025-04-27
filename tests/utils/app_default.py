from typing import Any

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from typing_extensions import Annotated

from fastapi_auth_oidc import OIDCAuth
from fastapi_auth_oidc.exceptions import UnauthenticatedException


app = FastAPI()


@app.get("/get_user")
def read_root(user: Annotated[dict[str, Any], Depends(OIDCAuth())]):
    return user


@app.exception_handler(UnauthenticatedException)
def unauthenticated_exception_handler(request, exc):
    return JSONResponse({"detail": "Unauthenticated"}, status_code=401)
