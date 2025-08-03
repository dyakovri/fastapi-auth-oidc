# FastAPI OIDC Security

This library allows your server-side application to check credentials with ease using OpenID Connect
token flows. Use it with Firebase, Keycloak, Authentik or other OIDC providers.


## Simple usage

You can just add `auth_user` dependency to take token data into your FastAPI routes.

```python
from fastapi import FastAPI
from fastapi_auth_oidc import OIDCProvider, IDToken
from fastapi_auth_oidc.exceptions import AuthenticationException


app = FastAPI()
auth_user = OIDCProvider(
    configuration_uri="https://example.domain/issuer/.well-known/openid-configuration",
    client_id="my-client",
)


@app.exception_handler(AuthenticationException)
def invalid_credentials(request: Request, exc: InvalidCredentialsException):
    return JSONResponse(
        status_code=403,
        content={"detail": "Invalid token"},
    )


@app.get("/me")
def get_me(
    user: Annotated[IDToken | None, Depends(auth_user)],
):
    return user.model_dump() if user else {}
```


## Advanced authorization

For authorization with this package you shoud create security guards. Example below provides
`NamedTuple` with 2 authorization methods: authenticated and is_admin. They uses FastAPI dependency
injection to ensure user and validate token. Now you shoud alse use them as dependencies.

```python
from typing import Annotated, NamedTuple

from fastapi import Depends
from fastapi_auth_oidc import IDToken, OIDCProvider
from fastapi_auth_oidc import IDToken, OIDCProvider
from fastapi_auth_oidc.exceptions import UnauthenticatedException


# Taking a new property mapping from JWT
class MyIDToken(IDToken):
    my_app_permissions: str | None = None

# Setting up provider
auth_user = OIDCProvider(
    configuration_uri=str(settings.oidc_configuration_uri),
    client_id=settings.oidc_client_id,
    token_type=MyIDToken,
)
TokenData = Annotated[MyIDToken | None, Depends(auth_user)]


# Check if user token set and valid
def get_authenticated(user: TokenData):
    if not user:
        raise UnauthenticatedException()
    return user


# Check if user has `my_app_permissions` field in JWT token and it equals to `admin`.
def get_is_admin(user: Annotated[MyIDToken, Depends(get_authenticated)]):
    if not user.my_app_permissions == "admin":
        raise Exception()
    return user


# This utilities in pretty form
class User(NamedTuple):
    authenticated = Annotated[IDToken, Depends(get_authenticated)]
    is_admin = Annotated[IDToken, Depends(get_is_admin)]

# Usage
app = FastAPI()

@app.get("/everybody")
def get_me(user: TokenData):
    """Everybody can open `"/everybody` =)"""
    return user.model_dump() if user else {}


@app.get("/authenticated")
def get_me(user: User.authenticated):
    """Only users with valid JWT token will get their data"""
    return user.model_dump()


@app.get("/admin")
def get_me(user: User.is_admin):
    """Only users with `my_app_permissions == "admin"` can get their data"""
    return user.model_dump()
```
