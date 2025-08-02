# FastAPI OIDC Security

This library allows your server-side application to check credentials with ease using OpenID Connect token flows. Use it with Firebase, Keycloak, Authentik or other OIDC providers.


## Simple usage

```python
from fastapi import FastAPI
from fastapi_auth_oidc import OIDCProvider, IDToken

app = FastAPI()
auth_user = OIDCProvider(
    configuration_uri="https://example.domain/issuer/.well-known/openid-configuration",
    client_id="my-client",
)

@app.get("/me")
def get_me(
    user: Annotated[IDToken | None, Depends(auth_user)],
):
    return user.model_dump() if user else {}
```

**You must process errors and absent token manually!**
