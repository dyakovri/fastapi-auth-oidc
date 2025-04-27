# FastAPI OIDC Security

This library allows your server-side application to check credentials with ease using OpenID Connect token flows. Use it with Firebase, Keycloak, Authentik or other OIDC providers.


## Simple usage

You should provide OIDC configuration to the lib with one of the following ways:

1. Environment variables

    ```env
    OIDC_CONFIGURATION_URI=https://example.com/.well-known/openid-configuration
    ```

2. Programmatically (use this method if you want several auth providers)

    Create python file with base configuration (e.g. `auth.py`):

    ```python
    from fastapi_auth_oidc import OIDCAuthFactory

    OIDCAuth = OIDCAuthFactory(configuration_uri='https://example.com/.well-known/openid-configuration')
    ```

Then use factory in your handlers

```python
from fastapi_auth_oidc import OIDCAuth  # if you use env vars
# from .auth import OIDCAuth  # if you use programmatically configured factory
from fastapi import FastAPI


app = FastAPI()

@app.get("/")
def read_root(user: Annotated[dict[str, Any], Depends(OIDCAuth())]):
    return user
```


## Advanced configuration

You can customize various settings in your (default) factory and in each instance


### Factory settings

| Env name               | Factory arg name  | Default value            | Type         | Comment                                                                      |
| ---------------------- | ----------------- | ------------------------ | ------------ | ---------------------------------------------------------------------------- |
| OIDC_CONFIGURATION_URI | configuration_uri | -                        | String (url) | Fetched data will be named `config` further                                  |
| OIDC_JWKS_URI          | jwks_uri          | `config["jwks_uri"]`     | String (url) | Shoud be provided if no `jwks_uri` in configuration from `configuration_uri` |
| OIDC_USERINFO_URI      | userinfo_uri      | `config["userinfo_uri"]` | String (url) | URI to fetch user info in JWT or JSON format                                 |
| OIDC_ISSUER            | issuer            | `config["issuer"]`       | String       | If no `issuer` provided, check will be skipped                               |


### Provider settings

| Provider arg name | Default value | Type | Comment                                                                                               |
| ----------------- | ------------- | ---- | ----------------------------------------------------------------------------------------------------- |
| auto_error        | `True`        | Bool | If no credentials or credentials wrong, `UnauthenticatedException` will be thrown                     |
| force_check       | `False`       | Bool | Will check token on server for additional security, otherwise will check locally                      |
| fetch_userdata    | `False`       | Bool | If `fetch_userdata == True` and `userinfo_endpoint` provided, will return data from userdata endpoint |
