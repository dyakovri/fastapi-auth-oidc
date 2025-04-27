from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    OIDC_CONFIGURATION_URI: str | None = None
    OIDC_JWKS_URI: str | None = None
    OIDC_USERINFO_URI: str | None = None
    OIDC_ISSUER: str | None = None
