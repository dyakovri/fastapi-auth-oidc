import os

OIDC_CONFIGURATION_URI: str | None = os.getenv("OIDC_CONFIGURATION_URI", None)
OIDC_JWKS_URI: str | None = os.getenv("OIDC_JWKS_URI", None)
OIDC_USERINFO_URI: str | None = os.getenv("OIDC_USERINFO_URI", None)
OIDC_ISSUER: str | None = os.getenv("OIDC_ISSUER", None)
