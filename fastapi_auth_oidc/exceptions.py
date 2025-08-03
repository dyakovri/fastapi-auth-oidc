"""`fastapi_auth_oidc` exception types."""


class FastAPIAuthOIDCException(Exception):
    """Base `fastapi_auth_oidc` exception."""


class AuthenticationException(FastAPIAuthOIDCException):
    """User can't be authenticated."""


class InvalidCredentialsException(AuthenticationException):
    """Token can't be decoded or missing."""


class UnauthenticatedException(AuthenticationException):
    """Invalid token.

    The wrong token parameters: audience, signature, lifestyle, etc.
    """
