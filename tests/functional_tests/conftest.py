from unittest.mock import patch

import pytest

from tests.utils.jwt import create_jwks


@pytest.fixture
def openid_config():
    with patch(
        "fastapi_auth_oidc.OIDCAuthFactory.configuration",
        return_value={
            "issuer": "https://example.com",
            "jwks_uri": "https://example.com/jwks",
        },
    ):
        yield


@pytest.fixture
def jwks_config():
    with patch(
        "fastapi_auth_oidc.OIDCAuthFactory.jwks",
        return_value=create_jwks(),
    ):
        yield
