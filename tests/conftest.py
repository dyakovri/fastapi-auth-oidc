from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from .utils.app import app
from .utils.jwt import create_jwks


@pytest.fixture(scope="session")
def client():
    yield TestClient(app)


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
