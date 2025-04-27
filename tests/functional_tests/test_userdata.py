import json
from datetime import datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from tests.utils.app import app
from tests.utils.jwt import generate_jwt


@pytest.fixture(scope="session")
def client():
    yield TestClient(app)


@pytest.fixture
def userdata_response_json():
    with patch(
        "fastapi_auth_oidc.provider.OIDCAuthProvider._get_userdata",
        return_value=json.dumps(
            {
                "username": "test",
                "email": "admin@dyakov.space",
            }
        ),
    ):
        yield


@pytest.fixture
def userdata_response_jwt():
    with patch(
        "fastapi_auth_oidc.provider.OIDCAuthProvider._get_userdata",
        return_value=generate_jwt(
            1,
            datetime(2000, 1, 1),
            datetime(2999, 12, 31),
            {
                "username": "test",
                "email": "admin@dyakov.space",
            },
        ),
    ):
        yield


def test_ok_userdata_token_jwt(client: TestClient, openid_config, jwks_config, userdata_response_jwt):
    token = generate_jwt(1, datetime(2000, 1, 1), datetime(2999, 12, 31))
    response = client.get(
        "/get_userdata",
        headers={"Authorization": "Bearer {token}".format(token=token)},
    )
    assert response.status_code == 200
    assert response.json() == {"username": "test", "email": "admin@dyakov.space", 'exp': 32503593600, 'iat': 946684800, 'iss': 'test', 'sub': '1'}


def test_ok_userdata_token_json(client: TestClient, openid_config, jwks_config, userdata_response_json):
    token = generate_jwt(1, datetime(2000, 1, 1), datetime(2999, 12, 31))
    response = client.get(
        "/get_userdata",
        headers={"Authorization": "Bearer {token}".format(token=token)},
    )
    assert response.status_code == 200
    assert response.json() == {"username": "test", "email": "admin@dyakov.space"}
