from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from tests.utils.app_factory import app
from tests.utils.jwt import generate_jwt


@pytest.fixture(scope="session")
def client():
    yield TestClient(app)


def test_no_token(client: TestClient, openid_config, jwks_config):
    response = client.get("/get_user")
    assert response.status_code == 401


def test_invalid_token(client: TestClient, openid_config, jwks_config):
    response = client.get(
        "/get_user",
        headers={"Authorization": "Bearer invalid"},
    )
    assert response.status_code == 401


def test_invalid_date_token(client: TestClient, openid_config, jwks_config):
    token = generate_jwt(1, datetime(2000, 1, 1), datetime(2000, 1, 2))
    response = client.get(
        "/get_user",
        headers={"Authorization": "Bearer {token}".format(token=token)},
    )
    assert response.status_code == 401


def test_ok_token(client: TestClient, openid_config, jwks_config):
    token = generate_jwt(1, datetime(2000, 1, 1), datetime(2999, 12, 31))
    response = client.get(
        "/get_user",
        headers={"Authorization": "Bearer {token}".format(token=token)},
    )
    assert response.status_code == 200
