from unittest.mock import PropertyMock

import pytest
from pytest_mock import MockerFixture

from fastapi_auth_oidc import OIDCProvider


@pytest.fixture
def mock_oidc_config(mocker: MockerFixture):
    """Patch the configuration function with a mock."""
    mock_config = mocker.patch(
        "fastapi_auth_oidc.settings.OidcSettingsProvider.configuration",
        new_callable=PropertyMock,
    )
    mock_config.return_value = {
        "issuer": "https://localhost:8080/application/o/app/",
        "authorization_endpoint": "https://localhost:8080/application/o/authorize/",
        "token_endpoint": "https://localhost:8080/application/o/token/",
        "userinfo_endpoint": "https://localhost:8080/application/o/userinfo/",
        "end_session_endpoint": "https://localhost:8080/application/o/app/end-session/",
        "introspection_endpoint": "https://localhost:8080/application/o/introspect/",
        "revocation_endpoint": "https://localhost:8080/application/o/revoke/",
        "device_authorization_endpoint": "https://localhost:8080/application/o/device/",
        "response_types_supported": [
            "code",
            "id_token",
            "id_token token",
            "code token",
            "code id_token",
            "code id_token token",
        ],
        "response_modes_supported": ["query", "fragment", "form_post"],
        "jwks_uri": "https://localhost:8080/application/o/app/jwks/",
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "implicit",
            "client_credentials",
            "password",
            "urn:ietf:params:oauth:grant-type:device_code",
        ],
        "id_token_signing_alg_values_supported": ["RS256"],
        "subject_types_supported": ["public"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "acr_values_supported": ["goauthentik.io/providers/oauth2/default"],
        "scopes_supported": ["profile", "openid", "email"],
        "request_parameter_supported": False,
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "acr",
            "amr",
            "nonce",
            "email",
            "email_verified",
            "name",
            "given_name",
            "preferred_username",
            "nickname",
            "groups",
        ],
        "claims_parameter_supported": False,
        "code_challenge_methods_supported": ["plain", "S256"],
    }
    yield


auth_user = OIDCProvider(
    configuration_uri="http://localhost:8080/.well-known/openid-configuration",
    client_id="client_id",
)


def test_properties(mock_oidc_config):
    """Ensure all properties are set correctly."""
    assert auth_user.configuration_uri == "http://localhost:8080/.well-known/openid-configuration"
    assert auth_user.jwks_uri == "https://localhost:8080/application/o/app/jwks/"
    assert auth_user.userinfo_endpoint == "https://localhost:8080/application/o/userinfo/"
    assert auth_user.authorization_endpoint == "https://localhost:8080/application/o/authorize/"
    assert auth_user.token_endpoint == "https://localhost:8080/application/o/token/"
