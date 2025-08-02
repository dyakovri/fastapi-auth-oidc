import base64
import hashlib
import pathlib
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from typing import Any

from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class JwtSettings:
    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    pem_private_key: bytes
    pem_public_key: bytes
    n: str
    e: str
    kid: str


@lru_cache(1)
def get_private_key() -> rsa.RSAPrivateKey:
    with open(pathlib.Path(__file__).parent.parent / "private_key.pem", "rb") as key_file:
        key_bytes = key_file.read()
    return serialization.load_pem_private_key(key_bytes, password=None)


def to_base64url(value: int) -> str:
    """Функция для преобразования числа в Base64URL"""
    # Преобразуем число в байты
    byte_length = (value.bit_length() + 7) // 8
    byte_data = value.to_bytes(byte_length, byteorder='big')
    # Кодируем в Base64 и удаляем padding (=)
    return base64.urlsafe_b64encode(byte_data).rstrip(b'=').decode('utf-8')


@lru_cache(1)
def ensure_jwt_settings() -> JwtSettings:
    private_key = get_private_key()
    public_key = private_key.public_key()
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_numbers = public_key.public_numbers()
    n = to_base64url(public_numbers.n)
    e = to_base64url(public_numbers.e)
    kid = hashlib.sha256(pem_public_key).hexdigest()[:16]
    return JwtSettings(
        private_key=private_key,
        public_key=public_key,
        pem_private_key=pem_private_key,
        pem_public_key=pem_public_key,
        n=n,
        e=e,
        kid=kid,
    )


@lru_cache(1)
def create_jwks() -> dict[str, str]:
    jwt_settings = ensure_jwt_settings()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": jwt_settings.kid,
        "alg": "RS256",
        "n": jwt_settings.n,
        "e": jwt_settings.e,
    }


def generate_jwt(user_id: int, create_ts: datetime, expire_ts: datetime, other_claims: dict[str, Any] = None) -> str:
    other_claims = other_claims or {}
    claims = {
        "sub": f"{user_id}",
        "iss": "test",
        "iat": int(create_ts.timestamp()),
        "exp": int(expire_ts.timestamp()),
    }
    claims.update(other_claims)
    jwt_settings = ensure_jwt_settings()
    return jwt.encode(
        claims,
        jwt_settings.pem_private_key,
        algorithm="RS256",
    )


def decode_jwt(token: str) -> dict[str, Any]:
    jwt_settings = ensure_jwt_settings()
    return jwt.decode(
        token,
        jwt_settings.pem_public_key,
        algorithms=["RS256"],
    )
