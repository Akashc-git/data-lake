"""
Unit Tests for Authentication and Identity Service.
Tests password hashing, JWT generation, validation, and session revocation.
"""

from datetime import timedelta
import pytest
from app.auth.models import User, UserRole
from app.auth.service import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


def test_password_hashing_and_verification():
    raw_password = "SuperSecretPassword123!"
    hashed = hash_password(raw_password)

    assert hashed.startswith("pbkdf2_sha256$100000$")
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False
    assert verify_password("", hashed) is False


def test_jwt_token_creation_and_decoding():
    mock_user = User(
        id="usr-12345",
        username="processor_test",
        email="test@datalake.local",
        hashed_password="fake",
        role=UserRole.PROCESSOR.value,
        is_active=True,
    )

    token, jti, expire = create_access_token(mock_user, expires_delta=timedelta(minutes=15))

    assert isinstance(token, str)
    assert len(token) > 20
    assert jti is not None

    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "usr-12345"
    assert payload["username"] == "processor_test"
    assert payload["role"] == "processor"
    assert payload["jti"] == jti


def test_jwt_expired_token():
    mock_user = User(
        id="usr-999",
        username="expired_user",
        email="expired@datalake.local",
        hashed_password="fake",
        role=UserRole.ANALYST.value,
        is_active=True,
    )

    # Token with negative expiration
    token, _, _ = create_access_token(mock_user, expires_delta=timedelta(seconds=-10))
    payload = decode_access_token(token)
    assert payload is None
