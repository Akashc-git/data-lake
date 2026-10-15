"""
Authentication and Session Service for CF-PS-15.
Provides secure password hashing, JWT generation/validation, and database session tracking.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import secrets
from typing import Optional, Tuple
import uuid

import jwt
from sqlalchemy.orm import Session

from app.auth.models import User, UserSession, UserRole
from app.config import get_settings

settings = get_settings()


def hash_password(password: str) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a random 16-byte salt and 100,000 iterations.
    Pure Python standard library implementation guaranteed compatible across Python 3.11+.
    """
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    return f"pbkdf2_sha256$100000${salt}${key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain-text password against a stored PBKDF2-HMAC-SHA256 hash in constant time.
    """
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4:
            return False
        algorithm, iterations_str, salt, stored_hash = parts
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iterations_str)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(key.hex(), stored_hash)
    except Exception:
        return False


def create_access_token(user: User, expires_delta: Optional[timedelta] = None) -> Tuple[str, str, datetime]:
    """
    Generates a signed JWT access token containing identity claims and unique JTI.
    Returns: (token_str, jti, expiration_datetime)
    """
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)

    jti = str(uuid.uuid4())
    payload = {
        "sub": user.id,
        "username": user.username,
        "role": user.role,
        "jti": jti,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    encoded_jwt = jwt.encode(payload, settings.SESSION_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt, jti, expire


def decode_access_token(token: str) -> Optional[dict]:
    """
    Decodes and validates a JWT token signature and expiration.
    """
    try:
        payload = jwt.decode(
            token,
            settings.SESSION_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except (jwt.PyJWTError, Exception):
        return None


def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """Retrieves user by username from database."""
    return db.query(User).filter(User.username == username).first()


def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    """Retrieves user by ID from database."""
    return db.query(User).filter(User.id == user_id).first()


def create_user(
    db: Session,
    username: str,
    email: str,
    password: str,
    role: UserRole = UserRole.ANALYST,
) -> User:
    """Creates a new user record with hashed password."""
    hashed_pwd = hash_password(password)
    new_user = User(
        id=str(uuid.uuid4()),
        username=username.strip().lower(),
        email=email.strip().lower(),
        hashed_password=hashed_pwd,
        role=role.value if isinstance(role, UserRole) else role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    """Verifies username and password credentials."""
    user = get_user_by_username(db, username.strip().lower())
    if not user:
        return None
    if not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    return user


def create_session_record(
    db: Session,
    user_id: str,
    token_jti: str,
    expires_at: datetime,
    ip_address: Optional[str] = None,
) -> UserSession:
    """Stores server-side session metadata for revocation tracking."""
    session_rec = UserSession(
        id=str(uuid.uuid4()),
        user_id=user_id,
        token_jti=token_jti,
        expires_at=expires_at,
        is_revoked=False,
        ip_address=ip_address,
    )
    db.add(session_rec)
    db.commit()
    db.refresh(session_rec)
    return session_rec


def revoke_session(db: Session, token_jti: str) -> bool:
    """Marks a session token as revoked in the database."""
    session_rec = db.query(UserSession).filter(UserSession.token_jti == token_jti).first()
    if session_rec:
        session_rec.is_revoked = True
        db.commit()
        return True
    return False


def is_session_revoked(db: Session, token_jti: str) -> bool:
    """Checks whether a token JTI has been invalidated."""
    session_rec = db.query(UserSession).filter(UserSession.token_jti == token_jti).first()
    if session_rec and session_rec.is_revoked:
        return True
    return False
