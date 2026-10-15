"""
FastAPI dependencies for authentication, database sessions, and role-based access control.
"""

from typing import Generator, List, Optional
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.auth.models import Base, User, UserRole
from app.auth.service import decode_access_token, get_user_by_id, is_session_revoked
from app.config import get_settings

settings = get_settings()

# Database engine & sessionmaker
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

security_bearer = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    """Database session dependency per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_token(
    request: Request,
    auth_header: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> Optional[str]:
    """Extracts JWT token from Authorization header or cookie."""
    if auth_header and auth_header.credentials:
        return auth_header.credentials
    cookie_token = request.cookies.get("access_token")
    if cookie_token:
        if cookie_token.startswith("Bearer "):
            return cookie_token[7:]
        return cookie_token
    return None


def get_current_user(
    token: Optional[str] = Depends(get_current_token),
    db: Session = Depends(get_db),
) -> User:
    """
    Validates JWT token, verifies that session has not been revoked,
    and returns active User model.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jti = payload.get("jti")
    if not jti or is_session_revoked(db, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or was revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token claims.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_role(*allowed_roles: UserRole):
    """
    Dependency factory that enforces server-side role requirements.
    Prevents privilege escalation and client-side role manipulation.
    """
    allowed_values = [r.value if isinstance(r, UserRole) else r for r in allowed_roles]

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Identity role '{current_user.role}' lacks permission for this resource. Permitted roles: {allowed_values}",
            )
        return current_user

    return role_checker
