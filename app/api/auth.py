"""
Authentication API Endpoints for CF-PS-15 Data Lake Access Control.
Provides secure login, session revocation (logout), and identity introspection.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.audit.logger import log_security_event
from app.audit.models import AuditOutcome
from app.auth.dependencies import get_current_user, get_current_token, get_db
from app.auth.models import TokenResponse, UserLogin, UserResponse, User, UserRole
from app.auth.service import authenticate_user, create_access_token, create_session_record, decode_access_token, revoke_session
from app.authorization.policies import POLICIES

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(
    login_data: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """
    Authenticates user credentials, issues a signed JWT, creates a server-side session,
    and sets an HTTP-only cookie.
    """
    client_ip = request.client.host if request.client else "unknown"
    user = authenticate_user(db, login_data.username, login_data.password)

    if not user:
        log_security_event(
            db=db,
            actor_username=login_data.username,
            actor_role="unknown",
            operation="AUTH_LOGIN_FAILED",
            resource="/api/auth/login",
            outcome=AuditOutcome.DENIED,
            status_code=status.HTTP_401_UNAUTHORIZED,
            reason="Invalid username or password.",
            enforcement_layer="Application Auth",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate token & server-side session
    token_str, jti, expires_at = create_access_token(user)
    create_session_record(
        db=db,
        user_id=user.id,
        token_jti=jti,
        expires_at=expires_at,
        ip_address=client_ip,
    )

    # Set secure cookie
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token_str}",
        httponly=True,
        max_age=8 * 3600,
        samesite="lax",
        secure=False,  # Set to True in production HTTPS
    )

    log_security_event(
        db=db,
        actor_username=user.username,
        actor_role=user.role,
        operation="AUTH_LOGIN_SUCCESS",
        resource="/api/auth/login",
        outcome=AuditOutcome.ALLOWED,
        status_code=status.HTTP_200_OK,
        reason="User successfully authenticated.",
        enforcement_layer="Application Auth",
        ip_address=client_ip,
    )

    return TokenResponse(
        access_token=token_str,
        token_type="bearer",
        expires_in_minutes=480,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    token: str = Depends(get_current_token),
    db: Session = Depends(get_db),
):
    """
    Revokes the current session JTI in the database and clears the session cookie.
    """
    client_ip = request.client.host if request.client else "unknown"
    payload = decode_access_token(token) if token else None
    if payload and "jti" in payload:
        revoke_session(db, payload["jti"])

    response.delete_cookie(key="access_token")

    log_security_event(
        db=db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        operation="AUTH_LOGOUT",
        resource="/api/auth/logout",
        outcome=AuditOutcome.ALLOWED,
        status_code=status.HTTP_200_OK,
        reason="User logged out; session revoked.",
        enforcement_layer="Application Auth",
        ip_address=client_ip,
    )

    return {"message": "Successfully logged out and revoked session token."}


@router.get("/me")
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """
    Returns current user identity details and server-side policy permissions matrix.
    """
    user_policies = [
        {
            "resource": key[1],
            "action": key[2],
            "allowed": val[0],
            "reason": val[1],
            "enforcement_layer": val[2],
        }
        for key, val in POLICIES.items()
        if key[0] == current_user.role
    ]

    return {
        "user": UserResponse.model_validate(current_user),
        "effective_permissions": user_policies,
    }
