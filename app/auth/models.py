"""
Authentication and Identity Models for CF-PS-15 Data Lake Access Control.
Includes SQLAlchemy ORM models, Enums, and Pydantic schemas.
"""

from datetime import datetime, timezone
from enum import Enum
import uuid
from typing import Optional

from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship
from pydantic import BaseModel, EmailStr, Field, ConfigDict

Base = declarative_base()


class UserRole(str, Enum):
    """Supported identity roles with distinct data-lake permissions."""
    ADMIN = "admin"
    PROCESSOR = "processor"
    ANALYST = "analyst"


class User(Base):
    """User account entity stored in the application database."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.ANALYST.value)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    last_login = Column(DateTime, nullable=True)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """Server-side session tracking for token revocation and auditing."""
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_jti = Column(String(36), unique=True, nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)

    user = relationship("User", back_populates="sessions")


# Pydantic Schemas for Requests and Responses
class UserLogin(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.ANALYST


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserResponse
