"""
Audit Models and Schemas for CF-PS-15 Data Lake Access Control.
Provides persistent audit trail schema for all security events, access checks,
and cloud storage operations.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid

from sqlalchemy import Column, String, Integer, DateTime, Text
from pydantic import BaseModel, ConfigDict

from app.auth.models import Base


class AuditOutcome(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class AuditEvent(Base):
    """Persistent audit record stored in SQLite and optionally exported to B2."""
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    actor_username = Column(String(50), nullable=False, index=True)
    actor_role = Column(String(20), nullable=False, index=True)
    operation = Column(String(100), nullable=False, index=True)
    resource = Column(String(255), nullable=False, index=True)
    outcome = Column(String(20), nullable=False, index=True)
    status_code = Column(Integer, nullable=True)
    correlation_id = Column(String(36), nullable=False, index=True)
    reason = Column(Text, nullable=True)
    enforcement_layer = Column(String(50), nullable=False, default="Application RBAC")
    ip_address = Column(String(45), nullable=True)
    details = Column(Text, nullable=True)


class AuditEventResponse(BaseModel):
    id: str
    timestamp: datetime
    actor_username: str
    actor_role: str
    operation: str
    resource: str
    outcome: str
    status_code: Optional[int] = None
    correlation_id: str
    reason: Optional[str] = None
    enforcement_layer: str
    ip_address: Optional[str] = None
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AuditLogFilter(BaseModel):
    actor: Optional[str] = None
    role: Optional[str] = None
    operation: Optional[str] = None
    resource: Optional[str] = None
    outcome: Optional[str] = None
    status_code: Optional[int] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = 100
    offset: int = 0
