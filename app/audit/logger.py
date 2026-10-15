"""
Audit Logging Utilities for CF-PS-15 Data Lake Access Control.
Provides safe, sanitized logging of security actions, permissions checks, and API calls.
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, Optional
import uuid
from sqlalchemy.orm import Session

from app.audit.models import AuditEvent, AuditOutcome

logger = logging.getLogger("audit")

# Sensitive key patterns to mask
SENSITIVE_PATTERNS = re.compile(
    r'(password|secret|token|authorization|key_id|access_key|credentials)',
    re.IGNORECASE
)


def mask_sensitive_data(data: Any) -> Any:
    """Recursively masks passwords, secrets, and auth tokens from logged payloads."""
    if isinstance(data, dict):
        masked = {}
        for k, v in data.items():
            if SENSITIVE_PATTERNS.search(k):
                masked[k] = "[REDACTED]"
            elif isinstance(v, (dict, list)):
                masked[k] = mask_sensitive_data(v)
            else:
                masked[k] = v
        return masked
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data


def log_security_event(
    db: Session,
    actor_username: str,
    actor_role: str,
    operation: str,
    resource: str,
    outcome: AuditOutcome,
    status_code: Optional[int] = None,
    correlation_id: Optional[str] = None,
    reason: Optional[str] = None,
    enforcement_layer: str = "Application RBAC",
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> AuditEvent:
    """
    Persists an immutable audit log entry in the database.
    Ensures zero sensitive credentials or private tokens are leaked.
    """
    cid = correlation_id or str(uuid.uuid4())
    sanitized_details = None
    if details:
        try:
            sanitized_details = json.dumps(mask_sensitive_data(details))
        except Exception:
            sanitized_details = "[Unserializable Details Sanitized]"

    event = AuditEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        actor_username=actor_username,
        actor_role=actor_role,
        operation=operation,
        resource=resource,
        outcome=outcome.value if isinstance(outcome, AuditOutcome) else outcome,
        status_code=status_code,
        correlation_id=cid,
        reason=reason,
        enforcement_layer=enforcement_layer,
        ip_address=ip_address,
        details=sanitized_details,
    )

    try:
        db.add(event)
        db.commit()
        db.refresh(event)
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to persist audit log event {cid}: {exc}")

    return event
