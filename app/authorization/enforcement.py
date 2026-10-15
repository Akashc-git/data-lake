"""
Authorization Enforcement Engine for CF-PS-15.
Evaluates identity policies, logs security decisions to the audit trail,
and halts unauthorized requests with HTTP 403 Forbidden.
"""

from typing import Optional
import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.auth.models import User
from app.authorization.policies import ResourceType, ActionType, check_policy, PolicyDecision
from app.audit.models import AuditEvent, AuditOutcome


def enforce_access(
    user: User,
    resource_type: ResourceType,
    action: ActionType,
    resource_name: Optional[str] = None,
    db: Optional[Session] = None,
    correlation_id: Optional[str] = None,
) -> PolicyDecision:
    """
    Enforces authorization policy against current user identity.
    If denied, records a DENIED audit event and raises HTTP 403.
    """
    decision = check_policy(user.role, resource_type, action)
    cid = correlation_id or str(uuid.uuid4())
    target_res = resource_name or resource_type.value

    if not decision.is_allowed:
        if db is not None:
            audit_entry = AuditEvent(
                id=str(uuid.uuid4()),
                actor_username=user.username,
                actor_role=user.role,
                operation=f"{action.value}_{resource_type.value.upper()}",
                resource=target_res,
                outcome=AuditOutcome.DENIED.value,
                status_code=status.HTTP_403_FORBIDDEN,
                correlation_id=cid,
                reason=decision.reason,
                enforcement_layer=decision.enforcement_layer,
                details=f'{{"attempted_action": "{action.value}", "resource_type": "{resource_type.value}"}}',
            )
            try:
                db.add(audit_entry)
                db.commit()
            except Exception:
                db.rollback()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "Access Denied",
                "reason": decision.reason,
                "role": user.role,
                "action": action.value,
                "resource": target_res,
                "enforcement_layer": decision.enforcement_layer,
                "correlation_id": cid,
            },
        )

    return decision
