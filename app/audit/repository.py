"""
Audit Log Repository for CF-PS-15 Data Lake Access Control.
Provides advanced filtering, pagination, CSV/JSON export generation,
and synchronization to the B2 audit bucket.
"""

import csv
from datetime import datetime, timezone
import io
import json
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.audit.models import AuditEvent, AuditLogFilter


def query_audit_logs(db: Session, filters: AuditLogFilter) -> Tuple[List[AuditEvent], int]:
    """
    Queries audit events with multi-field filtering and pagination.
    Returns (events, total_count).
    """
    query = db.query(AuditEvent)

    if filters.actor:
        query = query.filter(AuditEvent.actor_username.ilike(f"%{filters.actor}%"))
    if filters.role:
        query = query.filter(AuditEvent.actor_role == filters.role)
    if filters.operation:
        query = query.filter(AuditEvent.operation.ilike(f"%{filters.operation}%"))
    if filters.resource:
        query = query.filter(AuditEvent.resource.ilike(f"%{filters.resource}%"))
    if filters.outcome:
        query = query.filter(AuditEvent.outcome == filters.outcome)
    if filters.status_code is not None:
        query = query.filter(AuditEvent.status_code == filters.status_code)
    if filters.start_date:
        query = query.filter(AuditEvent.timestamp >= filters.start_date)
    if filters.end_date:
        query = query.filter(AuditEvent.timestamp <= filters.end_date)

    total = query.count()
    events = (
        query.order_by(desc(AuditEvent.timestamp))
        .offset(filters.offset)
        .limit(filters.limit)
        .all()
    )
    return events, total


def export_audit_logs_csv(db: Session, filters: AuditLogFilter) -> str:
    """Exports filtered audit events as an RFC 4180 compliant CSV string."""
    # Fetch without limit for export (capped at safe 10,000)
    export_filters = AuditLogFilter(**filters.model_dump())
    export_filters.limit = 10000
    export_filters.offset = 0

    events, _ = query_audit_logs(db, export_filters)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Event ID",
        "Timestamp (UTC)",
        "Actor",
        "Role",
        "Operation",
        "Resource",
        "Outcome",
        "Status Code",
        "Correlation ID",
        "Enforcement Layer",
        "Reason",
        "IP Address"
    ])

    for e in events:
        writer.writerow([
            e.id,
            e.timestamp.isoformat() if e.timestamp else "",
            e.actor_username,
            e.actor_role,
            e.operation,
            e.resource,
            e.outcome,
            e.status_code or "",
            e.correlation_id,
            e.enforcement_layer,
            e.reason or "",
            e.ip_address or ""
        ])

    return output.getvalue()


def export_audit_logs_json(db: Session, filters: AuditLogFilter) -> str:
    """Exports filtered audit events as formatted JSON."""
    export_filters = AuditLogFilter(**filters.model_dump())
    export_filters.limit = 10000
    export_filters.offset = 0

    events, _ = query_audit_logs(db, export_filters)

    data = [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "actor": e.actor_username,
            "role": e.actor_role,
            "operation": e.operation,
            "resource": e.resource,
            "outcome": e.outcome,
            "status_code": e.status_code,
            "correlation_id": e.correlation_id,
            "enforcement_layer": e.enforcement_layer,
            "reason": e.reason,
            "ip_address": e.ip_address,
            "details": json.loads(e.details) if e.details else None
        }
        for e in events
    ]
    return json.dumps(data, indent=2)
