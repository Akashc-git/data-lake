"""
Audit Logs and Security Reports API Endpoints for CF-PS-15.
Provides filtered audit trails, RFC 4180 CSV exports, JSON evidence dumps,
and comprehensive compliance security reports for Administrators.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.audit.models import AuditEvent, AuditEventResponse, AuditLogFilter, AuditOutcome
from app.audit.repository import export_audit_logs_csv, export_audit_logs_json, query_audit_logs
from app.auth.dependencies import get_current_user, get_db, require_role
from app.auth.models import User, UserRole
from app.authorization.enforcement import enforce_access
from app.authorization.policies import ActionType, POLICIES, ResourceType
from app.config import get_settings
from app.api.access_tests import AccessTestRecord
from app.datasets.metadata import ProcessingJob
from app.security.credentials import get_credential_posture

router = APIRouter(tags=["Audit & Security Reports"])
settings = get_settings()


class AuditListResponse(BaseModel):
    total_count: int
    offset: int
    limit: int
    events: List[AuditEventResponse]


@router.get("/audit-logs")
def get_audit_logs(
    actor: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    operation: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    status_code: Optional[int] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    export_format: Optional[str] = Query(None, description="'csv' or 'json'"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """
    Retrieves filtered audit logs.
    Restricted to Administrator role. Supports CSV and JSON exports.
    """
    filters = AuditLogFilter(
        actor=actor,
        role=role,
        operation=operation,
        resource=resource,
        outcome=outcome,
        status_code=status_code,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )

    if export_format == "csv":
        csv_data = export_audit_logs_csv(db, filters)
        return PlainTextResponse(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="audit_logs_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.csv"'},
        )
    elif export_format == "json":
        json_data = export_audit_logs_json(db, filters)
        return Response(
            content=json_data,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="audit_logs_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.json"'},
        )

    events, total = query_audit_logs(db, filters)
    return AuditListResponse(
        total_count=total,
        offset=offset,
        limit=limit,
        events=[AuditEventResponse.model_validate(e) for e in events],
    )


@router.get("/reports/security")
def get_security_report(
    current_user: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """
    Compiles an authoritative compliance security report detailing:
    1. Configured cloud buckets and isolation posture.
    2. Identity-to-credential mapping and least-privilege capabilities.
    3. Effective permission matrices.
    4. Real cloud permission test verification results (11 test cases).
    5. Failed and inconclusive tests with actual provider responses.
    6. Historical processing jobs and audit cross-references.
    """
    now_utc = datetime.now(timezone.utc)

    # 1. Bucket Configuration
    buckets_posture = {
        "b2_endpoint": settings.B2_ENDPOINT_URL or "Unconfigured",
        "region": settings.B2_REGION,
        "raw_bucket": {
            "name": settings.B2_RAW_BUCKET or "Unset",
            "isolation": "Dedicated private raw bucket. Write/delete blocked for analysts.",
        },
        "curated_bucket": {
            "name": settings.B2_CURATED_BUCKET or "Unset",
            "isolation": "Dedicated private curated bucket. Write blocked for analysts.",
        },
        "audit_bucket": {
            "name": settings.B2_AUDIT_BUCKET or "Unset",
            "isolation": "Dedicated private audit evidence bucket. Restricted to admin.",
        },
    }

    # 2. Identity-to-credential mapping
    credentials_posture = [
        {
            "identity": p.identity_name,
            "role": p.role,
            "target_bucket": p.target_bucket,
            "access_key_masked": p.access_key_masked,
            "is_configured": p.is_configured,
            "intended_capabilities": p.intended_capabilities,
            "cloud_restrictions": p.cloud_restrictions,
        }
        for p in get_credential_posture()
    ]

    # 3. Policy rules summary
    effective_policies = [
        {
            "role": key[0],
            "resource": key[1],
            "action": key[2],
            "allowed": val[0],
            "reason": val[1],
            "enforcement_layer": val[2],
        }
        for key, val in POLICIES.items()
    ]

    # 4. Latest permission tests
    latest_test = db.query(AccessTestRecord).order_by(desc(AccessTestRecord.timestamp)).first()
    test_results_summary = {
        "last_run_id": latest_test.run_id if latest_test else None,
        "last_run_timestamp": latest_test.timestamp.isoformat() if latest_test else None,
        "total_probes": 0,
        "passed": 0,
        "failed": 0,
        "inconclusive": 0,
        "verification_status": "UNEXECUTED",
        "detailed_results": [],
    }

    if latest_test:
        test_records = db.query(AccessTestRecord).filter(AccessTestRecord.run_id == latest_test.run_id).all()
        passed = sum(1 for r in test_records if r.pass_fail == "PASS")
        failed = sum(1 for r in test_records if r.pass_fail == "FAIL")
        inconclusive = sum(1 for r in test_records if r.pass_fail == "INCONCLUSIVE")

        # Strict verification rule:
        # "Do not label the project fully verified if any mandatory security test is failing, unconfigured, or inconclusive."
        if failed > 0:
            status_label = "FAILED (Security Non-Compliance Detected)"
        elif inconclusive > 0 or len(test_records) < 11:
            status_label = "INCONCLUSIVE (Missing Cloud Credentials or Incomplete Tests)"
        elif passed == 11:
            status_label = "FULLY_VERIFIED (All 11 Mandatory Cloud Probes Passed)"
        else:
            status_label = "PARTIALLY_VERIFIED"

        test_results_summary.update({
            "total_probes": len(test_records),
            "passed": passed,
            "failed": failed,
            "inconclusive": inconclusive,
            "verification_status": status_label,
            "detailed_results": [
                {
                    "test_id": r.test_id,
                    "identity": r.identity,
                    "operation": r.requested_operation,
                    "target_resource": r.target_resource,
                    "expected": r.expected_result,
                    "actual": r.actual_result,
                    "status_code": r.status_code,
                    "provider_response": r.provider_response,
                    "pass_fail": r.pass_fail,
                    "enforcement_layer": r.enforcement_layer,
                    "evidence_reference": r.evidence_reference,
                    "notes": r.notes,
                }
                for r in test_records
            ],
        })

    # 5. Recent Processing Jobs
    recent_jobs = (
        db.query(ProcessingJob)
        .order_by(desc(ProcessingJob.started_at))
        .limit(10)
        .all()
    )
    jobs_summary = [
        {
            "job_id": j.id,
            "raw_dataset_id": j.raw_dataset_id,
            "curated_dataset_id": j.curated_dataset_id,
            "status": j.status,
            "input_rows": j.input_row_count,
            "output_rows": j.output_row_count,
            "missing_handled": j.missing_values_handled,
            "duplicates_removed": j.duplicates_removed,
            "output_checksum": j.output_checksum,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "duration_seconds": j.duration_seconds,
            "error_details": j.error_details,
        }
        for j in recent_jobs
    ]

    return {
        "report_id": f"REP-{now_utc.strftime('%Y%m%d%H%M%S')}",
        "report_timestamp": now_utc.isoformat(),
        "generated_by": current_user.username,
        "buckets_posture": buckets_posture,
        "credentials_posture": credentials_posture,
        "effective_policies": effective_policies,
        "access_tests_summary": test_results_summary,
        "recent_processing_jobs": jobs_summary,
    }
