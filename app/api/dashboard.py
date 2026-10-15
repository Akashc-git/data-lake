"""
Dashboard and Storage Status API Endpoints for CF-PS-15.
Provides real-time computed data-lake metrics, B2 connectivity diagnostics,
and audit activity summaries. Zero hardcoded values.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.audit.models import AuditEvent, AuditOutcome
from app.auth.dependencies import get_current_user, get_db
from app.auth.models import User
from app.config import get_settings
from app.datasets.metadata import DatasetRecord, DatasetBucketType, ProcessingJob
from app.api.access_tests import AccessTestRecord
from app.storage.b2_client import get_processor_raw_client, get_processor_curated_client, get_admin_client
from app.storage.bucket_service import verify_bucket_reachability, get_bucket_storage_stats

router = APIRouter(tags=["Dashboard & Storage"])
settings = get_settings()


class StorageBucketStatus(BaseModel):
    bucket_role: str
    bucket_name: str
    status: str
    reachable: bool
    message: str
    object_count: int = 0
    total_size_bytes: int = 0


class StorageStatusResponse(BaseModel):
    is_configured: bool
    endpoint_url: str
    region: str
    buckets: List[StorageBucketStatus]
    timestamp: datetime


class DashboardMetricsResponse(BaseModel):
    timestamp: datetime
    b2_connected: bool
    b2_configured: bool
    raw_object_count: int
    curated_object_count: int
    raw_storage_bytes: int
    curated_storage_bytes: int
    total_processing_jobs: int
    successful_processing_jobs: int
    failed_processing_jobs: int
    allowed_requests_count: int
    denied_requests_count: int
    latest_tests_passed: int
    latest_tests_failed: int
    latest_tests_inconclusive: int
    recent_audit_events: List[Dict[str, Any]]


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """Health check endpoint validating application and database responsiveness."""
    db_healthy = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_healthy = False

    return {
        "status": "healthy" if db_healthy else "degraded",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "b2_configured": settings.is_b2_configured,
        "database_connected": db_healthy,
        "timestamp": datetime.now(timezone.utc),
    }


# Helper import for raw query in health check
from sqlalchemy import text


@router.get("/storage/status", response_model=StorageStatusResponse)
def get_storage_status(current_user: User = Depends(get_current_user)):
    """
    Probes real cloud reachability for Raw, Curated, and Audit buckets in Backblaze B2.
    """
    raw_client = get_processor_raw_client() or get_admin_client()
    curated_client = get_processor_curated_client() or get_admin_client()
    admin_client = get_admin_client()

    raw_probe = verify_bucket_reachability(raw_client, settings.B2_RAW_BUCKET)
    raw_stats = get_bucket_storage_stats(raw_client, settings.B2_RAW_BUCKET) if raw_probe.get("reachable") else {}

    cur_probe = verify_bucket_reachability(curated_client, settings.B2_CURATED_BUCKET)
    cur_stats = get_bucket_storage_stats(curated_client, settings.B2_CURATED_BUCKET) if cur_probe.get("reachable") else {}

    audit_probe = verify_bucket_reachability(admin_client, settings.B2_AUDIT_BUCKET)
    audit_stats = get_bucket_storage_stats(admin_client, settings.B2_AUDIT_BUCKET) if audit_probe.get("reachable") else {}

    bucket_statuses = [
        StorageBucketStatus(
            bucket_role="Raw Storage",
            bucket_name=settings.B2_RAW_BUCKET or "Unconfigured",
            status=raw_probe.get("status", "UNCONFIGURED"),
            reachable=raw_probe.get("reachable", False),
            message=raw_probe.get("message", ""),
            object_count=raw_stats.get("object_count", 0),
            total_size_bytes=raw_stats.get("total_size_bytes", 0),
        ),
        StorageBucketStatus(
            bucket_role="Curated Storage",
            bucket_name=settings.B2_CURATED_BUCKET or "Unconfigured",
            status=cur_probe.get("status", "UNCONFIGURED"),
            reachable=cur_probe.get("reachable", False),
            message=cur_probe.get("message", ""),
            object_count=cur_stats.get("object_count", 0),
            total_size_bytes=cur_stats.get("total_size_bytes", 0),
        ),
        StorageBucketStatus(
            bucket_role="Audit Evidence",
            bucket_name=settings.B2_AUDIT_BUCKET or "Unconfigured",
            status=audit_probe.get("status", "UNCONFIGURED"),
            reachable=audit_probe.get("reachable", False),
            message=audit_probe.get("message", ""),
            object_count=audit_stats.get("object_count", 0),
            total_size_bytes=audit_stats.get("total_size_bytes", 0),
        ),
    ]

    return StorageStatusResponse(
        is_configured=settings.is_b2_configured,
        endpoint_url=settings.B2_ENDPOINT_URL or "Unset",
        region=settings.B2_REGION,
        buckets=bucket_statuses,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/dashboard/metrics", response_model=DashboardMetricsResponse)
def get_dashboard_metrics(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Computes live metrics across database records, B2 bucket objects,
    processing job statuses, and permission checks.
    """
    # 1. Dataset counts from DB
    raw_db_count = db.query(DatasetRecord).filter(DatasetRecord.bucket_type == DatasetBucketType.RAW.value).count()
    cur_db_count = db.query(DatasetRecord).filter(DatasetRecord.bucket_type == DatasetBucketType.CURATED.value).count()

    # 2. Processing Jobs
    total_jobs = db.query(ProcessingJob).count()
    succ_jobs = db.query(ProcessingJob).filter(ProcessingJob.status == "SUCCESS").count()
    failed_jobs = db.query(ProcessingJob).filter(ProcessingJob.status == "FAILED").count()

    # 3. Audit Outcomes
    allowed_count = db.query(AuditEvent).filter(AuditEvent.outcome == AuditOutcome.ALLOWED.value).count()
    denied_count = db.query(AuditEvent).filter(AuditEvent.outcome == AuditOutcome.DENIED.value).count()

    # 4. Cloud Storage stats (if B2 reachable)
    raw_client = get_processor_raw_client() or get_admin_client()
    cur_client = get_processor_curated_client() or get_admin_client()

    raw_cloud_stats = get_bucket_storage_stats(raw_client, settings.B2_RAW_BUCKET)
    cur_cloud_stats = get_bucket_storage_stats(cur_client, settings.B2_CURATED_BUCKET)

    # Use cloud count if reachable, else database count
    raw_obj_count = raw_cloud_stats["object_count"] if raw_cloud_stats["accessible"] else raw_db_count
    cur_obj_count = cur_cloud_stats["object_count"] if cur_cloud_stats["accessible"] else cur_db_count
    raw_bytes = raw_cloud_stats.get("total_size_bytes", 0)
    cur_bytes = cur_cloud_stats.get("total_size_bytes", 0)
    b2_connected = raw_cloud_stats["accessible"] or cur_cloud_stats["accessible"]

    # 5. Latest Access Test Run summary
    latest_test = db.query(AccessTestRecord).order_by(desc(AccessTestRecord.timestamp)).first()
    passed_tests = 0
    failed_tests = 0
    inconclusive_tests = 0

    if latest_test:
        run_records = db.query(AccessTestRecord).filter(AccessTestRecord.run_id == latest_test.run_id).all()
        passed_tests = sum(1 for r in run_records if r.pass_fail == "PASS")
        failed_tests = sum(1 for r in run_records if r.pass_fail == "FAIL")
        inconclusive_tests = sum(1 for r in run_records if r.pass_fail == "INCONCLUSIVE")

    # 6. Recent Audit Events (last 10)
    recent_events = (
        db.query(AuditEvent)
        .order_by(desc(AuditEvent.timestamp))
        .limit(10)
        .all()
    )
    serialized_events = [
        {
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "actor": e.actor_username,
            "role": e.actor_role,
            "operation": e.operation,
            "resource": e.resource,
            "outcome": e.outcome,
            "status_code": e.status_code,
            "correlation_id": e.correlation_id,
            "reason": e.reason,
        }
        for e in recent_events
    ]

    return DashboardMetricsResponse(
        timestamp=datetime.now(timezone.utc),
        b2_connected=b2_connected,
        b2_configured=settings.is_b2_configured,
        raw_object_count=raw_obj_count,
        curated_object_count=cur_obj_count,
        raw_storage_bytes=raw_bytes,
        curated_storage_bytes=cur_bytes,
        total_processing_jobs=total_jobs,
        successful_processing_jobs=succ_jobs,
        failed_processing_jobs=failed_jobs,
        allowed_requests_count=allowed_count,
        denied_requests_count=denied_count,
        latest_tests_passed=passed_tests,
        latest_tests_failed=failed_tests,
        latest_tests_inconclusive=inconclusive_tests,
        recent_audit_events=serialized_events,
    )
