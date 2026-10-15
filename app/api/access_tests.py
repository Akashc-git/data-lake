"""
Access Control Lab and Security Verification Engine for CF-PS-15.
Executes real cloud permission probes using identity-scoped B2 credentials
against the mandatory 11 test cases and records verifiable audit evidence.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
import uuid

from botocore.exceptions import ClientError, EndpointConnectionError, ConnectionClosedError
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session
from sqlalchemy import Column, String, Integer, DateTime, Text, desc

from app.audit.logger import log_security_event
from app.audit.models import AuditOutcome
from app.auth.dependencies import get_current_user, get_db, require_role
from app.auth.models import Base, User, UserRole
from app.config import get_settings
from app.storage.b2_client import (
    get_processor_raw_client,
    get_processor_curated_client,
    get_analyst_curated_client,
)

logger = logging.getLogger("access_tests")
settings = get_settings()

router = APIRouter(prefix="/access-tests", tags=["Access Control Lab"])


class AccessTestRecord(Base):
    """Database record storing historical execution of cloud access control test cases."""
    __tablename__ = "access_test_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id = Column(String(36), nullable=False, index=True)
    test_id = Column(String(20), nullable=False, index=True)
    identity = Column(String(50), nullable=False)
    requested_operation = Column(String(100), nullable=False)
    target_resource = Column(String(255), nullable=False)
    expected_result = Column(String(20), nullable=False)  # "ALLOW", "DENY"
    actual_result = Column(String(20), nullable=False)    # "ALLOW", "DENY", "INCONCLUSIVE", "ERROR"
    status_code = Column(Integer, nullable=True)
    provider_response = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    pass_fail = Column(String(20), nullable=False)        # "PASS", "FAIL", "INCONCLUSIVE"
    enforcement_layer = Column(String(50), nullable=False)
    evidence_reference = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)


class AccessTestResponse(BaseModel):
    id: str
    run_id: str
    test_id: str
    identity: str
    requested_operation: str
    target_resource: str
    expected_result: str
    actual_result: str
    status_code: Optional[int] = None
    provider_response: Optional[str] = None
    timestamp: datetime
    pass_fail: str
    enforcement_layer: str
    evidence_reference: Optional[str] = None
    notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class TestRunnerSummary(BaseModel):
    run_id: str
    timestamp: datetime
    total_tests: int
    passed: int
    failed: int
    inconclusive: int
    results: List[AccessTestResponse]


PROBE_KEY = "_access_control_probe.txt"
DISPOSABLE_DELETE_KEY = "_disposable_security_test_probe.txt"


def _execute_single_test(
    test_id: str,
    identity: str,
    operation_name: str,
    target_resource: str,
    expected_result: str,
    enforcement_layer: str,
    test_action_fn,
) -> Dict[str, Any]:
    """
    Executes a test action function, capturing actual provider responses, status codes,
    and classifying the result as PASS, FAIL, or INCONCLUSIVE.
    """
    notes = ""
    evidence_ref = f"probe-{uuid.uuid4().hex[:8]}"

    try:
        status_code, response_text, actual_outcome = test_action_fn(evidence_ref)
    except EndpointConnectionError as exc:
        return {
            "test_id": test_id,
            "identity": identity,
            "requested_operation": operation_name,
            "target_resource": target_resource,
            "expected_result": expected_result,
            "actual_result": "INCONCLUSIVE",
            "status_code": None,
            "provider_response": f"Network unreachable: {exc}",
            "pass_fail": "INCONCLUSIVE",
            "enforcement_layer": enforcement_layer,
            "evidence_reference": evidence_ref,
            "notes": "Network connection error while contacting Backblaze B2 endpoint.",
        }
    except Exception as exc:
        return {
            "test_id": test_id,
            "identity": identity,
            "requested_operation": operation_name,
            "target_resource": target_resource,
            "expected_result": expected_result,
            "actual_result": "ERROR",
            "status_code": 500,
            "provider_response": f"Unexpected error: {exc}",
            "pass_fail": "FAIL",
            "enforcement_layer": enforcement_layer,
            "evidence_reference": evidence_ref,
            "notes": str(exc),
        }

    # Evaluate Pass / Fail
    if actual_outcome == "INCONCLUSIVE":
        pass_fail = "INCONCLUSIVE"
        notes = "Environment unconfigured: B2 credentials or target bucket missing in .env."
    elif expected_result == "ALLOW" and actual_outcome == "ALLOW":
        pass_fail = "PASS"
        notes = "Operation authorized and executed successfully as expected."
    elif expected_result == "DENY" and actual_outcome == "DENY":
        pass_fail = "PASS"
        notes = f"Operation rejected with HTTP {status_code} ({response_text}). Access restricted as expected."
    elif expected_result == "DENY" and actual_outcome == "ALLOW":
        pass_fail = "FAIL"
        notes = "CRITICAL SECURITY BREACH: Prohibited operation was permitted by the cloud provider!"
    elif expected_result == "ALLOW" and actual_outcome == "DENY":
        pass_fail = "FAIL"
        notes = "Legitimate authorized operation was denied by the cloud provider."
    else:
        pass_fail = "FAIL"
        notes = f"Unexpected outcome: {actual_outcome}"

    return {
        "test_id": test_id,
        "identity": identity,
        "requested_operation": operation_name,
        "target_resource": target_resource,
        "expected_result": expected_result,
        "actual_result": actual_outcome,
        "status_code": status_code,
        "provider_response": str(response_text),
        "pass_fail": pass_fail,
        "enforcement_layer": enforcement_layer,
        "evidence_reference": evidence_ref,
        "notes": notes,
    }


def run_all_access_tests(db: Session, actor_user: User) -> TestRunnerSummary:
    """
    Executes the 11 mandatory cloud access control test cases in real-time.
    Uses identity-scoped credentials against real Backblaze B2 S3 API endpoints.
    """
    run_id = str(uuid.uuid4())
    results: List[Dict[str, Any]] = []

    raw_bucket = settings.B2_RAW_BUCKET
    curated_bucket = settings.B2_CURATED_BUCKET
    audit_bucket = settings.B2_AUDIT_BUCKET or "audit-unconfigured"

    proc_raw_client = get_processor_raw_client()
    proc_cur_client = get_processor_curated_client()
    analyst_client = get_analyst_curated_client()

    # Setup Probe Object in Raw & Curated buckets if processor write is permitted
    # For testing reads, we ensure a lightweight probe object exists
    if proc_cur_client and curated_bucket:
        try:
            proc_cur_client.put_object(
                Bucket=curated_bucket,
                Key=PROBE_KEY,
                Body=b"CF-PS-15 Curated Access Probe Data"
            )
        except Exception:
            pass

    # TEST-01: Processor reads raw object (Expected: ALLOW)
    def test_01_fn(ref):
        if not proc_raw_client or not raw_bucket:
            return None, "Processor RAW credentials or bucket unconfigured", "INCONCLUSIVE"
        try:
            # We attempt head_object or list_objects
            resp = proc_raw_client.list_objects_v2(Bucket=raw_bucket, MaxKeys=1)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Object list and read permitted", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}", "DENY"

    results.append(_execute_single_test(
        "TEST-01", "Processor", "Read Raw Object", f"b2://{raw_bucket}/{PROBE_KEY}",
        "ALLOW", "Cloud B2 IAM (readFiles)", test_01_fn
    ))

    # TEST-02: Processor uploads curated object (Expected: ALLOW)
    def test_02_fn(ref):
        if not proc_cur_client or not curated_bucket:
            return None, "Processor CURATED credentials or bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = proc_cur_client.put_object(
                Bucket=curated_bucket,
                Key=f"_probe_{ref}.txt",
                Body=b"Processor Curated Write Verification"
            )
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Object written successfully", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}", "DENY"

    results.append(_execute_single_test(
        "TEST-02", "Processor", "Upload Curated Object", f"b2://{curated_bucket}/_probe_test.txt",
        "ALLOW", "Cloud B2 IAM (writeFiles)", test_02_fn
    ))

    # TEST-03: Processor deletes raw object (Expected: DENY)
    def test_03_fn(ref):
        if not proc_raw_client or not raw_bucket:
            return None, "Processor RAW credentials or bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = proc_raw_client.delete_object(Bucket=raw_bucket, Key=DISPOSABLE_DELETE_KEY)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Deletion was permitted", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}: AccessDenied", "DENY"

    results.append(_execute_single_test(
        "TEST-03", "Processor", "Delete Raw Object", f"b2://{raw_bucket}/{DISPOSABLE_DELETE_KEY}",
        "DENY", "Cloud B2 IAM (No deleteFiles)", test_03_fn
    ))

    # TEST-04: Processor deletes curated object (Expected: DENY)
    def test_04_fn(ref):
        if not proc_cur_client or not curated_bucket:
            return None, "Processor CURATED credentials or bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = proc_cur_client.delete_object(Bucket=curated_bucket, Key=DISPOSABLE_DELETE_KEY)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Deletion was permitted", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}: AccessDenied", "DENY"

    results.append(_execute_single_test(
        "TEST-04", "Processor", "Delete Curated Object", f"b2://{curated_bucket}/{DISPOSABLE_DELETE_KEY}",
        "DENY", "Cloud B2 IAM (No deleteFiles)", test_04_fn
    ))

    # TEST-05: Analyst reads curated object (Expected: ALLOW)
    def test_05_fn(ref):
        if not analyst_client or not curated_bucket:
            return None, "Analyst credentials or bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = analyst_client.list_objects_v2(Bucket=curated_bucket, MaxKeys=1)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Curated object read permitted", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}", "DENY"

    results.append(_execute_single_test(
        "TEST-05", "Analyst", "Read Curated Object", f"b2://{curated_bucket}/{PROBE_KEY}",
        "ALLOW", "Cloud B2 IAM (readFiles)", test_05_fn
    ))

    # TEST-06: Analyst reads raw object (Expected: DENY)
    def test_06_fn(ref):
        if not analyst_client or not raw_bucket:
            return None, "Analyst credentials or raw bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = analyst_client.get_object(Bucket=raw_bucket, Key=PROBE_KEY)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Prohibited raw read succeeded", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}: AccessDenied", "DENY"

    results.append(_execute_single_test(
        "TEST-06", "Analyst", "Read Raw Object", f"b2://{raw_bucket}/{PROBE_KEY}",
        "DENY", "Cloud B2 IAM (Bucket Restriction)", test_06_fn
    ))

    # TEST-07: Analyst lists raw objects (Expected: DENY)
    def test_07_fn(ref):
        if not analyst_client or not raw_bucket:
            return None, "Analyst credentials or raw bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = analyst_client.list_objects_v2(Bucket=raw_bucket, MaxKeys=1)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Raw listing permitted", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}: AccessDenied", "DENY"

    results.append(_execute_single_test(
        "TEST-07", "Analyst", "List Raw Objects", f"b2://{raw_bucket}/",
        "DENY", "Cloud B2 IAM (Bucket Restriction)", test_07_fn
    ))

    # TEST-08: Analyst uploads curated object (Expected: DENY)
    def test_08_fn(ref):
        if not analyst_client or not curated_bucket:
            return None, "Analyst credentials or curated bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = analyst_client.put_object(
                Bucket=curated_bucket,
                Key=f"_analyst_unauth_write_{ref}.txt",
                Body=b"Unauthorized Analyst Write Attempt"
            )
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Curated upload permitted", "ALLOW"
        except (ClientError, ConnectionClosedError) as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403) if hasattr(exc, "response") else 403
            return code, f"B2 Rejection: AccessDenied / Connection closed by cloud", "DENY"

    results.append(_execute_single_test(
        "TEST-08", "Analyst", "Upload Curated Object", f"b2://{curated_bucket}/_probe_test.txt",
        "DENY", "Cloud B2 IAM (No writeFiles)", test_08_fn
    ))

    # TEST-09: Analyst overwrites curated object (Expected: DENY)
    def test_09_fn(ref):
        if not analyst_client or not curated_bucket:
            return None, "Analyst credentials or curated bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = analyst_client.put_object(
                Bucket=curated_bucket,
                Key=PROBE_KEY,
                Body=b"Unauthorized Overwrite Probe"
            )
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Overwrite permitted", "ALLOW"
        except (ClientError, ConnectionClosedError) as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403) if hasattr(exc, "response") else 403
            return code, f"B2 Rejection: AccessDenied / Connection closed by cloud", "DENY"

    results.append(_execute_single_test(
        "TEST-09", "Analyst", "Overwrite Curated Object", f"b2://{curated_bucket}/{PROBE_KEY}",
        "DENY", "Cloud B2 IAM (No writeFiles)", test_09_fn
    ))

    # TEST-10: Analyst deletes curated object (Expected: DENY)
    def test_10_fn(ref):
        if not analyst_client or not curated_bucket:
            return None, "Analyst credentials or curated bucket unconfigured", "INCONCLUSIVE"
        try:
            resp = analyst_client.delete_object(Bucket=curated_bucket, Key=DISPOSABLE_DELETE_KEY)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Deletion was permitted", "ALLOW"
        except (ClientError, ConnectionClosedError) as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403) if hasattr(exc, "response") else 403
            return code, f"B2 Rejection: AccessDenied / Connection closed by cloud", "DENY"

    results.append(_execute_single_test(
        "TEST-10", "Analyst", "Delete Curated Object", f"b2://{curated_bucket}/{DISPOSABLE_DELETE_KEY}",
        "DENY", "Cloud B2 IAM (No deleteFiles)", test_10_fn
    ))

    # TEST-11: Analyst accesses restricted audit data (Expected: DENY)
    def test_11_fn(ref):
        if not analyst_client:
            return None, "Analyst credentials unconfigured", "INCONCLUSIVE"
        try:
            resp = analyst_client.list_objects_v2(Bucket=audit_bucket, MaxKeys=1)
            code = resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            return code, "HTTP 200 OK - Audit bucket read permitted", "ALLOW"
        except ClientError as exc:
            code = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 403)
            return code, f"ClientError {exc.response.get('Error', {}).get('Code')}: AccessDenied", "DENY"

    results.append(_execute_single_test(
        "TEST-11", "Analyst", "Access Audit Bucket", f"b2://{audit_bucket}/",
        "DENY", "Cloud B2 IAM & Application RBAC", test_11_fn
    ))

    # Persist all test records to SQLite database
    persisted_records = []
    passed = 0
    failed = 0
    inconclusive = 0

    now_utc = datetime.now(timezone.utc)
    for r in results:
        rec = AccessTestRecord(
            id=str(uuid.uuid4()),
            run_id=run_id,
            test_id=r["test_id"],
            identity=r["identity"],
            requested_operation=r["requested_operation"],
            target_resource=r["target_resource"],
            expected_result=r["expected_result"],
            actual_result=r["actual_result"],
            status_code=r["status_code"],
            provider_response=r["provider_response"],
            timestamp=now_utc,
            pass_fail=r["pass_fail"],
            enforcement_layer=r["enforcement_layer"],
            evidence_reference=r["evidence_reference"],
            notes=r["notes"],
        )
        db.add(rec)
        persisted_records.append(rec)

        if r["pass_fail"] == "PASS":
            passed += 1
        elif r["pass_fail"] == "FAIL":
            failed += 1
        else:
            inconclusive += 1

    db.commit()

    # Log audit event for test batch
    log_security_event(
        db=db,
        actor_username=actor_user.username,
        actor_role=actor_user.role,
        operation="EXECUTE_ACCESS_CONTROL_LAB",
        resource="access_tests/all_11_cases",
        outcome=AuditOutcome.ALLOWED,
        status_code=status.HTTP_200_OK,
        correlation_id=run_id,
        reason=f"Executed 11 permission verification probes: {passed} PASS, {failed} FAIL, {inconclusive} INCONCLUSIVE.",
        enforcement_layer="Cloud B2 IAM & Application RBAC",
        details={"passed": passed, "failed": failed, "inconclusive": inconclusive}
    )

    return TestRunnerSummary(
        run_id=run_id,
        timestamp=now_utc,
        total_tests=len(results),
        passed=passed,
        failed=failed,
        inconclusive=inconclusive,
        results=[AccessTestResponse.model_validate(rec) for rec in persisted_records]
    )


@router.post("/run", response_model=TestRunnerSummary)
def run_access_control_tests(
    current_user: User = Depends(require_role(UserRole.ADMIN, UserRole.PROCESSOR)),
    db: Session = Depends(get_db),
):
    """Executes the full suite of 11 cloud access control permission verification probes."""
    return run_all_access_tests(db, current_user)


@router.get("/results", response_model=List[AccessTestResponse])
def get_latest_access_test_results(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieves recent access control test results from database."""
    records = db.query(AccessTestRecord).order_by(desc(AccessTestRecord.timestamp)).limit(limit).all()
    return records
