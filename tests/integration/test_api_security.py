"""
API Security Integration Tests for CF-PS-15.
Verifies role-based access control, unauthenticated rejection, privilege escalation immunity,
and boundary enforcement across all endpoints.
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure all ORM models are imported so Base.metadata knows about them
from app.auth.dependencies import Base, get_db
from app.auth.models import User, UserRole, UserSession
from app.audit.models import AuditEvent
from app.datasets.metadata import DatasetRecord, ProcessingJob
from app.api.access_tests import AccessTestRecord
from app.auth.service import create_access_token, create_session_record, create_user
from app.main import app

# In-memory SQLite with StaticPool so all connections share the same memory database
TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DB_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Create all tables on the test engine
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)


@pytest.fixture(scope="module")
def seeded_users():
    """Seeds test identities: admin, processor, analyst and active sessions."""
    db = TestingSessionLocal()
    admin_user = create_user(db, "test_admin", "admin@test.local", "AdminPass123!", UserRole.ADMIN)
    proc_user = create_user(db, "test_processor", "proc@test.local", "ProcPass123!", UserRole.PROCESSOR)
    analyst_user = create_user(db, "test_analyst", "analyst@test.local", "AnalystPass123!", UserRole.ANALYST)

    admin_tok, admin_jti, admin_exp = create_access_token(admin_user)
    create_session_record(db, admin_user.id, admin_jti, admin_exp)

    proc_tok, proc_jti, proc_exp = create_access_token(proc_user)
    create_session_record(db, proc_user.id, proc_jti, proc_exp)

    analyst_tok, a_jti, a_exp = create_access_token(analyst_user)
    create_session_record(db, analyst_user.id, a_jti, a_exp)

    db.close()
    return {
        "admin": {"user": admin_user, "token": admin_tok},
        "processor": {"user": proc_user, "token": proc_tok},
        "analyst": {"user": analyst_user, "token": analyst_tok},
    }


def test_unauthenticated_requests_are_rejected():
    """Unauthenticated access to protected endpoints must return 401 Unauthorized."""
    res1 = client.get("/api/datasets/raw")
    assert res1.status_code == 401

    res2 = client.get("/api/dashboard/metrics")
    assert res2.status_code == 401

    res3 = client.get("/api/audit-logs")
    assert res3.status_code == 401


def test_analyst_cannot_access_raw_datasets(seeded_users):
    """Analyst identity must be rejected with 403 Forbidden on raw dataset listing."""
    headers = {"Authorization": f"Bearer {seeded_users['analyst']['token']}"}
    res = client.get("/api/datasets/raw", headers=headers)
    assert res.status_code == 403
    data = res.json()
    assert "Access Denied" in str(data) or "lacks permission" in str(data)


def test_analyst_cannot_upload_dataset(seeded_users):
    """Analyst identity cannot upload raw data products."""
    headers = {"Authorization": f"Bearer {seeded_users['analyst']['token']}"}
    files = {"file": ("probe.csv", b"a,b,c\n1,2,3")}
    res = client.post("/api/datasets/upload", headers=headers, files=files)
    assert res.status_code == 403


def test_analyst_cannot_access_audit_logs(seeded_users):
    """Analyst identity is strictly prohibited from viewing compliance audit logs."""
    headers = {"Authorization": f"Bearer {seeded_users['analyst']['token']}"}
    res = client.get("/api/audit-logs", headers=headers)
    assert res.status_code == 403


def test_processor_cannot_access_audit_logs(seeded_users):
    """Processor identity cannot access compliance audit logs (Admin only)."""
    headers = {"Authorization": f"Bearer {seeded_users['processor']['token']}"}
    res = client.get("/api/audit-logs", headers=headers)
    assert res.status_code == 403


def test_admin_can_access_audit_logs(seeded_users):
    """Administrator identity is authorized to access audit logs."""
    headers = {"Authorization": f"Bearer {seeded_users['admin']['token']}"}
    res = client.get("/api/audit-logs", headers=headers)
    assert res.status_code == 200
    assert "events" in res.json()


def test_privilege_escalation_immunity(seeded_users):
    """
    Client-supplied roles in headers or bodies cannot escalate privileges.
    The role is enforced from the signed JWT subject in database.
    """
    analyst_token = seeded_users["analyst"]["token"]
    headers = {
        "Authorization": f"Bearer {analyst_token}",
        "X-User-Role": "admin",
        "Role": "admin"
    }
    res = client.get("/api/audit-logs?role=admin", headers=headers)
    assert res.status_code == 403


def test_invalid_dataset_id_returns_404(seeded_users):
    """Invalid dataset IDs return 404 without leaking server internals or bypassing auth."""
    headers = {"Authorization": f"Bearer {seeded_users['admin']['token']}"}
    res = client.get("/api/datasets/nonexistent-uuid-99999/metadata", headers=headers)
    assert res.status_code == 404
