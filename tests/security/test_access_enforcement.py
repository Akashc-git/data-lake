"""
Security Verification Tests for Access Control Enforcement - CF-PS-15.
Tests the 11 mandatory permission rules and verifies that unconfigured environments
are honestly reported as INCONCLUSIVE.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.access_tests import run_all_access_tests
from app.auth.models import Base, User, UserRole
from app.authorization.policies import ActionType, ResourceType, check_policy
from app.config import get_settings

TEST_DB_URL = "sqlite:///:memory:"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)

settings = get_settings()


MANDATORY_CASES = [
    ("TEST-01", UserRole.PROCESSOR.value, ResourceType.RAW_DATASET, ActionType.READ, True),
    ("TEST-02", UserRole.PROCESSOR.value, ResourceType.CURATED_DATASET, ActionType.WRITE, True),
    ("TEST-03", UserRole.PROCESSOR.value, ResourceType.RAW_DATASET, ActionType.DELETE, False),
    ("TEST-04", UserRole.PROCESSOR.value, ResourceType.CURATED_DATASET, ActionType.DELETE, False),
    ("TEST-05", UserRole.ANALYST.value, ResourceType.CURATED_DATASET, ActionType.READ, True),
    ("TEST-06", UserRole.ANALYST.value, ResourceType.RAW_DATASET, ActionType.READ, False),
    ("TEST-07", UserRole.ANALYST.value, ResourceType.RAW_BUCKET, ActionType.LIST, False),
    ("TEST-08", UserRole.ANALYST.value, ResourceType.CURATED_DATASET, ActionType.WRITE, False),
    ("TEST-09", UserRole.ANALYST.value, ResourceType.CURATED_DATASET, ActionType.WRITE, False),
    ("TEST-10", UserRole.ANALYST.value, ResourceType.CURATED_DATASET, ActionType.DELETE, False),
    ("TEST-11", UserRole.ANALYST.value, ResourceType.AUDIT_LOGS, ActionType.READ, False),
]


@pytest.mark.parametrize("test_id,role,resource,action,expected_allow", MANDATORY_CASES)
def test_policy_engine_matches_problem_specification(test_id, role, resource, action, expected_allow):
    """Verifies that the policy decision engine evaluates all 11 test cases exactly as required."""
    decision = check_policy(role, resource, action)
    assert decision.is_allowed == expected_allow, (
        f"Mismatch on {test_id}: Expected {expected_allow}, got {decision.is_allowed} ({decision.reason})"
    )


def test_test_runner_reports_inconclusive_when_b2_unconfigured():
    """
    Mandatory Rule: When Backblaze B2 is not configured in .env,
    the test runner must report INCONCLUSIVE rather than fabricating success.
    """
    db = TestingSessionLocal()
    actor = User(id="u1", username="admin", email="admin@test.local", hashed_password="x", role="admin")

    summary = run_all_access_tests(db, actor)

    assert summary.total_tests == 11
    if not settings.is_b2_configured:
        assert summary.inconclusive > 0
        assert summary.failed == 0
        for r in summary.results:
            if "unconfigured" in (r.provider_response or "").lower():
                assert r.pass_fail == "INCONCLUSIVE"
    db.close()
