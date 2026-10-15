"""
Unit Tests for Authorization Policies.
Verifies permission decisions for Processor, Analyst, and Administrator identities
across all cloud data lake resources.
"""

import pytest
from app.auth.models import UserRole
from app.authorization.policies import ActionType, ResourceType, check_policy


def test_processor_permissions():
    # Processor can read and list raw datasets
    dec_read_raw = check_policy(UserRole.PROCESSOR.value, ResourceType.RAW_DATASET, ActionType.READ)
    assert dec_read_raw.is_allowed is True

    dec_list_raw = check_policy(UserRole.PROCESSOR.value, ResourceType.RAW_BUCKET, ActionType.LIST)
    assert dec_list_raw.is_allowed is True

    # Processor CANNOT delete raw datasets (immutability)
    dec_del_raw = check_policy(UserRole.PROCESSOR.value, ResourceType.RAW_DATASET, ActionType.DELETE)
    assert dec_del_raw.is_allowed is False

    # Processor CANNOT overwrite raw datasets
    dec_write_raw = check_policy(UserRole.PROCESSOR.value, ResourceType.RAW_DATASET, ActionType.WRITE)
    assert dec_write_raw.is_allowed is False

    # Processor CAN write to curated bucket
    dec_write_cur = check_policy(UserRole.PROCESSOR.value, ResourceType.CURATED_DATASET, ActionType.WRITE)
    assert dec_write_cur.is_allowed is True

    # Processor CANNOT delete curated datasets
    dec_del_cur = check_policy(UserRole.PROCESSOR.value, ResourceType.CURATED_DATASET, ActionType.DELETE)
    assert dec_del_cur.is_allowed is False


def test_analyst_permissions():
    # Analyst CANNOT read raw datasets
    dec_read_raw = check_policy(UserRole.ANALYST.value, ResourceType.RAW_DATASET, ActionType.READ)
    assert dec_read_raw.is_allowed is False

    # Analyst CANNOT list raw bucket
    dec_list_raw = check_policy(UserRole.ANALYST.value, ResourceType.RAW_BUCKET, ActionType.LIST)
    assert dec_list_raw.is_allowed is False

    # Analyst CAN read and list curated datasets
    dec_read_cur = check_policy(UserRole.ANALYST.value, ResourceType.CURATED_DATASET, ActionType.READ)
    assert dec_read_cur.is_allowed is True

    dec_list_cur = check_policy(UserRole.ANALYST.value, ResourceType.CURATED_BUCKET, ActionType.LIST)
    assert dec_list_cur.is_allowed is True

    # Analyst CANNOT write or upload curated datasets
    dec_write_cur = check_policy(UserRole.ANALYST.value, ResourceType.CURATED_DATASET, ActionType.WRITE)
    assert dec_write_cur.is_allowed is False

    # Analyst CANNOT delete curated datasets
    dec_del_cur = check_policy(UserRole.ANALYST.value, ResourceType.CURATED_DATASET, ActionType.DELETE)
    assert dec_del_cur.is_allowed is False

    # Analyst CANNOT read audit logs
    dec_audit = check_policy(UserRole.ANALYST.value, ResourceType.AUDIT_LOGS, ActionType.READ)
    assert dec_audit.is_allowed is False


def test_admin_permissions():
    # Admin can read audit logs and export
    dec_audit = check_policy(UserRole.ADMIN.value, ResourceType.AUDIT_LOGS, ActionType.READ)
    assert dec_audit.is_allowed is True

    dec_export = check_policy(UserRole.ADMIN.value, ResourceType.AUDIT_LOGS, ActionType.EXPORT)
    assert dec_export.is_allowed is True

    # Admin CANNOT delete raw datasets (preserves audit integrity)
    dec_del_raw = check_policy(UserRole.ADMIN.value, ResourceType.RAW_DATASET, ActionType.DELETE)
    assert dec_del_raw.is_allowed is False


def test_default_deny_on_undefined_action():
    # Unmapped role or resource
    decision = check_policy("guest_role", ResourceType.RAW_DATASET, ActionType.READ)
    assert decision.is_allowed is False
    assert "Default Deny" in decision.reason
