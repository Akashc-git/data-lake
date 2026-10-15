"""
Authorization Policies for CF-PS-15 Data Lake Access Control.
Defines explicit permission matrices for Processor, Analyst, and Administrator roles
across raw, curated, and audit resources.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Tuple

from app.auth.models import UserRole


class ResourceType(str, Enum):
    RAW_BUCKET = "raw_bucket"
    RAW_DATASET = "raw_dataset"
    CURATED_BUCKET = "curated_bucket"
    CURATED_DATASET = "curated_dataset"
    AUDIT_BUCKET = "audit_bucket"
    AUDIT_LOGS = "audit_logs"
    PROCESSING_PIPELINE = "processing_pipeline"
    ACCESS_TESTS = "access_tests"
    SECURITY_REPORTS = "security_reports"


class ActionType(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    DELETE = "DELETE"
    LIST = "LIST"
    EXECUTE = "EXECUTE"
    EXPORT = "EXPORT"


@dataclass
class PolicyDecision:
    is_allowed: bool
    reason: str
    enforcement_layer: str  # "Application RBAC" or "Backblaze B2 IAM"


# Baseline Policy Matrix: (UserRole, ResourceType, ActionType) -> (is_allowed, reason, enforcement_layer)
POLICIES: Dict[Tuple[str, str, str], Tuple[bool, str, str]] = {
    # ---------------- PROCESSOR ROLE ----------------
    (UserRole.PROCESSOR.value, ResourceType.RAW_BUCKET.value, ActionType.LIST.value): (
        True, "Processor is authorized to list raw objects for ingestion and validation.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.RAW_DATASET.value, ActionType.READ.value): (
        True, "Processor is authorized to read raw datasets for pipeline ingestion.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.RAW_DATASET.value, ActionType.WRITE.value): (
        False, "Raw datasets are immutable source evidence. Overwriting raw files is strictly prohibited.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.RAW_DATASET.value, ActionType.DELETE.value): (
        False, "Raw storage is append-only. Processor identity is denied delete capability.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.CURATED_BUCKET.value, ActionType.LIST.value): (
        True, "Processor can list curated bucket objects.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.CURATED_DATASET.value, ActionType.READ.value): (
        True, "Processor can inspect curated outputs.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.CURATED_DATASET.value, ActionType.WRITE.value): (
        True, "Processor is authorized to publish validated, curated datasets to the curated bucket.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.CURATED_DATASET.value, ActionType.DELETE.value): (
        False, "Curated datasets cannot be deleted by processor identity.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.PROCESSING_PIPELINE.value, ActionType.EXECUTE.value): (
        True, "Processor is authorized to execute cleaning and transformation pipelines.", "Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.AUDIT_LOGS.value, ActionType.READ.value): (
        False, "Audit logs are confidential administrative records.", "Application RBAC"
    ),
    (UserRole.PROCESSOR.value, ResourceType.AUDIT_BUCKET.value, ActionType.WRITE.value): (
        False, "Processor credentials are restricted from accessing audit bucket.", "Cloud B2 IAM & Application RBAC"
    ),

    # ---------------- ANALYST ROLE ----------------
    (UserRole.ANALYST.value, ResourceType.RAW_BUCKET.value, ActionType.LIST.value): (
        False, "Analyst is strictly forbidden from listing raw data-lake contents.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.RAW_DATASET.value, ActionType.READ.value): (
        False, "Analyst is denied read and download access to raw datasets containing unvetted or sensitive PII.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.RAW_DATASET.value, ActionType.WRITE.value): (
        False, "Analyst cannot write or modify raw objects.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.RAW_DATASET.value, ActionType.DELETE.value): (
        False, "Analyst cannot delete raw objects.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.CURATED_BUCKET.value, ActionType.LIST.value): (
        True, "Analyst is authorized to list verified curated datasets.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.CURATED_DATASET.value, ActionType.READ.value): (
        True, "Analyst is authorized to read and download vetted curated datasets.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.CURATED_DATASET.value, ActionType.WRITE.value): (
        False, "Analyst is read-only on curated bucket; uploading or overwriting is prohibited.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.CURATED_DATASET.value, ActionType.DELETE.value): (
        False, "Analyst lacks delete capability on curated datasets.", "Cloud B2 IAM & Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.PROCESSING_PIPELINE.value, ActionType.EXECUTE.value): (
        False, "Analyst cannot trigger ingestion or transformation pipelines.", "Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.AUDIT_LOGS.value, ActionType.READ.value): (
        False, "Analyst is prohibited from viewing security audit trails.", "Application RBAC"
    ),
    (UserRole.ANALYST.value, ResourceType.AUDIT_BUCKET.value, ActionType.READ.value): (
        False, "Audit evidence bucket is locked to administrative access only.", "Cloud B2 IAM & Application RBAC"
    ),

    # ---------------- ADMIN ROLE ----------------
    (UserRole.ADMIN.value, ResourceType.RAW_BUCKET.value, ActionType.LIST.value): (
        True, "Admin can list raw objects for operational oversight.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.RAW_DATASET.value, ActionType.READ.value): (
        True, "Admin can inspect raw objects for diagnostic purposes.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.RAW_DATASET.value, ActionType.WRITE.value): (
        False, "Raw datasets are strictly append-only; even administrators do not overwrite raw evidence.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.RAW_DATASET.value, ActionType.DELETE.value): (
        False, "Raw source deletion is blocked to maintain audit integrity.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.CURATED_BUCKET.value, ActionType.LIST.value): (
        True, "Admin can list curated objects.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.CURATED_DATASET.value, ActionType.READ.value): (
        True, "Admin can read curated datasets.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.CURATED_DATASET.value, ActionType.WRITE.value): (
        True, "Admin has write authorization on curated storage if necessary.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.CURATED_DATASET.value, ActionType.DELETE.value): (
        False, "Curated data deletion is blocked by policy to preserve reproducible analyses.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.AUDIT_LOGS.value, ActionType.READ.value): (
        True, "Admin is authorized to review audit logs and export evidence.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.AUDIT_LOGS.value, ActionType.EXPORT.value): (
        True, "Admin is authorized to export audit logs as CSV or JSON.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.ACCESS_TESTS.value, ActionType.EXECUTE.value): (
        True, "Admin is authorized to trigger cloud access control verification tests.", "Application RBAC"
    ),
    (UserRole.ADMIN.value, ResourceType.SECURITY_REPORTS.value, ActionType.READ.value): (
        True, "Admin is authorized to generate and view compliance security reports.", "Application RBAC"
    ),
}


def check_policy(role: str, resource_type: ResourceType, action: ActionType) -> PolicyDecision:
    """
    Evaluates policy matrix for a given role, resource, and action.
    Defaults to strict DENY if no explicit rule matches.
    """
    key = (role, resource_type.value, action.value)
    if key in POLICIES:
        allowed, reason, layer = POLICIES[key]
        return PolicyDecision(is_allowed=allowed, reason=reason, enforcement_layer=layer)

    # Default deny
    return PolicyDecision(
        is_allowed=False,
        reason=f"Default Deny: No explicit policy rule permits role '{role}' to perform '{action.value}' on '{resource_type.value}'.",
        enforcement_layer="Application RBAC"
    )
