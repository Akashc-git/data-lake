"""
Security and Credential Management for CF-PS-15.
Provides identity-to-credential mappings, masking utilities, and configuration audits.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
from app.config import get_settings

settings = get_settings()


def mask_credential(val: Optional[str], visible_prefix: int = 4, visible_suffix: int = 4) -> str:
    """Masks secret or sensitive keys for UI display and safe logging."""
    if not val:
        return "[UNCONFIGURED]"
    val = val.strip()
    if len(val) <= (visible_prefix + visible_suffix):
        return "********"
    return f"{val[:visible_prefix]}...{val[-visible_suffix:]}"


@dataclass
class IdentityCredentialProfile:
    identity_name: str
    role: str
    target_bucket: str
    access_key_masked: str
    is_configured: bool
    intended_capabilities: List[str]
    cloud_restrictions: str


def get_credential_posture() -> List[IdentityCredentialProfile]:
    """
    Returns the configured credential mappings and their intended B2 capabilities.
    Never exposes raw secrets.
    """
    profiles = [
        IdentityCredentialProfile(
            identity_name="Processor (Raw Ingestion)",
            role="processor",
            target_bucket=settings.B2_RAW_BUCKET or "Unset",
            access_key_masked=mask_credential(settings.B2_PROCESSOR_RAW_ACCESS_KEY_ID),
            is_configured=bool(settings.B2_PROCESSOR_RAW_ACCESS_KEY_ID and settings.B2_PROCESSOR_RAW_SECRET_ACCESS_KEY),
            intended_capabilities=["listFiles", "readFiles"],
            cloud_restrictions="Scoped exclusively to RAW bucket; denied writeFiles and deleteFiles."
        ),
        IdentityCredentialProfile(
            identity_name="Processor (Curated Publishing)",
            role="processor",
            target_bucket=settings.B2_CURATED_BUCKET or "Unset",
            access_key_masked=mask_credential(settings.B2_PROCESSOR_CURATED_ACCESS_KEY_ID),
            is_configured=bool(settings.B2_PROCESSOR_CURATED_ACCESS_KEY_ID and settings.B2_PROCESSOR_CURATED_SECRET_ACCESS_KEY),
            intended_capabilities=["listFiles", "writeFiles"],
            cloud_restrictions="Scoped exclusively to CURATED bucket; denied deleteFiles."
        ),
        IdentityCredentialProfile(
            identity_name="Analyst (Curated Consumer)",
            role="analyst",
            target_bucket=settings.B2_CURATED_BUCKET or "Unset",
            access_key_masked=mask_credential(settings.B2_ANALYST_CURATED_ACCESS_KEY_ID),
            is_configured=bool(settings.B2_ANALYST_CURATED_ACCESS_KEY_ID and settings.B2_ANALYST_CURATED_SECRET_ACCESS_KEY),
            intended_capabilities=["listFiles", "readFiles"],
            cloud_restrictions="Scoped exclusively to CURATED bucket; strictly denied access to RAW and AUDIT buckets."
        ),
    ]

    if settings.B2_ADMIN_ACCESS_KEY_ID:
        profiles.append(
            IdentityCredentialProfile(
                identity_name="Administrator (Diagnostic/Audit)",
                role="admin",
                target_bucket="All Configured Buckets",
                access_key_masked=mask_credential(settings.B2_ADMIN_ACCESS_KEY_ID),
                is_configured=bool(settings.B2_ADMIN_ACCESS_KEY_ID and settings.B2_ADMIN_SECRET_ACCESS_KEY),
                intended_capabilities=["listBuckets", "listFiles", "readFiles", "writeFiles"],
                cloud_restrictions="Admin operations restricted by application policy from deleting raw source evidence."
            )
        )

    return profiles
