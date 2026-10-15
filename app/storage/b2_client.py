"""
Backblaze B2 S3-Compatible Client Factory.
Initializes identity-scoped boto3 S3 clients adhering strictly to the principle of least privilege.
"""

from typing import Any, Dict, Optional
import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, EndpointConnectionError

from app.config import get_settings

settings = get_settings()


def create_b2_client(
    access_key_id: Optional[str],
    secret_access_key: Optional[str],
    endpoint_url: Optional[str] = None,
    region_name: Optional[str] = None,
) -> Optional[Any]:
    """
    Creates a boto3 S3 client configured for Backblaze B2 S3-compatible API.
    Returns None if access key or secret are unconfigured or empty.
    """
    key_id = (access_key_id or "").strip()
    secret = (secret_access_key or "").strip()
    endpoint = (endpoint_url or settings.B2_ENDPOINT_URL or "").strip()
    if endpoint and not endpoint.startswith(("http://", "https://")):
        endpoint = f"https://{endpoint}"
    region = (region_name or settings.B2_REGION or "us-east-005").strip()

    if not key_id or not secret or not endpoint:
        return None

    # Enforce S3v4 signature standard used by Backblaze B2
    b2_config = Config(
        signature_version="s3v4",
        retries={"max_attempts": 3, "mode": "standard"},
        connect_timeout=10,
        read_timeout=30,
    )

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=key_id,
        aws_secret_access_key=secret,
        region_name=region,
        config=b2_config,
    )
    return client


def get_processor_raw_client() -> Optional[Any]:
    """Client for Processor reading from raw bucket."""
    return create_b2_client(
        settings.B2_PROCESSOR_RAW_ACCESS_KEY_ID,
        settings.B2_PROCESSOR_RAW_SECRET_ACCESS_KEY,
    )


def get_processor_curated_client() -> Optional[Any]:
    """Client for Processor publishing to curated bucket."""
    return create_b2_client(
        settings.B2_PROCESSOR_CURATED_ACCESS_KEY_ID,
        settings.B2_PROCESSOR_CURATED_SECRET_ACCESS_KEY,
    )


def get_analyst_curated_client() -> Optional[Any]:
    """Client for Analyst reading from curated bucket."""
    return create_b2_client(
        settings.B2_ANALYST_CURATED_ACCESS_KEY_ID,
        settings.B2_ANALYST_CURATED_SECRET_ACCESS_KEY,
    )


def get_admin_client() -> Optional[Any]:
    """Diagnostic/Setup client with administrative credentials if provided."""
    if settings.B2_ADMIN_ACCESS_KEY_ID and settings.B2_ADMIN_SECRET_ACCESS_KEY:
        return create_b2_client(
            settings.B2_ADMIN_ACCESS_KEY_ID,
            settings.B2_ADMIN_SECRET_ACCESS_KEY,
        )
    return None
