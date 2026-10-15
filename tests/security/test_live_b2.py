"""
Live Backblaze B2 Cloud Integration Tests.
Executes real operations against configured B2 buckets using identity-scoped credentials.
Separated strictly from unit tests. Automatically skipped if credentials are not configured.
"""

import uuid
import pytest
from botocore.exceptions import ClientError, ConnectionClosedError

from app.config import get_settings
from app.storage.b2_client import (
    get_analyst_curated_client,
    get_processor_curated_client,
    get_processor_raw_client,
)
from app.storage.object_service import download_object, upload_object

settings = get_settings()

PROBE_PREFIX = "_live_integration_probe"


@pytest.mark.skipif(
    not settings.is_b2_configured,
    reason="Requires active Backblaze B2 credentials in .env. Run scripts/check_b2_connection.py first.",
)
def test_live_b2_processor_raw_read():
    """Live test: Processor credentials can read objects in raw bucket."""
    raw_client = get_processor_raw_client()
    assert raw_client is not None

    # Probe list objects
    response = raw_client.list_objects_v2(Bucket=settings.B2_RAW_BUCKET, MaxKeys=5)
    assert response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200


@pytest.mark.skipif(
    not settings.is_b2_configured,
    reason="Requires active Backblaze B2 credentials in .env.",
)
def test_live_b2_processor_curated_write():
    """Live test: Processor credentials can write curated outputs to curated bucket."""
    curated_client = get_processor_curated_client()
    assert curated_client is not None

    probe_key = f"{PROBE_PREFIX}_{uuid.uuid4().hex[:8]}.txt"
    probe_body = b"CF-PS-15 Live Integration Curated Output"

    res = upload_object(
        client=curated_client,
        bucket_name=settings.B2_CURATED_BUCKET,
        key=probe_key,
        data=probe_body,
        content_type="text/plain",
    )
    assert res.get("http_status") == 200


@pytest.mark.skipif(
    not settings.is_b2_configured,
    reason="Requires active Backblaze B2 credentials in .env.",
)
def test_live_b2_analyst_denied_raw_bucket():
    """Live test: Analyst credentials are denied from listing or reading raw bucket."""
    analyst_client = get_analyst_curated_client()
    assert analyst_client is not None

    with pytest.raises(ClientError) as exc_info:
        analyst_client.list_objects_v2(Bucket=settings.B2_RAW_BUCKET, MaxKeys=1)

    code = exc_info.value.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code in (403, 400, 401), f"Expected cloud denial (403/400), got {code}"


@pytest.mark.skipif(
    not settings.is_b2_configured,
    reason="Requires active Backblaze B2 credentials in .env.",
)
def test_live_b2_analyst_denied_curated_write():
    """Live test: Analyst credentials cannot upload or write to curated bucket."""
    analyst_client = get_analyst_curated_client()
    assert analyst_client is not None

    probe_key = f"{PROBE_PREFIX}_unauthorized_write.txt"
    with pytest.raises((ClientError, ConnectionClosedError)) as exc_info:
        analyst_client.put_object(
            Bucket=settings.B2_CURATED_BUCKET,
            Key=probe_key,
            Body=b"Prohibited analyst write attempt",
        )

    # Cloud boundary verified: B2 rejects the request via 403 ClientError or socket reset
    assert exc_info.value is not None
