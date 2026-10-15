"""
Backblaze B2 Connectivity and Credentials Diagnostic Script.
Verifies real cloud reachability and bucket accessibility for all identities.
Usage:
    python -m scripts.check_b2_connection
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.config import get_settings
from app.security.credentials import mask_credential
from app.storage.b2_client import (
    get_processor_raw_client,
    get_processor_curated_client,
    get_analyst_curated_client,
    get_admin_client,
)
from app.storage.bucket_service import verify_bucket_reachability, get_bucket_storage_stats

settings = get_settings()


def check_b2_connection():
    print("=" * 75)
    print("CF-PS-15 BACKBLAZE B2 S3 API CONNECTIVITY DIAGNOSTICS")
    print("=" * 75)

    print(f"\nConfiguration Posture:")
    print(f"  Endpoint URL:    {settings.B2_ENDPOINT_URL or '[NOT CONFIGURED]'}")
    print(f"  Region:          {settings.B2_REGION or '[NOT CONFIGURED]'}")
    print(f"  Raw Bucket:      {settings.B2_RAW_BUCKET or '[NOT CONFIGURED]'}")
    print(f"  Curated Bucket:  {settings.B2_CURATED_BUCKET or '[NOT CONFIGURED]'}")
    print(f"  Audit Bucket:    {settings.B2_AUDIT_BUCKET or '[NOT CONFIGURED]'}")

    identities = [
        {
            "name": "Processor (Raw Ingestion)",
            "key_id": settings.B2_PROCESSOR_RAW_ACCESS_KEY_ID,
            "target_bucket": settings.B2_RAW_BUCKET,
            "client_getter": get_processor_raw_client,
        },
        {
            "name": "Processor (Curated Publishing)",
            "key_id": settings.B2_PROCESSOR_CURATED_ACCESS_KEY_ID,
            "target_bucket": settings.B2_CURATED_BUCKET,
            "client_getter": get_processor_curated_client,
        },
        {
            "name": "Analyst (Curated Reading)",
            "key_id": settings.B2_ANALYST_CURATED_ACCESS_KEY_ID,
            "target_bucket": settings.B2_CURATED_BUCKET,
            "client_getter": get_analyst_curated_client,
        },
    ]

    if settings.B2_ADMIN_ACCESS_KEY_ID:
        identities.append({
            "name": "Administrator (Setup/Diagnostic)",
            "key_id": settings.B2_ADMIN_ACCESS_KEY_ID,
            "target_bucket": settings.B2_AUDIT_BUCKET or settings.B2_CURATED_BUCKET,
            "client_getter": get_admin_client,
        })

    print("\nProbing Identity-Scoped Cloud Credentials:")
    for id_info in identities:
        print(f"\n--- Testing: {id_info['name']} ---")
        masked_key = mask_credential(id_info["key_id"])
        print(f"  Access Key ID:  {masked_key}")
        print(f"  Target Bucket:  {id_info['target_bucket'] or '[Unset]'}")

        client = id_info["client_getter"]()
        if not client:
            print("  [STATUS] UNCONFIGURED: Missing credentials or endpoint in .env.")
            continue

        probe = verify_bucket_reachability(client, id_info["target_bucket"])
        if probe["reachable"]:
            print(f"  [STATUS] CONNECTED (HTTP {probe.get('http_status', 200)})")
            stats = get_bucket_storage_stats(client, id_info["target_bucket"])
            print(f"           Live Objects in Bucket: {stats.get('object_count', 0)}")
            print(f"           Total Bytes Stored:     {stats.get('total_size_bytes', 0):,} bytes")
        else:
            print(f"  [STATUS] {probe['status']}: {probe['message']}")

    # Security Isolation Probe: Verify Analyst cannot read raw bucket
    print("\n--- Testing Cloud Boundary Isolation (Analyst -> Raw Bucket) ---")
    analyst_client = get_analyst_curated_client()
    if analyst_client and settings.B2_RAW_BUCKET:
        isolation_probe = verify_bucket_reachability(analyst_client, settings.B2_RAW_BUCKET)
        if not isolation_probe["reachable"] and isolation_probe.get("http_status") in (403, 401):
            print("  [VERIFIED] Cloud B2 rejected Analyst listing Raw Bucket (Access Denied as intended).")
        elif isolation_probe["reachable"]:
            print("  [SECURITY ALERT] Analyst was able to list Raw Bucket! Cloud boundary violation.")
        else:
            print(f"  [RESULT] {isolation_probe['status']}: {isolation_probe['message']}")
    else:
        print("  [SKIPPED] Analyst credentials or raw bucket not configured.")

    print("\n" + "=" * 75)
    print("DIAGNOSTIC SUMMARY COMPLETE")
    print("=" * 75)


if __name__ == "__main__":
    check_b2_connection()
