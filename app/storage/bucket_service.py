"""
Bucket Operations and Connectivity Verification for CF-PS-15.
Provides real-time cloud reachability testing and storage metrics against Backblaze B2.
"""

from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError, EndpointConnectionError
import logging

logger = logging.getLogger("bucket_service")


def verify_bucket_reachability(client: Any, bucket_name: str) -> Dict[str, Any]:
    """
    Executes a real cloud probe to determine if the target bucket is reachable
    and accessible with the provided credential.
    """
    if client is None:
        return {
            "bucket": bucket_name,
            "status": "UNCONFIGURED",
            "reachable": False,
            "message": "B2 credentials or endpoint not configured in environment.",
            "error_code": "NO_CREDENTIALS"
        }

    if not bucket_name:
        return {
            "bucket": "UNSET",
            "status": "UNCONFIGURED",
            "reachable": False,
            "message": "Bucket name is not configured in environment.",
            "error_code": "EMPTY_BUCKET_NAME"
        }

    try:
        # First attempt: list_objects_v2 to test read/list capability
        response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
        return {
            "bucket": bucket_name,
            "status": "CONNECTED",
            "reachable": True,
            "message": "Bucket verified accessible via B2 S3 API (Read/List capability).",
            "http_status": response.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
        }
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "UnknownClientError")
        msg = exc.response.get("Error", {}).get("Message", str(exc))
        http_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")

        # Second attempt: If list is denied (e.g., write-only application key), probe put_object capability
        try:
            probe_resp = client.put_object(
                Bucket=bucket_name,
                Key="_reachability_probe.tmp",
                Body=b"probe"
            )
            return {
                "bucket": bucket_name,
                "status": "CONNECTED",
                "reachable": True,
                "message": "Bucket verified accessible via B2 S3 API (Write capability).",
                "http_status": probe_resp.get("ResponseMetadata", {}).get("HTTPStatusCode", 200)
            }
        except Exception:
            pass

        return {
            "bucket": bucket_name,
            "status": "DENIED" if http_status in (403, 401) else "ERROR",
            "reachable": False,
            "message": f"Cloud rejected request: {msg}",
            "error_code": code,
            "http_status": http_status
        }
    except EndpointConnectionError as exc:
        return {
            "bucket": bucket_name,
            "status": "UNREACHABLE",
            "reachable": False,
            "message": f"Network failure contacting B2 endpoint: {exc}",
            "error_code": "ENDPOINT_CONNECTION_ERROR"
        }
    except Exception as exc:
        return {
            "bucket": bucket_name,
            "status": "ERROR",
            "reachable": False,
            "message": f"Unexpected error probing bucket: {exc}",
            "error_code": type(exc).__name__
        }


def get_bucket_storage_stats(client: Any, bucket_name: str) -> Dict[str, Any]:
    """
    Aggregates real cloud metrics: total object count and cumulative bytes stored.
    """
    if client is None or not bucket_name:
        return {
            "bucket": bucket_name or "UNSET",
            "object_count": 0,
            "total_size_bytes": 0,
            "accessible": False,
            "error": "Credentials or bucket unconfigured"
        }

    total_count = 0
    total_bytes = 0
    continuation_token = None

    try:
        while True:
            kwargs = {"Bucket": bucket_name, "MaxKeys": 1000}
            if continuation_token:
                kwargs["ContinuationToken"] = continuation_token

            response = client.list_objects_v2(**kwargs)
            contents = response.get("Contents", [])
            total_count += len(contents)
            total_bytes += sum(item.get("Size", 0) for item in contents)

            if response.get("IsTruncated"):
                continuation_token = response.get("NextContinuationToken")
            else:
                break

        return {
            "bucket": bucket_name,
            "object_count": total_count,
            "total_size_bytes": total_bytes,
            "accessible": True,
            "error": None
        }
    except Exception as exc:
        return {
            "bucket": bucket_name,
            "object_count": 0,
            "total_size_bytes": 0,
            "accessible": False,
            "error": str(exc)
        }
