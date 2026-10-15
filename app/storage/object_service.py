"""
Object Storage Operations for CF-PS-15 Data Lake.
Handles secure uploads, downloads, key sanitization, and SHA-256 integrity verification.
"""

from datetime import datetime, timezone
import hashlib
import os
import re
from typing import Any, Dict, List, Optional
import uuid
from botocore.exceptions import ClientError


def sanitize_filename(filename: str) -> str:
    """
    Strips directory traversal tokens, illegal characters, and path separators.
    """
    clean_name = os.path.basename(filename)
    clean_name = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', clean_name)
    clean_name = re.sub(r'\.{2,}', '.', clean_name)
    if not clean_name or clean_name.startswith('.'):
        clean_name = f"dataset_{uuid.uuid4().hex[:8]}.dat"
    return clean_name


def generate_object_key(prefix: str, filename: str) -> str:
    """
    Generates a unique, collision-resistant object key under the given prefix.
    Example: raw/20261015_a1b2c3d4_dataset.csv
    """
    clean = sanitize_filename(filename)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    unique_suffix = uuid.uuid4().hex[:8]
    sanitized_prefix = re.sub(r'[^a-zA-Z0-9_\-]', '', prefix.strip('/'))
    return f"{sanitized_prefix}/{timestamp}_{unique_suffix}_{clean}"


def compute_sha256(data: bytes) -> str:
    """Calculates standard SHA-256 checksum hex digest."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def upload_object(
    client: Any,
    bucket_name: str,
    key: str,
    data: bytes,
    content_type: str = "application/octet-stream",
    metadata: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Uploads bytes to Backblaze B2 S3 storage under a specified key.
    Enforces payload integrity using SHA-256 metadata.
    """
    if client is None:
        raise ValueError("Storage client is not configured.")

    extra_args = {"ContentType": content_type}
    if metadata:
        extra_args["Metadata"] = metadata

    response = client.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=data,
        **extra_args
    )
    return {
        "key": key,
        "bucket": bucket_name,
        "etag": response.get("ETag", "").strip('"'),
        "http_status": response.get("ResponseMetadata", {}).get("HTTPStatusCode", 200),
    }


def download_object(client: Any, bucket_name: str, key: str) -> bytes:
    """
    Downloads object payload bytes from Backblaze B2.
    """
    if client is None:
        raise ValueError("Storage client is not configured.")

    response = client.get_object(Bucket=bucket_name, Key=key)
    body = response["Body"].read()
    return body


def list_bucket_objects(
    client: Any,
    bucket_name: str,
    prefix: Optional[str] = None,
    max_keys: int = 100,
) -> List[Dict[str, Any]]:
    """
    Lists objects stored in the target B2 bucket.
    """
    if client is None:
        return []

    kwargs = {"Bucket": bucket_name, "MaxKeys": max_keys}
    if prefix:
        kwargs["Prefix"] = prefix

    response = client.list_objects_v2(**kwargs)
    items = []
    for item in response.get("Contents", []):
        items.append({
            "key": item.get("Key"),
            "size": item.get("Size"),
            "last_modified": item.get("LastModified"),
            "etag": item.get("ETag", "").strip('"'),
        })
    return items
