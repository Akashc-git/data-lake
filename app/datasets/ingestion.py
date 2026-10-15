"""
Dataset Ingestion Service for CF-PS-15 Data Lake.
Handles real file uploads, remote public URL ingestion with anti-SSRF protections,
cloud verification in Backblaze B2 raw bucket, and metadata registration.
"""

from datetime import datetime, timezone
import io
import json
import logging
from typing import Optional, Tuple
import uuid

from fastapi import HTTPException, status
import pandas as pd
import requests
from sqlalchemy.orm import Session

from app.audit.logger import log_security_event
from app.audit.models import AuditOutcome
from app.auth.models import User
from app.config import get_settings
from app.datasets.metadata import DatasetRecord, DatasetBucketType, ProcessingStatus
from app.datasets.validation import validate_dataframe, validate_public_dataset_url
from app.storage.b2_client import get_processor_raw_client
from app.storage.object_service import compute_sha256, generate_object_key, upload_object

logger = logging.getLogger("ingestion")
settings = get_settings()


def parse_dataset_bytes_to_df(data: bytes, file_format: str) -> pd.DataFrame:
    """Safely parses byte buffer into a pandas DataFrame."""
    buf = io.BytesIO(data)
    fmt = file_format.lower().strip('.')
    if fmt == "csv":
        return pd.read_csv(buf)
    elif fmt == "json":
        return pd.read_json(buf)
    elif fmt == "parquet":
        return pd.read_parquet(buf)
    else:
        raise ValueError(f"Unsupported format '{file_format}'. Supported formats: csv, json, parquet.")


def ingest_raw_dataset_bytes(
    db: Session,
    user: User,
    data: bytes,
    original_filename: str,
    dataset_name: Optional[str] = None,
    source_url: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> DatasetRecord:
    """
    Ingests and registers a raw dataset into Backblaze B2 raw storage.
    Enforces size limits, content integrity, and processor role validation.
    """
    cid = correlation_id or str(uuid.uuid4())
    file_size = len(data)

    if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File size ({file_size} bytes) exceeds maximum allowable limit ({settings.MAX_UPLOAD_SIZE_BYTES} bytes)."
        )

    ext = original_filename.split('.')[-1].lower() if '.' in original_filename else ""
    if ext not in ("csv", "json", "parquet"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file extension '.{ext}'. Supported extensions are .csv, .json, .parquet."
        )

    # Calculate SHA-256 Checksum
    checksum = compute_sha256(data)

    # Validate structure with pandas
    try:
        df = parse_dataset_bytes_to_df(data, ext)
        val_report = validate_dataframe(df)
        row_count = val_report.row_count
        columns = val_report.columns
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {ext.upper()} dataset content: {exc}"
        )

    # Verify B2 client configuration
    b2_client = get_processor_raw_client()
    raw_bucket = settings.B2_RAW_BUCKET

    if not b2_client or not raw_bucket:
        log_security_event(
            db=db,
            actor_username=user.username,
            actor_role=user.role,
            operation="RAW_INGESTION_ATTEMPT",
            resource=f"raw/{original_filename}",
            outcome=AuditOutcome.INCONCLUSIVE,
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            correlation_id=cid,
            reason="Backblaze B2 raw bucket or processor credentials are not configured in environment.",
            enforcement_layer="Cloud B2 IAM",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud storage unconfigured: B2_RAW_BUCKET and B2_PROCESSOR_RAW credentials must be set in .env."
        )

    # Generate isolated object key in raw/ prefix
    object_key = generate_object_key("raw", original_filename)

    # Upload to real Backblaze B2 raw bucket
    content_type_map = {
        "csv": "text/csv",
        "json": "application/json",
        "parquet": "application/vnd.apache.parquet"
    }
    content_type = content_type_map.get(ext, "application/octet-stream")

    try:
        upload_res = upload_object(
            client=b2_client,
            bucket_name=raw_bucket,
            key=object_key,
            data=data,
            content_type=content_type,
            metadata={"sha256": checksum, "ingested_by": user.username}
        )
    except Exception as exc:
        log_security_event(
            db=db,
            actor_username=user.username,
            actor_role=user.role,
            operation="RAW_UPLOAD_FAILED",
            resource=object_key,
            outcome=AuditOutcome.FAILED,
            status_code=status.HTTP_502_BAD_GATEWAY,
            correlation_id=cid,
            reason=f"Failed to upload raw object to B2: {exc}",
            enforcement_layer="Cloud B2 IAM",
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Cloud upload to Backblaze B2 failed: {exc}"
        )

    # Create dataset record
    ds_record = DatasetRecord(
        id=str(uuid.uuid4()),
        dataset_name=dataset_name or original_filename,
        bucket_type=DatasetBucketType.RAW.value,
        bucket_name=raw_bucket,
        object_key=object_key,
        source_url=source_url,
        retrieval_timestamp=datetime.now(timezone.utc),
        original_filename=original_filename,
        file_format=ext,
        file_size_bytes=file_size,
        sha256_checksum=checksum,
        row_count=row_count,
        column_names=json.dumps(columns),
        processing_status=ProcessingStatus.RAW_INGESTED.value,
        created_by=user.username,
    )
    db.add(ds_record)
    db.commit()
    db.refresh(ds_record)

    # Audit log entry
    log_security_event(
        db=db,
        actor_username=user.username,
        actor_role=user.role,
        operation="INGEST_RAW_DATASET",
        resource=object_key,
        outcome=AuditOutcome.ALLOWED,
        status_code=status.HTTP_201_CREATED,
        correlation_id=cid,
        reason="Dataset successfully ingested and verified in private raw storage.",
        enforcement_layer="Cloud B2 IAM & Application RBAC",
        details={
            "dataset_id": ds_record.id,
            "file_size": file_size,
            "row_count": row_count,
            "sha256": checksum,
            "etag": upload_res.get("etag")
        }
    )

    return ds_record


def ingest_from_public_url(
    db: Session,
    user: User,
    source_url: str,
    dataset_name: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> DatasetRecord:
    """
    Downloads a public dataset from a validated URL and ingests it into B2 raw bucket.
    Enforces anti-SSRF protections and streaming byte limits.
    """
    is_safe, reason = validate_public_dataset_url(source_url)
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL validation failed: {reason}"
        )

    try:
        response = requests.get(
            source_url,
            timeout=settings.INGESTION_TIMEOUT_SECONDS,
            stream=True,
            headers={"User-Agent": "CF-PS15-DataLakeIngest/1.0"}
        )
        response.raise_for_status()

        # Stream download with maximum size enforcement
        content_bytes = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            content_bytes.extend(chunk)
            if len(content_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Remote dataset exceeds maximum allowed size ({settings.MAX_UPLOAD_SIZE_BYTES} bytes)."
                )

        data = bytes(content_bytes)
    except requests.RequestException as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to fetch remote dataset from URL: {exc}"
        )

    # Extract filename from URL or default
    url_path = source_url.split('?')[0]
    filename = url_path.split('/')[-1]
    if not filename or '.' not in filename:
        filename = "public_dataset.csv"

    return ingest_raw_dataset_bytes(
        db=db,
        user=user,
        data=data,
        original_filename=filename,
        dataset_name=dataset_name or filename,
        source_url=source_url,
        correlation_id=correlation_id,
    )
