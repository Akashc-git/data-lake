"""
Data Processing Pipeline for CF-PS-15 Data Lake.
Orchestrates reading from private raw storage with processor read credentials,
validating schema, applying pandas transformations, and publishing curated datasets
to the private curated bucket with processor write credentials.
"""

from datetime import datetime, timezone
import io
import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

from fastapi import HTTPException, status
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit.logger import log_security_event
from app.audit.models import AuditOutcome
from app.auth.models import User, UserRole
from app.config import get_settings
from app.datasets.ingestion import parse_dataset_bytes_to_df
from app.datasets.metadata import DatasetRecord, DatasetBucketType, ProcessingJob, ProcessingStatus
from app.datasets.validation import validate_dataframe
from app.storage.b2_client import get_processor_raw_client, get_processor_curated_client
from app.storage.object_service import compute_sha256, download_object, generate_object_key, upload_object

logger = logging.getLogger("pipeline")
settings = get_settings()


class CleaningConfig(BaseModel):
    handle_missing: str = Field(default="drop", description="Strategy: 'drop', 'impute', or 'none'")
    remove_duplicates: bool = Field(default=True, description="Drop duplicate records")
    clean_column_headers: bool = Field(default=True, description="Standardize headers to snake_case")
    output_format: str = Field(default="csv", description="Output serialization format ('csv' or 'parquet')")


def clean_dataframe(df: pd.DataFrame, config: CleaningConfig) -> Tuple[pd.DataFrame, int, int]:
    """
    Applies configurable transformation and sanitization rules to the DataFrame.
    Returns: (cleaned_df, missing_handled_count, duplicates_removed_count)
    """
    df_transformed = df.copy()
    initial_rows = len(df_transformed)

    # 1. Clean column headers
    if config.clean_column_headers:
        df_transformed.columns = [
            str(col).strip().lower().replace(' ', '_').replace('-', '_')
            for col in df_transformed.columns
        ]

    # 2. Duplicate detection and removal
    duplicates_removed = 0
    if config.remove_duplicates:
        dups = df_transformed.duplicated().sum()
        duplicates_removed = int(dups)
        df_transformed = df_transformed.drop_duplicates().reset_index(drop=True)

    # 3. Missing values handling
    missing_handled = 0
    total_nulls = int(df_transformed.isnull().sum().sum())
    if config.handle_missing == "drop":
        before_drop = len(df_transformed)
        df_transformed = df_transformed.dropna().reset_index(drop=True)
        missing_handled = before_drop - len(df_transformed)
    elif config.handle_missing == "impute":
        for col in df_transformed.columns:
            if df_transformed[col].isnull().sum() > 0:
                if pd.api.types.is_numeric_dtype(df_transformed[col]):
                    fill_val = df_transformed[col].median()
                    df_transformed[col] = df_transformed[col].fillna(fill_val)
                else:
                    mode_series = df_transformed[col].mode()
                    fill_val = mode_series.iloc[0] if not mode_series.empty else "UNKNOWN"
                    df_transformed[col] = df_transformed[col].fillna(fill_val)
        missing_handled = total_nulls

    return df_transformed, missing_handled, duplicates_removed


def serialize_df_to_bytes(df: pd.DataFrame, fmt: str) -> Tuple[bytes, str]:
    """Serializes DataFrame to byte buffer and MIME type."""
    fmt = fmt.lower().strip('.')
    buf = io.BytesIO()
    if fmt == "csv":
        df.to_csv(buf, index=False)
        return buf.getvalue(), "text/csv"
    elif fmt == "parquet":
        df.to_parquet(buf, index=False)
        return buf.getvalue(), "application/vnd.apache.parquet"
    elif fmt == "json":
        df.to_json(buf, orient="records", indent=2)
        return buf.getvalue(), "application/json"
    else:
        df.to_csv(buf, index=False)
        return buf.getvalue(), "text/csv"


def run_pipeline(
    db: Session,
    user: User,
    raw_dataset_id: str,
    config: Optional[CleaningConfig] = None,
    correlation_id: Optional[str] = None,
) -> ProcessingJob:
    """
    Executes end-to-end data processing workflow:
    1. Authenticates Processor identity.
    2. Downloads raw dataset from private raw B2 bucket using Processor RAW read key.
    3. Audits schema and validates data.
    4. Applies transformations (missing values, deduplication, schema normalization).
    5. Serializes curated dataset and computes output SHA-256.
    6. Publishes to private curated B2 bucket using Processor CURATED write key.
    7. Persists dataset metadata and execution job history.
    """
    cid = correlation_id or str(uuid.uuid4())
    cleaning_cfg = config or CleaningConfig()
    start_time = time.time()
    started_at = datetime.now(timezone.utc)

    # 1. Retrieve raw record
    raw_record = db.query(DatasetRecord).filter(DatasetRecord.id == raw_dataset_id).first()
    if not raw_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Raw dataset with ID '{raw_dataset_id}' not found."
        )

    if raw_record.bucket_type != DatasetBucketType.RAW.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target dataset '{raw_dataset_id}' is already a curated dataset. Ingestion pipeline accepts raw datasets only."
        )

    # 2. Check storage clients
    raw_client = get_processor_raw_client()
    curated_client = get_processor_curated_client()

    if not raw_client or not curated_client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="B2 storage credentials for Processor (raw read and curated write) must be configured in .env."
        )

    # Initialize job tracking record
    job = ProcessingJob(
        id=str(uuid.uuid4()),
        raw_dataset_id=raw_record.id,
        status="RUNNING",
        input_row_count=raw_record.row_count or 0,
        initiated_by=user.username,
        started_at=started_at,
    )
    db.add(job)
    db.commit()

    try:
        # 3. Read original raw object from Backblaze B2 raw bucket
        raw_bytes = download_object(
            client=raw_client,
            bucket_name=raw_record.bucket_name,
            key=raw_record.object_key,
        )

        # 4. Parse DataFrame
        df_raw = parse_dataset_bytes_to_df(raw_bytes, raw_record.file_format)
        input_rows = len(df_raw)
        job.input_row_count = input_rows

        # Validation audit
        val_report = validate_dataframe(df_raw)
        job.validation_warnings = json.dumps(val_report.warnings)

        # 5. Transform and clean
        df_cleaned, missing_handled, dups_removed = clean_dataframe(df_raw, cleaning_cfg)
        output_rows = len(df_cleaned)

        # 6. Serialize output
        curated_bytes, content_type = serialize_df_to_bytes(df_cleaned, cleaning_cfg.output_format)
        curated_checksum = compute_sha256(curated_bytes)
        curated_size = len(curated_bytes)

        # 7. Generate unique curated object key
        clean_ext = cleaning_cfg.output_format.lower().strip('.')
        curated_filename = f"curated_{raw_record.original_filename.rsplit('.', 1)[0]}.{clean_ext}"
        curated_key = generate_object_key("curated", curated_filename)

        # 8. Upload to private curated B2 bucket
        curated_bucket = settings.B2_CURATED_BUCKET
        upload_res = upload_object(
            client=curated_client,
            bucket_name=curated_bucket,
            key=curated_key,
            data=curated_bytes,
            content_type=content_type,
            metadata={
                "sha256": curated_checksum,
                "curated_from": raw_record.id,
                "processed_by": user.username,
            }
        )

        # 9. Register curated dataset record
        curated_record = DatasetRecord(
            id=str(uuid.uuid4()),
            dataset_name=f"Curated - {raw_record.dataset_name}",
            bucket_type=DatasetBucketType.CURATED.value,
            bucket_name=curated_bucket,
            object_key=curated_key,
            source_url=raw_record.source_url,
            retrieval_timestamp=datetime.now(timezone.utc),
            original_filename=curated_filename,
            file_format=clean_ext,
            file_size_bytes=curated_size,
            sha256_checksum=curated_checksum,
            row_count=output_rows,
            column_names=json.dumps([str(c) for c in df_cleaned.columns]),
            processing_status=ProcessingStatus.PROCESSED.value,
            created_by=user.username,
            curated_from_id=raw_record.id,
        )
        db.add(curated_record)

        # Update raw record status
        raw_record.processing_status = ProcessingStatus.PROCESSED.value

        # Complete job record
        duration = round(time.time() - start_time, 3)
        job.curated_dataset_id = curated_record.id
        job.status = "SUCCESS"
        job.output_row_count = output_rows
        job.missing_values_handled = missing_handled
        job.duplicates_removed = dups_removed
        job.output_object_key = curated_key
        job.output_checksum = curated_checksum
        job.completed_at = datetime.now(timezone.utc)
        job.duration_seconds = duration

        db.commit()
        db.refresh(job)

        # Audit event
        log_security_event(
            db=db,
            actor_username=user.username,
            actor_role=user.role,
            operation="PROCESS_DATASET_SUCCESS",
            resource=curated_key,
            outcome=AuditOutcome.ALLOWED,
            status_code=status.HTTP_200_OK,
            correlation_id=cid,
            reason="Pipeline completed transformation and published curated dataset to B2 curated bucket.",
            enforcement_layer="Cloud B2 IAM & Application RBAC",
            details={
                "job_id": job.id,
                "raw_id": raw_record.id,
                "curated_id": curated_record.id,
                "input_rows": input_rows,
                "output_rows": output_rows,
                "missing_handled": missing_handled,
                "duplicates_removed": dups_removed,
                "curated_checksum": curated_checksum,
            }
        )

        return job

    except Exception as exc:
        duration = round(time.time() - start_time, 3)
        job.status = "FAILED"
        job.error_details = str(exc)
        job.completed_at = datetime.now(timezone.utc)
        job.duration_seconds = duration
        db.commit()

        log_security_event(
            db=db,
            actor_username=user.username,
            actor_role=user.role,
            operation="PROCESS_DATASET_FAILED",
            resource=raw_record.object_key,
            outcome=AuditOutcome.FAILED,
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            correlation_id=cid,
            reason=f"Pipeline processing failed: {exc}",
            enforcement_layer="Cloud B2 IAM & Application RBAC",
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Data processing pipeline failed: {exc}"
        )
