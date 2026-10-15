"""
Dataset API Endpoints for CF-PS-15 Data Lake.
Enforces strict role-based access control, object isolation, IDOR prevention,
and separate cloud credentials for raw and curated data operations.
"""

from datetime import datetime, timezone
import io
import json
import logging
from typing import Any, Dict, List, Optional
import uuid

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.audit.logger import log_security_event
from app.audit.models import AuditOutcome
from app.auth.dependencies import get_current_user, get_db, require_role
from app.auth.models import User, UserRole
from app.authorization.enforcement import enforce_access
from app.authorization.policies import ActionType, ResourceType
from app.config import get_settings
from app.datasets.ingestion import ingest_raw_dataset_bytes, ingest_from_public_url
from app.datasets.metadata import (
    DatasetBucketType,
    DatasetMetadataResponse,
    DatasetRecord,
    ProcessingJobResponse,
)
from app.processing.pipeline import CleaningConfig, run_pipeline
from app.storage.b2_client import (
    get_analyst_curated_client,
    get_processor_curated_client,
    get_processor_raw_client,
    get_admin_client,
)
from app.storage.object_service import download_object

logger = logging.getLogger("datasets_api")
settings = get_settings()

router = APIRouter(prefix="/datasets", tags=["Datasets"])


class RemoteIngestionRequest(BaseModel):
    source_url: str
    dataset_name: Optional[str] = None


class ProcessRequest(BaseModel):
    raw_dataset_id: str
    handle_missing: str = "drop"
    remove_duplicates: bool = True
    clean_column_headers: bool = True
    output_format: str = "csv"


@router.get("/raw", response_model=List[DatasetMetadataResponse])
def list_raw_datasets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Lists raw datasets.
    Processor and Admin only. Analyst role is strictly rejected with 403 Forbidden.
    """
    enforce_access(
        user=current_user,
        resource_type=ResourceType.RAW_DATASET,
        action=ActionType.LIST,
        resource_name="raw_datasets_list",
        db=db,
    )

    records = (
        db.query(DatasetRecord)
        .filter(DatasetRecord.bucket_type == DatasetBucketType.RAW.value)
        .order_by(desc(DatasetRecord.created_at))
        .all()
    )

    # Format column_names JSON to list
    results = []
    for r in records:
        cols = json.loads(r.column_names) if r.column_names else []
        results.append(
            DatasetMetadataResponse(
                id=r.id,
                dataset_name=r.dataset_name,
                bucket_type=r.bucket_type,
                bucket_name=r.bucket_name,
                object_key=r.object_key,
                source_url=r.source_url,
                retrieval_timestamp=r.retrieval_timestamp,
                original_filename=r.original_filename,
                file_format=r.file_format,
                file_size_bytes=r.file_size_bytes,
                sha256_checksum=r.sha256_checksum,
                row_count=r.row_count,
                column_names=cols,
                processing_status=r.processing_status,
                created_by=r.created_by,
                curated_from_id=r.curated_from_id,
                created_at=r.created_at,
            )
        )
    return results


@router.get("/curated", response_model=List[DatasetMetadataResponse])
def list_curated_datasets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Lists validated curated datasets.
    Permitted for Analyst, Processor, and Admin.
    """
    enforce_access(
        user=current_user,
        resource_type=ResourceType.CURATED_DATASET,
        action=ActionType.LIST,
        resource_name="curated_datasets_list",
        db=db,
    )

    records = (
        db.query(DatasetRecord)
        .filter(DatasetRecord.bucket_type == DatasetBucketType.CURATED.value)
        .order_by(desc(DatasetRecord.created_at))
        .all()
    )

    results = []
    for r in records:
        cols = json.loads(r.column_names) if r.column_names else []
        results.append(
            DatasetMetadataResponse(
                id=r.id,
                dataset_name=r.dataset_name,
                bucket_type=r.bucket_type,
                bucket_name=r.bucket_name,
                object_key=r.object_key,
                source_url=r.source_url,
                retrieval_timestamp=r.retrieval_timestamp,
                original_filename=r.original_filename,
                file_format=r.file_format,
                file_size_bytes=r.file_size_bytes,
                sha256_checksum=r.sha256_checksum,
                row_count=r.row_count,
                column_names=cols,
                processing_status=r.processing_status,
                created_by=r.created_by,
                curated_from_id=r.curated_from_id,
                created_at=r.created_at,
            )
        )
    return results


@router.post("/upload", response_model=DatasetMetadataResponse, status_code=status.HTTP_201_CREATED)
async def upload_raw_dataset(
    file: UploadFile = File(...),
    dataset_name: Optional[str] = Form(None),
    current_user: User = Depends(require_role(UserRole.PROCESSOR, UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """
    Uploads a raw dataset file to the private raw B2 bucket.
    Processor or Admin only.
    """
    content = await file.read()
    if not content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

    record = ingest_raw_dataset_bytes(
        db=db,
        user=current_user,
        data=content,
        original_filename=file.filename or "upload.csv",
        dataset_name=dataset_name,
    )

    cols = json.loads(record.column_names) if record.column_names else []
    return DatasetMetadataResponse(
        id=record.id,
        dataset_name=record.dataset_name,
        bucket_type=record.bucket_type,
        bucket_name=record.bucket_name,
        object_key=record.object_key,
        source_url=record.source_url,
        retrieval_timestamp=record.retrieval_timestamp,
        original_filename=record.original_filename,
        file_format=record.file_format,
        file_size_bytes=record.file_size_bytes,
        sha256_checksum=record.sha256_checksum,
        row_count=record.row_count,
        column_names=cols,
        processing_status=record.processing_status,
        created_by=record.created_by,
        curated_from_id=record.curated_from_id,
        created_at=record.created_at,
    )


@router.post("/ingest", response_model=DatasetMetadataResponse, status_code=status.HTTP_201_CREATED)
def ingest_remote_dataset(
    req: RemoteIngestionRequest,
    current_user: User = Depends(require_role(UserRole.PROCESSOR, UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """
    Ingests a public dataset from a validated URL with SSRF protections.
    Processor or Admin only.
    """
    record = ingest_from_public_url(
        db=db,
        user=current_user,
        source_url=req.source_url,
        dataset_name=req.dataset_name,
    )

    cols = json.loads(record.column_names) if record.column_names else []
    return DatasetMetadataResponse(
        id=record.id,
        dataset_name=record.dataset_name,
        bucket_type=record.bucket_type,
        bucket_name=record.bucket_name,
        object_key=record.object_key,
        source_url=record.source_url,
        retrieval_timestamp=record.retrieval_timestamp,
        original_filename=record.original_filename,
        file_format=record.file_format,
        file_size_bytes=record.file_size_bytes,
        sha256_checksum=record.sha256_checksum,
        row_count=record.row_count,
        column_names=cols,
        processing_status=record.processing_status,
        created_by=record.created_by,
        curated_from_id=record.curated_from_id,
        created_at=record.created_at,
    )


@router.post("/process", response_model=ProcessingJobResponse)
def process_dataset(
    req: ProcessRequest,
    current_user: User = Depends(require_role(UserRole.PROCESSOR, UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """
    Executes cleaning, validation, and curation pipeline on a raw dataset.
    Processor or Admin only.
    """
    config = CleaningConfig(
        handle_missing=req.handle_missing,
        remove_duplicates=req.remove_duplicates,
        clean_column_headers=req.clean_column_headers,
        output_format=req.output_format,
    )
    job = run_pipeline(
        db=db,
        user=current_user,
        raw_dataset_id=req.raw_dataset_id,
        config=config,
    )

    warnings = json.loads(job.validation_warnings) if job.validation_warnings else []
    return ProcessingJobResponse(
        id=job.id,
        raw_dataset_id=job.raw_dataset_id,
        curated_dataset_id=job.curated_dataset_id,
        status=job.status,
        input_row_count=job.input_row_count,
        output_row_count=job.output_row_count,
        missing_values_handled=job.missing_values_handled,
        duplicates_removed=job.duplicates_removed,
        validation_warnings=warnings,
        error_details=job.error_details,
        output_object_key=job.output_object_key,
        output_checksum=job.output_checksum,
        initiated_by=job.initiated_by,
        started_at=job.started_at,
        completed_at=job.completed_at,
        duration_seconds=job.duration_seconds,
    )


@router.get("/{dataset_id}/metadata", response_model=DatasetMetadataResponse)
def get_dataset_metadata(
    dataset_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Retrieves dataset metadata.
    Enforces that Analysts cannot access raw dataset metadata.
    """
    record = db.query(DatasetRecord).filter(DatasetRecord.id == dataset_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset with ID '{dataset_id}' not found."
        )

    # Enforce role-based access based on bucket type
    res_type = ResourceType.RAW_DATASET if record.bucket_type == DatasetBucketType.RAW.value else ResourceType.CURATED_DATASET
    enforce_access(
        user=current_user,
        resource_type=res_type,
        action=ActionType.READ,
        resource_name=record.object_key,
        db=db,
    )

    cols = json.loads(record.column_names) if record.column_names else []
    return DatasetMetadataResponse(
        id=record.id,
        dataset_name=record.dataset_name,
        bucket_type=record.bucket_type,
        bucket_name=record.bucket_name,
        object_key=record.object_key,
        source_url=record.source_url,
        retrieval_timestamp=record.retrieval_timestamp,
        original_filename=record.original_filename,
        file_format=record.file_format,
        file_size_bytes=record.file_size_bytes,
        sha256_checksum=record.sha256_checksum,
        row_count=record.row_count,
        column_names=cols,
        processing_status=record.processing_status,
        created_by=record.created_by,
        curated_from_id=record.curated_from_id,
        created_at=record.created_at,
    )


@router.get("/{dataset_id}/download")
def download_dataset(
    dataset_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Downloads dataset file content from Backblaze B2.
    CRITICAL: Analysts are STRICTLY DENIED from downloading raw datasets.
    Analysts can download curated datasets only.
    """
    record = db.query(DatasetRecord).filter(DatasetRecord.id == dataset_id).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset with ID '{dataset_id}' not found."
        )

    # 1. Enforce access control
    res_type = ResourceType.RAW_DATASET if record.bucket_type == DatasetBucketType.RAW.value else ResourceType.CURATED_DATASET
    enforce_access(
        user=current_user,
        resource_type=res_type,
        action=ActionType.READ,
        resource_name=record.object_key,
        db=db,
    )

    # 2. Select appropriate identity client
    if record.bucket_type == DatasetBucketType.RAW.value:
        client = get_processor_raw_client() or get_admin_client()
    else:
        if current_user.role == UserRole.ANALYST.value:
            client = get_analyst_curated_client()
        else:
            client = get_processor_curated_client() or get_admin_client()

    if not client:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Storage credentials for this operation are unconfigured."
        )

    # 3. Download from Backblaze B2
    try:
        content_bytes = download_object(client, record.bucket_name, record.object_key)
    except Exception as exc:
        log_security_event(
            db=db,
            actor_username=current_user.username,
            actor_role=current_user.role,
            operation="DOWNLOAD_DATASET_FAILED",
            resource=record.object_key,
            outcome=AuditOutcome.FAILED,
            status_code=status.HTTP_502_BAD_GATEWAY,
            reason=f"Cloud download failed: {exc}",
            enforcement_layer="Cloud B2 IAM",
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to retrieve object from Backblaze B2: {exc}"
        )

    # 4. Log successful audit trail
    log_security_event(
        db=db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        operation=f"DOWNLOAD_{record.bucket_type.upper()}_DATASET",
        resource=record.object_key,
        outcome=AuditOutcome.ALLOWED,
        status_code=status.HTTP_200_OK,
        reason=f"Successfully downloaded {record.bucket_type} dataset.",
        enforcement_layer="Cloud B2 IAM & Application RBAC",
    )

    # MIME types
    mime_map = {
        "csv": "text/csv",
        "json": "application/json",
        "parquet": "application/vnd.apache.parquet",
    }
    media_type = mime_map.get(record.file_format.lower(), "application/octet-stream")

    return StreamingResponse(
        io.BytesIO(content_bytes),
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{record.original_filename}"',
            "X-SHA256-Checksum": record.sha256_checksum,
        },
    )
