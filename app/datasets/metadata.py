"""
Dataset Metadata and Processing History Models for CF-PS-15 Data Lake.
Tracks real raw and curated datasets, schema definitions, checksums, and transformation runs.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import Column, String, Integer, Float, DateTime, Text, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from pydantic import BaseModel, ConfigDict

from app.auth.models import Base


class DatasetBucketType(str, Enum):
    RAW = "raw"
    CURATED = "curated"


class ProcessingStatus(str, Enum):
    RAW_INGESTED = "raw_ingested"
    VALIDATED = "validated"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


class DatasetRecord(Base):
    """Stores verified metadata for datasets stored in Backblaze B2."""
    __tablename__ = "dataset_records"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    dataset_name = Column(String(100), nullable=False, index=True)
    bucket_type = Column(String(20), nullable=False, index=True)  # "raw" or "curated"
    bucket_name = Column(String(100), nullable=False)
    object_key = Column(String(255), unique=True, nullable=False, index=True)
    source_url = Column(String(500), nullable=True)
    retrieval_timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_format = Column(String(20), nullable=False)  # csv, json, parquet
    file_size_bytes = Column(BigInteger, nullable=False)
    sha256_checksum = Column(String(64), nullable=False, index=True)
    row_count = Column(Integer, nullable=True)
    column_names = Column(Text, nullable=True)  # JSON-serialized list of columns
    processing_status = Column(String(30), nullable=False, default=ProcessingStatus.RAW_INGESTED.value)
    created_by = Column(String(50), nullable=False)
    curated_from_id = Column(String(36), ForeignKey("dataset_records.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    curated_records = relationship("DatasetRecord", backref="raw_source", remote_side=[id])
    jobs_as_source = relationship("ProcessingJob", foreign_keys="ProcessingJob.raw_dataset_id", back_populates="raw_dataset")
    jobs_as_curated = relationship("ProcessingJob", foreign_keys="ProcessingJob.curated_dataset_id", back_populates="curated_dataset")


class ProcessingJob(Base):
    """Tracks persistent history of data transformation and curation pipelines."""
    __tablename__ = "processing_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    raw_dataset_id = Column(String(36), ForeignKey("dataset_records.id"), nullable=False, index=True)
    curated_dataset_id = Column(String(36), ForeignKey("dataset_records.id"), nullable=True, index=True)
    status = Column(String(20), nullable=False, index=True)  # "SUCCESS", "FAILED"
    input_row_count = Column(Integer, nullable=False)
    output_row_count = Column(Integer, nullable=True)
    missing_values_handled = Column(Integer, default=0, nullable=False)
    duplicates_removed = Column(Integer, default=0, nullable=False)
    validation_warnings = Column(Text, nullable=True)  # JSON-serialized list
    error_details = Column(Text, nullable=True)
    output_object_key = Column(String(255), nullable=True)
    output_checksum = Column(String(64), nullable=True)
    initiated_by = Column(String(50), nullable=False)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)

    raw_dataset = relationship("DatasetRecord", foreign_keys=[raw_dataset_id], back_populates="jobs_as_source")
    curated_dataset = relationship("DatasetRecord", foreign_keys=[curated_dataset_id], back_populates="jobs_as_curated")


# Pydantic Schemas
class DatasetMetadataResponse(BaseModel):
    id: str
    dataset_name: str
    bucket_type: str
    bucket_name: str
    object_key: str
    source_url: Optional[str] = None
    retrieval_timestamp: datetime
    original_filename: str
    file_format: str
    file_size_bytes: int
    sha256_checksum: str
    row_count: Optional[int] = None
    column_names: Optional[List[str]] = None
    processing_status: str
    created_by: str
    curated_from_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ProcessingJobResponse(BaseModel):
    id: str
    raw_dataset_id: str
    curated_dataset_id: Optional[str] = None
    status: str
    input_row_count: int
    output_row_count: Optional[int] = None
    missing_values_handled: int
    duplicates_removed: int
    validation_warnings: Optional[List[str]] = None
    error_details: Optional[str] = None
    output_object_key: Optional[str] = None
    output_checksum: Optional[str] = None
    initiated_by: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None

    model_config = ConfigDict(from_attributes=True)
