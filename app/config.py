"""
Configuration module for CF-PS-15 Data Lake Access Control Dashboard.
Loads environment variables and provides structured application settings.
"""

from functools import lru_cache
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Configuration
    APP_NAME: str = "CF-PS-15 Data Lake Access Control"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_PREFIX: str = "/api"
    API_BASE_URL: str = "http://127.0.0.1:8000"

    # Database & Security
    DATABASE_URL: str = "sqlite:///./app.db"
    SESSION_SECRET_KEY: str = "temporary-insecure-key-override-in-production-env"
    ADMIN_BOOTSTRAP_SECRET: str = "AdminSecure2026!"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 480  # 8 hours

    # Backblaze B2 S3-Compatible API Settings
    B2_ENDPOINT_URL: str = ""
    B2_REGION: str = "us-east-005"

    # B2 Buckets (Must be separate private buckets)
    B2_RAW_BUCKET: str = ""
    B2_CURATED_BUCKET: str = ""
    B2_AUDIT_BUCKET: str = ""

    # Processor Credentials: RAW Bucket Scoped (Read-only capabilities: listObjects, getObject)
    B2_PROCESSOR_RAW_ACCESS_KEY_ID: str = ""
    B2_PROCESSOR_RAW_SECRET_ACCESS_KEY: str = ""

    # Processor Credentials: CURATED Bucket Scoped (Write capabilities: putObject, listObjects)
    B2_PROCESSOR_CURATED_ACCESS_KEY_ID: str = ""
    B2_PROCESSOR_CURATED_SECRET_ACCESS_KEY: str = ""

    # Analyst Credentials: CURATED Bucket Scoped (Read-only capabilities: listObjects, getObject)
    B2_ANALYST_CURATED_ACCESS_KEY_ID: str = ""
    B2_ANALYST_CURATED_SECRET_ACCESS_KEY: str = ""

    # Optional Admin/Setup Credential for diagnostic bucket health checks
    B2_ADMIN_ACCESS_KEY_ID: str = ""
    B2_ADMIN_SECRET_ACCESS_KEY: str = ""

    # Remote ingestion constraints (Anti-SSRF & Size)
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    INGESTION_TIMEOUT_SECONDS: int = 15

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def is_b2_configured(self) -> bool:
        """Checks whether the minimal required B2 credentials and buckets are populated."""
        return bool(
            self.B2_ENDPOINT_URL.strip()
            and self.B2_RAW_BUCKET.strip()
            and self.B2_CURATED_BUCKET.strip()
            and (
                (self.B2_PROCESSOR_RAW_ACCESS_KEY_ID.strip() and self.B2_PROCESSOR_RAW_SECRET_ACCESS_KEY.strip())
                or (self.B2_ANALYST_CURATED_ACCESS_KEY_ID.strip() and self.B2_ANALYST_CURATED_SECRET_ACCESS_KEY.strip())
                or (self.B2_ADMIN_ACCESS_KEY_ID.strip() and self.B2_ADMIN_SECRET_ACCESS_KEY.strip())
            )
        )


@lru_cache()
def get_settings() -> Settings:
    """Returns cached application settings."""
    return Settings()
