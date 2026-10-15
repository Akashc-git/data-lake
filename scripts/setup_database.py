"""
Database Initialization Script for CF-PS-15 Data Lake Access Control.
Creates all required SQLite tables and verifies schema integrity.
Usage:
    python -m scripts.setup_database
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlalchemy import inspect
from app.auth.dependencies import engine
from app.auth.models import Base
# Ensure all models are registered with Base.metadata
from app.audit.models import AuditEvent
from app.datasets.metadata import DatasetRecord, ProcessingJob
from app.api.access_tests import AccessTestRecord
from app.config import get_settings

settings = get_settings()


def setup_database():
    print("=" * 70)
    print("CF-PS-15 DATA LAKE ACCESS CONTROL - DATABASE SETUP")
    print("=" * 70)
    print(f"Target Database URL: {settings.DATABASE_URL}")

    print("\nCreating database tables...")
    Base.metadata.create_all(bind=engine)

    # Verify tables
    inspector = inspect(engine)
    created_tables = inspector.get_table_names()

    expected_tables = [
        "users",
        "user_sessions",
        "audit_events",
        "dataset_records",
        "processing_jobs",
        "access_test_records",
    ]

    print("\nVerification Checklist:")
    all_ok = True
    for tbl in expected_tables:
        if tbl in created_tables:
            print(f"  [OK] Table '{tbl}' created successfully.")
        else:
            print(f"  [MISSING] Table '{tbl}' was NOT created!")
            all_ok = False

    if all_ok:
        print("\nDatabase initialization completed successfully.")
    else:
        print("\nDatabase initialization encountered errors.")
        sys.exit(1)


if __name__ == "__main__":
    setup_database()
