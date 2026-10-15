"""
Identity Provisioning Script for CF-PS-15 Data Lake Access Control.
Provisions the initial Administrator, Processor, and Analyst identities securely.
Usage:
    python -m scripts.bootstrap_users
"""

import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.auth.dependencies import SessionLocal, engine
from app.auth.models import Base, User, UserRole
from app.auth.service import create_user, get_user_by_username
from app.config import get_settings

settings = get_settings()


def bootstrap_users():
    print("=" * 70)
    print("CF-PS-15 DATA LAKE ACCESS CONTROL - USER BOOTSTRAP")
    print("=" * 70)

    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    identities = [
        {
            "username": "admin",
            "email": "admin@datalake.local",
            "password": settings.ADMIN_BOOTSTRAP_SECRET or "AdminSecure2026!",
            "role": UserRole.ADMIN,
            "description": "System Administrator with full governance, auditing, and diagnostic rights."
        },
        {
            "username": "processor_user",
            "email": "processor@datalake.local",
            "password": "ProcessorPass2026!",
            "role": UserRole.PROCESSOR,
            "description": "Data Pipeline Operator authorized to ingest raw data and publish curated datasets."
        },
        {
            "username": "analyst_user",
            "email": "analyst@datalake.local",
            "password": "AnalystPass2026!",
            "role": UserRole.ANALYST,
            "description": "Data Consumer restricted strictly to reading/downloading vetted curated datasets."
        },
    ]

    print("\nProvisioning Default Roles & Credentials:")
    for id_info in identities:
        existing = get_user_by_username(db, id_info["username"])
        if existing:
            print(f"  [EXISTS] User '{id_info['username']}' ({existing.role}) already present.")
        else:
            user = create_user(
                db=db,
                username=id_info["username"],
                email=id_info["email"],
                password=id_info["password"],
                role=id_info["role"],
            )
            print(f"  [CREATED] User '{user.username}' with role '{user.role}'.")
            print(f"            Description: {id_info['description']}")
            print(f"            Temporary Password: {id_info['password']}")

    db.close()
    print("\nUser bootstrapping completed successfully.")
    print("Note: In production environments, immediately rotate temporary credentials after login.")


if __name__ == "__main__":
    bootstrap_users()
