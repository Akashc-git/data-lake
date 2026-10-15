"""
Unit Tests for Data Validation and Anti-SSRF URL Verification.
"""

import pandas as pd
import pytest
from app.datasets.validation import validate_dataframe, validate_public_dataset_url


def test_dataframe_validation_clean():
    df = pd.DataFrame({
        "id": [1, 2, 3],
        "feature_a": [10.5, 20.2, 30.1],
        "category": ["A", "B", "C"]
    })

    report = validate_dataframe(df)
    assert report.is_valid is True
    assert report.row_count == 3
    assert report.column_count == 3
    assert report.missing_value_count == 0
    assert report.duplicate_row_count == 0
    assert report.quality_score == 100.0


def test_dataframe_validation_with_nulls_and_duplicates():
    df = pd.DataFrame({
        "id": [1, 2, 2, 4],
        "val": [10.0, None, None, 40.0],
    })

    report = validate_dataframe(df)
    assert report.missing_value_count == 2
    assert report.duplicate_row_count == 1
    assert len(report.warnings) >= 1
    assert report.quality_score < 100.0


def test_anti_ssrf_rejects_private_ips():
    # Loopback
    is_safe, reason = validate_public_dataset_url("http://127.0.0.1:8080/data.csv")
    assert is_safe is False
    assert "private or restricted" in reason or "restricted" in reason

    # Localhost string
    is_safe, reason = validate_public_dataset_url("http://localhost:5000/test.csv")
    assert is_safe is False

    # AWS/Cloud metadata IP
    is_safe, reason = validate_public_dataset_url("http://169.254.169.254/latest/meta-data/")
    assert is_safe is False
    assert "restricted" in reason


def test_anti_ssrf_rejects_non_http_schemes():
    is_safe, reason = validate_public_dataset_url("ftp://ftp.example.com/data.csv")
    assert is_safe is False
    assert "Only HTTP and HTTPS" in reason

    is_safe, reason = validate_public_dataset_url("file:///etc/passwd")
    assert is_safe is False
