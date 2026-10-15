"""
Unit Tests for Data Transformation Pipeline.
Tests pandas cleaning, deduplication, missing-value imputation, and SHA-256 calculation.
"""

import pandas as pd
import pytest
from app.processing.pipeline import CleaningConfig, clean_dataframe
from app.storage.object_service import compute_sha256


def test_clean_dataframe_drop_missing_and_dedup():
    df = pd.DataFrame({
        "First Name": ["Alice", "Bob", "Alice", "David"],
        "Age": [25, None, 25, 40],
        "Score": [90.0, 85.0, 90.0, 70.0],
    })

    cfg = CleaningConfig(
        handle_missing="drop",
        remove_duplicates=True,
        clean_column_headers=True,
        output_format="csv",
    )

    cleaned_df, missing_handled, dups_removed = clean_dataframe(df, cfg)

    # Columns should be lower and snake_case
    assert list(cleaned_df.columns) == ["first_name", "age", "score"]
    # Duplicates removed (1 duplicate row for Alice)
    assert dups_removed == 1
    # Bob has missing Age and should be dropped
    assert len(cleaned_df) == 2
    assert "Alice" in cleaned_df["first_name"].values
    assert "David" in cleaned_df["first_name"].values


def test_clean_dataframe_impute_missing():
    df = pd.DataFrame({
        "Feature": [10.0, 20.0, None, 40.0],
        "Category": ["X", "X", None, "Y"],
    })

    cfg = CleaningConfig(
        handle_missing="impute",
        remove_duplicates=False,
        clean_column_headers=True,
        output_format="csv",
    )

    cleaned_df, missing_handled, _ = clean_dataframe(df, cfg)
    assert cleaned_df["feature"].isnull().sum() == 0
    # Median of 10, 20, 40 is 20
    assert cleaned_df.loc[2, "feature"] == 20.0
    # Mode of Category is X
    assert cleaned_df.loc[2, "category"] == "X"


def test_sha256_checksum_deterministic():
    payload1 = b"CF-PS-15 Benchmark Data Payload 2026"
    payload2 = b"CF-PS-15 Benchmark Data Payload 2026"
    payload3 = b"Different Payload"

    hash1 = compute_sha256(payload1)
    hash2 = compute_sha256(payload2)
    hash3 = compute_sha256(payload3)

    assert hash1 == hash2
    assert hash1 != hash3
    assert len(hash1) == 64
