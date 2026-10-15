"""
Dataset Validation and Security Rules for CF-PS-15.
Provides DataFrame schema analysis, missing-value detection, duplicate auditing,
and anti-SSRF URL verification.
"""

from dataclasses import dataclass, field
import ipaddress
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import pandas as pd


@dataclass
class ValidationReport:
    is_valid: bool
    row_count: int
    column_count: int
    columns: List[str]
    column_types: Dict[str, str]
    missing_value_count: int
    missing_by_column: Dict[str, int]
    duplicate_row_count: int
    warnings: List[str] = field(default_factory=list)
    quality_score: float = 100.0


def validate_dataframe(df: pd.DataFrame) -> ValidationReport:
    """
    Performs comprehensive schema and quality inspection on an ingested dataset.
    """
    row_count, col_count = df.shape
    columns = [str(c) for c in df.columns]
    column_types = {str(k): str(v) for k, v in df.dtypes.to_dict().items()}

    missing_by_col = df.isnull().sum().to_dict()
    missing_by_col = {str(k): int(v) for k, v in missing_by_col.items() if v > 0}
    total_missing = sum(missing_by_col.values())

    duplicates = int(df.duplicated().sum())

    warnings: List[str] = []
    if total_missing > 0:
        warnings.append(f"Detected {total_missing} missing values across {len(missing_by_col)} columns.")
    if duplicates > 0:
        warnings.append(f"Detected {duplicates} duplicate rows.")

    # Quality score estimation (0 to 100)
    penalty = 0.0
    if row_count > 0:
        penalty += (total_missing / (row_count * max(col_count, 1))) * 50.0
        penalty += (duplicates / row_count) * 30.0
    quality_score = max(0.0, min(100.0, 100.0 - penalty))

    return ValidationReport(
        is_valid=row_count > 0 and col_count > 0,
        row_count=row_count,
        column_count=col_count,
        columns=columns,
        column_types=column_types,
        missing_value_count=total_missing,
        missing_by_column=missing_by_col,
        duplicate_row_count=duplicates,
        warnings=warnings,
        quality_score=round(quality_score, 2),
    )


def validate_public_dataset_url(url_str: str) -> Tuple[bool, str]:
    """
    Enforces strict Anti-SSRF (Server-Side Request Forgery) protection:
    1. Scheme must be http or https.
    2. Hostname must resolve to a valid IP.
    3. Target IP must NOT be loopback, private RFC-1918, link-local, carrier-grade NAT, or cloud metadata.
    """
    try:
        parsed = urlparse(url_str.strip())
        if parsed.scheme.lower() not in ("http", "https"):
            return False, "Only HTTP and HTTPS protocols are permitted for remote ingestion."

        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL: Missing hostname."

        # Prohibit known cloud metadata addresses by host string
        if hostname in ("169.254.169.254", "metadata.google.internal", "localhost"):
            return False, "Target destination is restricted (cloud metadata / localhost)."

        # Resolve DNS
        addr_info = socket.getaddrinfo(hostname, None)
        if not addr_info:
            return False, "Hostname could not be resolved."

        for entry in addr_info:
            ip_str = entry[4][0]
            ip_obj = ipaddress.ip_address(ip_str)

            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            ):
                return False, f"Target IP address '{ip_str}' is within a private or restricted network range."

        return True, ""
    except Exception as exc:
        return False, f"Anti-SSRF URL verification failed: {exc}"
