"""
REST API Client for Streamlit Dashboard.
Communicates with the FastAPI backend using signed JWT tokens and structured error handling.
Prevents cloud credentials from ever entering the browser context.
"""

from datetime import datetime, timezone
import os
from typing import Any, Dict, List, Optional, Tuple
import requests
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")


def _get_auth_headers() -> Dict[str, str]:
    """Retrieves Bearer authorization headers from Streamlit session state."""
    token = st.session_state.get("auth_token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def api_login(username: str, password: str) -> Tuple[bool, str]:
    """Authenticates with FastAPI backend and stores token in session state."""
    url = f"{API_BASE_URL}/api/auth/login"
    try:
        resp = requests.post(url, json={"username": username, "password": password}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            st.session_state["auth_token"] = data["access_token"]
            st.session_state["user_profile"] = data["user"]
            st.session_state["logged_in"] = True
            return True, "Login successful."
        else:
            err_msg = resp.json().get("detail", "Invalid credentials")
            return False, str(err_msg)
    except requests.RequestException as exc:
        return False, f"Backend connection failed: {exc}"


def api_logout():
    """Logs out from FastAPI backend and clears Streamlit state."""
    url = f"{API_BASE_URL}/api/auth/logout"
    try:
        requests.post(url, headers=_get_auth_headers(), timeout=5)
    except Exception:
        pass
    st.session_state["auth_token"] = None
    st.session_state["user_profile"] = None
    st.session_state["logged_in"] = False


def api_get_health() -> Dict[str, Any]:
    """Fetches system health status."""
    url = f"{API_BASE_URL}/api/health"
    try:
        resp = requests.get(url, timeout=5)
        return resp.json() if resp.status_code == 200 else {"status": "error", "b2_configured": False}
    except Exception:
        return {"status": "offline", "b2_configured": False}


def api_get_storage_status() -> Dict[str, Any]:
    """Fetches storage connectivity status for raw, curated, and audit buckets."""
    url = f"{API_BASE_URL}/api/storage/status"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), timeout=15)
        return resp.json() if resp.status_code == 200 else {"is_configured": False, "buckets": []}
    except Exception as exc:
        return {"is_configured": False, "buckets": [], "error": str(exc)}


def api_get_dashboard_metrics() -> Dict[str, Any]:
    """Fetches computed dashboard metrics."""
    url = f"{API_BASE_URL}/api/dashboard/metrics"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), timeout=15)
        return resp.json() if resp.status_code == 200 else {}
    except Exception:
        return {}


def api_list_raw_datasets() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Fetches list of raw datasets. Returns (items, error_message)."""
    url = f"{API_BASE_URL}/api/datasets/raw"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), timeout=10)
        if resp.status_code == 200:
            return resp.json(), None
        elif resp.status_code == 403:
            return [], "403 Forbidden: Identity role lacks permission to list raw datasets."
        return [], resp.json().get("detail", "Error retrieving raw datasets.")
    except Exception as exc:
        return [], str(exc)


def api_list_curated_datasets() -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Fetches list of curated datasets."""
    url = f"{API_BASE_URL}/api/datasets/curated"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), timeout=10)
        if resp.status_code == 200:
            return resp.json(), None
        return [], resp.json().get("detail", "Error retrieving curated datasets.")
    except Exception as exc:
        return [], str(exc)


def api_upload_dataset(file_bytes: bytes, filename: str, dataset_name: Optional[str]) -> Tuple[bool, Any]:
    """Uploads raw dataset file to backend."""
    url = f"{API_BASE_URL}/api/datasets/upload"
    files = {"file": (filename, file_bytes)}
    data = {"dataset_name": dataset_name} if dataset_name else {}
    try:
        resp = requests.post(url, headers=_get_auth_headers(), files=files, data=data, timeout=30)
        if resp.status_code in (200, 201):
            return True, resp.json()
        return False, resp.json().get("detail", "Upload failed.")
    except Exception as exc:
        return False, str(exc)


def api_ingest_remote(source_url: str, dataset_name: Optional[str]) -> Tuple[bool, Any]:
    """Triggers backend ingestion from verified public URL."""
    url = f"{API_BASE_URL}/api/datasets/ingest"
    payload = {"source_url": source_url, "dataset_name": dataset_name}
    try:
        resp = requests.post(url, headers=_get_auth_headers(), json=payload, timeout=30)
        if resp.status_code in (200, 201):
            return True, resp.json()
        return False, resp.json().get("detail", "Remote ingestion failed.")
    except Exception as exc:
        return False, str(exc)


def api_run_processing(raw_dataset_id: str, cleaning_config: Dict[str, Any]) -> Tuple[bool, Any]:
    """Triggers backend data processing pipeline."""
    url = f"{API_BASE_URL}/api/datasets/process"
    payload = {"raw_dataset_id": raw_dataset_id, **cleaning_config}
    try:
        resp = requests.post(url, headers=_get_auth_headers(), json=payload, timeout=60)
        if resp.status_code == 200:
            return True, resp.json()
        return False, resp.json().get("detail", "Pipeline execution failed.")
    except Exception as exc:
        return False, str(exc)


def api_download_dataset(dataset_id: str) -> Tuple[Optional[bytes], Optional[str], Optional[str]]:
    """
    Downloads dataset file bytes.
    Returns: (content_bytes, filename, error_message)
    """
    url = f"{API_BASE_URL}/api/datasets/{dataset_id}/download"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), stream=True, timeout=30)
        if resp.status_code == 200:
            content_disp = resp.headers.get("Content-Disposition", "")
            filename = "dataset.dat"
            if "filename=" in content_disp:
                filename = content_disp.split("filename=")[-1].strip('"')
            return resp.content, filename, None
        elif resp.status_code == 403:
            return None, None, "403 Forbidden: Identity role is denied download access to this dataset."
        return None, None, resp.json().get("detail", "Download failed.")
    except Exception as exc:
        return None, None, str(exc)


def api_run_access_tests() -> Tuple[bool, Any]:
    """Runs the 11 cloud access control tests."""
    url = f"{API_BASE_URL}/api/access-tests/run"
    try:
        resp = requests.post(url, headers=_get_auth_headers(), timeout=60)
        if resp.status_code == 200:
            return True, resp.json()
        return False, resp.json().get("detail", "Access tests failed to execute.")
    except Exception as exc:
        return False, str(exc)


def api_get_access_test_results() -> List[Dict[str, Any]]:
    """Fetches recent access test records."""
    url = f"{API_BASE_URL}/api/access-tests/results"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), timeout=10)
        return resp.json() if resp.status_code == 200 else []
    except Exception:
        return []


def api_get_audit_logs(params: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], int, Optional[str]]:
    """Queries audit logs. Restricted to Admin."""
    url = f"{API_BASE_URL}/api/audit-logs"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("events", []), data.get("total_count", 0), None
        elif resp.status_code == 403:
            return [], 0, "403 Forbidden: Audit logs are restricted to Administrator identity."
        return [], 0, resp.json().get("detail", "Error retrieving audit logs.")
    except Exception as exc:
        return [], 0, str(exc)


def api_get_security_report() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Generates authoritative security report for Administrator."""
    url = f"{API_BASE_URL}/api/reports/security"
    try:
        resp = requests.get(url, headers=_get_auth_headers(), timeout=20)
        if resp.status_code == 200:
            return resp.json(), None
        elif resp.status_code == 403:
            return None, "403 Forbidden: Security reports are restricted to Administrator identity."
        return None, resp.json().get("detail", "Failed to compile security report.")
    except Exception as exc:
        return None, str(exc)
