"""
Audit Logs Page - CF-PS-15 Data Lake Access Control.
Provides multi-field filtering, pagination, and CSV/JSON export of immutable security events.
Restricted to Administrator identity.
"""

from datetime import datetime
import json
import pandas as pd
import requests
import streamlit as st

from api_client import API_BASE_URL, _get_auth_headers, api_get_audit_logs
from components.metrics import render_status_badge

st.set_page_config(page_title="Audit Logs", page_icon="📜", layout="wide")

st.markdown(
    """
    <style>
    .stApp { background-color: #F5F7FB; }
    h1, h2, h3 { color: #14213D !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

user = st.session_state.get("user_profile")
user_role = user.get("role", "analyst") if user else "analyst"
username = user.get("username", "anonymous") if user else "anonymous"

st.title("Security Audit Trail")
st.markdown(
    f"<p style='color: #64748B; font-size: 0.95rem; margin-top: -0.75rem;'>"
    f"Active Identity: <strong>{username}</strong> • Role: <code>{user_role.upper()}</code>"
    f"</p>",
    unsafe_allow_html=True,
)

# Enforce Administrator restriction
if user_role != "admin":
    st.markdown(
        """
        <div style="
            background-color: #FEE2E2;
            border: 2px solid #DC2626;
            border-radius: 8px;
            padding: 1.5rem;
            margin: 1.5rem 0;
        ">
            <div style="font-size: 1.25rem; font-weight: 700; color: #DC2626;">
                ⛔ Access Restricted (403 Forbidden)
            </div>
            <div style="font-size: 0.95rem; color: #991B1B; margin-top: 0.5rem; line-height: 1.5;">
                Audit trails and compliance logs contain sensitive operational tracking data and are
                <strong>restricted to Administrator identities only</strong>.<br>
                Please switch to the <strong>Administrator</strong> profile in the sidebar to review audit logs.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# Filter Bar
with st.expander("🔍 Filter Audit Trail", expanded=True):
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    with f_col1:
        actor_filter = st.text_input("Actor Username:", placeholder="e.g. processor_user")
    with f_col2:
        role_filter = st.selectbox("Role Filter:", ["All", "admin", "processor", "analyst"])
    with f_col3:
        outcome_filter = st.selectbox("Outcome:", ["All", "ALLOWED", "DENIED", "FAILED", "INCONCLUSIVE"])
    with f_col4:
        operation_filter = st.text_input("Operation Substring:", placeholder="e.g. DOWNLOAD, UPLOAD")

# Build query params
params = {"limit": 100, "offset": 0}
if actor_filter:
    params["actor"] = actor_filter
if role_filter != "All":
    params["role"] = role_filter
if outcome_filter != "All":
    params["outcome"] = outcome_filter
if operation_filter:
    params["operation"] = operation_filter

events, total_count, err = api_get_audit_logs(params)

if err:
    st.error(f"Failed to fetch audit events: {err}")
    st.stop()

# Header with Export Buttons
col_count, col_exp_csv, col_exp_json = st.columns([3, 1, 1])
with col_count:
    st.markdown(f"**Found {total_count} matching audit events (Showing top {len(events)}):**")
with col_exp_csv:
    csv_url = f"{API_BASE_URL}/api/audit-logs?export_format=csv"
    try:
        csv_resp = requests.get(csv_url, headers=_get_auth_headers(), timeout=10)
        if csv_resp.status_code == 200:
            st.download_button(
                label="📥 Export CSV",
                data=csv_resp.content,
                file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )
    except Exception:
        pass

with col_exp_json:
    json_url = f"{API_BASE_URL}/api/audit-logs?export_format=json"
    try:
        json_resp = requests.get(json_url, headers=_get_auth_headers(), timeout=10)
        if json_resp.status_code == 200:
            st.download_button(
                label="📥 Export JSON",
                data=json_resp.content,
                file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )
    except Exception:
        pass

st.write("")

if not events:
    st.info("No audit events match the specified filter criteria.")
else:
    for e in events:
        out = e.get("outcome", "ALLOWED")
        out_badge = "success" if out == "ALLOWED" else ("error" if out == "DENIED" else "warning")

        st.markdown(
            f"""
            <div style="background: white; border: 1px solid #E2E8F0; border-radius: 8px; padding: 0.9rem 1.1rem; margin-bottom: 0.65rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-weight: 700; color: #14213D; font-size: 0.95rem;">{e.get('operation')}</span>
                        <span style="margin-left: 0.5rem; font-size: 0.75rem; background: #F1F5F9; color: #14213D; padding: 0.15rem 0.45rem; border-radius: 4px;">
                            Actor: <code>{e.get('actor_username')}</code> ({e.get('actor_role')})
                        </span>
                    </div>
                    <div>
                        {render_status_badge(out, out_badge)}
                    </div>
                </div>
                <div style="font-size: 0.8rem; color: #64748B; font-family: monospace; margin: 0.35rem 0;">
                    Target: {e.get('resource')} • Status: HTTP {e.get('status_code') or 'N/A'} • Timestamp: {e.get('timestamp')}
                </div>
                <div style="font-size: 0.8rem; color: #475569;">
                    <strong>Decision Context:</strong> {e.get('reason') or 'No extra reason provided.'} 
                    (Correlation ID: <code>{e.get('correlation_id')}</code>)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
