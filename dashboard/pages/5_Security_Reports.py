"""
Security Reports Page - CF-PS-15 Data Lake Access Control.
Compiles comprehensive compliance and evidence reports for Administrator review.
Enforces strict labeling: never marks project verified if tests are failing or inconclusive.
"""

from datetime import datetime
import json
import streamlit as st

from api_client import api_get_security_report
from components.metrics import render_metric_card, render_status_badge

st.set_page_config(page_title="Security & Compliance Reports", page_icon="📋", layout="wide")

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

st.title("Security & Compliance Evidence Report")
st.markdown(
    f"<p style='color: #64748B; font-size: 0.95rem; margin-top: -0.75rem;'>"
    f"Active Identity: <strong>{username}</strong> • Role: <code>{user_role.upper()}</code>"
    f"</p>",
    unsafe_allow_html=True,
)

# Admin Authorization Check
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
                Formal security compliance reports and cloud architecture audits are
                <strong>restricted to Administrator identities</strong>.<br>
                Please switch to the Administrator role using the sidebar.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# Fetch report from backend
report_data, err = api_get_security_report()

if err:
    st.error(f"Failed to generate security report: {err}")
    st.stop()

# Executive Summary Banner
tests_summary = report_data.get("access_tests_summary", {})
verification_status = tests_summary.get("verification_status", "UNEXECUTED")
passed = tests_summary.get("passed", 0)
failed = tests_summary.get("failed", 0)
inconclusive = tests_summary.get("inconclusive", 0)

status_theme = {
    "FULLY_VERIFIED": ("#16A34A", "#DCFCE7", "✅ COMPLIANCE FULLY VERIFIED"),
    "INCONCLUSIVE": ("#D97706", "#FEF3C7", "⚠️ VERIFICATION INCONCLUSIVE (UNCONFIGURED B2 CREDENTIALS)"),
    "FAILED": ("#DC2626", "#FEE2E2", "❌ NON-COMPLIANT (BOUNDARY BREACH DETECTED)"),
    "UNEXECUTED": ("#64748B", "#F1F5F9", "ℹ️ UNEXECUTED (NO TESTS RUN YET)"),
}

theme_key = "FULLY_VERIFIED" if "FULLY_VERIFIED" in verification_status else ("FAILED" if failed > 0 else ("INCONCLUSIVE" if inconclusive > 0 else "UNEXECUTED"))
fg_col, bg_col, title_txt = status_theme[theme_key]

st.markdown(
    f"""
    <div style="background-color: {bg_col}; border: 2px solid {fg_col}; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem;">
        <div style="font-size: 1.25rem; font-weight: 700; color: {fg_col};">{title_txt}</div>
        <div style="font-size: 0.9rem; color: #14213D; margin-top: 0.4rem; line-height: 1.4;">
            <strong>Evaluation Summary:</strong> {verification_status}<br>
            <strong>Mandatory Probes:</strong> {passed} Passed • {failed} Failed • {inconclusive} Inconclusive.<br>
            <em>Rule: The system is never labeled fully verified if any mandatory cloud probe is failing, unconfigured, or inconclusive.</em>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Export Report Download
col_rep_head, col_rep_dl = st.columns([3, 1])
with col_rep_head:
    st.markdown(f"**Report ID:** `{report_data.get('report_id')}` • **Timestamp:** `{report_data.get('report_timestamp')}`")
with col_rep_dl:
    st.download_button(
        label="📥 Download Evidence JSON",
        data=json.dumps(report_data, indent=2),
        file_name=f"security_report_{report_data.get('report_id')}.json",
        mime="application/json",
        use_container_width=True,
    )

st.divider()

# Section 1: Configured Buckets
st.markdown("### 1. Cloud Storage Architecture & Bucket Partitioning")
buckets = report_data.get("buckets_posture", {})
st.markdown(
    f"""
    * **B2 Endpoint URL:** `{buckets.get('b2_endpoint')}`
    * **Region:** `{buckets.get('region')}`
    * **Raw Storage Bucket:** `{buckets.get('raw_bucket', {}).get('name')}` — *{buckets.get('raw_bucket', {}).get('isolation')}*
    * **Curated Storage Bucket:** `{buckets.get('curated_bucket', {}).get('name')}` — *{buckets.get('curated_bucket', {}).get('isolation')}*
    * **Audit Evidence Bucket:** `{buckets.get('audit_bucket', {}).get('name')}` — *{buckets.get('audit_bucket', {}).get('isolation')}*
    """
)

st.write("")

# Section 2: Identity-to-Credential Mapping
st.markdown("### 2. Identity-to-Credential Posture")
creds = report_data.get("credentials_posture", [])

for c in creds:
    conf_badge = render_status_badge("CONFIGURED", "success") if c.get("is_configured") else render_status_badge("UNCONFIGURED", "warning")
    st.markdown(
        f"""
        <div style="background: white; border: 1px solid #E2E8F0; border-radius: 6px; padding: 0.9rem 1.1rem; margin-bottom: 0.65rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="font-weight: 700; color: #14213D;">{c.get('identity')}</span>
                <div>{conf_badge}</div>
            </div>
            <div style="font-size: 0.82rem; color: #64748B; margin-top: 0.25rem;">
                Target Bucket: <code>{c.get('target_bucket')}</code> • Scoped Key: <code>{c.get('access_key_masked')}</code>
            </div>
            <div style="font-size: 0.8rem; color: #14213D; margin-top: 0.35rem;">
                <strong>Intended Capabilities:</strong> <code>{', '.join(c.get('intended_capabilities', []))}</code>
            </div>
            <div style="font-size: 0.78rem; color: #475569; margin-top: 0.2rem;">
                <strong>Cloud Restriction:</strong> {c.get('cloud_restrictions')}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.write("")

# Section 3: Cloud Test Results & Provider Responses
st.markdown("### 3. Real Cloud Permission Probes & Provider Evidence")
detailed_tests = tests_summary.get("detailed_results", [])

if not detailed_tests:
    st.info("No permission test probes recorded yet. Please run the suite in the Access Control Lab.")
else:
    for t in detailed_tests:
        pf = t.get("pass_fail", "INCONCLUSIVE")
        pf_b = "success" if pf == "PASS" else ("error" if pf == "FAIL" else "warning")

        st.markdown(
            f"""
            <div style="background: white; border: 1px solid #E2E8F0; border-radius: 6px; padding: 0.85rem 1rem; margin-bottom: 0.5rem;">
                <div style="display: flex; justify-content: space-between;">
                    <span style="font-weight: 700; color: #14213D; font-size: 0.9rem;">{t.get('test_id')} • {t.get('identity')} • {t.get('operation')}</span>
                    <div>{render_status_badge(pf, pf_b)}</div>
                </div>
                <div style="font-size: 0.78rem; color: #64748B; font-family: monospace; margin: 0.2rem 0;">
                    Target: {t.get('target_resource')} | Expected: {t.get('expected')} | Actual: {t.get('actual')} | Status: {t.get('status_code')}
                </div>
                <div style="font-size: 0.8rem; color: #14213D;">
                    <strong>Provider Response:</strong> <code>{t.get('provider_response')}</code>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
