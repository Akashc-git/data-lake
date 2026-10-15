"""
Access Control Lab - CF-PS-15.
Interactive security test harness that executes the 11 mandatory cloud permission checks
against Backblaze B2 using identity-scoped credentials.
"""

from datetime import datetime
import pandas as pd
import streamlit as st

from api_client import api_get_access_test_results, api_run_access_tests
from components.metrics import render_metric_card, render_status_badge

st.set_page_config(page_title="Access Control Lab", page_icon="🧪", layout="wide")

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

st.title("Access Control Lab")
st.markdown(
    f"<p style='color: #64748B; font-size: 0.95rem; margin-top: -0.75rem;'>"
    f"Active Identity: <strong>{username}</strong> • Role: <code>{user_role.upper()}</code>"
    f"</p>",
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div style="background: white; border-left: 4px solid #2563EB; border-radius: 4px; padding: 1rem; margin-bottom: 1.25rem;">
        <div style="font-weight: 700; color: #14213D; font-size: 0.95rem;">Automated Cloud Permission Verification Suite</div>
        <div style="color: #64748B; font-size: 0.85rem; margin-top: 0.25rem; line-height: 1.4;">
            Executes real cloud requests against Backblaze B2 S3 API using identity-scoped credentials.
            Verifies that Processor and Analyst identities possess exact intended capabilities and are strictly prevented
            from unauthorized reads, writes, overwrites, or deletions.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Test Runner Trigger
col_run, col_info = st.columns([1, 2])
with col_run:
    run_btn = st.button("🚀 Execute Cloud Permission Tests", type="primary", use_container_width=True)
with col_info:
    st.markdown("<p style='color: #64748B; font-size: 0.8rem; padding-top: 0.5rem;'>Non-destructive: Uses disposable test probes and scoped test keys. Production datasets are untouched.</p>", unsafe_allow_html=True)

test_run_data = None
if run_btn:
    with st.spinner("Executing 11 cloud permission probes against Backblaze B2 S3 API..."):
        success, res = api_run_access_tests()
        if success:
            test_run_data = res
            st.success("Test execution run completed.")
        else:
            st.error(f"Test suite execution failed: {res}")

# Scorecard summary
recent_results = api_get_access_test_results()

if test_run_data:
    passed = test_run_data.get("passed", 0)
    failed = test_run_data.get("failed", 0)
    inconclusive = test_run_data.get("inconclusive", 0)
    total = test_run_data.get("total_tests", 11)
    display_records = test_run_data.get("results", [])
elif recent_results:
    latest_run_id = recent_results[0].get("run_id")
    display_records = [r for r in recent_results if r.get("run_id") == latest_run_id]
    passed = sum(1 for r in display_records if r.get("pass_fail") == "PASS")
    failed = sum(1 for r in display_records if r.get("pass_fail") == "FAIL")
    inconclusive = sum(1 for r in display_records if r.get("pass_fail") == "INCONCLUSIVE")
    total = len(display_records)
else:
    passed = 0
    failed = 0
    inconclusive = 0
    total = 11
    display_records = []

# Scorecard Cards
sc1, sc2, sc3, sc4 = st.columns(4)
with sc1:
    render_metric_card("Total Probes", str(total), "11 Mandatory Test Cases", "#14213D")
with sc2:
    render_metric_card("Passed", str(passed), "Expected matches Actual", "#16A34A")
with sc3:
    render_metric_card("Failed", str(failed), "Security boundary breach", "#DC2626" if failed > 0 else "#64748B")
with sc4:
    render_metric_card("Inconclusive", str(inconclusive), "Unconfigured B2 credentials", "#D97706" if inconclusive > 0 else "#64748B")

if inconclusive > 0:
    st.info(
        "ℹ️ **Inconclusive Results Notice:**\n\n"
        "Per compliance standards, an unconfigured or unreachable credential is an **inconclusive test**, "
        "not a successful denial. Populate valid Backblaze B2 credentials in `.env` to verify cloud-level enforcement."
    )

st.write("")
st.markdown("### Permission Verification Results Matrix")

if not display_records:
    st.info("No test runs recorded yet. Click 'Execute Cloud Permission Tests' above to run the verification suite.")
else:
    for t in display_records:
        pf_status = t.get("pass_fail", "INCONCLUSIVE")
        pf_badge = "success" if pf_status == "PASS" else ("error" if pf_status == "FAIL" else "warning")

        exp = t.get("expected_result")
        act = t.get("actual_result")
        status_code = t.get("status_code") or "N/A"

        st.markdown(
            f"""
            <div style="background: white; border: 1px solid #E2E8F0; border-radius: 8px; padding: 1.1rem; margin-bottom: 0.85rem;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-weight: 700; color: #14213D; font-size: 1rem;">{t.get('test_id')}: {t.get('requested_operation')}</span>
                        <span style="margin-left: 0.75rem; font-size: 0.8rem; background: #F1F5F9; color: #14213D; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600;">
                            Identity: {t.get('identity')}
                        </span>
                    </div>
                    <div>
                        {render_status_badge(pf_status, pf_badge)}
                    </div>
                </div>
                <div style="font-size: 0.8rem; color: #64748B; font-family: monospace; margin: 0.4rem 0;">
                    Target Resource: {t.get('target_resource')}
                </div>
                <div style="font-size: 0.85rem; color: #14213D; display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem; margin-top: 0.5rem; background: #F8FAFC; padding: 0.6rem; border-radius: 6px;">
                    <div><strong>Expected:</strong> <code>{exp}</code></div>
                    <div><strong>Actual:</strong> <code>{act}</code></div>
                    <div><strong>Status Code:</strong> <code>{status_code}</code></div>
                    <div><strong>Enforcement:</strong> {t.get('enforcement_layer')}</div>
                </div>
                <div style="font-size: 0.8rem; color: #64748B; margin-top: 0.45rem;">
                    <strong>Provider Response:</strong> <code>{t.get('provider_response') or 'None'}</code>
                </div>
                <div style="font-size: 0.78rem; color: #475569; margin-top: 0.25rem;">
                    <strong>Rationale:</strong> {t.get('notes') or ''} (Ref: <code>{t.get('evidence_reference') or ''}</code>)
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
