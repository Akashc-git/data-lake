"""
CF-PS-15 Data Lake Access Control Dashboard - Home / Overview.
Provides live cloud storage health, real-time access control metrics,
identity switching, and audit event monitoring.
"""

from datetime import datetime, timezone
import pandas as pd
import streamlit as st

from api_client import (
    api_get_dashboard_metrics,
    api_get_health,
    api_get_storage_status,
    api_login,
    api_logout,
)
from components.charts import render_audit_outcomes_donut, render_job_outcomes_chart
from components.metrics import render_metric_card, render_status_badge

# Configure Page
st.set_page_config(
    page_title="CF-PS-15 Data Lake Access Control",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling adhering strictly to the design palette
st.markdown(
    """
    <style>
    /* Background & Global Typography */
    .stApp {
        background-color: #F5F7FB;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Headers */
    h1, h2, h3, h4 {
        color: #14213D !important;
        font-weight: 700 !important;
    }
    
    /* Buttons */
    div.stButton > button:first-child {
        background-color: #2563EB;
        color: white;
        border-radius: 6px;
        font-weight: 600;
        border: none;
        padding: 0.5rem 1rem;
        transition: all 0.2s ease-in-out;
    }
    div.stButton > button:first-child:hover {
        background-color: #1D4ED8;
        color: white;
        box-shadow: 0 4px 6px -1px rgba(37, 99, 235, 0.2);
    }
    
    /* Card Container */
    .metric-card-container {
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize Session State
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "auth_token" not in st.session_state:
    st.session_state["auth_token"] = None
if "user_profile" not in st.session_state:
    st.session_state["user_profile"] = None

# Auto-login default demo user (Administrator) on first load if not authenticated
if not st.session_state["logged_in"]:
    api_login("admin", "AdminSecure2026!")

# ==============================================================================
# SIDEBAR: Identity & Access Management
# ==============================================================================
with st.sidebar:
    st.markdown("### 🛡️ Access Control Console")
    st.markdown("<p style='color: #64748B; font-size: 0.85rem;'>CF-PS-15 • Backblaze B2 Data Lake</p>", unsafe_allow_html=True)
    st.divider()

    # Active User Display
    user = st.session_state.get("user_profile")
    if st.session_state.get("logged_in") and user:
        role = user.get("role", "analyst")
        badge_type = "success" if role == "admin" else ("info" if role == "processor" else "warning")
        
        st.markdown(f"**Active Identity:** `{user.get('username')}`")
        st.markdown(f"**Assigned Role:** {render_status_badge(role.upper(), badge_type)}", unsafe_allow_html=True)
        
        if st.button("Log Out", key="sidebar_logout_btn"):
            api_logout()
            st.rerun()
    else:
        st.warning("Not Authenticated")

    st.divider()
    st.markdown("#### Quick Identity Switcher")
    st.markdown("<p style='color: #64748B; font-size: 0.8rem;'>Test the interface with distinct permission profiles:</p>", unsafe_allow_html=True)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("Processor", help="Switch to Data Pipeline Processor"):
            api_login("processor_user", "ProcessorPass2026!")
            st.rerun()
    with col_btn2:
        if st.button("Analyst", help="Switch to Curated Data Analyst"):
            api_login("analyst_user", "AnalystPass2026!")
            st.rerun()

    if st.button("Administrator", help="Switch to System Administrator"):
        api_login("admin", "AdminSecure2026!")
        st.rerun()

    st.divider()
    st.markdown("#### Cloud Target")
    st.markdown(
        """
        * **Provider:** Backblaze B2 (S3 API)
        * **Storage:** Multi-Bucket Partitioning
        * **Enforcement:** Cloud IAM + RBAC
        """
    )


# ==============================================================================
# MAIN PAGE: Overview
# ==============================================================================
col_title, col_refresh = st.columns([4, 1])
with col_title:
    st.title("Data Lake Access Control Dashboard")
    st.markdown(
        "<p style='color: #64748B; margin-top: -0.75rem; font-size: 1rem;'>"
        "Real-time governance, permission testing, and pipeline telemetry for Backblaze B2 storage."
        "</p>",
        unsafe_allow_html=True,
    )
with col_refresh:
    st.write("")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.rerun()

# 1. Cloud & System Connectivity Banner
storage_status = api_get_storage_status()
health_info = api_get_health()

b2_configured = storage_status.get("is_configured", False)
buckets = storage_status.get("buckets", [])

with st.expander("🌐 Cloud Connectivity & Bucket Status", expanded=not b2_configured):
    if not b2_configured:
        st.warning(
            "⚠️ **Backblaze B2 Credentials Not Configured in `.env`**\n\n"
            "The dashboard is operating in local/diagnostic mode. Cloud access probes will report "
            "`INCONCLUSIVE` until real B2 credentials and bucket names are populated in your local `.env` file.\n\n"
            "See `scripts/check_b2_connection.py` and `README.md` for setup instructions."
        )
    else:
        b_cols = st.columns(len(buckets) if buckets else 3)
        for idx, b in enumerate(buckets):
            with b_cols[idx]:
                b_status = b.get("status", "UNCONFIGURED")
                b_color = "#16A34A" if b.get("reachable") else "#DC2626"
                st.markdown(
                    f"""
                    <div style="background: white; border: 1px solid #E2E8F0; border-radius: 6px; padding: 0.75rem;">
                        <div style="font-size: 0.8rem; font-weight: 600; color: #14213D;">{b.get('bucket_role')}</div>
                        <div style="font-size: 0.95rem; font-weight: 700; color: {b_color}; margin: 0.2rem 0;">
                            {b.get('bucket_name')}
                        </div>
                        <div style="font-size: 0.75rem; color: #64748B;">{b.get('message', '')}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

# 2. Live Computed Metrics
metrics = api_get_dashboard_metrics()
now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)

with m_col1:
    render_metric_card(
        title="Raw Objects",
        value=str(metrics.get("raw_object_count", 0)),
        subtitle="Private Raw Bucket",
        status_color="#14213D",
        icon="📦",
    )

with m_col2:
    render_metric_card(
        title="Curated Objects",
        value=str(metrics.get("curated_object_count", 0)),
        subtitle="Vetted Curated Bucket",
        status_color="#2563EB",
        icon="✨",
    )

with m_col3:
    succ = metrics.get("successful_processing_jobs", 0)
    failed = metrics.get("failed_processing_jobs", 0)
    total_jobs = metrics.get("total_processing_jobs", 0)
    render_metric_card(
        title="Pipeline Runs",
        value=f"{succ}/{total_jobs}",
        subtitle=f"{failed} failed runs",
        status_color="#16A34A" if failed == 0 else "#D97706",
        icon="⚙️",
    )

with m_col4:
    allowed = metrics.get("allowed_requests_count", 0)
    denied = metrics.get("denied_requests_count", 0)
    render_metric_card(
        title="Enforcements",
        value=f"{allowed} / {denied}",
        subtitle="Allowed vs Denied",
        status_color="#2563EB",
        icon="⚖️",
    )

with m_col5:
    passed_tests = metrics.get("latest_tests_passed", 0)
    failed_tests = metrics.get("latest_tests_failed", 0)
    inconclusive = metrics.get("latest_tests_inconclusive", 0)
    test_val = f"{passed_tests}/11" if (passed_tests + failed_tests + inconclusive) > 0 else "0/11"
    t_color = "#16A34A" if passed_tests == 11 else ("#D97706" if inconclusive > 0 else "#DC2626")
    render_metric_card(
        title="Cloud Probes",
        value=test_val,
        subtitle=f"{inconclusive} unconfigured" if inconclusive > 0 else "Verified",
        status_color=t_color,
        icon="🧪",
    )

st.markdown(f"<p style='color: #64748B; font-size: 0.75rem; margin-top: -0.5rem;'>Dashboard last refreshed: {now_str}</p>", unsafe_allow_html=True)
st.write("")

# 3. Operational Charts
chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("#### Access Control Decisions")
    render_audit_outcomes_donut(
        allowed=metrics.get("allowed_requests_count", 0),
        denied=metrics.get("denied_requests_count", 0),
    )

with chart_col2:
    st.markdown("#### Data Processing Pipeline Health")
    render_job_outcomes_chart(
        successful=metrics.get("successful_processing_jobs", 0),
        failed=metrics.get("failed_processing_jobs", 0),
    )

st.write("")

# 4. Recent Cloud Operations and Audit Activity
st.markdown("#### Recent Cloud Operations & Security Events")
recent_events = metrics.get("recent_audit_events", [])

if not recent_events:
    st.info("No security events or cloud operations recorded yet. Ingest a dataset or run access control tests to generate live audit logs.")
else:
    df_events = pd.DataFrame(recent_events)
    display_df = df_events[["timestamp", "actor", "role", "operation", "resource", "outcome", "correlation_id"]]
    display_df.columns = ["Timestamp", "Actor", "Role", "Operation", "Target Resource", "Outcome", "Correlation ID"]
    st.dataframe(display_df, use_container_width=True, hide_index=True)
