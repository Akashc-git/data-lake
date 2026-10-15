"""
Data Processing Pipeline Page - CF-PS-15.
Allows authorized Processors to run schema validation, clean records with pandas,
and publish curated data products to Backblaze B2.
"""

from datetime import datetime
import pandas as pd
import streamlit as st

from api_client import api_list_raw_datasets, api_run_processing, api_get_dashboard_metrics
from components.metrics import render_metric_card, render_status_badge

st.set_page_config(page_title="Data Processing Pipeline", page_icon="⚙️", layout="wide")

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

st.title("Data Processing Pipeline")
st.markdown(
    f"<p style='color: #64748B; font-size: 0.95rem; margin-top: -0.75rem;'>"
    f"Active Identity: <strong>{username}</strong> • Role: <code>{user_role.upper()}</code>"
    f"</p>",
    unsafe_allow_html=True,
)

if user_role not in ("processor", "admin"):
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
                Data transformation pipelines can only be executed by identities with the <strong>Processor</strong> or <strong>Administrator</strong> role.<br>
                Analyst identities are restricted to consuming vetted curated outputs.
                Please switch identities using the sidebar quick switcher.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

# 1. Fetch available raw datasets
raw_datasets, err = api_list_raw_datasets()

if err:
    st.error(f"Failed to fetch raw datasets: {err}")
    st.stop()

if not raw_datasets:
    st.warning("⚠️ No raw datasets available. Please ingest a raw dataset first in the Data Lake Explorer.")
    st.stop()

col_select, col_config = st.columns([1, 1])

with col_select:
    st.markdown("### 1. Select Raw Source Dataset")
    ds_options = {d["id"]: f"{d['dataset_name']} ({d['original_filename']} - {d['row_count']} rows)" for d in raw_datasets}
    selected_id = st.selectbox("Available Raw Datasets:", options=list(ds_options.keys()), format_func=lambda x: ds_options[x])

    selected_record = next((d for d in raw_datasets if d["id"] == selected_id), None)

    if selected_record:
        st.markdown(
            f"""
            <div style="background: white; border: 1px solid #E2E8F0; border-radius: 8px; padding: 1rem; margin-top: 0.75rem;">
                <div style="font-weight: 700; color: #14213D; font-size: 1rem;">{selected_record['dataset_name']}</div>
                <div style="font-size: 0.8rem; color: #64748B; font-family: monospace; margin: 0.3rem 0;">
                    B2 Key: {selected_record['object_key']}
                </div>
                <div style="font-size: 0.82rem; color: #14213D; display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem;">
                    <div><strong>Original Format:</strong> {selected_record['file_format'].upper()}</div>
                    <div><strong>Input Row Count:</strong> {selected_record['row_count']}</div>
                    <div><strong>Payload Size:</strong> {round(selected_record['file_size_bytes'] / 1024, 2)} KB</div>
                    <div><strong>Current Status:</strong> {selected_record['processing_status']}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

with col_config:
    st.markdown("### 2. Transformation Settings")
    with st.form("pipeline_config_form"):
        missing_strategy = st.selectbox(
            "Missing Value Treatment:",
            ["drop", "impute", "none"],
            format_func=lambda x: {
                "drop": "Drop rows containing missing values (Strict Quality)",
                "impute": "Impute (Numeric: Median, Categorical: Mode)",
                "none": "Preserve missing values as nulls"
            }[x]
        )

        remove_dups = st.checkbox("Deduplication: Remove duplicate records", value=True)
        clean_headers = st.checkbox("Standardize column headers (snake_case, strip spaces)", value=True)
        output_fmt = st.selectbox("Curated Output Format:", ["csv", "parquet"], index=0)

        submit_btn = st.form_submit_button("🚀 Run Pipeline & Publish to Curated Bucket", type="primary", use_container_width=True)

# 2. Execution & Results Display
if submit_btn and selected_record:
    cfg = {
        "handle_missing": missing_strategy,
        "remove_duplicates": remove_dups,
        "clean_column_headers": clean_headers,
        "output_format": output_fmt,
    }

    with st.spinner("Downloading raw object from B2 raw bucket, running transformations, and publishing curated output..."):
        success, job_res = api_run_processing(selected_record["id"], cfg)

        if success:
            st.success("✅ **Pipeline Execution Successful!** Curated dataset published to private curated bucket.")
            
            # Metric Results Cards
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                render_metric_card("Input Rows", str(job_res.get("input_row_count", 0)), "Original source count", "#14213D")
            with c2:
                render_metric_card("Output Rows", str(job_res.get("output_row_count", 0)), "Curated clean count", "#2563EB")
            with c3:
                render_metric_card("Deduplicated", str(job_res.get("duplicates_removed", 0)), "Rows pruned", "#D97706")
            with c4:
                render_metric_card("Execution Time", f"{job_res.get('duration_seconds', 0)}s", "End-to-end runtime", "#16A34A")

            # Output Provenance
            st.markdown(
                f"""
                <div style="background: white; border: 1px solid #16A34A; border-radius: 8px; padding: 1rem; margin-top: 1rem;">
                    <div style="font-weight: 700; color: #16A34A; font-size: 0.95rem;">Published Curated Artifact:</div>
                    <div style="font-family: monospace; font-size: 0.85rem; color: #14213D; margin: 0.3rem 0;">
                        Target Object Key: <strong>{job_res.get('output_object_key')}</strong>
                    </div>
                    <div style="font-family: monospace; font-size: 0.8rem; color: #64748B;">
                        Curated Checksum (SHA-256): {job_res.get('output_checksum')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.error(f"❌ **Pipeline Execution Failed:** {job_res}")
