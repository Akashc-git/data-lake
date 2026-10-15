"""
Data Lake Explorer - CF-PS-15.
Provides role-segregated navigation of Raw and Curated storage tiers.
Enforces strict denial of raw datasets for Analyst sessions.
"""

from datetime import datetime
import io
import pandas as pd
import streamlit as st

from api_client import (
    api_download_dataset,
    api_ingest_remote,
    api_list_curated_datasets,
    api_list_raw_datasets,
    api_upload_dataset,
)
from components.metrics import render_status_badge

st.set_page_config(page_title="Data Lake Explorer", page_icon="🗄️", layout="wide")

st.markdown(
    """
    <style>
    .stApp { background-color: #F5F7FB; }
    h1, h2, h3 { color: #14213D !important; }
    </style>
    """,
    unsafe_allow_html=True,
)

# Active User Context
user = st.session_state.get("user_profile")
user_role = user.get("role", "analyst") if user else "analyst"
username = user.get("username", "anonymous") if user else "anonymous"

st.title("Data Lake Explorer")
st.markdown(
    f"<p style='color: #64748B; font-size: 0.95rem; margin-top: -0.75rem;'>"
    f"Active Identity: <strong>{username}</strong> • Role: <code>{user_role.upper()}</code>"
    f"</p>",
    unsafe_allow_html=True,
)

tab_curated, tab_raw = st.tabs(["✨ Curated Datasets (Analytical Tier)", "🔒 Raw Datasets (Restricted Tier)"])

# ==============================================================================
# TAB 1: Curated Datasets
# ==============================================================================
with tab_curated:
    st.markdown("### Vetted Curated Datasets")
    st.markdown("<p style='color: #64748B; font-size: 0.85rem;'>Cleaned, validated, and published data products accessible by Analysts and Processors.</p>", unsafe_allow_html=True)

    curated_items, cur_err = api_list_curated_datasets()

    if cur_err:
        st.error(f"Error accessing curated storage: {cur_err}")
    elif not curated_items:
        st.info("No curated datasets published yet. Run the Data Processing Pipeline on a raw dataset to generate curated outputs.")
    else:
        # Search & Filtering
        col_search, col_filter = st.columns([3, 1])
        with col_search:
            search_term = st.text_input("🔍 Search curated datasets by name or key:", key="cur_search")
        with col_filter:
            format_filter = st.selectbox("Format Filter:", ["All", "csv", "parquet", "json"], key="cur_format")

        filtered = curated_items
        if search_term:
            filtered = [d for d in filtered if search_term.lower() in d["dataset_name"].lower() or search_term.lower() in d["object_key"].lower()]
        if format_filter != "All":
            filtered = [d for d in filtered if d.get("file_format") == format_filter]

        st.markdown(f"**Showing {len(filtered)} curated datasets:**")

        for ds in filtered:
            with st.container():
                st.markdown(
                    f"""
                    <div style="background: white; border: 1px solid #E2E8F0; border-radius: 8px; padding: 1.1rem; margin-bottom: 0.85rem;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="font-size: 1.1rem; font-weight: 700; color: #14213D;">{ds.get('dataset_name')}</span>
                            <span style="font-size: 0.8rem; background: #DBEAFE; color: #2563EB; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600;">
                                {ds.get('file_format', '').upper()}
                            </span>
                        </div>
                        <div style="font-size: 0.8rem; color: #64748B; margin-top: 0.4rem; font-family: monospace;">
                            B2 Key: {ds.get('object_key')}
                        </div>
                        <div style="font-size: 0.82rem; color: #14213D; margin-top: 0.5rem; display: flex; gap: 1.5rem;">
                            <span><strong>Rows:</strong> {ds.get('row_count', 'N/A')}</span>
                            <span><strong>Size:</strong> {round(ds.get('file_size_bytes', 0) / 1024, 2)} KB</span>
                            <span><strong>SHA-256:</strong> <code>{ds.get('sha256_checksum', '')[:16]}...</code></span>
                            <span><strong>Created By:</strong> {ds.get('created_by')}</span>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                col_meta, col_dl = st.columns([4, 1])
                with col_meta:
                    with st.expander("Inspect Columns & Schema"):
                        cols = ds.get("column_names") or []
                        st.write("**Columns:**", cols if cols else "No columns recorded")
                        st.write("**Curated From Raw ID:**", ds.get("curated_from_id", "N/A"))
                with col_dl:
                    if st.button("⬇️ Download", key=f"dl_cur_{ds['id']}", use_container_width=True):
                        content, fname, dl_err = api_download_dataset(ds["id"])
                        if dl_err:
                            st.error(dl_err)
                        elif content:
                            st.download_button(
                                label="Confirm Save",
                                data=content,
                                file_name=fname or f"{ds['original_filename']}",
                                mime="text/csv" if ds["file_format"] == "csv" else "application/octet-stream",
                                key=f"save_cur_{ds['id']}",
                                use_container_width=True,
                            )


# ==============================================================================
# TAB 2: Raw Datasets
# ==============================================================================
with tab_raw:
    st.markdown("### Private Raw Storage")
    st.markdown("<p style='color: #64748B; font-size: 0.85rem;'>Immutable source records. Strictly restricted to Processor and Admin identities.</p>", unsafe_allow_html=True)

    # ENFORCE ACCESS CONTROL: Analyst is strictly prohibited
    if user_role == "analyst":
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
                    ⛔ Access Denied (403 Forbidden)
                </div>
                <div style="font-size: 0.95rem; color: #991B1B; margin-top: 0.5rem; line-height: 1.5;">
                    Your active role (<strong>Analyst</strong>) is prohibited from viewing, listing, or downloading
                    unvetted raw datasets.<br>
                    Raw storage may contain unmasked personally identifiable information (PII) or unvalidated source records.
                    Please consult your system administrator or switch to the <strong>Processor</strong> profile in the sidebar to perform ingestion.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        # Authorized Processors / Administrators View
        st.success(f"Identity '{username}' verified as authorized {user_role.upper()} for raw storage operations.")

        # Ingestion Section
        with st.expander("📤 Ingest New Raw Dataset", expanded=False):
            ingest_mode = st.radio("Ingestion Source:", ["Upload Local File", "Ingest from Public URL"], horizontal=True)

            if ingest_mode == "Upload Local File":
                uploaded_file = st.file_uploader("Select CSV, JSON, or Parquet file:", type=["csv", "json", "parquet"])
                custom_name = st.text_input("Dataset Title (optional):", key="raw_upload_name")

                if st.button("Upload to Private Raw Bucket", type="primary"):
                    if not uploaded_file:
                        st.warning("Please select a file to upload.")
                    else:
                        with st.spinner("Uploading and calculating SHA-256 integrity hash..."):
                            file_bytes = uploaded_file.read()
                            succ, res = api_upload_dataset(
                                file_bytes=file_bytes,
                                filename=uploaded_file.name,
                                dataset_name=custom_name or uploaded_file.name,
                            )
                            if succ:
                                st.success(f"Dataset successfully ingested under key `{res.get('object_key')}`!")
                                st.rerun()
                            else:
                                st.error(f"Ingestion failed: {res}")

            else:
                remote_url = st.text_input(
                    "Public Dataset URL (Must be verified HTTP/HTTPS; anti-SSRF enforced):",
                    value="https://raw.githubusercontent.com/mwaskom/seaborn-data/master/iris.csv"
                )
                remote_name = st.text_input("Dataset Title (optional):", value="UCI Iris Reference Dataset")

                if st.button("Fetch and Ingest from URL", type="primary"):
                    with st.spinner("Validating destination, streaming content, and uploading to Backblaze B2 raw bucket..."):
                        succ, res = api_ingest_remote(source_url=remote_url, dataset_name=remote_name)
                        if succ:
                            st.success(f"Remote dataset ingested successfully: `{res.get('object_key')}`")
                            st.rerun()
                        else:
                            st.error(f"Remote ingestion failed: {res}")

        st.divider()

        # Raw Datasets List
        raw_items, raw_err = api_list_raw_datasets()
        if raw_err:
            st.error(f"Error accessing raw storage: {raw_err}")
        elif not raw_items:
            st.info("No raw datasets currently stored in B2 raw bucket. Use the ingestion form above to add your first dataset.")
        else:
            st.markdown(f"**Found {len(raw_items)} Raw Datasets:**")
            for ds in raw_items:
                with st.container():
                    st.markdown(
                        f"""
                        <div style="background: white; border: 1px solid #E2E8F0; border-radius: 8px; padding: 1.1rem; margin-bottom: 0.85rem;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 1.1rem; font-weight: 700; color: #14213D;">{ds.get('dataset_name')}</span>
                                <span style="font-size: 0.8rem; background: #FEF3C7; color: #D97706; padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 600;">
                                    RAW SOURCE ({ds.get('file_format', '').upper()})
                                </span>
                            </div>
                            <div style="font-size: 0.8rem; color: #64748B; margin-top: 0.4rem; font-family: monospace;">
                                B2 Key: {ds.get('object_key')}
                            </div>
                            <div style="font-size: 0.82rem; color: #14213D; margin-top: 0.5rem; display: flex; gap: 1.5rem;">
                                <span><strong>Rows:</strong> {ds.get('row_count', 'N/A')}</span>
                                <span><strong>Size:</strong> {round(ds.get('file_size_bytes', 0) / 1024, 2)} KB</span>
                                <span><strong>SHA-256:</strong> <code>{ds.get('sha256_checksum', '')[:16]}...</code></span>
                                <span><strong>Status:</strong> {ds.get('processing_status')}</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    col_meta, col_dl = st.columns([4, 1])
                    with col_meta:
                        with st.expander("Source Details & Columns"):
                            st.write("**Source URL:**", ds.get("source_url") or "Local File Upload")
                            st.write("**Columns:**", ds.get("column_names") or [])
                    with col_dl:
                        if st.button("⬇️ Download Raw", key=f"dl_raw_{ds['id']}", use_container_width=True):
                            content, fname, dl_err = api_download_dataset(ds["id"])
                            if dl_err:
                                st.error(dl_err)
                            elif content:
                                st.download_button(
                                    label="Save File",
                                    data=content,
                                    file_name=fname or f"{ds['original_filename']}",
                                    mime="text/csv" if ds["file_format"] == "csv" else "application/octet-stream",
                                    key=f"save_raw_{ds['id']}",
                                    use_container_width=True,
                                )
