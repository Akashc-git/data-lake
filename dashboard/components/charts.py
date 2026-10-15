"""
Plotly Chart Renderers for CF-PS-15 Data Lake Access Control Dashboard.
Implements the required design palette:
Navy: #14213D, Blue: #2563EB, Card: #FFFFFF, Success: #16A34A,
Warning: #D97706, Error: #DC2626, Secondary: #64748B.
"""

from typing import Dict, List
import plotly.graph_objects as go
import streamlit as st


CHART_LAYOUT_DEFAULTS = dict(
    paper_bgcolor="#FFFFFF",
    plot_bgcolor="#FFFFFF",
    font=dict(family="Inter, -apple-system, sans-serif", color="#14213D", size=12),
    margin=dict(l=20, r=20, t=35, b=20),
)


def render_audit_outcomes_donut(allowed: int, denied: int):
    """Renders a donut chart illustrating allowed vs. denied request ratios."""
    if allowed == 0 and denied == 0:
        st.info("No audit access events recorded yet.")
        return

    labels = ["Allowed Operations", "Denied Requests (Access Control)"]
    values = [allowed, denied]
    colors = ["#16A34A", "#DC2626"]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.6,
                marker=dict(colors=colors, line=dict(color="#FFFFFF", width=2)),
                textinfo="label+value",
                hoverinfo="label+percent",
            )
        ]
    )
    fig.update_layout(
        title=dict(text="Authorization Decisions", font=dict(size=14, color="#14213D")),
        showlegend=False,
        **CHART_LAYOUT_DEFAULTS,
        height=260,
    )
    st.plotly_chart(fig, use_container_width=True)


def render_job_outcomes_chart(successful: int, failed: int):
    """Renders a bar chart for pipeline execution health."""
    if successful == 0 and failed == 0:
        st.info("No data transformation jobs executed yet.")
        return

    fig = go.Figure(
        data=[
            go.Bar(
                x=["Successful Jobs", "Failed Jobs"],
                y=[successful, failed],
                marker_color=["#2563EB", "#DC2626"],
                text=[successful, failed],
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        title=dict(text="Pipeline Job Health", font=dict(size=14, color="#14213D")),
        yaxis=dict(title="Execution Count", gridcolor="#F1F5F9"),
        xaxis=dict(showgrid=False),
        **CHART_LAYOUT_DEFAULTS,
        height=260,
    )
    st.plotly_chart(fig, use_container_width=True)


def render_storage_distribution_chart(raw_bytes: int, curated_bytes: int):
    """Renders storage volume distribution between raw and curated buckets."""
    if raw_bytes == 0 and curated_bytes == 0:
        st.info("No storage data present.")
        return

    raw_mb = round(raw_bytes / (1024 * 1024), 2)
    cur_mb = round(curated_bytes / (1024 * 1024), 2)

    fig = go.Figure(
        data=[
            go.Bar(
                x=["Raw Bucket", "Curated Bucket"],
                y=[raw_mb, cur_mb],
                marker_color=["#14213D", "#2563EB"],
                text=[f"{raw_mb} MB", f"{cur_mb} MB"],
                textposition="auto",
            )
        ]
    )
    fig.update_layout(
        title=dict(text="Storage Volume Distribution (MB)", font=dict(size=14, color="#14213D")),
        yaxis=dict(title="Megabytes (MB)", gridcolor="#F1F5F9"),
        xaxis=dict(showgrid=False),
        **CHART_LAYOUT_DEFAULTS,
        height=260,
    )
    st.plotly_chart(fig, use_container_width=True)
