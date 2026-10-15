"""
Custom Metric Cards and Status Badges for CF-PS-15 Streamlit Dashboard.
Implements the required color palette:
Navy: #14213D, Blue: #2563EB, Background: #F5F7FB, Card: #FFFFFF,
Success: #16A34A, Warning: #D97706, Error: #DC2626, Secondary: #64748B.
"""

from typing import Optional
import streamlit as st


def render_metric_card(
    title: str,
    value: str,
    subtitle: Optional[str] = None,
    status_color: Optional[str] = None,
    icon: Optional[str] = None,
):
    """Renders a modern, polished metric card adhering to the project design palette."""
    val_color = status_color or "#2563EB"
    icon_html = f"<span style='font-size: 1.3rem; margin-right: 0.4rem;'>{icon}</span>" if icon else ""
    sub_html = f"<div style='font-size: 0.8rem; color: #64748B; margin-top: 0.25rem;'>{subtitle}</div>" if subtitle else ""

    card_html = f"""
    <div style="
        background-color: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 1.1rem 1.25rem;
        box-shadow: 0 1px 3px rgba(20, 33, 61, 0.05);
        margin-bottom: 0.75rem;
    ">
        <div style="font-size: 0.85rem; font-weight: 600; color: #14213D; text-transform: uppercase; letter-spacing: 0.04em;">
            {icon_html}{title}
        </div>
        <div style="font-size: 1.85rem; font-weight: 700; color: {val_color}; margin-top: 0.35rem; font-feature-settings: 'tnum';">
            {value}
        </div>
        {sub_html}
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_status_badge(text: str, badge_type: str = "info") -> str:
    """Returns an inline HTML badge styled for status indicators."""
    colors = {
        "success": ("#16A34A", "#DCFCE7"),
        "error": ("#DC2626", "#FEE2E2"),
        "warning": ("#D97706", "#FEF3C7"),
        "info": ("#2563EB", "#DBEAFE"),
        "neutral": ("#64748B", "#F1F5F9"),
    }
    fg, bg = colors.get(badge_type.lower(), colors["neutral"])
    return f"""
    <span style="
        background-color: {bg};
        color: {fg};
        padding: 0.2rem 0.55rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        display: inline-block;
        border: 1px solid {fg}33;
    ">{text}</span>
    """
