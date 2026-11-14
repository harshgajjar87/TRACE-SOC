"""Centralized notification and flash message system for CYFROG."""

from __future__ import annotations

import streamlit as st


def notify_success(message: str, icon: str = "✅") -> None:
    """Queue a success notification that survives st.rerun()."""
    st.session_state["_flash_message"] = {
        "type": "success",
        "text": message,
        "icon": icon,
    }


def notify_error(message: str, icon: str = "❌") -> None:
    """Queue an error notification that survives st.rerun()."""
    st.session_state["_flash_message"] = {
        "type": "error",
        "text": message,
        "icon": icon,
    }


def notify_info(message: str, icon: str = "ℹ️") -> None:
    """Queue an info notification that survives st.rerun()."""
    st.session_state["_flash_message"] = {
        "type": "info",
        "text": message,
        "icon": icon,
    }


def notify_warning(message: str, icon: str = "⚠️") -> None:
    """Queue a warning notification that survives st.rerun()."""
    st.session_state["_flash_message"] = {
        "type": "warning",
        "text": message,
        "icon": icon,
    }


def render_notifications() -> None:
    """Render any queued flash message as both an alert banner and floating toast."""
    msg = st.session_state.pop("_flash_message", None)
    if not msg:
        return

    m_type = msg.get("type", "info")
    text = msg.get("text", "")
    icon = msg.get("icon", "🔔")

    if m_type == "success":
        st.success(text, icon=icon)
    elif m_type == "error":
        st.error(text, icon=icon)
    elif m_type == "warning":
        st.warning(text, icon=icon)
    else:
        st.info(text, icon=icon)

    try:
        st.toast(text, icon=icon)
    except Exception:
        pass

