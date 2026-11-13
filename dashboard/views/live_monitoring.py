"""
TRACE-SOC — Live Monitoring dashboard page.

Provides Start / Stop collection controls that launch the monitoring
runner in a background daemon thread, keeping the Streamlit UI
responsive. The DB-backed monitoring_status table is the source of
truth for all status displays.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone

import streamlit as st

from monitoring.engine import (
    create_monitoring_schema,
    get_monitoring_runs,
    get_monitoring_status,
    get_monitoring_summary,
    update_service_status,
)
from monitoring.runner import run_continuous_monitoring, stop_event
from collectors.windows_event_collector import DEFAULT_CHANNELS


# ---------------------------------------------------------------------------
# Thread management helpers
# ---------------------------------------------------------------------------

_THREAD_KEY = "_monitoring_thread"


def _monitoring_thread_alive() -> bool:
    """Return True if a monitoring thread is running in this session."""
    t: threading.Thread | None = st.session_state.get(_THREAD_KEY)
    return t is not None and t.is_alive()


def _start_collection(
    channels: list[str],
    interval: int,
    max_events: int,
) -> None:
    """
    Launch run_continuous_monitoring in a background daemon thread.
    The thread is stored in session_state so we can check its liveness.
    """
    # Clear any previous stop signal
    stop_event.clear()

    def _target():
        try:
            run_continuous_monitoring(
                channels=channels,
                polling_interval_seconds=interval,
                max_events=max_events,
            )
        except Exception:
            # Errors are already recorded in the DB by run_monitoring_cycle
            pass

    t = threading.Thread(target=_target, name="trace-soc-monitor", daemon=True)
    t.start()
    st.session_state[_THREAD_KEY] = t


def _stop_collection() -> None:
    """Signal the background thread to stop after its current cycle."""
    stop_event.set()
    # Mark status immediately so the UI reflects STOPPED without waiting
    # for the thread to finish its cleanup
    update_service_status("STOPPED")


# ---------------------------------------------------------------------------
# Main render
# ---------------------------------------------------------------------------

def render_live_monitoring():
    create_monitoring_schema()

    # ── Page header ────────────────────────────────────────────────────────
    st.markdown("""
    <div class='top-banner'>
      <div class='eyebrow'>COMMAND CENTER  /  LIVE MONITORING</div>
      <div class='banner-title'>Live Monitoring</div>
      <div class='banner-sub'>
        Control Windows event collection and track polling health in real time.
      </div>
    </div>""", unsafe_allow_html=True)

    # ── Live status ────────────────────────────────────────────────────────
    status = get_monitoring_status()
    summary = get_monitoring_summary()
    service_status = status.get("service_status", "UNKNOWN")

    # Reconcile DB status with actual thread state
    thread_alive = _monitoring_thread_alive()
    if service_status == "RUNNING" and not thread_alive:
        # Thread died (app restart / previous session) — correct the DB
        update_service_status("STOPPED")
        service_status = "STOPPED"
        status = get_monitoring_status()

    # ── Status banner ──────────────────────────────────────────────────────
    _STATUS_STYLES = {
        "RUNNING": ("🟢", "#34d399", "Collection is active"),
        "STOPPED": ("⚪", "#7188a5", "Collection is stopped"),
        "ERROR":   ("🔴", "#fb7185", "Collection error — see details below"),
    }
    icon, color, label = _STATUS_STYLES.get(
        service_status, ("⚪", "#7188a5", service_status)
    )
    st.markdown(
        f"<div style='display:flex;align-items:center;gap:10px;"
        f"background:#0e1a2b;border:1px solid #1e3550;border-radius:12px;"
        f"padding:14px 20px;margin-bottom:20px;'>"
        f"<span style='font-size:1.5rem;'>{icon}</span>"
        f"<div>"
        f"<div style='font-size:1.1rem;font-weight:700;color:{color};'>"
        f"Service {service_status}</div>"
        f"<div style='font-size:.85rem;color:#7a96b4;margin-top:2px;'>{label}</div>"
        f"</div></div>",
        unsafe_allow_html=True,
    )

    # ── Control panel ──────────────────────────────────────────────────────
    st.markdown("<div class='section-kicker'>COLLECTION CONTROLS</div>",
                unsafe_allow_html=True)

    with st.container():
        ctrl_cols = st.columns([1, 1, 1, 2])

        with ctrl_cols[0]:
            interval = st.number_input(
                "Polling interval (sec)",
                min_value=10,
                max_value=3600,
                value=int(status.get("polling_interval_seconds") or 60),
                step=10,
                help="How often to poll Windows Event Logs.",
            )

        with ctrl_cols[1]:
            max_events = st.number_input(
                "Max events per cycle",
                min_value=10,
                max_value=5000,
                value=500,
                step=50,
                help="Maximum events collected per polling cycle.",
            )

        with ctrl_cols[2]:
            available_channels = list(DEFAULT_CHANNELS)
            selected_channels = st.multiselect(
                "Channels",
                options=available_channels,
                default=available_channels,
                help="Windows Event Log channels to collect from.",
            )

    st.write("")
    btn_cols = st.columns([1, 1, 4])

    is_running = service_status == "RUNNING" and thread_alive

    with btn_cols[0]:
        start_disabled = is_running
        if st.button(
            "▶  Start Collection",
            type="primary",
            disabled=start_disabled,
            use_container_width=True,
            help="Launch background collection. The page will auto-refresh.",
        ):
            if not selected_channels:
                st.error("Select at least one channel before starting.")
            else:
                _start_collection(
                    channels=selected_channels,
                    interval=int(interval),
                    max_events=int(max_events),
                )
                st.success(
                    f"Collection started — polling every {interval}s "
                    f"across {len(selected_channels)} channel(s)."
                )
                st.rerun()

    with btn_cols[1]:
        stop_disabled = not is_running
        if st.button(
            "■  Stop Collection",
            type="secondary",
            disabled=stop_disabled,
            use_container_width=True,
            help="Signal the background thread to stop after the current cycle.",
        ):
            _stop_collection()
            st.info("Stop signal sent. Collection will finish the current cycle then halt.")
            st.rerun()

    # Auto-refresh while running
    if is_running:
        st.caption(
            f"⟳  Auto-refresh every {max(interval, 15)}s while collection is active."
        )
        # st.rerun() on a timer — Streamlit doesn't have native auto-refresh,
        # so we use a small fragment-free trick via time.sleep + rerun.
        # We only do this if the user hasn't just clicked a button.
        import time
        time.sleep(0)   # yield, keeps UI responsive
        st.markdown(
            f"<meta http-equiv='refresh' content='{max(interval, 15)}'>",
            unsafe_allow_html=True,
        )

    if status.get("last_error"):
        st.error(f"Last collection error: {status['last_error']}")

    st.divider()

    # ── Metrics ────────────────────────────────────────────────────────────
    st.markdown("<div class='section-kicker'>COLLECTION STATISTICS</div>",
                unsafe_allow_html=True)

    m1, m2, m3, m4, m5, m6 = st.columns(6)
    metric_data = [
        (m1, "TOTAL CYCLES",   summary["total_runs"],       "#67d5f5"),
        (m2, "SUCCESSFUL",     summary["successful_runs"],   "#34d399"),
        (m3, "FAILED",         summary["failed_runs"],       "#fb7185"),
        (m4, "EVENTS RCVD",    summary["total_received"],    "#a5b4fc"),
        (m5, "EVENTS STORED",  summary["total_inserted"],    "#38bdf8"),
        (m6, "DUPLICATES",     summary["total_duplicates"],  "#fbbf24"),
    ]
    for col, label, value, color in metric_data:
        with col:
            st.markdown(
                f"<div class='metric-card'>"
                f"<div class='metric-label'>{label}</div>"
                f"<div class='metric-value' style='color:{color};'>{value:,}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

    # ── Service detail row ─────────────────────────────────────────────────
    st.write("")
    d1, d2, d3 = st.columns(3)
    d1.metric("Polling interval",
              f"{status.get('polling_interval_seconds', 0)}s")
    d2.metric("Last run",
              str(status.get("last_run_at_utc") or "—")[:19].replace("T", " "))
    d3.metric("Last success",
              str(status.get("last_success_at_utc") or "—")[:19].replace("T", " "))

    st.divider()

    # ── Collection history ─────────────────────────────────────────────────
    st.markdown("<div class='section-kicker'>RECENT COLLECTION HISTORY</div>",
                unsafe_allow_html=True)

    runs = get_monitoring_runs(limit=50)

    if not runs:
        st.info("No collection cycles recorded yet. Start collection above.")
    else:
        display = []
        for r in runs:
            display.append({
                "id":          r["id"],
                "started":     str(r.get("started_at_utc") or "")[:19].replace("T", " "),
                "completed":   str(r.get("completed_at_utc") or "")[:19].replace("T", " "),
                "status":      r["status"],
                "received":    r["total_received"],
                "inserted":    r["total_inserted"],
                "duplicates":  r["total_duplicates"],
            })
        st.dataframe(display, use_container_width=True, hide_index=True)

        # Cycle detail expander
        with st.expander("Cycle details"):
            selected_id = st.selectbox(
                "Select cycle",
                options=[r["id"] for r in runs],
                format_func=lambda x: (
                    f"#{x}  {next(r['started_at_utc'][:19] for r in runs if r['id']==x)}"
                ),
            )
            selected_run = next(r for r in runs if r["id"] == selected_id)

            c1, c2, c3 = st.columns(3)
            c1.metric("Status",    selected_run["status"])
            c2.metric("Received",  selected_run["total_received"])
            c3.metric("Inserted",  selected_run["total_inserted"])

            try:
                channel_data = json.loads(selected_run["channels_json"] or "{}")
                if channel_data:
                    st.json(channel_data)
            except (TypeError, json.JSONDecodeError):
                pass

            if selected_run["error_message"]:
                st.error(selected_run["error_message"])

    # ── Manual refresh ─────────────────────────────────────────────────────
    st.write("")
    if st.button("↻  Refresh page", use_container_width=False):
        st.rerun()

    st.caption(
        "Collection runs in a background thread within this Streamlit session. "
        "If you close the browser tab or restart Streamlit, collection stops automatically."
    )
