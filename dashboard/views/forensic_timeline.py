"""Day 24 dashboard view — Forensic Timeline Analysis."""

from __future__ import annotations

from datetime import datetime, date, time as dt_time, timedelta, timezone
import streamlit as st

from forensics.timeline import build_forensic_timeline, get_timeline_summary
from forensics.engine import ARTIFACT_TYPES, ARTIFACT_STATUSES
from database.db import get_connection


def _get_db_time_bounds() -> tuple[date, date]:
    """Return earliest and latest date in normalized_events, defaulting to recent week."""
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM normalized_events"
        ).fetchone()
        conn.close()
        if row and row[0] and row[1]:
            d_min = datetime.fromisoformat(str(row[0])[:19]).date()
            d_max = datetime.fromisoformat(str(row[1])[:19]).date()
            return d_min, d_max
    except Exception:
        pass
    today = datetime.now(timezone.utc).date()
    return today - timedelta(days=7), today


_SOURCE_COLORS = {
    "endpoint_telemetry": "#38bdf8",
    "forensic_artifact": "#34d399",
    "investigation_story": "#a5b4fc",
    "alert": "#fb7185",
}


def render_forensic_timeline():
    st.markdown("""
    <div class='top-banner'>
      <div class='eyebrow'>FORENSICS  /  TIMELINE</div>
      <div class='banner-title'>Forensic Timeline Analysis</div>
      <div class='banner-sub'>Reconstruct a unified chronological view from endpoint telemetry, forensic artifacts and investigation alerts.</div>
    </div>""", unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with right:
        if st.button("↻ Refresh", use_container_width=True):
            st.rerun()

    # Filters
    st.markdown("<div class='section-kicker'>TIMELINE FILTERS</div>", unsafe_allow_html=True)

    f_host, f_preset = st.columns([1.5, 1.5])
    with f_host:
        hostname = st.text_input(
            "Hostname (partial match)",
            placeholder="e.g. LAB-PC, HarshGajjar",
            key="tl_host",
        )
    with f_preset:
        preset = st.selectbox(
            "Time Range Preset",
            [
                "All Available Time",
                "Full Database Range",
                "Last 24 Hours",
                "Last 3 Days",
                "Last 7 Days",
                "Custom Date & Time Selection",
            ],
            index=0,
            key="tl_preset",
        )

    db_min_date, db_max_date = _get_db_time_bounds()

    start_time: str | None = None
    end_time: str | None = None

    if preset == "All Available Time":
        start_time = None
        end_time = None
        st.caption("ℹ️ Showing all chronological events without time constraints.")

    elif preset == "Full Database Range":
        start_time = f"{db_min_date.isoformat()}T00:00:00"
        end_time = f"{db_max_date.isoformat()}T23:59:59"
        st.caption(f"🗓️ Entire recorded activity window: **{db_min_date}** to **{db_max_date}**.")

    elif preset == "Last 24 Hours":
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(hours=24)
        start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%S")
        st.caption(f"⏱️ Filtering from **{start_time.replace('T', ' ')} UTC** to **{end_time.replace('T', ' ')} UTC**.")

    elif preset == "Last 3 Days":
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(days=3)
        start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%S")
        st.caption(f"⏱️ Filtering from **{start_time.replace('T', ' ')} UTC** to **{end_time.replace('T', ' ')} UTC**.")

    elif preset == "Last 7 Days":
        now = datetime.now(timezone.utc)
        start_dt = now - timedelta(days=7)
        start_time = start_dt.strftime("%Y-%m-%dT%H:%M:%S")
        end_time = now.strftime("%Y-%m-%dT%H:%M:%S")
        st.caption(f"⏱️ Filtering from **{start_time.replace('T', ' ')} UTC** to **{end_time.replace('T', ' ')} UTC**.")

    elif preset == "Custom Date & Time Selection":
        d1, t1, d2, t2 = st.columns(4)
        with d1:
            start_date = st.date_input("Start Date", value=db_min_date, key="tl_start_date")
        with t1:
            start_time_val = st.time_input("Start Time (UTC)", value=dt_time(0, 0, 0), key="tl_start_time")
        with d2:
            end_date = st.date_input("End Date", value=db_max_date, key="tl_end_date")
        with t2:
            end_time_val = st.time_input("End Time (UTC)", value=dt_time(23, 59, 59), key="tl_end_time")

        start_time = f"{start_date.isoformat()}T{start_time_val.strftime('%H:%M:%S')}"
        end_time = f"{end_date.isoformat()}T{end_time_val.strftime('%H:%M:%S')}"
        st.caption(f"📅 Custom selection: **{start_time.replace('T', ' ')} UTC** → **{end_time.replace('T', ' ')} UTC**")

    with st.expander("⚙️ Manual ISO Timestamp Override (optional)"):
        use_manual = st.checkbox("Enable manual ISO string entry", value=False, key="tl_manual_chk")
        if use_manual:
            m1, m2 = st.columns(2)
            manual_start = m1.text_input("Start time (ISO UTC)", value=start_time or "", key="tl_man_start")
            manual_end = m2.text_input("End time (ISO UTC)", value=end_time or "", key="tl_man_end")
            start_time = manual_start.strip() or None
            end_time = manual_end.strip() or None

    s1, s2, s3, s4 = st.columns(4)
    story_id_raw = s1.number_input("Story ID (0 = all)", min_value=0, step=1, value=0, key="tl_story")
    inc_telemetry = s2.checkbox("Endpoint telemetry", value=True)
    inc_artifacts = s3.checkbox("Forensic artifacts", value=True)
    inc_alerts = s4.checkbox("Investigation alerts", value=True)

    max_entries = st.slider("Max entries per source", 100, 2000, 500, step=100)

    if st.button("Build Timeline", type="primary"):
        story_id = int(story_id_raw) if story_id_raw else None

        with st.spinner("Reconstructing timeline…"):
            timeline = build_forensic_timeline(
                hostname=hostname.strip() or None,
                start_time=start_time.strip() or None,
                end_time=end_time.strip() or None,
                story_id=story_id,
                include_telemetry=inc_telemetry,
                include_artifacts=inc_artifacts,
                include_alerts=inc_alerts,
                max_entries=max_entries,
            )

        summary = get_timeline_summary(timeline)

        # Summary metrics
        st.write("")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Entries", summary["total_entries"])
        m2.metric("Unique Hosts", len(summary["unique_hosts"]))
        m3.metric("Unique Users", len(summary["unique_users"]))
        m4.metric("Sources", len(summary["by_source"]))

        if summary["earliest"] or summary["latest"]:
            st.caption(
                f"Period: {str(summary['earliest'] or '')[:19].replace('T',' ')} "
                f"→ {str(summary['latest'] or '')[:19].replace('T',' ')}"
            )

        # Source breakdown
        if summary["by_source"]:
            st.markdown("<div class='section-kicker'>ENTRIES BY SOURCE</div>", unsafe_allow_html=True)
            src_cols = st.columns(len(summary["by_source"]))
            for col, (src, cnt) in zip(src_cols, summary["by_source"].items()):
                color = _SOURCE_COLORS.get(src, "#94a3b8")
                col.markdown(
                    f"<div class='metric-card'>"
                    f"<div class='metric-label'>{src.replace('_', ' ').upper()}</div>"
                    f"<div class='metric-value' style='color:{color};'>{cnt}</div>"
                    f"</div>", unsafe_allow_html=True,
                )

        st.write("")
        st.markdown("<div class='section-kicker'>TIMELINE</div>", unsafe_allow_html=True)

        if timeline:
            display = []
            for e in timeline:
                display.append({
                    "timestamp": str(e.get("timestamp_utc") or "")[:19].replace("T", " "),
                    "source": e.get("source", ""),
                    "hostname": e.get("hostname") or "—",
                    "username": e.get("username") or "—",
                    "source_ip": e.get("source_ip") or "—",
                    "event_id": e.get("event_id") or "—",
                    "description": e.get("description") or "",
                    "detail": str(e.get("detail") or "")[:120],
                    "image": str(e.get("image") or "")[-60:] or "—",
                })
            st.dataframe(display, use_container_width=True, hide_index=True)
            st.caption(
                f"Showing {len(display)} of {summary['total_entries']} timeline entries. "
                "Sorted by UTC timestamp ascending."
            )
        else:
            st.info("No timeline entries found with the selected filters. Try widening the time range or hostname.")

    else:
        st.info("Configure filters above and click **Build Timeline** to reconstruct a forensic timeline.")
        st.caption(
            "The timeline merges endpoint telemetry events, forensic artifact collection records "
            "and investigation alerts into a unified chronological view."
        )
