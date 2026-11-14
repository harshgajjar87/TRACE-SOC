"""Day 26 dashboard view — IOC-to-Event Correlation."""

from __future__ import annotations

import streamlit as st

try:
    import plotly.express as px
    _PLOTLY = True
except ImportError:
    _PLOTLY = False

from threat_intel.correlator import (
    create_ioc_correlation_schema,
    run_ioc_correlation,
    get_correlations,
    get_correlation_summary,
    add_analyst_note_to_correlation,
)
from threat_intel.engine import IOC_TYPES
from dashboard.notifications import notify_success


_SEV_COLORS = {
    "CRITICAL": "#fb7185",
    "HIGH": "#fb923c",
    "MEDIUM": "#fbbf24",
    "LOW": "#38bdf8",
    "INFO": "#94a3b8",
}


def _style_chart(fig, height=300):
    fig.update_layout(
        template="plotly_dark", height=height,
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#b9c9dc"),
        margin=dict(l=12, r=12, t=48, b=12),
        legend=dict(font=dict(color="#a9bdd3")),
    )
    return fig


def render_ioc_correlation():
    create_ioc_correlation_schema()

    st.markdown("""
    <div class='top-banner'>
      <div class='eyebrow'>THREAT INTELLIGENCE  /  IOC CORRELATION</div>
      <div class='banner-title'>IOC-to-Event Correlation</div>
      <div class='banner-sub'>Match active threat indicators against stored endpoint telemetry to surface events touching known bad infrastructure.</div>
    </div>""", unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with right:
        if st.button("↻ Refresh", key="refresh_ioc_corr_btn", use_container_width=True):
            st.rerun()

    if "ioc_scan_success_msg" in st.session_state:
        st.success(st.session_state.pop("ioc_scan_success_msg"))

    # Summary cards
    summary = get_correlation_summary()
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(
        f"<div class='metric-card'><div class='metric-label'>TOTAL CORRELATIONS</div>"
        f"<div class='metric-value' style='color:#67d5f5;'>{summary.get('total_correlations', 0)}</div></div>",
        unsafe_allow_html=True,
    )
    m2.markdown(
        f"<div class='metric-card'><div class='metric-label'>AFFECTED EVENTS</div>"
        f"<div class='metric-value' style='color:#fb7185;'>{summary.get('affected_events', 0)}</div></div>",
        unsafe_allow_html=True,
    )
    m3.markdown(
        f"<div class='metric-card'><div class='metric-label'>IOC TYPES</div>"
        f"<div class='metric-value' style='color:#a5b4fc;'>{len(summary.get('by_type', []))}</div></div>",
        unsafe_allow_html=True,
    )
    m4.markdown(
        f"<div class='metric-card'><div class='metric-label'>TOP INDICATOR HITS</div>"
        f"<div class='metric-value' style='color:#34d399;'>{len(summary.get('top_indicators', []))}</div></div>",
        unsafe_allow_html=True,
    )

    st.write("")

    # Run correlation engine
    st.markdown("<div class='section-kicker'>RUN IOC CORRELATION SCAN</div>", unsafe_allow_html=True)
    r1, r2, r3 = st.columns([1, 1, 2])
    ev_limit = r1.number_input("Event limit", min_value=100, max_value=50000, value=5000, step=500, key="ic_ev_limit")
    ioc_limit = r2.number_input("IOC limit", min_value=10, max_value=10000, value=2000, step=100, key="ic_ioc_limit")

    if r3.button("▶ Run Correlation Scan", type="primary", key="btn_run_ioc_scan"):
        with st.spinner("Scanning events against active IOCs…"):
            run_result = run_ioc_correlation(
                event_limit=int(ev_limit),
                ioc_limit=int(ioc_limit),
            )
        dup = run_result.get("duplicate_correlations", 0)
        dup_txt = f" ({dup:,} already existed)" if dup else ""
        notify_success(
            f"Scan complete — {run_result['events_scanned']:,} events scanned against "
            f"{run_result['iocs_checked']:,} active IOCs: "
            f"{run_result['new_correlations']:,} new correlations found{dup_txt}."
        )
        st.rerun()

    st.write("")
    left_col, right_col = st.columns([1, 1])

    with left_col:
        st.markdown("<div class='section-kicker'>BY SEVERITY</div>", unsafe_allow_html=True)
        if _PLOTLY and summary.get("by_severity"):
            fig = px.bar(
                summary["by_severity"],
                x="severity", y="count",
                color="severity",
                color_discrete_map=_SEV_COLORS,
            )
            fig.update_traces(marker_line_width=0)
            st.plotly_chart(_style_chart(fig), use_container_width=True, config={"displayModeBar": False})
        else:
            st.info("No correlations yet. Run a scan above.")

    with right_col:
        st.markdown("<div class='section-kicker'>TOP INDICATORS</div>", unsafe_allow_html=True)
        top = summary.get("top_indicators", [])
        if top:
            st.dataframe(
                [{"indicator": t["indicator"], "type": t["ioc_type"], "event_hits": t["event_hits"]}
                 for t in top],
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.info("No correlations yet.")

    st.write("")
    st.markdown("<div class='section-kicker'>CORRELATION RESULTS</div>", unsafe_allow_html=True)

    cf1, cf2, cf3 = st.columns(3)
    sev_f = cf1.selectbox("Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], key="ic_sev")
    type_f = cf2.selectbox("IOC type", ["ALL", *IOC_TYPES], key="ic_type")
    ind_f = cf3.text_input("Indicator search", key="ic_ind")

    rows = get_correlations(
        ioc_severity=sev_f if sev_f != "ALL" else None,
        ioc_type=type_f if type_f != "ALL" else None,
        indicator=ind_f or None,
        limit=500,
    )

    if rows:
        display = [{
            "id": r["id"],
            "timestamp": str(r.get("timestamp_utc") or "")[:19].replace("T", " "),
            "hostname": r.get("hostname") or "—",
            "username": r.get("username") or "—",
            "source_ip": r.get("source_ip") or "—",
            "ioc_type": r.get("ioc_type"),
            "indicator": r.get("indicator"),
            "matched_field": r.get("matched_field"),
            "confidence": r.get("match_confidence"),
            "severity": r.get("ioc_severity"),
            "source": r.get("ioc_source"),
            "note": r.get("analyst_note") or "",
        } for r in rows]
        st.dataframe(display, use_container_width=True, hide_index=True)

        # Analyst note addition
        with st.expander("Add analyst note to a correlation"):
            with st.form("add_corr_note"):
                corr_id = st.number_input("Correlation ID", min_value=1, step=1)
                note_text = st.text_area("Note")
                if st.form_submit_button("Save Note"):
                    ok = add_analyst_note_to_correlation(int(corr_id), note_text)
                    if ok:
                        notify_success(f"Analyst note saved to correlation #{corr_id}.")
                        st.rerun()
                    else:
                        st.warning("Correlation not found.")
    else:
        st.info("No correlation results found. Run a scan and ensure IOCs are loaded.")

    st.info(
        "A correlation match means an active IOC indicator value appears in stored event data. "
        "It is a signal for analyst review, not proof of compromise."
    )
