"""Day 28 dashboard view — System Health and Database Optimizer."""

from __future__ import annotations

import streamlit as st

try:
    import plotly.express as px
    _PLOTLY = True
except ImportError:
    _PLOTLY = False

from database.optimizer import (
    get_database_file_metrics,
    get_table_row_counts,
    get_index_list,
    get_system_health,
    run_analyze,
    run_integrity_check,
    run_foreign_key_check,
    run_vacuum,
)


_STATUS_COLORS = {
    "OK": "#34d399",
    "WARN": "#fbbf24",
    "MISSING": "#fb7185",
    "ERROR": "#fb7185",
}

_HEALTH_COLORS = {
    "HEALTHY": "#34d399",
    "DEGRADED": "#fbbf24",
    "CRITICAL": "#fb7185",
}


def render_system_health():
    st.markdown("""
    <div class='top-banner'>
      <div class='eyebrow'>SYSTEM  /  HEALTH & OPTIMIZATION</div>
      <div class='banner-title'>System Health</div>
      <div class='banner-sub'>Monitor database health, run maintenance operations and check component status.</div>
    </div>""", unsafe_allow_html=True)

    left, right = st.columns([3, 1])
    with right:
        if st.button("↻ Refresh", use_container_width=True):
            st.rerun()

    # Overall health check
    health = get_system_health()
    overall = health.get("status", "UNKNOWN")
    db = health.get("database", {})

    h_color = _HEALTH_COLORS.get(overall, "#94a3b8")
    st.markdown(
        f"<div class='top-banner' style='margin-bottom:16px;'>"
        f"<div class='eyebrow'>OVERALL STATUS</div>"
        f"<div class='banner-title' style='color:{h_color};font-size:2rem;'>{overall}</div>"
        f"<div class='banner-sub'>Checked at {str(health.get('checked_at_utc', ''))[:19].replace('T', ' ')} UTC</div>"
        f"</div>", unsafe_allow_html=True,
    )

    # DB file metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.markdown(
        f"<div class='metric-card'><div class='metric-label'>DB SIZE</div>"
        f"<div class='metric-value' style='color:#67d5f5;'>{db.get('size_mb', 0):.2f} MB</div></div>",
        unsafe_allow_html=True,
    )
    m2.markdown(
        f"<div class='metric-card'><div class='metric-label'>PAGES</div>"
        f"<div class='metric-value' style='color:#a5b4fc;'>{db.get('page_count', 0):,}</div></div>",
        unsafe_allow_html=True,
    )
    m3.markdown(
        f"<div class='metric-card'><div class='metric-label'>FREE PAGES</div>"
        f"<div class='metric-value' style='color:#fbbf24;'>{db.get('freelist_pages', 0):,}</div></div>",
        unsafe_allow_html=True,
    )
    m4.markdown(
        f"<div class='metric-card'><div class='metric-label'>FRAGMENTATION</div>"
        f"<div class='metric-value' style='color:{'#fb7185' if db.get('fragmentation_pct', 0) >= 20 else '#34d399'};'>"
        f"{db.get('fragmentation_pct', 0):.1f}%</div></div>",
        unsafe_allow_html=True,
    )

    st.write("")
    tab1, tab2, tab3, tab4 = st.tabs(["🗄️ Tables & Indexes", "🔧 Maintenance", "🧩 Components", "📐 Raw Metrics"])

    with tab1:
        st.markdown("<div class='section-kicker'>TABLE ROW COUNTS</div>", unsafe_allow_html=True)
        table_counts = get_table_row_counts()
        if table_counts:
            if _PLOTLY:
                top_tables = table_counts[:20]
                fig = px.bar(
                    top_tables,
                    x="table", y="row_count",
                    color="row_count",
                    color_continuous_scale=["#164e63", "#0ea5e9", "#67e8f9"],
                    labels={"table": "Table", "row_count": "Rows"},
                )
                fig.update_layout(
                    template="plotly_dark", height=360,
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#b9c9dc"),
                    margin=dict(l=12, r=12, t=28, b=80),
                    coloraxis_showscale=False,
                    xaxis_tickangle=-45,
                )
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            st.dataframe(table_counts, use_container_width=True, hide_index=True)
        else:
            st.info("No tables found.")

        st.write("")
        st.markdown("<div class='section-kicker'>INDEXES</div>", unsafe_allow_html=True)
        indexes = get_index_list()
        if indexes:
            st.dataframe(
                [{"name": i["name"], "table": i["table_name"]} for i in indexes],
                use_container_width=True,
                hide_index=True,
            )
            st.caption(f"{len(indexes)} indexes defined.")
        else:
            st.info("No indexes found.")

    with tab2:
        st.markdown("<div class='section-kicker'>DATABASE MAINTENANCE</div>", unsafe_allow_html=True)
        st.caption(
            "ANALYZE updates query planner statistics and is safe to run any time. "
            "VACUUM rewrites the database file to reclaim free space — it is safe but can take a moment."
        )

        col1, col2, col3, col4 = st.columns(4)

        if col1.button("▶ Run ANALYZE", use_container_width=True):
            result = run_analyze()
            st.success(f"ANALYZE completed in {result['elapsed_seconds']}s. {result['note']}")

        if col2.button("🔍 Integrity Check", use_container_width=True):
            result = run_integrity_check()
            if result["status"] == "OK":
                st.success("Integrity check passed — no issues found.")
            else:
                st.error(f"Integrity issues found: {result['results']}")

        if col3.button("🔗 Foreign Key Check", use_container_width=True):
            result = run_foreign_key_check()
            if result["status"] == "OK":
                st.success("No foreign key violations found.")
            else:
                st.warning(f"{result['violation_count']} violation(s) found.")
                st.dataframe(result["violations"], use_container_width=True, hide_index=True)

        st.write("")
        st.markdown("<div class='section-kicker'>VACUUM (DEFRAGMENT)</div>", unsafe_allow_html=True)
        st.warning(
            "VACUUM rewrites the entire database file. It is non-destructive but can take several seconds "
            "on larger databases. Only run this when the application is not actively writing data."
        )
        if st.button("🧹 Run VACUUM", type="secondary"):
            with st.spinner("Running VACUUM — this may take a moment…"):
                result = run_vacuum()
            reclaimed_mb = result.get("reclaimed_mb", 0)
            st.success(
                f"VACUUM completed in {result['elapsed_seconds']}s. "
                f"Reclaimed {reclaimed_mb:.3f} MB."
            )
            st.rerun()

    with tab3:
        st.markdown("<div class='section-kicker'>COMPONENT STATUS</div>", unsafe_allow_html=True)
        components = health.get("components", [])
        if components:
            display = []
            for c in components:
                color = _STATUS_COLORS.get(c.get("status", ""), "#94a3b8")
                display.append({
                    "component": c["component"],
                    "type": c.get("type", ""),
                    "status": c.get("status", ""),
                    "detail": c.get("detail") or str(c.get("row_count", "")),
                })
            st.dataframe(display, use_container_width=True, hide_index=True)
        else:
            st.info("No component data available.")

    with tab4:
        st.markdown("<div class='section-kicker'>RAW DATABASE METRICS</div>", unsafe_allow_html=True)
        st.json(db)

        st.markdown("<div class='section-kicker'>CORE TABLE COUNTS</div>", unsafe_allow_html=True)
        core_counts = health.get("core_table_counts", {})
        if core_counts:
            st.dataframe(
                [{"table": k, "rows": v} for k, v in core_counts.items()],
                use_container_width=True,
                hide_index=True,
            )
