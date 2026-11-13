
"""TRACE-SOC security operations analytics dashboard."""

import pandas as pd
import streamlit as st

from datetime import date, timedelta

from analytics.engine import (
    get_soc_kpis,
    get_alert_trend,
    get_severity_distribution,
    get_case_status_distribution,
    get_analyst_workload,
    get_mttd_mttr_trend,
    format_duration,
)

from cases.engine import create_case_schema


def render_soc_analytics():

    create_case_schema()

    st.title("📊 SOC Analytics & Performance Center")

    st.caption(
        "Monitor security alerts, incident response performance "
        "and SOC operational metrics."
    )

    st.info(
        "MTTD and MTTR are calculated using the timestamp proxies "
        "documented in the analytics methodology. Missing or invalid "
        "timestamps are excluded from their averages."
    )

    # --------------------------------------------------
    # DATE FILTER
    # --------------------------------------------------

    st.subheader("Analytics date range")

    col1, col2 = st.columns(2)

    today = date.today()

    with col1:

        start_date = st.date_input(
            "Start date",
            value=today - timedelta(days=29),
            key="analytics_start_date",
        )

    with col2:

        end_date = st.date_input(
            "End date",
            value=today,
            key="analytics_end_date",
        )

    if start_date > end_date:

        st.error("Start date cannot be later than end date.")
        return

    kpis = get_soc_kpis(start_date, end_date)

    st.divider()

    # --------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------

    st.subheader("SOC Performance Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Alerts",
        kpis["total_alerts"],
    )

    col2.metric(
        "Open Alerts",
        kpis["open_alerts"],
    )

    col3.metric(
        "Critical Alerts",
        kpis["critical_alerts"],
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Cases",
        kpis["total_cases"],
    )

    col2.metric(
        "Open Cases",
        kpis["open_cases"],
    )

    col3.metric(
        "Resolved Cases",
        kpis["resolved_cases"],
    )

    st.divider()

    # --------------------------------------------------
    # MTTD AND MTTR
    # --------------------------------------------------

    st.subheader("Detection & Resolution Performance")

    col1, col2 = st.columns(2)

    with col1:

        st.markdown("### Mean Time To Detect (MTTD)")

        st.metric(
            "Average Detection Time",
            format_duration(kpis["mttd_seconds"]),
        )

        st.caption(
            f"Based on {kpis['mttd_sample_count']} valid alert records."
        )

        st.write(
            "Calculated as alert creation time minus first observed "
            "event time."
        )

    with col2:

        st.markdown("### Mean Time To Resolve (MTTR)")

        st.metric(
            "Average Resolution Time",
            format_duration(kpis["mttr_seconds"]),
        )

        st.caption(
            f"Based on {kpis['mttr_sample_count']} resolved cases."
        )

        st.write(
            "Calculated as case resolution time minus case creation time."
        )

    st.divider()

    # --------------------------------------------------
    # ALERT TREND
    # --------------------------------------------------

    st.subheader("Alert Generation Trend")

    trend_days = st.selectbox(
        "Select trend period",
        [7, 14, 30, 60, 90],
        index=2,
    )

    alert_trend = get_alert_trend(trend_days)

    trend_df = pd.DataFrame(alert_trend)

    if not trend_df.empty:

        trend_df["date"] = pd.to_datetime(trend_df["date"])

        trend_df = trend_df.set_index("date")

        st.line_chart(
            trend_df[["alert_count"]],
            use_container_width=True,
        )

    else:

        st.info("No alert trend data is available.")

    st.divider()

    # --------------------------------------------------
    # SEVERITY AND CASE STATUS
    # --------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("Alert Severity Distribution")

        severity_data = get_severity_distribution()

        severity_df = pd.DataFrame(severity_data)

        if severity_df["count"].sum() > 0:

            st.bar_chart(
                severity_df.set_index("severity")[["count"]],
                use_container_width=True,
            )

            st.dataframe(
                severity_df,
                use_container_width=True,
                hide_index=True,
            )

        else:

            st.info("No alert severity data is available.")

    with col2:

        st.subheader("Incident Case Status")

        case_data = get_case_status_distribution()

        case_df = pd.DataFrame(case_data)

        if case_df["count"].sum() > 0:

            st.bar_chart(
                case_df.set_index("status")[["count"]],
                use_container_width=True,
            )

            st.dataframe(
                case_df,
                use_container_width=True,
                hide_index=True,
            )

        else:

            st.info("No case status data is available.")

    st.divider()

    # --------------------------------------------------
    # ANALYST WORKLOAD
    # --------------------------------------------------

    st.subheader("SOC Analyst Workload")

    workload = get_analyst_workload()

    if workload:

        workload_df = pd.DataFrame(workload)

        st.bar_chart(
            workload_df.set_index("analyst")[[
                "assigned_cases",
                "resolved_cases",
            ]],
            use_container_width=True,
        )

        st.dataframe(
            workload_df,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info("No analyst assignment data is available.")

    st.divider()

    # --------------------------------------------------
    # MTTD / MTTR TREND
    # --------------------------------------------------

    st.subheader("Detection and Resolution Trend")

    performance_trend = get_mttd_mttr_trend(trend_days)

    performance_df = pd.DataFrame(performance_trend)

    if not performance_df.empty:

        display_df = performance_df[
            ["date", "mttd_seconds", "mttr_seconds"]
        ].copy()

        display_df = display_df.set_index("date")

        display_df = display_df.rename(columns={
            "mttd_seconds": "MTTD (seconds)",
            "mttr_seconds": "MTTR (seconds)",
        })

        st.line_chart(
            display_df,
            use_container_width=True,
        )

        st.caption(
            "Days without valid observations or resolved cases have "
            "no corresponding measurement."
        )

        with st.expander("View daily performance data"):

            st.dataframe(
                performance_df,
                use_container_width=True,
                hide_index=True,
            )

    else:

        st.info("No detection or resolution trend data is available.")

    # --------------------------------------------------
    # EXPORT
    # --------------------------------------------------

    st.divider()

    st.subheader("Export Analytics")

    csv_data = trend_df.reset_index().to_csv(index=False)

    st.download_button(
        "Download Alert Trend CSV",
        data=csv_data,
        file_name="tracesoc_alert_trend.csv",
        mime="text/csv",
        use_container_width=True,
    )

    st.success(
        "CYFROG analytics dashboard loaded successfully."
    )
