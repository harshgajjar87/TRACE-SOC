
"""TRACE-SOC advanced risk intelligence dashboard."""

import json

import pandas as pd
import streamlit as st
from dashboard.notifications import notify_success

from risk.engine import (
    create_risk_schema,
    assess_all_alerts,
    calculate_alert_risk,
    get_all_alerts,
    get_latest_risk_assessments,
    get_risk_summary,
)


def render_risk_intelligence():

    create_risk_schema()

    st.title("🎯 Advanced Threat Correlation & Risk Intelligence")

    st.caption(
        "Correlate security alerts, enrich threat context "
        "and prioritize investigation using explainable risk scores."
    )

    st.info(
        "Risk scores are heuristic prioritization values, not "
        "probabilities of compromise. IOC matches use exact IP "
        "indicators from linked normalized events."
    )

    # --------------------------------------------------
    # ASSESSMENT CONTROL
    # --------------------------------------------------

    col1, col2 = st.columns([3, 1])

    with col1:

        st.markdown("### Risk assessment engine")

        st.write(
            "Run the scoring engine to evaluate all existing alerts "
            "and save their latest risk assessments."
        )

    with col2:

        if st.button(
            "Run Risk Assessment",
            type="primary",
            use_container_width=True,
        ):

            try:

                with st.spinner("Correlating alerts and calculating risk..."):

                    results = assess_all_alerts()

                notify_success(
                    f"Assessment completed for {len(results)} alerts."
                )
                st.rerun()

            except Exception as error:

                st.error(f"Risk assessment failed: {error}")

    st.divider()

    summary = get_risk_summary()

    # --------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------

    st.subheader("Risk Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Assessed Alerts",
        summary["total_assessed"],
    )

    col2.metric(
        "Average Risk Score",
        summary["average_score"],
    )

    col3.metric(
        "High / Critical Risk",
        summary["high_and_critical"],
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Critical",
        summary["distribution"]["CRITICAL"],
    )

    col2.metric(
        "High",
        summary["distribution"]["HIGH"],
    )

    col3.metric(
        "Medium",
        summary["distribution"]["MEDIUM"],
    )

    col4.metric(
        "Low",
        summary["distribution"]["LOW"],
    )

    st.divider()

    # --------------------------------------------------
    # RISK DISTRIBUTION
    # --------------------------------------------------

    st.subheader("Risk Level Distribution")

    distribution_df = pd.DataFrame([
        {
            "Risk Level": level,
            "Alerts": count,
        }
        for level, count in summary["distribution"].items()
    ])

    if summary["total_assessed"]:

        st.bar_chart(
            distribution_df.set_index("Risk Level"),
            use_container_width=True,
        )

    else:

        st.info(
            "No risk assessments available. Click Run Risk Assessment."
        )

    st.divider()

    # --------------------------------------------------
    # RISK RANKING
    # --------------------------------------------------

    st.subheader("Ranked Security Alerts")

    assessments = get_latest_risk_assessments()

    if assessments:

        table_data = [
            {
                "Alert ID": item["alert_id"],
                "Rule": item["rule_name"],
                "Severity": item["severity"],
                "Risk Score": item["risk_score"],
                "Risk Level": item["risk_level"],
                "Alert Status": item["status"],
                "Hostname": item["hostname"],
                "Source IP": item["source_ip"],
            }
            for item in assessments
        ]

        ranking_df = pd.DataFrame(table_data)

        st.dataframe(
            ranking_df,
            use_container_width=True,
            hide_index=True,
        )

        # ----------------------------------------------
        # SELECT ALERT FOR INVESTIGATION
        # ----------------------------------------------

        st.markdown("### Investigate risk assessment")

        alert_ids = [
            item["alert_id"]
            for item in assessments
        ]

        selected_alert_id = st.selectbox(
            "Select alert",
            alert_ids,
        )

        if st.button("Recalculate Selected Alert"):

            try:

                calculate_alert_risk(
                    selected_alert_id,
                    save=True,
                )

                notify_success(f"Risk assessment updated for alert #{selected_alert_id}.")
                st.rerun()

            except Exception as error:

                st.error(str(error))

        result = next(
            (
                item for item in assessments
                if item["alert_id"] == selected_alert_id
            ),
            None,
        )

        if result:

            st.divider()

            st.markdown("### Risk assessment details")

            col1, col2, col3 = st.columns(3)

            col1.metric(
                "Risk Score",
                f"{result['risk_score']}/100",
            )

            col2.metric(
                "Risk Level",
                result["risk_level"],
            )

            col3.metric(
                "Alert Severity",
                result["severity"],
            )

            # ------------------------------------------
            # SCORING FACTORS
            # ------------------------------------------

            st.markdown("### Risk score explanation")

            try:

                factors = json.loads(
                    result["factors_json"] or "[]"
                )

            except (ValueError, TypeError):

                factors = []

            if factors:

                factor_df = pd.DataFrame([
                    {
                        "Risk Factor": factor["factor"],
                        "Points": factor["points"],
                        "Explanation": factor["reason"],
                    }
                    for factor in factors
                ])

                st.dataframe(
                    factor_df,
                    use_container_width=True,
                    hide_index=True,
                )

            # ------------------------------------------
            # RELATED ALERTS
            # ------------------------------------------

            st.markdown("### Correlated alerts")

            try:

                related_ids = json.loads(
                    result["related_alert_ids_json"] or "[]"
                )

            except (ValueError, TypeError):

                related_ids = []

            if related_ids:

                st.write(
                    "Related alerts found:",
                    ", ".join(str(value) for value in related_ids),
                )

            else:

                st.info(
                    "No related alerts were identified in the "
                    "configured correlation window."
                )

            # ------------------------------------------
            # IOC MATCHES
            # ------------------------------------------

            st.markdown("### Threat intelligence matches")

            try:

                ioc_result = calculate_alert_risk(
                    selected_alert_id,
                    save=False,
                )

                matches = ioc_result["ioc_matches"]

            except Exception:

                matches = []

            if matches:

                ioc_df = pd.DataFrame(matches)

                st.dataframe(
                    ioc_df,
                    use_container_width=True,
                    hide_index=True,
                )

            else:

                st.info(
                    "No active exact IP threat intelligence matches "
                    "were found in the linked events."
                )

    else:

        st.warning(
            "No risk assessment history is available. "
            "Run the risk assessment engine first."
        )

    st.divider()

    # --------------------------------------------------
    # EXPORT
    # --------------------------------------------------

    st.subheader("Export Risk Assessment")

    if assessments:

        export_df = pd.DataFrame([
            {
                "alert_id": item["alert_id"],
                "rule_id": item["rule_id"],
                "rule_name": item["rule_name"],
                "severity": item["severity"],
                "risk_score": item["risk_score"],
                "risk_level": item["risk_level"],
                "alert_status": item["status"],
                "hostname": item["hostname"],
                "username": item["username"],
                "source_ip": item["source_ip"],
                "assessed_at_utc": item["assessed_at_utc"],
            }
            for item in assessments
        ])

        st.download_button(
            "Download Risk Assessment CSV",
            data=export_df.to_csv(index=False),
            file_name="tracesoc_risk_assessments.csv",
            mime="text/csv",
            use_container_width=True,
        )

    else:

        st.info("Run risk assessments before exporting.")
