
"""TRACE-SOC MITRE ATT&CK coverage dashboard."""

import pandas as pd
import streamlit as st

from attack.engine import (
    create_attack_schema,
    sync_alert_mappings,
    register_technique,
    map_alert_to_technique,
    get_techniques,
    get_mapped_alerts,
    get_unmapped_alerts,
    get_technique_coverage,
    get_tactic_distribution,
    get_attack_coverage_summary,
    get_technique_details,
)


def render_attack_coverage():

    create_attack_schema()

    st.title("🎯 MITRE ATT&CK Coverage Center")

    st.caption(
        "Explore alert mappings, ATT&CK tactics, techniques "
        "and detection coverage gaps."
    )

    st.info(
        "Existing alert mappings are imported from their stored "
        "MITRE fields. Automatically imported metadata remains "
        "unverified until checked against an authoritative ATT&CK reference."
    )

    # --------------------------------------------------
    # SYNC EXISTING ALERTS
    # --------------------------------------------------

    col1, col2 = st.columns([3, 1])

    with col1:

        st.markdown("### Synchronize existing alert mappings")

        st.write(
            "Import the MITRE tactic and technique fields already "
            "stored in your detection alerts."
        )

    with col2:

        if st.button(
            "Sync Alert Mappings",
            type="primary",
            use_container_width=True,
        ):

            try:

                result = sync_alert_mappings()

                st.success(
                    f"Processed: {result['processed_alerts']} | "
                    f"Mapping records: {result['mapped_records']} | "
                    f"Skipped: {result['skipped_alerts']}"
                )

                st.rerun()

            except Exception as error:

                st.error(f"Synchronization failed: {error}")

    st.divider()

    summary = get_attack_coverage_summary()

    # --------------------------------------------------
    # KPI CARDS
    # --------------------------------------------------

    st.subheader("ATT&CK Coverage Overview")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Alerts",
        summary["total_alerts"],
    )

    col2.metric(
        "Mapped Alerts",
        summary["mapped_alerts"],
    )

    col3.metric(
        "Unmapped Alerts",
        summary["unmapped_alerts"],
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Alert Mapping Rate",
        f"{summary['alert_mapping_percentage']}%",
    )

    col2.metric(
        "Observed Techniques",
        summary["observed_techniques"],
    )

    col3.metric(
        "Verified Techniques",
        summary["verified_techniques"],
    )

    st.caption(
        f"Catalog observation rate: "
        f"{summary['catalog_observation_percentage']}% of the "
        f"{summary['total_catalog_techniques']} configured catalog "
        "techniques have at least one linked alert. This is not "
        "coverage of the entire MITRE ATT&CK framework."
    )

    st.divider()

    # --------------------------------------------------
    # TACTIC DISTRIBUTION
    # --------------------------------------------------

    st.subheader("Tactic Distribution")

    tactics = get_tactic_distribution()

    if tactics:

        tactic_df = pd.DataFrame(tactics)

        st.bar_chart(
            tactic_df.set_index("tactic")[["alert_count"]],
            use_container_width=True,
        )

        st.dataframe(
            tactic_df,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No ATT&CK mappings are available. Synchronize alert mappings first."
        )

    st.divider()

    # --------------------------------------------------
    # TECHNIQUE CATALOG
    # --------------------------------------------------

    st.subheader("Technique Coverage")

    coverage = get_technique_coverage()

    if coverage:

        coverage_df = pd.DataFrame(coverage)

        st.dataframe(
            coverage_df,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info("No techniques have been registered yet.")

    st.divider()

    # --------------------------------------------------
    # UNMAPPED ALERTS
    # --------------------------------------------------

    st.subheader("Unmapped Alerts")

    unmapped = get_unmapped_alerts()

    if unmapped:

        unmapped_df = pd.DataFrame(unmapped)

        st.dataframe(
            unmapped_df,
            use_container_width=True,
            hide_index=True,
        )

        st.caption(
            "These alerts have no linked ATT&CK mapping. "
            "A missing mapping is a coverage gap, not proof "
            "that the detection rule is ineffective."
        )

    else:

        st.success("All existing alerts have at least one mapping.")

    st.divider()

    # --------------------------------------------------
    # REGISTER VERIFIED TECHNIQUE
    # --------------------------------------------------

    st.subheader("Register Verified ATT&CK Technique")

    st.caption(
        "Use the official MITRE ATT&CK reference to verify "
        "the technique ID, name and tactic before registration."
    )

    with st.form("register_attack_technique"):

        technique_id = st.text_input(
            "Technique ID",
            placeholder="Example: T1110",
        )

        technique_name = st.text_input(
            "Technique name",
            placeholder="Example: Brute Force",
        )

        tactic = st.text_input(
            "Tactic",
            placeholder="Example: Credential Access",
        )

        description = st.text_area(
            "Description",
            placeholder="Describe the verified technique.",
        )

        register_submitted = st.form_submit_button(
            "Register Technique",
            type="primary",
        )

        if register_submitted:

            try:

                registered_id = register_technique(
                    technique_id=technique_id,
                    technique_name=technique_name,
                    tactic=tactic,
                    description=description,
                )

                st.success(
                    f"Technique {registered_id} registered successfully."
                )

                st.rerun()

            except Exception as error:

                st.error(str(error))

    st.divider()

    # --------------------------------------------------
    # MANUAL ALERT MAPPING
    # --------------------------------------------------

    st.subheader("Map Alert to Verified Technique")

    techniques = get_techniques()
    mapped_alerts = get_mapped_alerts()
    unmapped_alerts = get_unmapped_alerts()

    if unmapped_alerts and techniques:

        alert_options = {
            (
                f"Alert #{alert['id']} | "
                f"{alert['rule_name']} | "
                f"{alert['severity']}"
            ): alert["id"]
            for alert in unmapped_alerts
        }

        technique_options = {
            (
                f"{technique['technique_id']} | "
                f"{technique['technique_name']} | "
                f"{technique['tactic']}"
            ): technique
            for technique in techniques
        }

        with st.form("manual_attack_mapping"):

            selected_alert = st.selectbox(
                "Select unmapped alert",
                list(alert_options.keys()),
            )

            selected_technique_label = st.selectbox(
                "Select verified technique",
                list(technique_options.keys()),
            )

            confidence = st.selectbox(
                "Mapping confidence",
                ["LOW", "MEDIUM", "HIGH"],
                index=1,
            )

            mapped_by = st.text_input(
                "Mapped by analyst",
                placeholder="SOC Analyst",
            )

            map_submitted = st.form_submit_button(
                "Create ATT&CK Mapping",
            )

            if map_submitted:

                selected_technique = technique_options[
                    selected_technique_label
                ]

                try:

                    map_alert_to_technique(
                        alert_id=alert_options[selected_alert],
                        technique_id=selected_technique["technique_id"],
                        tactic=selected_technique["tactic"],
                        mapped_by=mapped_by,
                        confidence=confidence,
                    )

                    st.success("Alert mapped successfully.")

                    st.rerun()

                except Exception as error:

                    st.error(str(error))

    elif not techniques:

        st.info(
            "Register a verified technique before manually mapping alerts."
        )

    else:

        st.info("No unmapped alerts are currently available.")

    st.divider()

    # --------------------------------------------------
    # TECHNIQUE INVESTIGATION
    # --------------------------------------------------

    st.subheader("Investigate a Technique")

    if techniques:

        technique_ids = [
            item["technique_id"]
            for item in techniques
        ]

        selected_id = st.selectbox(
            "Select technique ID",
            technique_ids,
        )

        details = get_technique_details(selected_id)

        if details:

            technique = details["technique"]

            st.markdown(
                f"### {technique['technique_id']} – "
                f"{technique['technique_name']}"
            )

            st.write("**Tactic:**", technique["tactic"])

            st.write(
                "**Description:**",
                technique["description"] or "No description available.",
            )

            st.write("**Metadata source:**", technique["source"])

            if details["alerts"]:

                st.markdown("### Associated alerts")

                st.dataframe(
                    pd.DataFrame(details["alerts"]),
                    use_container_width=True,
                    hide_index=True,
                )

            else:

                st.info("No alerts are currently linked to this technique.")

    # --------------------------------------------------
    # EXPORT
    # --------------------------------------------------

    st.divider()

    st.subheader("Export ATT&CK Coverage")

    if coverage:

        export_df = pd.DataFrame(coverage)

        st.download_button(
            "Download ATT&CK Coverage CSV",
            data=export_df.to_csv(index=False),
            file_name="tracesoc_attack_coverage.csv",
            mime="text/csv",
            use_container_width=True,
        )

    else:

        st.info("Register techniques before exporting coverage.")
