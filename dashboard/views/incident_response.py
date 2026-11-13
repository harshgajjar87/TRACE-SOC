"""TRACE-SOC incident response dashboard page."""

import streamlit as st
import pandas as pd

from response.engine import (
    create_response_schema,
    get_available_alerts,
    get_response_runs,
    get_run_details,
    create_playbook_run,
    verify_response_evidence,
)

from response.playbooks import get_playbooks


def render_incident_response():

    create_response_schema()

    st.title("🛡️ Incident Response Center")

    st.caption(
        "Execute analyst-approved response playbooks and maintain "
        "an auditable incident response history."
    )

    st.info(
        "Safety: This module records recommendations and preserves "
        "evidence hashes. It does not block IPs, isolate hosts, "
        "disable accounts or modify endpoint configurations."
    )

    alerts = get_available_alerts()

    runs = get_response_runs()

    total_runs = len(runs)

    completed_runs = sum(
        1 for run in runs if run["status"] == "COMPLETED"
    )

    evidence_records = 0

    for run in runs:
        details = get_run_details(run["id"])
        if details:
            evidence_records += len(details["evidence"])

    col1, col2, col3 = st.columns(3)

    col1.metric("Available Alerts", len(alerts))
    col2.metric("Playbook Runs", total_runs)
    col3.metric("Completed Runs", completed_runs)

    st.divider()

    tab1, tab2, tab3 = st.tabs([
        "Run Playbook",
        "Response History",
        "Evidence Verification",
    ])

    # --------------------------------------------------
    # TAB 1: RUN PLAYBOOK
    # --------------------------------------------------

    with tab1:

        st.subheader("Start Incident Response")

        if not alerts:
            st.warning(
                "No alerts are available. Generate or import detection "
                "alerts before running a response playbook."
            )

        else:

            alert_options = {
                (
                    f"Alert #{alert['id']} | "
                    f"{alert['rule_name']} | "
                    f"{alert['severity']} | "
                    f"{alert['status']}"
                ): alert["id"]
                for alert in alerts
            }

            selected_alert_label = st.selectbox(
                "Select an alert",
                list(alert_options.keys()),
            )

            selected_alert_id = alert_options[selected_alert_label]

            selected_alert = next(
                alert for alert in alerts
                if alert["id"] == selected_alert_id
            )

            with st.expander("View selected alert details", expanded=True):

                st.write(
                    "**Rule:**",
                    selected_alert.get("rule_name"),
                )

                st.write(
                    "**Severity:**",
                    selected_alert.get("severity"),
                )

                st.write(
                    "**Hostname:**",
                    selected_alert.get("hostname") or "Not available",
                )

                st.write(
                    "**Username:**",
                    selected_alert.get("username") or "Not available",
                )

                st.write(
                    "**Source IP:**",
                    selected_alert.get("source_ip") or "Not available",
                )

                st.write(
                    "**Description:**",
                    selected_alert.get("description") or "Not available",
                )

            playbooks = get_playbooks()

            playbook_options = {
                f"{value['name']} — {value['description']}": key
                for key, value in playbooks.items()
            }

            selected_playbook_label = st.selectbox(
                "Select a response playbook",
                list(playbook_options.keys()),
            )

            selected_playbook_id = playbook_options[
                selected_playbook_label
            ]

            selected_playbook = playbooks[selected_playbook_id]

            st.markdown("### Playbook execution steps")

            for index, step in enumerate(
                selected_playbook["steps"], start=1
            ):

                with st.container(border=True):

                    st.markdown(
                        f"**Step {index}: {step['name']}**"
                    )

                    st.write(step["description"])

                    st.caption(
                        f"Action type: {step['action_type']}"
                    )

            st.divider()

            st.markdown("### Analyst approval")

            analyst_name = st.text_input(
                "Approved by (analyst name)",
                placeholder="Enter analyst name",
                max_chars=120,
            )

            approval_note = st.text_area(
                "Approval note",
                placeholder=(
                    "Example: Reviewed alert details and approved "
                    "the evidence preservation and triage workflow."
                ),
            )

            st.warning(
                "By clicking the approval button, you authorize CYFROG "
                "to execute the selected local workflow and record its "
                "steps. No external containment action will be performed."
            )

            if st.button(
                "Approve and Execute Playbook",
                type="primary",
                use_container_width=True,
            ):

                if not analyst_name.strip():

                    st.error("Please enter the analyst name.")

                else:

                    try:

                        run_id = create_playbook_run(
                            alert_id=selected_alert_id,
                            playbook_id=selected_playbook_id,
                            approved_by=analyst_name,
                            approval_note=approval_note,
                        )

                        st.success(
                            f"Playbook executed successfully! Run ID: {run_id}"
                        )

                        st.rerun()

                    except Exception as error:

                        st.error(
                            f"Playbook execution failed: {error}"
                        )

    # --------------------------------------------------
    # TAB 2: RESPONSE HISTORY
    # --------------------------------------------------

    with tab2:

        st.subheader("Response Execution History")

        history = get_response_runs(limit=200)

        if not history:

            st.info("No response playbooks have been executed yet.")

        else:

            history_data = []

            for run in history:

                history_data.append({
                    "Run ID": run["id"],
                    "Alert ID": run["alert_id"],
                    "Playbook": run["playbook_name"],
                    "Status": run["status"],
                    "Approved By": run["approved_by"],
                    "Started At": run["started_at_utc"],
                    "Completed At": run["completed_at_utc"],
                })

            st.dataframe(
                pd.DataFrame(history_data),
                use_container_width=True,
                hide_index=True,
            )

            run_ids = [run["id"] for run in history]

            selected_run_id = st.selectbox(
                "Select a run to inspect",
                run_ids,
            )

            details = get_run_details(selected_run_id)

            if details:

                run = details["run"]

                st.markdown("### Run details")

                st.write("**Playbook:**", run["playbook_name"])
                st.write("**Approved by:**", run["approved_by"])
                st.write("**Approval note:**", run["approval_note"] or "None")
                st.write("**Status:**", run["status"])

                st.markdown("### Execution steps")

                if details["steps"]:

                    step_data = [
                        {
                            "Step": step["step_name"],
                            "Action": step["action_type"],
                            "Status": step["status"],
                            "Details": step["details"],
                            "Executed At": step["executed_at_utc"],
                        }
                        for step in details["steps"]
                    ]

                    st.dataframe(
                        pd.DataFrame(step_data),
                        use_container_width=True,
                        hide_index=True,
                    )

                else:

                    st.info("No execution steps were recorded.")

    # --------------------------------------------------
    # TAB 3: EVIDENCE VERIFICATION
    # --------------------------------------------------

    with tab3:

        st.subheader("Response Evidence Integrity")

        st.write(
            "This section checks whether the raw event evidence "
            "still matches the SHA-256 hashes recorded during "
            "the response workflow."
        )

        if not runs:

            st.info("Execute a playbook first.")

        else:

            run_options = {
                f"Run #{run['id']} - {run['playbook_name']}": run["id"]
                for run in runs
            }

            selected_evidence_run = st.selectbox(
                "Select response run",
                list(run_options.keys()),
                key="evidence_run_select",
            )

            run_id = run_options[selected_evidence_run]

            details = get_run_details(run_id)

            if not details or not details["evidence"]:

                st.warning(
                    "No raw evidence was linked to this response run. "
                    "The selected alert may not have linked normalized "
                    "event IDs or raw event records."
                )

            else:

                if st.button(
                    "Verify Evidence Integrity",
                    type="primary",
                ):

                    results = verify_response_evidence(run_id)

                    if results:

                        st.markdown("### Verification results")

                        result_data = [
                            {
                                "Raw Event ID": item["raw_event_id"],
                                "Recorded SHA256": item["recorded_sha256"],
                                "Current SHA256": item["current_sha256"],
                                "Integrity": (
                                    "PASS"
                                    if item["verified"]
                                    else "MISMATCH"
                                ),
                            }
                            for item in results
                        ]

                        st.dataframe(
                            pd.DataFrame(result_data),
                            use_container_width=True,
                            hide_index=True,
                        )

                        passed = sum(
                            1 for item in results if item["verified"]
                        )

                        st.metric(
                            "Evidence records verified",
                            f"{passed}/{len(results)}",
                        )

                        if passed == len(results):

                            st.success(
                                "All checked evidence hashes match."
                            )

                        else:

                            st.error(
                                "One or more evidence hashes do not match."
                            )

                    else:

                        st.warning("No evidence records were available.")