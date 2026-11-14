
"""TRACE-SOC incident case management dashboard."""

import pandas as pd
import streamlit as st

from cases.engine import (
    CASE_STATUSES,
    CASE_PRIORITIES,
    create_case_schema,
    get_cases,
    get_case_details,
    get_case_summary,
    create_case,
    add_alert_to_case,
    add_case_note,
    update_case,
)

from response.engine import get_available_alerts
from dashboard.notifications import notify_success


def render_case_management():

    create_case_schema()

    st.title("📁 Incident Case Management")

    st.caption(
        "Manage security incidents, assign analysts, "
        "document investigations and track case activity."
    )

    summary = get_case_summary()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Cases", summary["total"])

    col2.metric(
        "Open Cases",
        summary["by_status"].get("OPEN", 0),
    )

    col3.metric(
        "In Progress",
        summary["by_status"].get("IN_PROGRESS", 0),
    )

    col4.metric(
        "Assigned Cases",
        summary["assigned"],
    )

    st.divider()

    tab1, tab2, tab3 = st.tabs(
        [
            "Case Overview",
            "Create Case",
            "Case Investigation",
        ],
        key="case_management_active_tab",
    )

    # --------------------------------------------------
    # TAB 1: CASE OVERVIEW
    # --------------------------------------------------

    with tab1:

        st.subheader("Incident Case Inventory")

        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:
            status_filter = st.selectbox(
                "Filter by status",
                ["ALL"] + list(CASE_STATUSES),
            )

        with filter_col2:
            priority_filter = st.selectbox(
                "Filter by priority",
                ["ALL"] + list(CASE_PRIORITIES),
            )

        cases = get_cases(
            status=status_filter,
            priority=priority_filter,
        )

        if cases:

            table_data = [
                {
                    "Case ID": case["case_number"],
                    "Title": case["title"],
                    "Status": case["status"],
                    "Priority": case["priority"],
                    "Assigned To": case["assigned_to"] or "Unassigned",
                    "Linked Alerts": case["alert_count"],
                    "Created By": case["created_by"],
                    "Created At": case["created_at_utc"],
                }
                for case in cases
            ]

            st.dataframe(
                pd.DataFrame(table_data),
                use_container_width=True,
                hide_index=True,
            )

        else:

            st.info(
                "No cases found. Create a case from the Create Case tab."
            )

    # --------------------------------------------------
    # TAB 2: CREATE CASE
    # --------------------------------------------------

    with tab2:

        st.subheader("Create a New Incident Case")

        alerts = get_available_alerts()

        with st.form("create_case_form", clear_on_submit=True):

            title = st.text_input(
                "Case title",
                placeholder="Example: Suspicious authentication activity",
            )

            description = st.text_area(
                "Incident description",
                placeholder="Describe the incident and investigation objective.",
            )

            col1, col2 = st.columns(2)

            with col1:
                priority = st.selectbox(
                    "Priority",
                    CASE_PRIORITIES,
                    index=2,
                )

            with col2:
                created_by = st.text_input(
                    "Created by",
                    placeholder="SOC Analyst",
                )

            assigned_to = st.text_input(
                "Assign to analyst (optional)",
                placeholder="Enter analyst name",
            )

            st.markdown("### Attach existing alerts")

            alert_options = {
                (
                    f"Alert #{alert['id']} | "
                    f"{alert['rule_name']} | "
                    f"{alert['severity']}"
                ): alert["id"]
                for alert in alerts
            }

            selected_alert_labels = st.multiselect(
                "Select related alerts",
                list(alert_options.keys()),
            )

            selected_alert_ids = [
                alert_options[label]
                for label in selected_alert_labels
            ]

            submitted = st.form_submit_button(
                "Create Incident Case",
                type="primary",
                use_container_width=True,
            )

            if submitted:

                try:

                    case_id = create_case(
                        title=title,
                        description=description,
                        priority=priority,
                        created_by=created_by,
                        assigned_to=assigned_to,
                        alert_ids=selected_alert_ids,
                    )

                    notify_success(
                        f"Case created successfully! Case ID: "
                        f"TRACE-CASE-{case_id:05d}"
                    )
                    st.rerun()

                except Exception as error:

                    st.error(f"Unable to create case: {error}")

    # --------------------------------------------------
    # TAB 3: CASE INVESTIGATION
    # --------------------------------------------------

    with tab3:

        st.subheader("Investigate an Existing Case")

        cases = get_cases()

        if not cases:

            st.info("Create a case before starting an investigation.")

        else:

            case_options = {
                f"{case['case_number']} | {case['title']}": case["id"]
                for case in cases
            }

            selected_label = st.selectbox(
                "Select incident case",
                list(case_options.keys()),
            )

            case_id = case_options[selected_label]

            details = get_case_details(case_id)

            if details:

                case = details["case"]

                st.markdown("### Case information")

                col1, col2, col3 = st.columns(3)

                col1.metric("Case Status", case["status"])
                col2.metric("Priority", case["priority"])
                col3.metric("Linked Alerts", len(details["alerts"]))

                st.write("**Case number:**", case["case_number"])
                st.write("**Title:**", case["title"])
                st.write(
                    "**Description:**",
                    case["description"] or "No description",
                )
                st.write("**Created by:**", case["created_by"])
                st.write(
                    "**Assigned to:**",
                    case["assigned_to"] or "Unassigned",
                )

                st.divider()

                # --------------------------------------
                # UPDATE CASE
                # --------------------------------------

                st.markdown("### Update case")

                with st.form("update_case_form"):

                    new_status = st.selectbox(
                        "Status",
                        CASE_STATUSES,
                        index=CASE_STATUSES.index(case["status"]),
                    )

                    new_priority = st.selectbox(
                        "Priority",
                        CASE_PRIORITIES,
                        index=CASE_PRIORITIES.index(case["priority"]),
                    )

                    new_assigned_to = st.text_input(
                        "Assigned analyst",
                        value=case["assigned_to"] or "",
                    )

                    updated_by = st.text_input(
                        "Updated by",
                        placeholder="SOC Analyst",
                        key="case_updated_by",
                    )

                    update_submitted = st.form_submit_button(
                        "Save Case Changes",
                    )

                    if update_submitted:

                        try:

                            if not updated_by.strip():
                                raise ValueError(
                                    "Please enter the analyst name."
                                )

                            update_case(
                                case_id=case_id,
                                performed_by=updated_by,
                                status=new_status,
                                priority=new_priority,
                                assigned_to=new_assigned_to,
                            )

                            notify_success(f"Case TRACE-CASE-{case_id:05d} updated successfully.")
                            st.rerun()

                        except Exception as error:

                            st.error(str(error))

                st.divider()

                # --------------------------------------
                # LINK ADDITIONAL ALERTS
                # --------------------------------------

                st.markdown("### Link additional alerts")

                all_alerts = get_available_alerts()

                linked_ids = {
                    alert["id"]
                    for alert in details["alerts"]
                }

                unlinked_alerts = [
                    alert for alert in all_alerts
                    if alert["id"] not in linked_ids
                ]

                if unlinked_alerts:

                    alert_options = {
                        (
                            f"Alert #{alert['id']} | "
                            f"{alert['rule_name']} | "
                            f"{alert['severity']}"
                        ): alert["id"]
                        for alert in unlinked_alerts
                    }

                    selected_alert = st.selectbox(
                        "Select an alert to link",
                        list(alert_options.keys()),
                        key="link_alert_select",
                    )

                    link_analyst = st.text_input(
                        "Linked by",
                        key="link_analyst",
                    )

                    if st.button("Link Alert to Case"):

                        try:

                            add_alert_to_case(
                                case_id,
                                alert_options[selected_alert],
                                link_analyst,
                            )

                            notify_success(f"Alert {selected_alert} linked to case successfully.")
                            st.rerun()

                        except Exception as error:

                            st.error(str(error))

                else:

                    st.info("No additional unlinked alerts are available.")

                # --------------------------------------
                # LINKED ALERTS
                # --------------------------------------

                st.divider()

                st.markdown("### Linked alerts")

                if details["alerts"]:

                    alert_data = [
                        {
                            "Alert ID": alert["id"],
                            "Rule": alert["rule_name"],
                            "Severity": alert["severity"],
                            "Status": alert["status"],
                            "Hostname": alert["hostname"],
                            "Username": alert["username"],
                            "Source IP": alert["source_ip"],
                        }
                        for alert in details["alerts"]
                    ]

                    st.dataframe(
                        pd.DataFrame(alert_data),
                        use_container_width=True,
                        hide_index=True,
                    )

                else:

                    st.info("No alerts are linked to this case.")

                # --------------------------------------
                # ANALYST NOTES
                # --------------------------------------

                st.divider()

                st.markdown("### Investigation notes")

                with st.form("case_note_form"):

                    note_analyst = st.text_input(
                        "Analyst name",
                        key="note_analyst",
                    )

                    note_text = st.text_area(
                        "Investigation finding",
                        placeholder=(
                            "Record observations, evidence, "
                            "findings or investigation decisions."
                        ),
                    )

                    note_submitted = st.form_submit_button(
                        "Add Investigation Note",
                    )

                    if note_submitted:

                        try:

                            add_case_note(
                                case_id,
                                note_analyst,
                                note_text,
                            )

                            notify_success(f"Investigation note added to case #{case_id}.")
                            st.rerun()

                        except Exception as error:

                            st.error(str(error))

                for note in details["notes"]:

                    with st.container(border=True):

                        st.write(note["note"])

                        st.caption(
                            f"By {note['analyst']} | "
                            f"{note['created_at_utc']}"
                        )

                # --------------------------------------
                # CASE ACTIVITY TIMELINE
                # --------------------------------------

                st.divider()

                st.markdown("### Case activity timeline")

                if details["activity"]:

                    for activity in details["activity"]:

                        with st.container(border=True):

                            st.markdown(
                                f"**{activity['activity_type']}**"
                            )

                            st.write(activity["description"])

                            st.caption(
                                f"By {activity['performed_by']} | "
                                f"{activity['created_at_utc']}"
                            )

                else:

                    st.info("No activity has been recorded.")
