
"""TRACE-SOC Alert Management Center."""

import streamlit as st

from dashboard.data_access import (
    ALERT_STATUSES,
    SEVERITIES,
    get_alerts,
    update_alert_status,
    get_alert_status_history,
)


def show_table(rows, empty_message="No records found."):
    if rows:
        st.dataframe(
            rows,
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info(empty_message)


def render_alert_management():

    st.title("🚨 Alert Management Center")

    st.caption(
        "Review, investigate and manage security detection alerts."
    )

    # -------------------------------------------------
    # ALERT SUMMARY
    # -------------------------------------------------

    all_alerts = get_alerts(limit=1000)

    total = len(all_alerts)

    open_count = sum(
        1 for alert in all_alerts
        if alert.get("status", "").upper()
        in ("NEW", "INVESTIGATING")
    )

    critical_count = sum(
        1 for alert in all_alerts
        if alert.get("severity", "").upper() == "CRITICAL"
        and alert.get("status", "").upper()
        not in ("RESOLVED", "FALSE_POSITIVE")
    )

    resolved_count = sum(
        1 for alert in all_alerts
        if alert.get("status", "").upper() == "RESOLVED"
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Alerts", total)
    col2.metric("Open Alerts", open_count)
    col3.metric("Critical Open", critical_count)
    col4.metric("Resolved", resolved_count)

    st.divider()

    # -------------------------------------------------
    # FILTERS
    # -------------------------------------------------

    st.subheader("Search and Filter Alerts")

    col1, col2, col3 = st.columns([1, 1, 2])

    status = col1.selectbox(
        "Alert Status",
        ["ALL", *ALERT_STATUSES]
    )

    severity = col2.selectbox(
        "Severity",
        ["ALL", *SEVERITIES]
    )

    search = col3.text_input(
        "Search",
        placeholder="Rule ID, hostname, username or IP"
    )

    alerts = get_alerts(
        status=status,
        severity=severity,
        search=search,
        limit=1000
    )

    st.write(f"**{len(alerts)} matching alert(s)**")

    # -------------------------------------------------
    # ALERT TABLE
    # -------------------------------------------------

    st.subheader("Detection Alerts")

    display_columns = [
        "id",
        "rule_id",
        "rule_name",
        "severity",
        "status",
        "hostname",
        "username",
        "source_ip",
        "event_count",
        "created_at_utc",
    ]

    display_rows = [
        {
            key: alert.get(key)
            for key in display_columns
        }
        for alert in alerts
    ]

    show_table(
        display_rows,
        "No alerts match the selected filters."
    )

    if not alerts:
        return

    st.divider()

    # -------------------------------------------------
    # SELECT ALERT
    # -------------------------------------------------

    st.subheader("Alert Investigation")

    alert_ids = [alert["id"] for alert in alerts]

    selected_id = st.selectbox(
        "Select an alert",
        alert_ids,
        format_func=lambda alert_id: (
            f"#{alert_id} - "
            f"{next(
                a['rule_name']
                for a in alerts
                if a['id'] == alert_id
            )}"
        )
    )

    selected_alert = next(
        alert for alert in alerts
        if alert["id"] == selected_id
    )

    st.markdown(
        f"### {selected_alert.get('rule_name') or 'Unnamed alert'}"
    )

    # -------------------------------------------------
    # ALERT DETAILS
    # -------------------------------------------------

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Detection Information**")

        st.write(
            f"Rule ID: {selected_alert.get('rule_id')}"
        )

        st.write(
            f"Severity: {selected_alert.get('severity')}"
        )

        st.write(
            f"Status: {selected_alert.get('status')}"
        )

        st.write(
            f"Description: {selected_alert.get('description') or 'Not available'}"
        )

        st.write(
            f"MITRE Tactic: {selected_alert.get('mitre_tactic') or 'Not mapped'}"
        )

        st.write(
            f"MITRE Technique: {selected_alert.get('mitre_technique') or 'Not mapped'}"
        )

    with col2:
        st.markdown("**Affected System Information**")

        st.write(
            f"Hostname: {selected_alert.get('hostname') or 'Unknown'}"
        )

        st.write(
            f"Username: {selected_alert.get('username') or 'Unknown'}"
        )

        st.write(
            f"Source IP: {selected_alert.get('source_ip') or 'Unknown'}"
        )

        st.write(
            f"Event Count: {selected_alert.get('event_count', 0)}"
        )

        st.write(
            f"First Seen: {selected_alert.get('first_seen') or 'Unknown'}"
        )

        st.write(
            f"Last Seen: {selected_alert.get('last_seen') or 'Unknown'}"
        )

    # -------------------------------------------------
    # STATUS UPDATE
    # -------------------------------------------------

    st.divider()

    st.subheader("Update Investigation Status")

    current_status = (
        selected_alert.get("status") or "NEW"
    ).upper()

    status_options = list(ALERT_STATUSES)

    default_index = (
        status_options.index(current_status)
        if current_status in status_options
        else 0
    )

    new_status = st.selectbox(
        "New Status",
        status_options,
        index=default_index,
        key=f"alert_status_{selected_id}"
    )

    analyst_note = st.text_area(
        "Analyst Investigation Notes",
        placeholder=(
            "Describe your investigation, findings "
            "or reason for changing the status..."
        ),
        key=f"alert_note_{selected_id}"
    )

    if st.button(
        "Save Alert Status",
        type="primary",
        use_container_width=True
    ):

        try:

            updated = update_alert_status(
                selected_id,
                new_status,
                analyst_note
            )

            if updated:
                st.success(
                    "Alert status successfully updated."
                )
                st.rerun()

            else:
                st.error("Alert not found.")

        except ValueError as error:
            st.error(str(error))

    # -------------------------------------------------
    # STATUS HISTORY
    # -------------------------------------------------

    st.divider()

    st.subheader("Analyst Activity History")

    history = get_alert_status_history(selected_id)

    if history:

        show_table(history)

    else:

        st.info(
            "No status changes have been recorded yet."
        )

    # -------------------------------------------------
    # RAW ALERT EVIDENCE
    # -------------------------------------------------

    st.divider()

    with st.expander("View Original Alert Evidence"):

        import json

        evidence = selected_alert.get("evidence_json")

        if evidence:

            try:
                parsed_evidence = json.loads(evidence)

                st.json(parsed_evidence)

            except (json.JSONDecodeError, TypeError):
                st.warning(
                    "Alert evidence is not valid JSON."
                )

        else:

            st.info(
                "No evidence JSON is attached to this alert."
            )
