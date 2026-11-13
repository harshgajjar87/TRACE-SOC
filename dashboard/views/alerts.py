
"""TRACE-SOC Alert Management Center."""

import streamlit as st

import json

from dashboard.data_access import (
    ALERT_STATUSES,
    SEVERITIES,
    get_alerts,
    update_alert_status,
    get_alert_status_history,
    get_alert_linked_evidence,
    verify_linked_raw_evidence,
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
    # LINKED DIGITAL EVIDENCE
    # -------------------------------------------------

    st.divider()
    st.subheader("🔗 Linked Digital Evidence")

    linked_evidence = get_alert_linked_evidence(selected_id)

    if not linked_evidence:
        st.warning(
            "No linked normalized event records found for this alert. "
            "The alert may have been generated before event linkage "
            "was introduced, or the evidence_json contains no recognized "
            "normalized_event_ids."
        )

        # Still show the raw evidence_json for debugging
        with st.expander("Raw evidence_json (debug)"):
            raw_ev = selected_alert.get("evidence_json")
            if raw_ev:
                try:
                    st.json(json.loads(raw_ev))
                except (json.JSONDecodeError, TypeError):
                    st.code(raw_ev)
            else:
                st.info("No evidence_json attached to this alert.")

    else:
        st.success(f"{len(linked_evidence)} linked event record(s) found.")

        # ── Normalized event summary table ────────────────────────────
        st.markdown("#### Normalized Event Records")
        summary_rows = [{
            "norm_id":    ev.get("normalized_event_id"),
            "event_id":   ev.get("windows_event_id"),
            "timestamp":  str(ev.get("timestamp_utc") or "")[:19].replace("T", " "),
            "hostname":   ev.get("hostname") or "—",
            "username":   ev.get("username") or "—",
            "source_ip":  ev.get("source_ip") or "—",
            "image":      str(ev.get("image") or "")[-55:] or "—",
            "raw_id":     ev.get("raw_event_id"),
        } for ev in linked_evidence]

        st.dataframe(summary_rows, use_container_width=True, hide_index=True)

        # ── Per-event detail + XML + integrity ───────────────────────
        st.markdown("#### Original XML Evidence & Integrity Verification")
        st.caption(
            "VERIFIED means the stored XML blob matches its recorded "
            "SHA-256 baseline. It does not independently prove "
            "original acquisition authenticity."
        )

        _STATUS_COLORS = {
            "VERIFIED":    "#34d399",
            "MISMATCH":    "#fb7185",
            "NO_BASELINE": "#fbbf24",
            "NOT_FOUND":   "#94a3b8",
        }

        for ev in linked_evidence:
            norm_id  = ev.get("normalized_event_id")
            raw_id   = ev.get("raw_event_id")
            win_eid  = ev.get("windows_event_id") or "?"
            ts       = str(ev.get("timestamp_utc") or "")[:19].replace("T", " ")
            host     = ev.get("hostname") or "—"
            label    = f"Event {win_eid}  ·  {ts}  ·  {host}  (norm #{norm_id})"

            with st.expander(label):
                # Structured fields
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Event fields**")
                    for field, value in [
                        ("Windows Event ID", ev.get("windows_event_id")),
                        ("Provider",         ev.get("provider")),
                        ("Channel",          ev.get("channel")),
                        ("Event Type",       ev.get("event_type")),
                        ("Hostname",         ev.get("hostname")),
                        ("Username",         ev.get("username")),
                        ("Source IP",        ev.get("source_ip")),
                        ("Destination IP",   ev.get("destination_ip")),
                    ]:
                        if value:
                            st.write(f"**{field}:** {value}")

                with c2:
                    st.markdown("**Process / command**")
                    for field, value in [
                        ("Image",        ev.get("image")),
                        ("Command line", ev.get("command_line")),
                    ]:
                        if value:
                            st.write(f"**{field}:** `{value}`")

                    extra = ev.get("extra_data_json")
                    if extra:
                        try:
                            st.markdown("**Extra data**")
                            st.json(json.loads(extra))
                        except (json.JSONDecodeError, TypeError):
                            st.write(extra)

                # Integrity check
                st.markdown("**Integrity verification**")
                if raw_id:
                    result = verify_linked_raw_evidence(raw_id)
                    vstatus = result.get("status", "UNKNOWN")
                    vcolor  = _STATUS_COLORS.get(vstatus, "#94a3b8")
                    st.markdown(
                        f"<span style='background:{vcolor}22;"
                        f"border:1px solid {vcolor};border-radius:6px;"
                        f"padding:3px 10px;color:{vcolor};"
                        f"font-weight:700;font-size:.85rem;'>"
                        f"{vstatus}</span>"
                        f"&nbsp;&nbsp;"
                        f"<span style='color:#7a96b4;font-size:.8rem;'>"
                        f"raw_event #{raw_id} · "
                        f"Source: {result.get('source_file') or '—'}</span>",
                        unsafe_allow_html=True,
                    )
                    if vstatus == "MISMATCH":
                        st.error(
                            f"Hash mismatch — stored XML may have been altered.  \n"
                            f"Expected: `{result.get('expected_sha256')}`  \n"
                            f"Actual:   `{result.get('actual_sha256')}`"
                        )
                    elif vstatus == "VERIFIED":
                        st.caption(
                            f"SHA-256: `{result.get('actual_sha256')}`"
                        )
                else:
                    st.caption("No raw_event_id — cannot verify integrity.")

                # Raw XML
                xml_text = ev.get("raw_xml_text")
                if xml_text:
                    st.markdown("**Raw Windows XML**")
                    st.code(xml_text, language="xml")
                else:
                    st.caption("No raw XML stored for this event.")

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
    # RAW ALERT EVIDENCE (preserved for reference)
    # -------------------------------------------------

    with st.expander("View raw evidence_json"):
        evidence = selected_alert.get("evidence_json")
        if evidence:
            try:
                st.json(json.loads(evidence))
            except (json.JSONDecodeError, TypeError):
                st.warning("Alert evidence is not valid JSON.")
        else:
            st.info("No evidence JSON is attached to this alert.")
