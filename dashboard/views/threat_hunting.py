
"""TRACE-SOC Threat Hunting workspace."""

import csv
import io
import json
from datetime import date, time, datetime, timezone

import streamlit as st

from hunting.engine import (
    HUNT_TYPES,
    create_hunting_schema,
    search_hunt,
    get_event_detail,
    analyze_detection_gaps,
    save_hunt,
    list_saved_hunts,
    delete_saved_hunt,
)

def _date_value(value, fallback):
    if isinstance(value, datetime):
        return value.date()

    if isinstance(value, date):
        return value

    if isinstance(value, str):
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return fallback

    return fallback

def _to_csv(rows):
    if not rows:
        return ""

    output = io.StringIO()
    columns = [
        "normalized_event_id",
        "timestamp_utc",
        "event_id",
        "event_type",
        "hostname",
        "username",
        "source_ip",
        "destination_ip",
        "image",
        "command_line",
        "detection_linkage",
        "raw_event_id",
    ]

    writer = csv.DictWriter(
        output,
        fieldnames=columns,
        extrasaction="ignore"
    )

    writer.writeheader()
    writer.writerows(rows)

    return output.getvalue()


def render_threat_hunting():

    create_hunting_schema()

    st.markdown("## 🔎 Advanced Threat Hunting")

    st.caption(
        "Search endpoint telemetry, investigate indicators and identify "
        "events without linked detection alerts."
    )

    # --------------------------------------------------
    # SAVED HUNTS
    # --------------------------------------------------

    with st.expander("Saved Hunting Queries", expanded=False):

        saved = list_saved_hunts()

        if saved:

            labels = {
                item["id"]: (
                    f"#{item['id']} — {item['name']} "
                    f"({item['hunt_type']})"
                )
                for item in saved
            }

            selected_saved = st.selectbox(
                "Load a saved hunt",
                options=list(labels),
                format_func=lambda value: labels[value],
                key="saved_hunt_selection"
            )

            selected_item = next(
                item for item in saved
                if item["id"] == selected_saved
            )

            st.write(
                selected_item.get("description") or "No description"
            )

            if st.button("Delete selected saved hunt"):
                delete_saved_hunt(selected_saved)
                st.success("Saved hunt deleted.")
                st.rerun()

            if st.button("Load selected hunt into search"):
                st.session_state["hunt_loaded_query"] = (
                    selected_item["query"]
                )
                st.session_state["hunt_loaded_type"] = (
                    selected_item["hunt_type"]
                )
                st.rerun()

        else:
            st.info("No saved hunting queries yet.")

    loaded = st.session_state.pop(
        "hunt_loaded_query",
        {}
    )

    loaded_type = st.session_state.pop(
        "hunt_loaded_type",
        "GENERAL"
    )

    # --------------------------------------------------
    # SEARCH FORM
    # --------------------------------------------------

    st.markdown("### Search configuration")

    hunt_type = st.selectbox(
        "Hunting method",
        HUNT_TYPES,
        index=HUNT_TYPES.index(loaded_type)
        if loaded_type in HUNT_TYPES else 0,
        format_func=lambda value: {
            "GENERAL": "General event search",
            "IP": "IP address IOC",
            "DOMAIN": "Domain IOC",
            "HASH": "File hash IOC",
            "PROCESS": "Process / executable",
            "COMMAND_LINE": "Command-line investigation",
        }[value],
        key="hunt_type"
    )

    c1, c2 = st.columns(2)

    indicator = c1.text_input(
        "Indicator / search value",
        value=str(loaded.get("indicator") or ""),
        placeholder="Example: 192.168.1.50 or powershell.exe"
    )

    hostname = c2.text_input(
        "Hostname",
        value=str(loaded.get("hostname") or "")
    )

    c3, c4, c5 = st.columns(3)

    username = c3.text_input(
        "Username",
        value=str(loaded.get("username") or "")
    )

    event_id = c4.text_input(
        "Event ID",
        value=str(loaded.get("event_id") or "")
    )

    event_type = c5.text_input(
        "Event type",
        value=str(loaded.get("event_type") or "")
    )

    c6, c7 = st.columns(2)

    start_date = c6.date_input(
    "Start date",
    value=_date_value(loaded.get("start_date"), date.today()),
    key="hunt_start_date"
)

    end_date = c7.date_input(
    "End date",
    value=_date_value(loaded.get("end_date"), date.today()),
    key="hunt_end_date"
)

    limit = st.slider(
        "Maximum results",
        min_value=50,
        max_value=2000,
        value=300,
        step=50
    )

    if start_date > end_date:
        st.error("Start date cannot be after end date.")
        return

    query = {
        "indicator": indicator.strip() or None,
        "hostname": hostname.strip() or None,
        "username": username.strip() or None,
        "event_id": event_id.strip() or None,
        "event_type": event_type.strip() or None,
        "start_time": datetime.combine(
            start_date,
            time.min,
            tzinfo=timezone.utc
        ).isoformat(),
        "end_time": datetime.combine(
            end_date,
            time.max,
            tzinfo=timezone.utc
        ).isoformat(),
        "limit": limit,
    }

    # --------------------------------------------------
    # RUN HUNT
    # --------------------------------------------------

    if st.button(
        "⌕ Execute Threat Hunt",
        type="primary",
        use_container_width=True
    ):

        try:
            events = search_hunt(
                hunt_type=hunt_type,
                **query
            )

            events = analyze_detection_gaps(events)

            st.session_state["advanced_hunt_results"] = events
            st.session_state["advanced_hunt_query"] = query
            st.session_state["advanced_hunt_type"] = hunt_type
            st.session_state.pop("selected_hunt_event", None)

        except Exception as exc:
            st.error(f"Threat hunt failed: {exc}")

    results = st.session_state.get(
        "advanced_hunt_results",
        []
    )

    # --------------------------------------------------
    # RESULTS
    # --------------------------------------------------

    if results:

        linked = sum(
            item["detection_linkage"] == "LINKED_TO_ALERT"
            for item in results
        )

        unlinked = len(results) - linked

        st.divider()
        st.markdown("### Hunting results")

        m1, m2, m3 = st.columns(3)

        m1.metric("Matching events", len(results))
        m2.metric("Linked to alerts", linked)
        m3.metric("No linked alert", unlinked)

        st.caption(
            "No linked alert means no matching normalized event ID was "
            "found in stored alert evidence. It does not prove malicious activity."
        )

        display_columns = [
            "normalized_event_id",
            "timestamp_utc",
            "event_id",
            "event_type",
            "hostname",
            "username",
            "source_ip",
            "destination_ip",
            "image",
            "detection_linkage",
        ]

        st.dataframe(
            [
                {
                    key: item.get(key)
                    for key in display_columns
                }
                for item in results
            ],
            use_container_width=True,
            hide_index=True
        )

        st.download_button(
            "⬇ Export hunt results as CSV",
            data=_to_csv(results),
            file_name="TRACE-SOC-threat-hunt.csv",
            mime="text/csv"
        )

        # --------------------------------------------------
        # EVENT DETAIL
        # --------------------------------------------------

        st.markdown("### Event investigation")

        event_ids = [
            item["normalized_event_id"]
            for item in results
        ]

        selected_event = st.selectbox(
            "Select an event to inspect",
            event_ids,
            format_func=lambda value: (
                f"Event #{value} — "
                f"{next(
                    str(item.get('event_id'))
                    for item in results
                    if item['normalized_event_id'] == value
                )}"
            ),
            key="selected_hunt_event"
        )

        if st.button("Load complete event evidence"):

            try:
                detail = get_event_detail(selected_event)

                if detail is None:
                    st.warning("Event not found.")
                else:
                    st.session_state["hunt_event_detail"] = detail

            except Exception as exc:
                st.error(f"Could not load event: {exc}")

        detail = st.session_state.get("hunt_event_detail")

        if (
            detail
            and detail.get("id") == selected_event
        ):

            st.markdown("#### Normalized event details")

            safe_detail = {
                key: value
                for key, value in detail.items()
                if key not in ("raw_xml_text",)
            }

            st.json(safe_detail)

            st.markdown("#### Evidence integrity")

            st.write(
                "Integrity status:",
                detail.get("integrity_status")
            )

            st.code(
                detail.get("actual_raw_xml_sha256") or "No hash available",
                language="text"
            )

            raw_xml = detail.get("raw_xml_text")

            if raw_xml is not None:

                with st.expander("View original raw XML"):

                    st.code(raw_xml, language="xml")

                    st.download_button(
                        "Download raw XML",
                        data=raw_xml.encode("utf-8"),
                        file_name=f"TRACE-SOC-event-{selected_event}.xml",
                        mime="application/xml"
                    )

    elif "advanced_hunt_results" in st.session_state:

        st.info("No matching events were found.")

    # --------------------------------------------------
    # SAVE CURRENT HUNT
    # --------------------------------------------------

    st.divider()
    st.markdown("### Save this hunting query")

    with st.form("save_hunt_form"):

        hunt_name = st.text_input(
            "Hunt name",
            placeholder="Example: Investigate suspicious PowerShell"
        )

        hunt_description = st.text_area(
            "Description",
            placeholder="Purpose of this hunting query..."
        )

        save_submitted = st.form_submit_button(
            "Save hunting query"
        )

        if save_submitted:

            if not hunt_name.strip():
                st.error("Please provide a hunt name.")

            else:

                try:

                    saved_query = dict(query)

                    saved_query["start_date"] = start_date.isoformat()
                    saved_query["end_date"] = end_date.isoformat()

                    save_hunt(
                        name=hunt_name,
                        hunt_type=hunt_type,
                        query=saved_query,
                        description=hunt_description
                    )

                    st.success("Hunting query saved successfully.")

                except Exception as exc:
                    st.error(f"Could not save hunt: {exc}")

