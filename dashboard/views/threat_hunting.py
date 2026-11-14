
"""TRACE-SOC Threat Hunting workspace."""

import csv
import io
import json
from datetime import date, time, datetime, timezone, timedelta

import streamlit as st
from dashboard.notifications import notify_success

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


def _get_default_date_range() -> tuple[date, date]:
    """Return default date bounds based on database telemetry, fallback to 14 days ago."""
    today = datetime.now(timezone.utc).date()
    try:
        from database.db import get_connection
        conn = get_connection()
        row = conn.execute(
            "SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM normalized_events"
        ).fetchone()
        conn.close()
        if row and row[0] and row[1]:
            d_min = datetime.fromisoformat(str(row[0])[:19]).date()
            d_max = datetime.fromisoformat(str(row[1])[:19]).date()
            return d_min, max(d_max, today)
    except Exception:
        pass
    return today - timedelta(days=14), today

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

    def_start, def_end = _get_default_date_range()

    # Initialize persistent state defaults so widget interactions (such as date changes)
    # never reset typed indicators or selected hunting methods.
    if "hunt_method" not in st.session_state:
        st.session_state["hunt_method"] = "GENERAL"
    if "hunt_indicator" not in st.session_state:
        st.session_state["hunt_indicator"] = ""
    if "hunt_hostname" not in st.session_state:
        st.session_state["hunt_hostname"] = ""
    if "hunt_username" not in st.session_state:
        st.session_state["hunt_username"] = ""
    if "hunt_event_id" not in st.session_state:
        st.session_state["hunt_event_id"] = ""
    if "hunt_event_type" not in st.session_state:
        st.session_state["hunt_event_type"] = ""
    if "hunt_start_date" not in st.session_state:
        st.session_state["hunt_start_date"] = def_start
    if "hunt_end_date" not in st.session_state:
        st.session_state["hunt_end_date"] = def_end
    if "hunt_limit" not in st.session_state:
        st.session_state["hunt_limit"] = 300

    st.markdown("## 🔎 Advanced Threat Hunting")

    st.caption(
        "Search endpoint telemetry, investigate indicators and identify "
        "events without linked detection alerts."
    )

    # --------------------------------------------------
    # SAVED HUNTS
    # --------------------------------------------------

    if "hunt_saved_success_msg" in st.session_state:
        st.success(st.session_state.pop("hunt_saved_success_msg"))

    if "hunt_load_msg" in st.session_state:
        st.info(st.session_state.pop("hunt_load_msg"))

    expand_saved = st.session_state.pop("hunt_saved_expand", False)

    with st.expander("Saved Hunting Queries", expanded=expand_saved):

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

            b_del, b_load = st.columns([1, 2])
            with b_del:
                if st.button("Delete selected saved hunt", use_container_width=True):
                    delete_saved_hunt(selected_saved)
                    notify_success("Saved hunt deleted.")
                    st.rerun()

            with b_load:
                if st.button("Load selected hunt into search", type="primary", use_container_width=True):
                    q = selected_item.get("query", {})
                    ht = str(selected_item.get("hunt_type", "GENERAL")).upper()
                    if ht in HUNT_TYPES:
                        st.session_state["hunt_method"] = ht
                    st.session_state["hunt_indicator"] = str(q.get("indicator") or "")
                    st.session_state["hunt_hostname"] = str(q.get("hostname") or "")
                    st.session_state["hunt_username"] = str(q.get("username") or "")
                    st.session_state["hunt_event_id"] = str(q.get("event_id") or "")
                    st.session_state["hunt_event_type"] = str(q.get("event_type") or "")
                    if q.get("start_date"):
                        st.session_state["hunt_start_date"] = _date_value(q["start_date"], def_start)
                    if q.get("end_date"):
                        st.session_state["hunt_end_date"] = _date_value(q["end_date"], def_end)
                    if q.get("limit"):
                        try:
                            st.session_state["hunt_limit"] = int(q["limit"])
                        except (ValueError, TypeError):
                            pass
                    st.session_state["hunt_load_msg"] = f"Loaded hunt #{selected_item['id']} — '{selected_item.get('name')}' ({ht}) into search."
                    st.rerun()

        else:
            st.info("No saved hunting queries yet.")

    # --------------------------------------------------
    # SEARCH FORM
    # --------------------------------------------------

    st.markdown("### Search configuration")

    hunt_type = st.selectbox(
        "Hunting method",
        HUNT_TYPES,
        format_func=lambda value: {
            "GENERAL": "General event search",
            "IP": "IP address IOC",
            "DOMAIN": "Domain IOC",
            "HASH": "File hash IOC",
            "PROCESS": "Process / executable",
            "COMMAND_LINE": "Command-line investigation",
        }.get(value, value),
        key="hunt_method"
    )

    c1, c2 = st.columns(2)

    indicator = c1.text_input(
        "Indicator / search value",
        placeholder="Example: 192.168.1.50 or powershell.exe",
        key="hunt_indicator"
    )

    hostname = c2.text_input(
        "Hostname",
        key="hunt_hostname"
    )

    c3, c4, c5 = st.columns(3)

    username = c3.text_input(
        "Username",
        key="hunt_username"
    )

    event_id = c4.text_input(
        "Event ID",
        key="hunt_event_id"
    )

    event_type = c5.text_input(
        "Event type",
        key="hunt_event_type"
    )

    c6, c7 = st.columns(2)

    start_date = c6.date_input(
        "Start date",
        key="hunt_start_date"
    )

    end_date = c7.date_input(
        "End date",
        key="hunt_end_date"
    )

    limit = st.slider(
        "Maximum results",
        min_value=50,
        max_value=2000,
        step=50,
        key="hunt_limit"
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

    b_run, b_reset = st.columns([3, 1])
    with b_run:
        execute_hunt = st.button(
            "⌕ Execute Threat Hunt",
            type="primary",
            use_container_width=True
        )
    with b_reset:
        if st.button("↺ Reset filters", use_container_width=True):
            st.session_state["hunt_method"] = "GENERAL"
            st.session_state["hunt_indicator"] = ""
            st.session_state["hunt_hostname"] = ""
            st.session_state["hunt_username"] = ""
            st.session_state["hunt_event_id"] = ""
            st.session_state["hunt_event_type"] = ""
            st.session_state["hunt_start_date"] = def_start
            st.session_state["hunt_end_date"] = def_end
            st.session_state["hunt_limit"] = 300
            st.session_state.pop("advanced_hunt_results", None)
            st.session_state.pop("advanced_hunt_query", None)
            st.rerun()

    if execute_hunt:

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

                    notify_success(f"Hunting query '{hunt_name}' saved successfully.")
                    st.session_state["hunt_saved_expand"] = True
                    st.rerun()

                except Exception as exc:
                    st.error(f"Could not save hunt: {exc}")

