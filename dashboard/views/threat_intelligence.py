
"""TRACE-SOC Threat Intelligence dashboard."""

import json
import streamlit as st
import pandas as pd

from pathlib import Path

from threat_intel.engine import (
    IOC_TYPES,
    SEVERITIES,
    add_indicator,
    get_indicators,
    lookup_indicator,
    enrich_events,
    import_json_feed,
    import_csv_feed,
    get_threat_intel_summary,
    create_threat_intel_schema,
    expire_indicators,
)

from database.db import get_connection


def get_recent_events(limit=500):
    connection = get_connection()
    connection.row_factory = __import__("sqlite3").Row

    try:
        rows = connection.execute("""
            SELECT
                id AS normalized_event_id,
                event_id,
                timestamp_utc,
                hostname,
                username,
                source_ip,
                destination_ip,
                image,
                command_line,
                extra_data_json
            FROM normalized_events
            ORDER BY timestamp_utc DESC, id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def render_threat_intelligence():

    create_threat_intel_schema()
    expire_indicators()

    st.markdown("## 🧠 Threat Intelligence Center")

    st.caption(
        "Manage local IOC intelligence, enrich endpoint events "
        "and investigate known indicators."
    )

    summary = get_threat_intel_summary()

    # -------------------------------------------------
    # SUMMARY CARDS
    # -------------------------------------------------

    c1, c2, c3 = st.columns(3)

    c1.metric("Total Indicators", summary["total"])
    c2.metric("Active Indicators", summary["active"])
    c3.metric("Intelligence Sources", summary["sources"])

    st.divider()

    # -------------------------------------------------
    # TABS
    # -------------------------------------------------

    tab_overview, tab_add, tab_import, tab_lookup, tab_enrich = st.tabs([
        "Overview",
        "Add IOC",
        "Import Feed",
        "IOC Lookup",
        "Event Enrichment",
    ])

    # -------------------------------------------------
    # OVERVIEW
    # -------------------------------------------------

    with tab_overview:

        st.markdown("### Active intelligence inventory")

        left, right = st.columns(2)

        with left:
            st.markdown("**IOC types**")

            if summary["by_type"]:
                st.dataframe(
                    summary["by_type"],
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No IOC indicators imported.")

        with right:
            st.markdown("**Severity distribution**")

            if summary["by_severity"]:
                st.dataframe(
                    summary["by_severity"],
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No severity information available.")

        st.markdown("### Indicator inventory")

        ioc_type_filter = st.selectbox(
            "IOC type filter",
            ["ALL", *IOC_TYPES],
            key="intel_inventory_type"
        )

        severity_filter = st.selectbox(
            "Severity filter",
            ["ALL", *SEVERITIES],
            key="intel_inventory_severity"
        )

        inventory_search = st.text_input(
            "Search indicator or source",
            key="intel_inventory_search"
        )

        indicators = get_indicators(
            ioc_type=ioc_type_filter,
            severity=severity_filter,
            search=inventory_search,
            active_only=False,
        )

        display = [
            {
                "id": item["id"],
                "type": item["ioc_type"],
                "indicator": item["indicator"],
                "source": item["source_name"],
                "confidence": item["confidence"],
                "severity": item["severity"],
                "active": bool(item["is_active"]),
                "expires": item["expires_at_utc"],
            }
            for item in indicators
        ]

        if display:
            st.dataframe(
                display,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No matching indicators.")

    # -------------------------------------------------
    # ADD IOC
    # -------------------------------------------------

    with tab_add:

        st.markdown("### Add an indicator manually")

        with st.form("add_ioc_form"):

            ioc_type = st.selectbox(
                "Indicator type",
                IOC_TYPES
            )

            indicator = st.text_input(
                "Indicator value",
                placeholder="IP, domain, URL or file hash"
            )

            source_name = st.text_input(
                "Intelligence source",
                value="Manual Analyst Entry"
            )

            source_reference = st.text_input(
                "Source reference (optional)"
            )

            confidence = st.slider(
                "Confidence",
                0,
                100,
                70
            )

            severity = st.selectbox(
                "Severity",
                SEVERITIES,
                index=1
            )

            description = st.text_area(
                "Description"
            )

            tags = st.text_input(
                "Tags (comma separated)",
                placeholder="phishing, malware, c2"
            )

            submitted = st.form_submit_button(
                "Add indicator",
                type="primary"
            )

            if submitted:

                try:

                    indicator_id = add_indicator(
                        indicator=indicator,
                        ioc_type=ioc_type,
                        source_name=source_name,
                        source_reference=source_reference or None,
                        confidence=confidence,
                        severity=severity,
                        description=description or None,
                        tags=[
                            item.strip()
                            for item in tags.split(",")
                            if item.strip()
                        ],
                    )

                    st.success(
                        f"Indicator saved successfully. ID: {indicator_id}"
                    )

                except (ValueError, TypeError) as exc:
                    st.error(str(exc))

    # -------------------------------------------------
    # IMPORT FEED
    # -------------------------------------------------

    with tab_import:

        st.markdown("### Import threat intelligence feed")

        st.info(
            "Only import feeds from sources you trust. "
            "Imported indicators retain their source name and confidence."
        )

        uploaded = st.file_uploader(
            "Upload JSON or CSV feed",
            type=["json", "csv"]
        )

        if uploaded is not None:

            if st.button(
                "Import indicators",
                type="primary"
            ):

                temporary_path = (
                    Path("data") / f"_temporary_ioc_feed.{uploaded.name.split('.')[-1]}"
                )

                temporary_path.parent.mkdir(
                    parents=True,
                    exist_ok=True
                )

                try:

                    temporary_path.write_bytes(
                        uploaded.getvalue()
                    )

                    if uploaded.name.lower().endswith(".json"):
                        result = import_json_feed(temporary_path)
                    else:
                        result = import_csv_feed(temporary_path)

                    st.success(
                        f"Imported {result['imported']} of {result['total']} records."
                    )

                    if result["errors"]:
                        st.warning("Some records could not be imported.")
                        st.dataframe(
                            result["errors"],
                            use_container_width=True
                        )

                except Exception as exc:
                    st.error(f"Feed import failed: {exc}")

                finally:
                    if temporary_path.exists():
                        temporary_path.unlink()

    # -------------------------------------------------
    # IOC LOOKUP
    # -------------------------------------------------

    with tab_lookup:

        st.markdown("### Search threat intelligence")

        lookup_value = st.text_input(
            "Enter IP, domain, URL or hash",
            key="intel_lookup_value"
        )

        if st.button("Lookup IOC", type="primary"):

            if not lookup_value.strip():
                st.warning("Enter an indicator first.")

            else:

                try:
                    matches = lookup_indicator(lookup_value)

                    st.session_state["intel_lookup_results"] = matches

                except ValueError as exc:
                    st.error(str(exc))

        matches = st.session_state.get(
            "intel_lookup_results",
            []
        )

        if matches:

            st.success(
                f"Found {len(matches)} active intelligence record(s)."
            )

            for item in matches:

                with st.container(border=True):

                    st.markdown(
                        f"**{item['ioc_type']} — {item['indicator']}**"
                    )

                    st.write(
                        f"Source: {item['source_name']}"
                    )

                    st.write(
                        f"Confidence: {item['confidence']} / 100"
                    )

                    st.write(
                        f"Severity: {item['severity']}"
                    )

                    st.write(
                        item.get("description") or "No description"
                    )

                    st.write(
                        f"Reference: {item.get('source_reference') or 'Not provided'}"
                    )

        elif "intel_lookup_results" in st.session_state:
            st.info("No active intelligence record matched this IOC.")

    # -------------------------------------------------
    # EVENT ENRICHMENT
    # -------------------------------------------------

    with tab_enrich:

        st.markdown("### Enrich endpoint events")

        limit = st.slider(
            "Number of recent events to inspect",
            50,
            1000,
            300,
            step=50,
            key="intel_enrichment_limit"
        )

        if st.button(
            "Run IOC enrichment",
            type="primary"
        ):

            try:

                events = get_recent_events(limit)

                results = enrich_events(events)

                st.session_state["intel_enrichment_results"] = results

            except Exception as exc:
                st.error(f"Enrichment failed: {exc}")

        results = st.session_state.get(
            "intel_enrichment_results",
            []
        )

        if results:

            matched = [
                event for event in results
                if event["threat_intel_match_count"] > 0
            ]

            st.metric(
                "Events with known IOC matches",
                len(matched)
            )

            if matched:

                rows = []

                for event in matched:

                    for ioc in event["threat_intel_matches"]:

                        rows.append({
                            "Event ID": event["normalized_event_id"],
                            "Timestamp": event.get("timestamp_utc"),
                            "Host": event.get("hostname"),
                            "IOC Type": ioc["ioc_type"],
                            "Indicator": ioc["indicator"],
                            "Source": ioc["source_name"],
                            "Confidence": ioc["confidence"],
                            "Severity": ioc["severity"],
                            "Matched Field": ioc["matched_field"],
                        })

                st.dataframe(
                    rows,
                    use_container_width=True,
                    hide_index=True
                )

                st.download_button(
                    "Export enrichment results",
                    data=pd.DataFrame(rows).to_csv(index=False),
                    file_name="TRACE-SOC-ioc-enrichment.csv",
                    mime="text/csv"
                )

            else:
                st.info(
                    "No known indicators matched the selected events. "
                    "This does not prove the events are benign."
                )
