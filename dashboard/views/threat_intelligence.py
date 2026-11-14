
"""TRACE-SOC Threat Intelligence dashboard."""

import json
import streamlit as st
import pandas as pd
from dashboard.notifications import notify_success

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


def get_events_to_enrich(scope="Active IOC Candidates (Database)", limit=500, host_filter=None):
    """Retrieve normalized events for threat intelligence enrichment."""
    connection = get_connection()
    connection.row_factory = __import__("sqlite3").Row

    try:
        if scope == "Active IOC Candidates (Database)":
            iocs = connection.execute(
                "SELECT indicator, ioc_type FROM ioc_indicators WHERE is_active = 1"
            ).fetchall()

            ip_indicators = [r["indicator"] for r in iocs if r["ioc_type"] == "IP"]
            other_indicators = [r["indicator"] for r in iocs if r["ioc_type"] != "IP"]

            conditions = []
            params = []

            if ip_indicators:
                placeholders = ",".join(["?"] * len(ip_indicators))
                conditions.append(f"source_ip IN ({placeholders}) OR destination_ip IN ({placeholders})")
                params.extend(ip_indicators)
                params.extend(ip_indicators)

            for ind in other_indicators:
                pattern = f"%{ind}%"
                conditions.append("(image LIKE ? OR command_line LIKE ? OR extra_data_json LIKE ?)")
                params.extend([pattern, pattern, pattern])

            if conditions:
                where_clause = " OR ".join(f"({c})" for c in conditions)
                if host_filter and host_filter.strip():
                    where_clause = f"({where_clause}) AND hostname LIKE ?"
                    params.append(f"%{host_filter.strip()}%")

                sql = f"""
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
                    WHERE {where_clause}
                    ORDER BY timestamp_utc DESC, id DESC
                    LIMIT ?
                """
                params.append(limit)
                rows = connection.execute(sql, params).fetchall()
                if rows:
                    return [dict(r) for r in rows]

        # Recent events scope fallback
        sql = """
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
        """
        params = []
        if host_filter and host_filter.strip():
            sql += " WHERE hostname LIKE ?"
            params.append(f"%{host_filter.strip()}%")

        sql += " ORDER BY timestamp_utc DESC, id DESC LIMIT ?"
        params.append(limit)

        rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_recent_events(limit=500):
    return get_events_to_enrich(scope="Recent Ingested Telemetry", limit=limit)


def render_threat_intelligence():

    create_threat_intel_schema()
    expire_indicators()

    h_col1, h_col2 = st.columns([4, 1])
    with h_col1:
        st.markdown("## 🧠 Threat Intelligence Center")
        st.caption(
            "Manage local IOC intelligence, enrich endpoint events "
            "and investigate known indicators."
        )
    with h_col2:
        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)
        if st.button("↻ Refresh Intel", key="refresh_threat_intel_btn", use_container_width=True):
            st.rerun()

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

    tab_overview, tab_add, tab_import, tab_lookup, tab_enrich = st.tabs(
        [
            "Overview",
            "Add IOC",
            "Import Feed",
            "IOC Lookup",
            "Event Enrichment",
        ],
        key="threat_intel_active_tab",
    )

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

                    notify_success(
                        f"Indicator '{indicator}' saved successfully (ID: {indicator_id})."
                    )
                    st.rerun()

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
        st.caption(
            "Correlate stored endpoint telemetry against active threat intelligence indicators (IPs, domains, hashes)."
        )

        e_col1, e_col2, e_col3 = st.columns([2, 1, 1])
        with e_col1:
            scope = st.selectbox(
                "Inspection Scope",
                [
                    "Active IOC Candidates (Database)",
                    "Recent Ingested Telemetry",
                ],
                index=0,
                key="intel_enrichment_scope",
                help="Active IOC Candidates searches all stored events for values touching active threat indicators."
            )

        with e_col2:
            limit = st.slider(
                "Event Limit",
                50,
                2000,
                500,
                step=50,
                key="intel_enrichment_limit"
            )

        with e_col3:
            host_filter = st.text_input("Hostname filter (optional)", key="intel_enrich_host")

        b_enrich_col, _ = st.columns([1, 3])
        with b_enrich_col:
            run_enrichment = st.button(
                "Run IOC enrichment",
                type="primary",
                key="btn_run_enrichment",
                use_container_width=True,
            )

        if run_enrichment:

            try:
                events = get_events_to_enrich(scope=scope, limit=limit, host_filter=host_filter)
                results = enrich_events(events)

                st.session_state["intel_enrichment_results"] = results
                st.session_state["intel_enrichment_scope_used"] = scope

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
                            "Description": ioc.get("description") or "",
                        })

                st.dataframe(
                    rows,
                    use_container_width=True,
                    hide_index=True
                )

                st.download_button(
                    "Export enrichment results",
                    data=pd.DataFrame(rows).to_csv(index=False),
                    file_name="CYFROG-ioc-enrichment.csv",
                    mime="text/csv"
                )

            else:
                st.info(
                    "No known indicators matched the selected events in this scope. "
                    "Try switching the scope to 'Active IOC Candidates (Database)' or broadening your filters."
                )
