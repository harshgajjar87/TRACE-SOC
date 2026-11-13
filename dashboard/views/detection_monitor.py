
"""TRACE-SOC automated detection and correlation dashboard."""

import json

import pandas as pd
import streamlit as st

from monitoring.analysis_pipeline import (
    create_analysis_schema,
    get_analysis_runs,
)


def render_detection_monitor():
    create_analysis_schema()

    st.title("Automated Detection Monitor")
    st.caption(
        "Detection results and investigation stories generated "
        "after successful endpoint collection cycles."
    )

    runs = get_analysis_runs(limit=100)

    if not runs:
        st.info(
            "No automated analysis cycles are recorded yet. "
            "Start the continuous monitoring service."
        )
        return

    successful = sum(
        1 for run in runs if run["status"] == "SUCCESS"
    )
    failed = sum(
        1 for run in runs if run["status"] == "FAILED"
    )

    total_alerts = sum(
        run["new_alerts_stored"] for run in runs
    )
    total_stories = sum(
        run["stories_created_or_updated"] for run in runs
    )

    st.subheader("Analysis statistics")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Analysis cycles", len(runs))
    col2.metric("Successful", successful)
    col3.metric("Failed", failed)
    col4.metric("New alerts stored", total_alerts)

    st.metric(
        "Stories created or updated",
        total_stories,
    )

    st.divider()
    st.subheader("Recent automated analysis")

    dataframe = pd.DataFrame(runs)

    display_columns = [
        "id",
        "started_at_utc",
        "status",
        "events_analysed",
        "correlation_events",
        "detection_matches",
        "new_alerts_stored",
        "stories_created_or_updated",
    ]

    st.dataframe(
        dataframe[display_columns],
        use_container_width=True,
        hide_index=True,
    )

    st.divider()
    st.subheader("Analysis cycle details")

    selected_id = st.selectbox(
        "Select an analysis cycle",
        options=[run["id"] for run in runs],
    )

    selected = next(
        run for run in runs if run["id"] == selected_id
    )

    st.write("**Status:**", selected["status"])
    st.write("**Started:**", selected["started_at_utc"])
    st.write("**Completed:**", selected["completed_at_utc"])
    st.write(
        "**Events analysed:**",
        selected["events_analysed"],
    )
    st.write(
        "**Events used for correlation:**",
        selected["correlation_events"],
    )
    st.write(
        "**Detection matches:**",
        selected["detection_matches"],
    )
    st.write(
        "**New alerts stored:**",
        selected["new_alerts_stored"],
    )
    st.write(
        "**Stories created or updated:**",
        selected["stories_created_or_updated"],
    )

    try:
        story_ids = json.loads(
            selected["story_ids_json"] or "[]"
        )
        st.write("**Story IDs:**", story_ids)
    except (TypeError, json.JSONDecodeError):
        st.warning("Could not parse story ID details.")

    if selected["error_message"]:
        st.error(selected["error_message"])

    if st.button("Refresh analysis data"):
        st.rerun()
