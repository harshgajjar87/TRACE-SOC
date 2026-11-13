
"""TRACE-SOC automated detection and investigation pipeline."""

import json
from datetime import timedelta

from database.db import get_connection
from detection.engine import run_detection_engine
from investigation.correlation import (
    get_all_events,
    parse_timestamp,
)
from investigation.story_builder import build_and_save_stories
from investigation.story_schema import create_story_tables
from monitoring.engine import create_monitoring_schema, utc_now


CORRELATION_WINDOW_MINUTES = 30
MAX_CORRELATION_EVENTS = 1200


def create_analysis_schema():
    """Create storage for automated analysis cycle results."""
    create_monitoring_schema()
    create_story_tables()

    connection = get_connection()

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitoring_analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at_utc TEXT NOT NULL,
                completed_at_utc TEXT,
                status TEXT NOT NULL,
                events_analysed INTEGER DEFAULT 0,
                correlation_events INTEGER DEFAULT 0,
                detection_matches INTEGER DEFAULT 0,
                new_alerts_stored INTEGER DEFAULT 0,
                stories_created_or_updated INTEGER DEFAULT 0,
                story_ids_json TEXT,
                error_message TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_analysis_runs_started
            ON monitoring_analysis_runs(started_at_utc);

            CREATE INDEX IF NOT EXISTS idx_analysis_runs_status
            ON monitoring_analysis_runs(status);
            """
        )
        connection.commit()
    finally:
        connection.close()


def select_recent_events(events):
    """
    Select events in the latest 30-minute event-time window.

    The latest event timestamp is used as the anchor. This makes
    historical imports and replay-based tests work as expected.
    """
    valid_events = []

    for event in events:
        timestamp = parse_timestamp(event.get("timestamp_utc"))
        if timestamp is not None and event.get("id") is not None:
            valid_events.append((timestamp, event))

    if not valid_events:
        return []

    latest_time = max(item[0] for item in valid_events)
    earliest_time = latest_time - timedelta(
        minutes=CORRELATION_WINDOW_MINUTES
    )

    recent = [
        event
        for timestamp, event in valid_events
        if earliest_time <= timestamp <= latest_time
    ]

    recent.sort(
        key=lambda event: event.get("timestamp_utc") or ""
    )

    # Keep the most recent records when the window is unusually busy.
    return recent[-MAX_CORRELATION_EVENTS:]


def save_analysis_result(
    status,
    started_at,
    metrics=None,
    story_ids=None,
    error_message=None,
):
    metrics = metrics or {}
    story_ids = story_ids or []

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO monitoring_analysis_runs (
                started_at_utc,
                completed_at_utc,
                status,
                events_analysed,
                correlation_events,
                detection_matches,
                new_alerts_stored,
                stories_created_or_updated,
                story_ids_json,
                error_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                started_at,
                utc_now(),
                status,
                metrics.get("events_analysed", 0),
                metrics.get("correlation_events", 0),
                metrics.get("detection_matches", 0),
                metrics.get("new_alerts_stored", 0),
                len(story_ids),
                json.dumps(story_ids),
                error_message,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def run_analysis_pipeline():
    """
    Run detection, recent-event correlation and story persistence.

    Detection uses the existing full-history rule engine. Correlation
    is restricted to a recent event-time window for performance.
    """
    create_analysis_schema()
    started_at = utc_now()

    print("\n========== TRACE-SOC AUTOMATED ANALYSIS ==========")

    try:
        # Existing 24-rule engine. Alert fingerprints prevent
        # duplicate alert records from being inserted.
        detection_result = run_detection_engine()

        # Load events for bounded correlation and story building.
        all_events = get_all_events()
        recent_events = select_recent_events(all_events)

        # Reuse the existing story builder and its evidence links.
        story_ids = build_and_save_stories(events=recent_events)

        metrics = {
            "events_analysed": detection_result.get(
                "events_analysed", len(all_events)
            ),
            "correlation_events": len(recent_events),
            "detection_matches": detection_result.get(
                "detection_matches", 0
            ),
            "new_alerts_stored": detection_result.get(
                "new_alerts_stored", 0
            ),
        }

        save_analysis_result(
            status="SUCCESS",
            started_at=started_at,
            metrics=metrics,
            story_ids=story_ids,
        )

        result = {
            "status": "SUCCESS",
            **metrics,
            "stories_created_or_updated": len(story_ids),
            "story_ids": story_ids,
        }

        print("\nAutomated analysis completed:", result)
        print("==================================================\n")

        return result

    except Exception as exc:
        save_analysis_result(
            status="FAILED",
            started_at=started_at,
            error_message=str(exc)[:2000],
        )

        result = {
            "status": "FAILED",
            "error": str(exc),
        }

        print("\nAutomated analysis failed:", exc)
        print("==================================================\n")

        return result


def get_analysis_runs(limit=50):
    if limit < 1:
        raise ValueError("Limit must be at least 1.")

    create_analysis_schema()
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT id, started_at_utc, completed_at_utc,
                   status, events_analysed, correlation_events,
                   detection_matches, new_alerts_stored,
                   stories_created_or_updated, story_ids_json,
                   error_message
            FROM monitoring_analysis_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [
            {
                "id": row[0],
                "started_at_utc": row[1],
                "completed_at_utc": row[2],
                "status": row[3],
                "events_analysed": row[4],
                "correlation_events": row[5],
                "detection_matches": row[6],
                "new_alerts_stored": row[7],
                "stories_created_or_updated": row[8],
                "story_ids_json": row[9],
                "error_message": row[10],
            }
            for row in rows
        ]
    finally:
        connection.close()
