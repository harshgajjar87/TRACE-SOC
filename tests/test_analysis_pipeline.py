
import sqlite3

import pytest

import database.db as db_module
import monitoring.analysis_pipeline as pipeline

from monitoring.analysis_pipeline import (
    create_analysis_schema,
    get_analysis_runs,
    run_analysis_pipeline,
    select_recent_events,
)


@pytest.fixture
def temporary_database(tmp_path, monkeypatch):
    database_path = tmp_path / "analysis_test.db"

    monkeypatch.setattr(
        db_module,
        "DATABASE_PATH",
        database_path,
    )

    db_module.create_tables()
    create_analysis_schema()

    return database_path


def test_analysis_schema_created(temporary_database):
    connection = sqlite3.connect(temporary_database)

    tables = {
        row[0]
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table'
            """
        ).fetchall()
    }

    connection.close()

    assert "monitoring_analysis_runs" in tables


def test_select_recent_events():
    events = [
        {
            "id": 1,
            "timestamp_utc": "2026-11-11T10:00:00+00:00",
        },
        {
            "id": 2,
            "timestamp_utc": "2026-11-11T10:15:00+00:00",
        },
        {
            "id": 3,
            "timestamp_utc": "2026-11-11T10:29:00+00:00",
        },
        {
            "id": 4,
            "timestamp_utc": "2026-11-11T10:31:00+00:00",
        },
    ]

    result = select_recent_events(events)

    # The latest event is the anchor, so the 30-minute
    # window begins at 10:01.
    assert [event["id"] for event in result] == [2, 3, 4]


def test_select_recent_events_ignores_invalid_timestamps():
    events = [
        {
            "id": 1,
            "timestamp_utc": "invalid timestamp",
        },
        {
            "id": 2,
            "timestamp_utc": "2026-11-11T10:00:00+00:00",
        },
    ]

    result = select_recent_events(events)

    assert [event["id"] for event in result] == [2]


def test_successful_analysis_pipeline(
    temporary_database,
    monkeypatch,
):
    monkeypatch.setattr(
        pipeline,
        "run_detection_engine",
        lambda: {
            "events_analysed": 100,
            "detection_matches": 3,
            "new_alerts_stored": 2,
            "coverage_gaps": [],
        },
    )

    monkeypatch.setattr(
        pipeline,
        "get_all_events",
        lambda: [
            {
                "id": 1,
                "timestamp_utc": "2026-11-11T10:00:00+00:00",
            },
            {
                "id": 2,
                "timestamp_utc": "2026-11-11T10:05:00+00:00",
            },
        ],
    )

    monkeypatch.setattr(
        pipeline,
        "build_and_save_stories",
        lambda events: [10],
    )

    result = run_analysis_pipeline()

    assert result["status"] == "SUCCESS"
    assert result["events_analysed"] == 100
    assert result["detection_matches"] == 3
    assert result["new_alerts_stored"] == 2
    assert result["stories_created_or_updated"] == 1
    assert result["story_ids"] == [10]

    runs = get_analysis_runs()

    assert len(runs) == 1
    assert runs[0]["status"] == "SUCCESS"


def test_failed_detection_is_recorded(
    temporary_database,
    monkeypatch,
):
    def failing_detection():
        raise RuntimeError("Detection test failure")

    monkeypatch.setattr(
        pipeline,
        "run_detection_engine",
        failing_detection,
    )

    result = run_analysis_pipeline()

    assert result["status"] == "FAILED"
    assert "Detection test failure" in result["error"]

    runs = get_analysis_runs()

    assert len(runs) == 1
    assert runs[0]["status"] == "FAILED"
    assert "Detection test failure" in runs[0]["error_message"]


def test_correlation_event_limit():
    events = [
        {
            "id": index,
            "timestamp_utc": (
                "2026-11-11T10:00:00+00:00"
            ),
        }
        for index in range(1, 1301)
    ]

    result = select_recent_events(events)

    assert len(result) == pipeline.MAX_CORRELATION_EVENTS
    assert result[0]["id"] == 101
    assert result[-1]["id"] == 1300

