
import sqlite3

import pytest

import database.db as db_module

from monitoring.engine import (
    create_monitoring_schema,
    get_monitoring_runs,
    get_monitoring_status,
    get_monitoring_summary,
)

from monitoring.runner import (
    run_monitoring_cycle,
    run_continuous_monitoring,
)


@pytest.fixture
def temporary_database(tmp_path, monkeypatch):
    database_path = tmp_path / "monitoring_test.db"

    monkeypatch.setattr(
        db_module,
        "DATABASE_PATH",
        database_path,
    )

    create_monitoring_schema()

    return database_path


def fake_successful_collector(**kwargs):
    return {
        "channels": {
            "System": {
                "received": 5,
                "inserted": 4,
                "duplicates": 1,
                "last_record_id": 1005,
            }
        },
        "total_received": 5,
        "total_inserted": 4,
        "total_duplicates": 1,
    }


def test_monitoring_schema_created(temporary_database):
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

    assert "monitoring_runs" in tables
    assert "monitoring_status" in tables


def test_initial_monitoring_status(temporary_database):
    status = get_monitoring_status()

    assert status["service_status"] == "STOPPED"


def test_successful_monitoring_cycle(temporary_database):
    summary = run_monitoring_cycle(
        channels=["System"],
        collector_function=fake_successful_collector,
    )

    assert summary["total_received"] == 5
    assert summary["total_inserted"] == 4

    runs = get_monitoring_runs()

    assert len(runs) == 1
    assert runs[0]["status"] == "SUCCESS"


def test_monitoring_summary(temporary_database):
    run_monitoring_cycle(
        channels=["System"],
        collector_function=fake_successful_collector,
    )

    summary = get_monitoring_summary()

    assert summary["total_runs"] == 1
    assert summary["successful_runs"] == 1
    assert summary["failed_runs"] == 0
    assert summary["total_received"] == 5
    assert summary["total_inserted"] == 4
    assert summary["total_duplicates"] == 1


def test_failed_monitoring_cycle_is_recorded(temporary_database):
    def failing_collector(**kwargs):
        raise RuntimeError("Test collection failure")

    with pytest.raises(RuntimeError):
        run_monitoring_cycle(
            channels=["System"],
            collector_function=failing_collector,
        )

    runs = get_monitoring_runs()

    assert len(runs) == 1
    assert runs[0]["status"] == "FAILED"
    assert "Test collection failure" in runs[0]["error_message"]


def test_failed_cycle_updates_last_error(temporary_database):
    def failing_collector(**kwargs):
        raise RuntimeError("Access denied")

    with pytest.raises(RuntimeError):
        run_monitoring_cycle(
            collector_function=failing_collector,
        )

    status = get_monitoring_status()

    assert "Access denied" in status["last_error"]


def test_continuous_monitoring_runs_requested_cycles(
    temporary_database,
):
    calls = []

    def fake_collector(**kwargs):
        calls.append(kwargs)

        return {
            "channels": {},
            "total_received": 0,
            "total_inserted": 0,
            "total_duplicates": 0,
        }

    cycles = run_continuous_monitoring(
        channels=["System"],
        polling_interval_seconds=1,
        collector_function=fake_collector,
        max_cycles=2,
    )

    assert cycles == 2
    assert len(calls) == 2

    status = get_monitoring_status()
    assert status["service_status"] == "STOPPED"

    summary = get_monitoring_summary()
    assert summary["total_runs"] == 2
    assert summary["successful_runs"] == 2


def test_invalid_polling_interval(temporary_database):
    with pytest.raises(ValueError):
        run_continuous_monitoring(
            polling_interval_seconds=0,
            max_cycles=1,
        )
