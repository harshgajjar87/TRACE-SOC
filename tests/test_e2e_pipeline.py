
import json
import hashlib
import sqlite3

import database.db as database

from detection.engine import run_detection_engine


def insert_synthetic_event(connection, index):
    """
    Insert one synthetic Windows Security event into
    raw_events and normalized_events.
    """

    timestamp = f"2026-11-09T10:00:0{index}+00:00"

    raw_xml = (
        f"<Event><EventID>4625</EventID>"
        f"<RecordID>{index}</RecordID></Event>"
    ).encode("utf-8")

    raw_hash = hashlib.sha256(raw_xml).hexdigest()

    fingerprint = hashlib.sha256(
        f"e2e-test-event-{index}".encode("utf-8")
    ).hexdigest()

    cursor = connection.execute("""
        INSERT INTO raw_events (
            event_fingerprint,
            source_file,
            source_file_sha256,
            raw_xml,
            event_id,
            provider,
            channel,
            record_id,
            timestamp_utc,
            hostname,
            collected_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        fingerprint,
        f"synthetic_event_{index}.xml",
        raw_hash,
        raw_xml,
        "4625",
        "Microsoft-Windows-Security-Auditing",
        "Security",
        str(index),
        timestamp,
        "E2E-TEST-PC",
        "2026-11-09T10:01:00+00:00"
    ))

    raw_event_id = cursor.lastrowid

    connection.execute("""
        INSERT INTO normalized_events (
            raw_event_id,
            event_id,
            provider,
            channel,
            record_id,
            timestamp_utc,
            hostname,
            username,
            source_ip,
            event_type,
            extra_data_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        raw_event_id,
        "4625",
        "Microsoft-Windows-Security-Auditing",
        "Security",
        str(index),
        timestamp,
        "E2E-TEST-PC",
        "testuser",
        "192.168.10.50",
        "authentication_failure",
        json.dumps({
            "TargetUserName": "testuser",
            "IpAddress": "192.168.10.50",
            "LogonType": "3"
        })
    ))


def test_complete_detection_pipeline(monkeypatch, tmp_path):
    """
    Test:
    SQLite event storage -> Detection Engine -> Alert storage
    -> Evidence linkage -> Duplicate prevention.
    """

    # Use an isolated temporary database.
    test_database = tmp_path / "tracesoc_e2e_test.db"

    monkeypatch.setattr(
        database,
        "DATABASE_PATH",
        test_database
    )

    # Create all project database tables.
    database.create_tables()

    connection = database.get_connection()

    try:
        # Insert five failed-login events.
        for index in range(1, 6):
            insert_synthetic_event(connection, index)

        connection.commit()

        # Verify raw and normalized event storage.
        raw_count = connection.execute(
            "SELECT COUNT(*) FROM raw_events"
        ).fetchone()[0]

        normalized_count = connection.execute(
            "SELECT COUNT(*) FROM normalized_events"
        ).fetchone()[0]

        assert raw_count == 5
        assert normalized_count == 5

    finally:
        connection.close()

    # Run the actual detection engine.
    result = run_detection_engine()

    assert result["events_analysed"] == 5
    assert result["detection_matches"] >= 1
    assert result["new_alerts_stored"] >= 1

    connection = database.get_connection()
    connection.row_factory = sqlite3.Row

    try:
        # Find the brute-force alert.
        alert = connection.execute("""
            SELECT *
            FROM alerts
            WHERE rule_id = 'TS001'
        """).fetchone()

        assert alert is not None
        assert alert["severity"] == "HIGH"
        assert alert["hostname"] == "E2E-TEST-PC"
        assert alert["source_ip"] == "192.168.10.50"
        assert alert["event_count"] == 5

        # Check the alert's evidence references.
        evidence = json.loads(alert["evidence_json"])

        event_ids = evidence["normalized_event_ids"]

        assert len(event_ids) == 5

        placeholders = ",".join("?" for _ in event_ids)

        linked_events = connection.execute(
            f"""
            SELECT id, raw_event_id
            FROM normalized_events
            WHERE id IN ({placeholders})
            """,
            event_ids
        ).fetchall()

        assert len(linked_events) == 5

        # Verify the linked original raw evidence exists.
        raw_ids = [row["raw_event_id"] for row in linked_events]

        raw_placeholders = ",".join("?" for _ in raw_ids)

        linked_raw_events = connection.execute(
            f"""
            SELECT id, raw_xml
            FROM raw_events
            WHERE id IN ({raw_placeholders})
            """,
            raw_ids
        ).fetchall()

        assert len(linked_raw_events) == 5

        # Verify evidence content has not been lost.
        assert all(row["raw_xml"] for row in linked_raw_events)

    finally:
        connection.close()

    # Run the engine again to test duplicate prevention.
    second_result = run_detection_engine()

    assert second_result["events_analysed"] == 5
    assert second_result["new_alerts_stored"] == 0

    connection = database.get_connection()

    try:
        alert_count = connection.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE rule_id = 'TS001'
        """).fetchone()[0]

        assert alert_count == 1

    finally:
        connection.close()
