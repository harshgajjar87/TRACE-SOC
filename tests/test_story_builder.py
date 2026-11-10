
import json
import sqlite3

import database.db as db
import investigation.story_builder as story_builder
import investigation.correlation as correlation

from database.db import create_tables
from investigation.story_schema import create_story_tables


def test_story_creation_and_duplicate_prevention(tmp_path, monkeypatch):

    # 1. Use a temporary database
    test_db = tmp_path / "trace_soc_story_test.db"
    monkeypatch.setattr(db, "DATABASE_PATH", test_db)

    # 2. Create database tables
    create_tables()
    create_story_tables()

    connection = db.get_connection()
    connection.row_factory = sqlite3.Row

    try:
        # 3. Insert two related normalized events
        events = [
            {
                "event_id": "4625",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "timestamp_utc": "2026-11-09T10:00:00Z",
                "hostname": "LAB-PC",
                "username": "testuser",
                "source_ip": "192.168.1.50",
                "event_type": "authentication",
            },
            {
                "event_id": "4625",
                "provider": "Microsoft-Windows-Security-Auditing",
                "channel": "Security",
                "timestamp_utc": "2026-11-09T10:02:00Z",
                "hostname": "LAB-PC",
                "username": "testuser",
                "source_ip": "192.168.1.50",
                "event_type": "authentication",
            },
        ]

        for event in events:
            # Insert a placeholder raw_event to satisfy the NOT NULL
            # foreign key constraint on normalized_events.raw_event_id
            raw_cursor = connection.execute("""
                INSERT INTO raw_events (
                    event_fingerprint, source_file, source_file_sha256,
                    raw_xml, event_id, provider, channel,
                    timestamp_utc, hostname, collected_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                f"fp-{event['timestamp_utc']}",
                "synthetic.xml",
                "0" * 64,
                b"<synthetic/>",
                event["event_id"],
                event["provider"],
                event["channel"],
                event["timestamp_utc"],
                event["hostname"],
                "2026-11-09T10:00:00Z"
            ))

            raw_event_id = raw_cursor.lastrowid

            connection.execute("""
                INSERT INTO normalized_events (
                    raw_event_id, event_id, provider, channel,
                    timestamp_utc, hostname, username, source_ip,
                    event_type, extra_data_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                raw_event_id,
                event["event_id"],
                event["provider"],
                event["channel"],
                event["timestamp_utc"],
                event["hostname"],
                event["username"],
                event["source_ip"],
                event["event_type"],
                json.dumps({})
            ))

        connection.commit()

        # 4. Insert an alert linked to the first event
        event_id = connection.execute("""
            SELECT id FROM normalized_events ORDER BY id LIMIT 1
        """).fetchone()["id"]

        evidence = {
            "normalized_event_ids": [event_id]
        }

        connection.execute("""
            INSERT INTO alerts (
                alert_fingerprint, rule_id, rule_name,
                description, severity, status, hostname,
                username, source_ip, first_seen, last_seen,
                event_count, mitre_tactic, mitre_technique,
                evidence_json, created_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "test-alert-fingerprint",
            "TS001",
            "Failed Login Detection",
            "Multiple failed login attempts",
            "HIGH",
            "NEW",
            "LAB-PC",
            "testuser",
            "192.168.1.50",
            "2026-11-09T10:00:00Z",
            "2026-11-09T10:02:00Z",
            2,
            "Credential Access",
            "T1110",
            json.dumps(evidence),
            "2026-11-09T10:03:00Z"
        ))

        connection.commit()

    finally:
        connection.close()

    # 5. Run the actual story builder
    story_builder.build_and_save_stories()

    # 6. Verify story and evidence links
    connection = db.get_connection()
    connection.row_factory = sqlite3.Row

    try:
        stories = connection.execute("""
            SELECT * FROM attack_stories
        """).fetchall()

        links = connection.execute("""
            SELECT * FROM story_events
        """).fetchall()

        assert len(stories) == 1
        assert stories[0]["event_count"] == 2
        assert stories[0]["alert_count"] == 1
        assert stories[0]["severity"] == "HIGH"

        assert len(links) == 2
        assert any(link["alert_id"] is not None for link in links)

    finally:
        connection.close()

    # 7. Run the builder again: no duplicate story should be created
    story_builder.build_and_save_stories()

    connection = db.get_connection()

    try:
        story_count = connection.execute("""
            SELECT COUNT(*) FROM attack_stories
        """).fetchone()[0]

        link_count = connection.execute("""
            SELECT COUNT(*) FROM story_events
        """).fetchone()[0]

        assert story_count == 1
        assert link_count == 2

    finally:
        connection.close()
