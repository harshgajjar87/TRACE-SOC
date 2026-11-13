
import json
import sqlite3

import database.db as db

from database.db import create_tables
from investigation.story_schema import create_story_tables

from hunting.engine import (
    create_hunting_schema,
    search_hunt,
    get_event_detail,
    analyze_detection_gaps,
    save_hunt,
    list_saved_hunts,
    delete_saved_hunt,
)


def setup_database(tmp_path, monkeypatch):

    test_db = tmp_path / "hunting_test.db"

    monkeypatch.setattr(db, "DATABASE_PATH", test_db)

    create_tables()
    create_story_tables()
    create_hunting_schema()

    connection = db.get_connection()

    raw_xml = b"<Event><System><EventID>1</EventID></System></Event>"

    import hashlib

    raw_hash = hashlib.sha256(raw_xml).hexdigest()

    connection.execute("""
        INSERT INTO raw_events (
            event_fingerprint,
            source_file,
            source_file_sha256,
            raw_xml,
            raw_xml_sha256,
            event_id,
            provider,
            channel,
            timestamp_utc,
            hostname,
            collected_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        "fingerprint-1",
        "sample.xml",
        raw_hash,
        sqlite3.Binary(raw_xml),
        raw_hash,
        "1",
        "TestProvider",
        "Security",
        "2026-11-10T10:00:00+00:00",
        "LAB-PC",
        "2026-11-10T10:01:00+00:00",
    ))

    raw_id = connection.execute(
        "SELECT id FROM raw_events"
    ).fetchone()[0]

    connection.execute("""
        INSERT INTO normalized_events (
            raw_event_id,
            event_id,
            provider,
            channel,
            timestamp_utc,
            hostname,
            username,
            image,
            command_line,
            source_ip,
            destination_ip,
            event_type,
            extra_data_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        raw_id,
        "1",
        "TestProvider",
        "Security",
        "2026-11-10T10:00:00+00:00",
        "LAB-PC",
        "testuser",
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe /c whoami",
        "192.168.1.50",
        "8.8.8.8",
        "process_creation",
        json.dumps({
            "QueryName": "example.test",
            "FileHash": "abc123"
        })
    ))

    connection.commit()
    connection.close()


def test_ip_hunt(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    results = search_hunt(
        hunt_type="IP",
        indicator="192.168.1.50"
    )

    assert len(results) == 1
    assert results[0]["hostname"] == "LAB-PC"


def test_process_hunt(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    results = search_hunt(
        hunt_type="PROCESS",
        indicator="cmd.exe"
    )

    assert len(results) == 1


def test_domain_hunt(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    results = search_hunt(
        hunt_type="DOMAIN",
        indicator="example.test"
    )

    assert len(results) == 1


def test_event_detail_integrity(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    detail = get_event_detail(1)

    assert detail is not None
    assert detail["integrity_status"] == "VERIFIED"
    assert detail["raw_xml_text"].startswith("<Event>")


def test_detection_gap_analysis(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    results = search_hunt()

    analyzed = analyze_detection_gaps(results)

    assert analyzed[0]["detection_linkage"] == "NO_LINKED_ALERT"


def test_alert_linkage(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    connection = db.get_connection()

    connection.execute("""
        INSERT INTO alerts (
            alert_fingerprint,
            rule_id,
            rule_name,
            severity,
            status,
            evidence_json,
            created_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        "alert-fingerprint",
        "TS001",
        "Test Alert",
        "HIGH",
        "NEW",
        json.dumps({"normalized_event_ids": [1]}),
        "2026-11-10T10:02:00+00:00"
    ))

    connection.commit()
    connection.close()

    results = analyze_detection_gaps(search_hunt())

    assert results[0]["detection_linkage"] == "LINKED_TO_ALERT"


def test_saved_hunt_lifecycle(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    hunt_id = save_hunt(
        "Suspicious IP Hunt",
        "IP",
        {"indicator": "192.168.1.50"}
    )

    saved = list_saved_hunts()

    assert len(saved) == 1
    assert saved[0]["id"] == hunt_id
    assert saved[0]["query"]["indicator"] == "192.168.1.50"

    assert delete_saved_hunt(hunt_id) is True
    assert list_saved_hunts() == []


def test_invalid_hunt_type_rejected(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    try:
        search_hunt(hunt_type="INVALID")
        assert False, "Expected ValueError"

    except ValueError:
        pass
