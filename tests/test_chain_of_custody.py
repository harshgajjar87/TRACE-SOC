
import hashlib
import json
import sqlite3

import pytest

import database.db as db
from database.db import create_tables, get_connection
from investigation.story_schema import create_story_tables
from investigation.evidence import verify_raw_event_integrity
from investigation.chain_of_custody import (
    create_chain_of_custody_schema,
    record_custody_event,
    get_custody_history,
    get_evidence_inventory,
    get_raw_event_blob,
    build_evidence_manifest,
)


@pytest.fixture
def test_database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATABASE_PATH", tmp_path / "test_tracesoc.db")

    create_tables()
    create_story_tables()
    create_chain_of_custody_schema()

    xml = b"<Event><System><EventID>4624</EventID></System></Event>"
    digest = hashlib.sha256(xml).hexdigest()

    connection = get_connection()
    try:
        with connection:
            cursor = connection.execute("""
                INSERT INTO raw_events (
                    event_fingerprint, source_file, source_file_sha256,
                    raw_xml, event_id, provider, channel, record_id,
                    timestamp_utc, hostname, collected_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "test-fingerprint-1",
                "test.xml",
                hashlib.sha256(b"test.xml").hexdigest(),
                xml,
                "4624",
                "Microsoft-Windows-Security-Auditing",
                "Security",
                "1",
                "2026-11-11T10:00:00+00:00",
                "TEST-PC",
                "2026-11-11T10:00:01+00:00",
            ))
            evidence_id = cursor.lastrowid
    finally:
        connection.close()

    return evidence_id, xml, digest


def test_integrity_verification(test_database):
    evidence_id, xml, digest = test_database

    result = verify_raw_event_integrity(evidence_id)

    assert result["status"] == "VERIFIED"
    assert result["actual_raw_xml_sha256"] == digest


def test_record_and_retrieve_custody_history(test_database):
    evidence_id, xml, digest = test_database

    record_custody_event(
        evidence_id,
        "ACCESSED",
        "Analyst A",
        "Reviewed evidence",
        sha256=digest,
    )

    history = get_custody_history(evidence_id)

    assert len(history) == 1
    assert history[0]["action"] == "ACCESSED"
    assert history[0]["actor"] == "Analyst A"


def test_inventory_contains_evidence(test_database):
    evidence_id, xml, digest = test_database

    inventory = get_evidence_inventory()

    assert len(inventory) == 1
    assert inventory[0]["raw_event_id"] == evidence_id
    assert inventory[0]["source_file"] == "test.xml"


def test_original_xml_is_preserved(test_database):
    evidence_id, xml, digest = test_database

    retrieved = get_raw_event_blob(evidence_id)

    assert retrieved == xml
    assert hashlib.sha256(retrieved).hexdigest() == digest


def test_manifest_contains_integrity_details(test_database):
    evidence_id, xml, digest = test_database

    verification = verify_raw_event_integrity(evidence_id)

    manifest = build_evidence_manifest(
        evidence_id,
        verification,
        "Analyst A",
        "Forensic review",
    )

    assert manifest["evidence"]["id"] == evidence_id
    assert manifest["integrity_verification"]["status"] == "VERIFIED"
    assert manifest["generated_by"] == "Analyst A"


def test_invalid_action_is_rejected(test_database):
    evidence_id, xml, digest = test_database

    with pytest.raises(ValueError):
        record_custody_event(
            evidence_id,
            "DELETE",
            "Analyst A",
        )


def test_missing_analyst_is_rejected(test_database):
    evidence_id, xml, digest = test_database

    with pytest.raises(ValueError):
        record_custody_event(
            evidence_id,
            "ACCESSED",
            "",
        )


def test_missing_evidence_is_rejected(test_database):
    with pytest.raises(ValueError):
        record_custody_event(
            999999,
            "ACCESSED",
            "Analyst A",
        )


def test_custody_details_are_json(test_database):
    evidence_id, xml, digest = test_database

    record_custody_event(
        evidence_id,
        "VERIFIED",
        "Analyst A",
        "Hash check",
        sha256=digest,
        details={"status": "VERIFIED"},
    )

    history = get_custody_history(evidence_id)

    assert history[0]["details"]["status"] == "VERIFIED"
