
"""Tests for TRACE-SOC MITRE ATT&CK coverage."""

import pytest

from database import db
from database.db import create_tables

from attack.engine import (
    create_attack_schema,
    validate_technique_id,
    register_technique,
    get_techniques,
    sync_alert_mappings,
    map_alert_to_technique,
    get_mapped_alerts,
    get_unmapped_alerts,
    get_technique_coverage,
    get_tactic_distribution,
    get_attack_coverage_summary,
    get_technique_details,
)


@pytest.fixture
def setup_database(tmp_path, monkeypatch):

    test_db = tmp_path / "test_attack.db"

    monkeypatch.setattr(
        db,
        "DATABASE_PATH",
        test_db,
    )

    create_tables()
    create_attack_schema()

    return test_db


def insert_test_alert(
    fingerprint,
    tactic=None,
    technique=None,
):

    conn = db.get_connection()

    try:

        cursor = conn.execute("""
            INSERT INTO alerts (
                alert_fingerprint,
                rule_id,
                rule_name,
                description,
                severity,
                status,
                hostname,
                username,
                source_ip,
                first_seen,
                last_seen,
                event_count,
                mitre_tactic,
                mitre_technique,
                evidence_json,
                created_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            fingerprint,
            "TS001",
            "Test Authentication Alert",
            "Test alert for ATT&CK mapping.",
            "HIGH",
            "NEW",
            "TEST-PC",
            "testuser",
            "192.168.1.10",
            "2026-11-10T10:00:00+00:00",
            "2026-11-10T10:05:00+00:00",
            5,
            tactic,
            technique,
            "{}",
            "2026-11-10T10:05:00+00:00",
        ))

        conn.commit()

        return cursor.lastrowid

    finally:

        conn.close()


def test_valid_technique_id():

    assert validate_technique_id("T1110") == "T1110"

    assert (
        validate_technique_id("T1059.001")
        == "T1059.001"
    )


def test_invalid_technique_id():

    with pytest.raises(ValueError):
        validate_technique_id("INVALID")

    with pytest.raises(ValueError):
        validate_technique_id("T123")


def test_register_technique(setup_database):

    register_technique(
        "T1110",
        "Brute Force",
        "Credential Access",
        "Adversaries may use brute force techniques.",
    )

    techniques = get_techniques()

    assert len(techniques) == 1

    assert techniques[0]["technique_id"] == "T1110"

    assert techniques[0]["source"] == "ANALYST_VERIFIED"


def test_existing_alert_mapping_sync(setup_database):

    insert_test_alert(
        "attack-sync-001",
        tactic="Credential Access",
        technique="T1110",
    )

    result = sync_alert_mappings()

    assert result["processed_alerts"] == 1
    assert result["mapped_records"] == 1
    assert result["skipped_alerts"] == 0

    mappings = get_mapped_alerts()

    assert len(mappings) == 1

    assert mappings[0]["technique_id"] == "T1110"

    assert (
        mappings[0]["mapping_source"]
        == "EXISTING_ALERT_METADATA"
    )


def test_sync_marks_unverified_metadata(setup_database):

    insert_test_alert(
        "attack-unverified-001",
        tactic="Credential Access",
        technique="T1110",
    )

    sync_alert_mappings()

    technique = get_techniques()[0]

    assert (
        technique["source"]
        == "ALERT_METADATA_UNVERIFIED"
    )


def test_invalid_existing_mapping_is_skipped(setup_database):

    insert_test_alert(
        "attack-invalid-001",
        tactic="Credential Access",
        technique="INVALID",
    )

    result = sync_alert_mappings()

    assert result["skipped_alerts"] == 1
    assert get_mapped_alerts() == []


def test_unmapped_alert_detection(setup_database):

    insert_test_alert("attack-unmapped-001")

    unmapped = get_unmapped_alerts()

    assert len(unmapped) == 1


def test_manual_alert_mapping(setup_database):

    alert_id = insert_test_alert(
        "attack-manual-001"
    )

    register_technique(
        "T1110",
        "Brute Force",
        "Credential Access",
    )

    map_alert_to_technique(
        alert_id=alert_id,
        technique_id="T1110",
        tactic="Credential Access",
        mapped_by="Test Analyst",
        confidence="HIGH",
    )

    mappings = get_mapped_alerts()

    assert len(mappings) == 1

    assert mappings[0]["confidence"] == "HIGH"

    assert mappings[0]["mapping_source"] == "ANALYST:Test Analyst"


def test_manual_mapping_rejects_missing_alert(setup_database):

    register_technique(
        "T1110",
        "Brute Force",
        "Credential Access",
    )

    with pytest.raises(ValueError):

        map_alert_to_technique(
            alert_id=99999,
            technique_id="T1110",
            tactic="Credential Access",
            mapped_by="Test Analyst",
        )


def test_manual_mapping_rejects_unregistered_technique(setup_database):

    alert_id = insert_test_alert("attack-missing-technique-001")

    with pytest.raises(ValueError):

        map_alert_to_technique(
            alert_id=alert_id,
            technique_id="T1110",
            tactic="Credential Access",
            mapped_by="Test Analyst",
        )


def test_technique_coverage(setup_database):

    alert_id = insert_test_alert(
        "attack-coverage-001",
        tactic="Credential Access",
        technique="T1110",
    )

    sync_alert_mappings()

    coverage = get_technique_coverage()

    assert len(coverage) == 1

    assert coverage[0]["technique_id"] == "T1110"

    assert coverage[0]["mapped_alert_count"] == 1


def test_tactic_distribution(setup_database):

    insert_test_alert(
        "attack-tactic-001",
        tactic="Credential Access",
        technique="T1110",
    )

    insert_test_alert(
        "attack-tactic-002",
        tactic="Credential Access",
        technique="T1110",
    )

    sync_alert_mappings()

    distribution = get_tactic_distribution()

    assert len(distribution) == 1

    assert distribution[0]["tactic"] == "Credential Access"

    assert distribution[0]["alert_count"] == 2


def test_attack_coverage_summary(setup_database):

    insert_test_alert(
        "attack-summary-001",
        tactic="Credential Access",
        technique="T1110",
    )

    insert_test_alert(
        "attack-summary-002",
    )

    sync_alert_mappings()

    summary = get_attack_coverage_summary()

    assert summary["total_alerts"] == 2
    assert summary["mapped_alerts"] == 1
    assert summary["unmapped_alerts"] == 1
    assert summary["alert_mapping_percentage"] == 50.0


def test_technique_details(setup_database):

    alert_id = insert_test_alert(
        "attack-details-001",
        tactic="Credential Access",
        technique="T1110",
    )

    sync_alert_mappings()

    details = get_technique_details("T1110")

    assert details is not None

    assert details["technique"]["technique_id"] == "T1110"

    assert len(details["alerts"]) == 1

    assert details["alerts"][0]["id"] == alert_id


def test_missing_technique_details(setup_database):

    assert get_technique_details("T1110") is None
