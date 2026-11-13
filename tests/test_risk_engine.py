
"""Tests for TRACE-SOC advanced risk scoring engine."""

import json

import pytest

from datetime import datetime, timedelta, timezone

from database import db
from database.db import create_tables

from threat_intel.engine import create_threat_intel_schema
from risk.engine import (
    create_risk_schema,
    classify_risk,
    calculate_alert_risk,
    assess_all_alerts,
    get_latest_risk_assessments,
    get_risk_summary,
    get_related_alerts,
)


@pytest.fixture
def setup_database(tmp_path, monkeypatch):

    test_db = tmp_path / "test_risk.db"

    monkeypatch.setattr(
        db,
        "DATABASE_PATH",
        test_db,
    )

    create_tables()
    create_threat_intel_schema()
    create_risk_schema()

    return test_db


def insert_test_alert(
    fingerprint,
    severity="HIGH",
    source_ip="192.168.1.10",
    hostname="TEST-PC",
    username="testuser",
    event_count=5,
    mitre="T1110",
):

    now = datetime.now(timezone.utc)

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
            "Test Security Alert",
            "Testing risk engine.",
            severity,
            "NEW",
            hostname,
            username,
            source_ip,
            (now - timedelta(seconds=120)).isoformat(),
            now.isoformat(),
            event_count,
            "Credential Access" if mitre else None,
            mitre,
            json.dumps({"normalized_event_ids": []}),
            now.isoformat(),
        ))

        conn.commit()

        return cursor.lastrowid

    finally:

        conn.close()


def test_risk_classification():

    assert classify_risk(90) == "CRITICAL"
    assert classify_risk(70) == "HIGH"
    assert classify_risk(45) == "MEDIUM"
    assert classify_risk(20) == "LOW"


def test_risk_score_is_capped():

    assert classify_risk(150) == "CRITICAL"
    assert classify_risk(-10) == "LOW"


def test_basic_risk_calculation(setup_database):

    alert_id = insert_test_alert(
        "risk-basic-001",
        severity="HIGH",
        event_count=5,
        mitre="T1110",
    )

    result = calculate_alert_risk(alert_id)

    # HIGH = 25, event volume = 5, MITRE = 5
    assert result["risk_score"] == 35
    assert result["risk_level"] == "MEDIUM"


def test_critical_alert_scoring(setup_database):

    alert_id = insert_test_alert(
        "risk-critical-001",
        severity="CRITICAL",
        event_count=1,
        mitre=None,
    )

    result = calculate_alert_risk(alert_id)

    assert result["risk_score"] == 35
    assert result["risk_level"] == "MEDIUM"


def test_event_volume_scoring(setup_database):

    alert_id = insert_test_alert(
        "risk-volume-001",
        severity="LOW",
        event_count=12,
        mitre=None,
    )

    result = calculate_alert_risk(alert_id)

    assert result["risk_score"] == 18


def test_mitre_mapping_scoring(setup_database):

    alert_id = insert_test_alert(
        "risk-mitre-001",
        severity="INFO",
        event_count=1,
        mitre="T1059",
    )

    result = calculate_alert_risk(alert_id)

    assert result["risk_score"] == 8


def test_ioc_match_adds_risk_points(setup_database):

    alert_id = insert_test_alert(
        "risk-ioc-001",
        severity="HIGH",
        source_ip="192.0.2.50",
        event_count=1,
        mitre=None,
    )

    conn = db.get_connection()

    
    conn = db.get_connection()

    try:

        raw_cursor = conn.execute("""
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
            "risk-test-raw-event-001",
            "risk_test.xml",
            "test-source-hash",
            b"<Event><System><EventID>3</EventID></System></Event>",
            3,
            "Microsoft-Windows-Sysmon",
            "Microsoft-Windows-Sysmon/Operational",
            "1",
            datetime.now(timezone.utc).isoformat(),
            "TEST-PC",
            datetime.now(timezone.utc).isoformat(),
        ))

        raw_event_id = raw_cursor.lastrowid

        cursor = conn.execute("""
            INSERT INTO normalized_events (
                raw_event_id,
                event_id,
                record_id,
                provider,
                channel,
                timestamp_utc,
                hostname,
                username,
                source_ip,
                destination_ip,
                event_type,
                extra_data_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            raw_event_id,
            3,
            1,
            "Microsoft-Windows-Sysmon",
            "Microsoft-Windows-Sysmon/Operational",
            datetime.now(timezone.utc).isoformat(),
            "TEST-PC",
            "testuser",
            "192.0.2.50",
            None,
            "NETWORK_CONNECTION",
            "{}",
        ))

        event_id = cursor.lastrowid

        conn.execute("""
            UPDATE alerts
            SET evidence_json = ?
            WHERE id = ?
        """, (
            json.dumps({
                "normalized_event_ids": [event_id]
            }),
            alert_id,
        ))

        conn.commit()

    finally:

        conn.close()

    from threat_intel.engine import add_indicator

    add_indicator(
        ioc_type="IP",
        indicator="192.0.2.50",
        source_name="Test Threat Feed",
        confidence=90,
        severity="HIGH",
    )

    result = calculate_alert_risk(alert_id)

    assert len(result["ioc_matches"]) == 1

    # HIGH = 25, IOC = 25
    assert result["risk_score"] == 50


def test_related_alert_detection(setup_database):

    first_id = insert_test_alert(
        "risk-related-001",
        source_ip="192.168.1.50",
    )

    second_id = insert_test_alert(
        "risk-related-002",
        source_ip="192.168.1.50",
    )

    third_id = insert_test_alert(
        "risk-related-003",
        source_ip="192.168.1.50",
    )

    related = get_related_alerts(first_id)

    related_ids = {
        item["id"]
        for item in related
    }

    assert second_id in related_ids
    assert third_id in related_ids


def test_repeated_alerts_increase_risk(setup_database):

    first_id = insert_test_alert(
        "risk-repeat-001",
        severity="HIGH",
        source_ip="192.168.1.60",
        event_count=1,
        mitre=None,
    )

    insert_test_alert(
        "risk-repeat-002",
        source_ip="192.168.1.60",
    )

    insert_test_alert(
        "risk-repeat-003",
        source_ip="192.168.1.60",
    )

    result = calculate_alert_risk(first_id)

    # HIGH = 25, repeated alerts = 15
    assert result["risk_score"] == 40


def test_assessment_is_saved(setup_database):

    alert_id = insert_test_alert("risk-save-001")

    result = calculate_alert_risk(alert_id, save=True)

    assessments = get_latest_risk_assessments()

    assert len(assessments) == 1

    assert assessments[0]["alert_id"] == alert_id

    assert (
        assessments[0]["risk_score"]
        == result["risk_score"]
    )


def test_bulk_risk_assessment(setup_database):

    insert_test_alert("risk-bulk-001")
    insert_test_alert("risk-bulk-002", severity="CRITICAL")

    results = assess_all_alerts()

    assert len(results) == 2

    assert results[0]["risk_score"] >= results[1]["risk_score"]

    assert len(get_latest_risk_assessments()) == 2


def test_risk_summary(setup_database):

    insert_test_alert("risk-summary-001")
    insert_test_alert("risk-summary-002", severity="CRITICAL")

    assess_all_alerts()

    summary = get_risk_summary()

    assert summary["total_assessed"] == 2

    assert summary["average_score"] > 0

    assert (
        summary["distribution"]["CRITICAL"]
        + summary["distribution"]["HIGH"]
        + summary["distribution"]["MEDIUM"]
        + summary["distribution"]["LOW"]
        == 2
    )


def test_unknown_alert_rejected(setup_database):

    with pytest.raises(ValueError):

        calculate_alert_risk(99999)


def test_assessment_without_saving(setup_database):

    alert_id = insert_test_alert("risk-no-save-001")

    result = calculate_alert_risk(
        alert_id,
        save=False,
    )

    assert result["risk_score"] > 0

    assert get_latest_risk_assessments() == []
