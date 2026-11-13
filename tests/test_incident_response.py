"""Tests for TRACE-SOC incident response playbooks."""

import json
import pytest

from database import db
from database.db import create_tables
from response.engine import (
    create_response_schema,
    get_available_alerts,
    get_response_runs,
    get_run_details,
    create_playbook_run,
    verify_response_evidence,
)
from response.playbooks import get_playbooks, get_playbook


@pytest.fixture
def setup_database(tmp_path, monkeypatch):

    test_db = tmp_path / "test_response.db"

    monkeypatch.setattr(
        db,
        "DATABASE_PATH",
        test_db,
    )

    create_tables()
    create_response_schema()

    return test_db


def insert_test_alert():

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
            "test-response-alert-001",
            "TS001",
            "Multiple Failed Logins",
            "Test authentication alert",
            "HIGH",
            "NEW",
            "TEST-PC",
            "testuser",
            "192.168.1.10",
            "2026-11-10T10:00:00+00:00",
            "2026-11-10T10:05:00+00:00",
            5,
            "Credential Access",
            "T1110",
            json.dumps({"normalized_event_ids": []}),
            "2026-11-10T10:05:00+00:00",
        ))

        conn.commit()

        return cursor.lastrowid

    finally:

        conn.close()


def test_playbooks_are_available(setup_database):

    playbooks = get_playbooks()

    assert len(playbooks) >= 4
    assert "general_alert_triage" in playbooks
    assert "authentication_response" in playbooks
    assert "suspicious_execution_response" in playbooks
    assert "network_ioc_response" in playbooks


def test_get_playbook():

    playbook = get_playbook("general_alert_triage")

    assert playbook is not None
    assert playbook["name"] == "General Alert Triage"


def test_invalid_playbook():

    assert get_playbook("invalid_playbook") is None


def test_available_alerts(setup_database):

    insert_test_alert()

    alerts = get_available_alerts()

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "TS001"


def test_playbook_requires_analyst_name(setup_database):

    alert_id = insert_test_alert()

    with pytest.raises(ValueError):

        create_playbook_run(
            alert_id=alert_id,
            playbook_id="general_alert_triage",
            approved_by="",
        )


def test_playbook_rejects_invalid_id(setup_database):

    alert_id = insert_test_alert()

    with pytest.raises(ValueError):

        create_playbook_run(
            alert_id=alert_id,
            playbook_id="invalid_playbook",
            approved_by="Test Analyst",
        )


def test_playbook_rejects_missing_alert(setup_database):

    with pytest.raises(ValueError):

        create_playbook_run(
            alert_id=99999,
            playbook_id="general_alert_triage",
            approved_by="Test Analyst",
        )


def test_successful_playbook_execution(setup_database):

    alert_id = insert_test_alert()

    run_id = create_playbook_run(
        alert_id=alert_id,
        playbook_id="general_alert_triage",
        approved_by="Test Analyst",
        approval_note="Approved for testing",
    )

    assert run_id > 0

    details = get_run_details(run_id)

    assert details is not None

    assert details["run"]["status"] == "COMPLETED"

    assert details["run"]["approved_by"] == "Test Analyst"

    assert len(details["steps"]) == 5

    assert all(
        step["status"] == "COMPLETED"
        for step in details["steps"]
    )


def test_execution_history(setup_database):

    alert_id = insert_test_alert()

    create_playbook_run(
        alert_id=alert_id,
        playbook_id="authentication_response",
        approved_by="Test Analyst",
    )

    history = get_response_runs()

    assert len(history) == 1

    assert (
        history[0]["playbook_id"]
        == "authentication_response"
    )


def test_run_details_include_approval_note(setup_database):

    alert_id = insert_test_alert()

    run_id = create_playbook_run(
        alert_id=alert_id,
        playbook_id="network_ioc_response",
        approved_by="SOC Analyst",
        approval_note="Network alert reviewed",
    )

    details = get_run_details(run_id)

    assert details["run"]["approval_note"] == "Network alert reviewed"


def test_evidence_verification_with_no_evidence(setup_database):

    alert_id = insert_test_alert()

    run_id = create_playbook_run(
        alert_id=alert_id,
        playbook_id="general_alert_triage",
        approved_by="Test Analyst",
    )

    results = verify_response_evidence(run_id)

    assert results == []