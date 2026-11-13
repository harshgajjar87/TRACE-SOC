
"""Tests for TRACE-SOC incident case management."""

import json
import pytest

from database import db
from database.db import create_tables

from cases.engine import (
    create_case_schema,
    create_case,
    get_cases,
    get_case_details,
    add_alert_to_case,
    add_case_note,
    update_case,
    get_case_summary,
)


@pytest.fixture
def setup_database(tmp_path, monkeypatch):

    test_db = tmp_path / "test_cases.db"

    monkeypatch.setattr(
        db,
        "DATABASE_PATH",
        test_db,
    )

    create_tables()
    create_case_schema()

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
            "case-test-alert-001",
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


def test_create_case(setup_database):

    case_id = create_case(
        title="Suspicious Login Investigation",
        description="Investigate repeated failed login attempts.",
        priority="HIGH",
        created_by="Test Analyst",
    )

    details = get_case_details(case_id)

    assert details is not None
    assert details["case"]["title"] == "Suspicious Login Investigation"
    assert details["case"]["status"] == "OPEN"
    assert details["case"]["priority"] == "HIGH"
    assert details["case"]["case_number"] == "TRACE-CASE-00001"


def test_create_case_with_alert(setup_database):

    alert_id = insert_test_alert()

    case_id = create_case(
        title="Authentication Incident",
        description="Investigate login activity.",
        priority="HIGH",
        created_by="Test Analyst",
        alert_ids=[alert_id],
    )

    details = get_case_details(case_id)

    assert len(details["alerts"]) == 1
    assert details["alerts"][0]["id"] == alert_id


def test_create_case_with_assignment(setup_database):

    case_id = create_case(
        title="Assigned Incident",
        description="Test assignment.",
        priority="MEDIUM",
        created_by="Test Analyst",
        assigned_to="Analyst A",
    )

    details = get_case_details(case_id)

    assert details["case"]["assigned_to"] == "Analyst A"


def test_reject_empty_title(setup_database):

    with pytest.raises(ValueError):

        create_case(
            title="",
            description="Test",
            priority="HIGH",
            created_by="Test Analyst",
        )


def test_reject_invalid_priority(setup_database):

    with pytest.raises(ValueError):

        create_case(
            title="Invalid Priority",
            description="Test",
            priority="UNKNOWN",
            created_by="Test Analyst",
        )


def test_reject_missing_alert(setup_database):

    with pytest.raises(ValueError):

        create_case(
            title="Invalid Alert Case",
            description="Test",
            priority="HIGH",
            created_by="Test Analyst",
            alert_ids=[99999],
        )


def test_add_case_note(setup_database):

    case_id = create_case(
        title="Note Test Case",
        description="Testing notes.",
        priority="LOW",
        created_by="Test Analyst",
    )

    add_case_note(
        case_id,
        "Analyst A",
        "Observed suspicious login activity.",
    )

    details = get_case_details(case_id)

    assert len(details["notes"]) == 1
    assert (
        details["notes"][0]["note"]
        == "Observed suspicious login activity."
    )


def test_add_alert_to_existing_case(setup_database):

    alert_id = insert_test_alert()

    case_id = create_case(
        title="Multiple Alert Case",
        description="Testing alert linking.",
        priority="HIGH",
        created_by="Test Analyst",
    )

    add_alert_to_case(
        case_id,
        alert_id,
        "Analyst A",
    )

    details = get_case_details(case_id)

    assert len(details["alerts"]) == 1


def test_duplicate_alert_link_rejected(setup_database):

    alert_id = insert_test_alert()

    case_id = create_case(
        title="Duplicate Test Case",
        description="Testing duplicate linking.",
        priority="MEDIUM",
        created_by="Test Analyst",
        alert_ids=[alert_id],
    )

    with pytest.raises(ValueError):

        add_alert_to_case(
            case_id,
            alert_id,
            "Analyst A",
        )


def test_update_case_status(setup_database):

    case_id = create_case(
        title="Status Test Case",
        description="Testing status.",
        priority="HIGH",
        created_by="Test Analyst",
    )

    update_case(
        case_id,
        performed_by="Analyst A",
        status="IN_PROGRESS",
    )

    details = get_case_details(case_id)

    assert details["case"]["status"] == "IN_PROGRESS"


def test_update_case_assignment(setup_database):

    case_id = create_case(
        title="Assignment Test",
        description="Testing assignment.",
        priority="MEDIUM",
        created_by="Test Analyst",
    )

    update_case(
        case_id,
        performed_by="Analyst A",
        assigned_to="Analyst B",
    )

    details = get_case_details(case_id)

    assert details["case"]["assigned_to"] == "Analyst B"


def test_case_activity_history(setup_database):

    case_id = create_case(
        title="Activity Test",
        description="Testing activity history.",
        priority="HIGH",
        created_by="Test Analyst",
    )

    add_case_note(
        case_id,
        "Analyst A",
        "Initial investigation completed.",
    )

    details = get_case_details(case_id)

    activity_types = [
        activity["activity_type"]
        for activity in details["activity"]
    ]

    assert "CASE_CREATED" in activity_types
    assert "NOTE_ADDED" in activity_types


def test_case_summary(setup_database):

    create_case(
        title="Case One",
        description="Test one.",
        priority="HIGH",
        created_by="Analyst A",
    )

    create_case(
        title="Case Two",
        description="Test two.",
        priority="MEDIUM",
        created_by="Analyst A",
    )

    summary = get_case_summary()

    assert summary["total"] == 2
    assert summary["by_status"]["OPEN"] == 2


def test_case_not_found(setup_database):

    assert get_case_details(99999) is None


def test_invalid_status_rejected(setup_database):

    case_id = create_case(
        title="Invalid Status Test",
        description="Testing validation.",
        priority="LOW",
        created_by="Test Analyst",
    )

    with pytest.raises(ValueError):

        update_case(
            case_id,
            performed_by="Analyst A",
            status="UNKNOWN",
        )
