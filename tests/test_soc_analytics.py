
"""Tests for TRACE-SOC SOC analytics."""

import json

import pytest

from datetime import datetime, timedelta, timezone

from database import db
from database.db import create_tables

from cases.engine import create_case_schema, create_case, update_case

from analytics.engine import (
    get_soc_kpis,
    get_alert_trend,
    get_severity_distribution,
    get_case_status_distribution,
    get_analyst_workload,
    get_mttd_mttr_trend,
    format_duration,
)


@pytest.fixture
def setup_database(tmp_path, monkeypatch):

    test_db = tmp_path / "test_analytics.db"

    monkeypatch.setattr(
        db,
        "DATABASE_PATH",
        test_db,
    )

    create_tables()
    create_case_schema()

    return test_db


def insert_test_alert(
    severity="HIGH",
    status="NEW",
):

    now = datetime.now(timezone.utc)

    first_seen = now - timedelta(seconds=120)

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
            f"analytics-test-{severity}-{status}-{now.timestamp()}",
            "TS001",
            "Test Security Alert",
            "Analytics testing alert",
            severity,
            status,
            "TEST-PC",
            "testuser",
            "192.168.1.10",
            first_seen.isoformat(),
            now.isoformat(),
            5,
            "Credential Access",
            "T1110",
            json.dumps({"normalized_event_ids": []}),
            now.isoformat(),
        ))

        conn.commit()

        return cursor.lastrowid

    finally:

        conn.close()


def test_soc_kpis(setup_database):

    insert_test_alert("CRITICAL", "NEW")
    insert_test_alert("HIGH", "RESOLVED")

    kpis = get_soc_kpis()

    assert kpis["total_alerts"] == 2
    assert kpis["open_alerts"] == 1
    assert kpis["critical_alerts"] == 1
    assert kpis["mttd_sample_count"] == 2


def test_alert_trend(setup_database):

    insert_test_alert()

    trend = get_alert_trend(7)

    assert len(trend) == 7

    assert sum(
        item["alert_count"] for item in trend
    ) == 1


def test_severity_distribution(setup_database):

    insert_test_alert("CRITICAL")
    insert_test_alert("HIGH")
    insert_test_alert("HIGH")

    distribution = get_severity_distribution()

    counts = {
        item["severity"]: item["count"]
        for item in distribution
    }

    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 2


def test_case_status_distribution(setup_database):

    create_case(
        title="Open Test Case",
        description="Open case.",
        priority="HIGH",
        created_by="Analyst A",
    )

    case_id = create_case(
        title="Resolved Test Case",
        description="Resolved case.",
        priority="MEDIUM",
        created_by="Analyst A",
    )

    update_case(
        case_id,
        performed_by="Analyst A",
        status="RESOLVED",
    )

    distribution = get_case_status_distribution()

    counts = {
        item["status"]: item["count"]
        for item in distribution
    }

    assert counts["OPEN"] == 1
    assert counts["RESOLVED"] == 1


def test_analyst_workload(setup_database):

    create_case(
        title="Analyst A Case",
        description="Test.",
        priority="HIGH",
        created_by="SOC Analyst",
        assigned_to="Analyst A",
    )

    create_case(
        title="Analyst B Case",
        description="Test.",
        priority="MEDIUM",
        created_by="SOC Analyst",
        assigned_to="Analyst B",
    )

    workload = get_analyst_workload()

    assert len(workload) == 2

    analysts = {
        item["analyst"]
        for item in workload
    }

    assert "Analyst A" in analysts
    assert "Analyst B" in analysts


def test_mttd_calculation(setup_database):

    insert_test_alert()

    kpis = get_soc_kpis()

    assert kpis["mttd_seconds"] is not None
    assert 100 <= kpis["mttd_seconds"] <= 140


def test_mttr_calculation(setup_database):

    case_id = create_case(
        title="MTTR Test Case",
        description="Testing resolution duration.",
        priority="HIGH",
        created_by="Analyst A",
    )

    update_case(
        case_id,
        performed_by="Analyst A",
        status="RESOLVED",
    )

    kpis = get_soc_kpis()

    assert kpis["mttr_seconds"] is not None
    assert kpis["mttr_seconds"] >= 0
    assert kpis["mttr_sample_count"] == 1


def test_format_duration():

    assert format_duration(30) == "30s"
    assert format_duration(90) == "1m 30s"
    assert format_duration(3600) == "1h 0m"
    assert format_duration(None) == "N/A"


def test_empty_analytics_database(setup_database):

    kpis = get_soc_kpis()

    assert kpis["total_alerts"] == 0
    assert kpis["total_cases"] == 0
    assert kpis["mttd_seconds"] is None
    assert kpis["mttr_seconds"] is None


def test_case_assignment_workload(setup_database):

    create_case(
        title="Unassigned Case",
        description="Test.",
        priority="LOW",
        created_by="SOC Analyst",
    )

    workload = get_analyst_workload()

    assert len(workload) == 1
    assert workload[0]["analyst"] == "Unassigned"
    assert workload[0]["assigned_cases"] == 1


def test_mttd_mttr_trend(setup_database):

    insert_test_alert()

    trend = get_mttd_mttr_trend(7)

    assert len(trend) == 7

    assert any(
        item["mttd_samples"] > 0
        for item in trend
    )
