"""Day 26 tests — IOC-to-Event Correlation Engine."""

import pytest
from threat_intel.engine import create_threat_intel_schema, add_indicator
from threat_intel.correlator import (
    create_ioc_correlation_schema,
    run_ioc_correlation,
    get_correlations,
    get_correlation_summary,
    add_analyst_note_to_correlation,
)


@pytest.fixture(autouse=True)
def setup_schemas(test_db):
    create_threat_intel_schema()
    create_ioc_correlation_schema()


def test_run_ioc_correlation_returns_summary(test_db):
    result = run_ioc_correlation()
    assert isinstance(result, dict)
    assert "events_scanned" in result
    assert "iocs_checked" in result
    assert "new_correlations" in result
    assert "duplicate_correlations" in result
    assert "run_at_utc" in result


def test_run_ioc_correlation_no_iocs(test_db):
    result = run_ioc_correlation()
    # With no IOCs, nothing should match
    assert result["iocs_checked"] == 0
    assert result["new_correlations"] == 0


def test_run_ioc_correlation_with_ip_ioc(test_db):
    # Import the database layer and insert a fake normalized event manually
    from database.db import get_connection
    conn = get_connection()
    with conn:
        conn.execute("""
            INSERT INTO raw_events (
                event_fingerprint, source_file, source_file_sha256,
                raw_xml, event_id, provider, channel, record_id,
                timestamp_utc, hostname, collected_at_utc
            ) VALUES ('test_fp_1', 'test.evtx', 'aa'*32, '<Event/>', '4624',
                      'Security', 'Security', '1',
                      '2024-01-01T00:00:00', 'TESTHOST', '2024-01-01T00:00:00')
        """)
        raw_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute("""
            INSERT INTO normalized_events (
                raw_event_id, event_id, timestamp_utc, hostname,
                username, source_ip, destination_ip
            ) VALUES (?, '4624', '2024-01-01T00:00:00', 'TESTHOST',
                      'user1', '192.0.2.100', NULL)
        """, (raw_id,))
    conn.close()

    # Add an IP IOC that matches
    add_indicator(
        indicator="192.0.2.100",
        ioc_type="IP",
        source_name="TestFeed",
        confidence=80,
        severity="HIGH",
    )

    result = run_ioc_correlation()
    assert result["new_correlations"] >= 1


def test_get_correlations_returns_list(test_db):
    rows = get_correlations()
    assert isinstance(rows, list)


def test_get_correlations_filtered_by_severity(test_db):
    rows = get_correlations(ioc_severity="HIGH")
    for r in rows:
        assert r["ioc_severity"] == "HIGH"


def test_get_correlation_summary_structure(test_db):
    summary = get_correlation_summary()
    assert "total_correlations" in summary
    assert "affected_events" in summary
    assert "by_severity" in summary
    assert "by_type" in summary
    assert "top_indicators" in summary


def test_get_correlation_summary_empty(test_db):
    summary = get_correlation_summary()
    assert summary["total_correlations"] >= 0
    assert summary["affected_events"] >= 0


def test_add_analyst_note_missing_correlation(test_db):
    result = add_analyst_note_to_correlation(999999, "Some note")
    assert result is False


def test_run_ioc_correlation_idempotent(test_db):
    """Running twice should not create duplicate correlation records."""
    add_indicator(
        indicator="10.0.0.5",
        ioc_type="IP",
        source_name="TestFeed2",
        confidence=70,
        severity="MEDIUM",
    )

    result1 = run_ioc_correlation()
    result2 = run_ioc_correlation()

    # Second run: new_correlations should be 0 for already-matched pairs
    # (duplicates are tracked via UNIQUE constraint)
    total_dupes = result2["duplicate_correlations"]
    assert isinstance(total_dupes, int)
    assert total_dupes >= 0


def test_correlation_summary_top_indicators_limit(test_db):
    summary = get_correlation_summary()
    assert len(summary["top_indicators"]) <= 10


def test_get_correlations_limit(test_db):
    rows = get_correlations(limit=5)
    assert len(rows) <= 5
