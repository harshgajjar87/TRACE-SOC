
import json

import database.db as db

from database.db import create_tables

from threat_intel.engine import (
    create_threat_intel_schema,
    normalize_ioc,
    add_indicator,
    lookup_indicator,
    enrich_event,
    enrich_events,
    import_records,
    get_indicators,
    get_threat_intel_summary,
    expire_indicators,
)


def setup_database(tmp_path, monkeypatch):

    test_db = tmp_path / "threat_intel_test.db"

    monkeypatch.setattr(db, "DATABASE_PATH", test_db)

    create_tables()
    create_threat_intel_schema()


def test_ip_normalization():

    assert normalize_ioc(
        "198.51.100.25",
        "IP"
    ) == "198.51.100.25"


def test_domain_normalization():

    assert normalize_ioc(
        "EXAMPLE-MALWARE.TEST.",
        "DOMAIN"
    ) == "example-malware.test"


def test_invalid_sha256_rejected():

    try:
        normalize_ioc("abc123", "SHA256")
        assert False, "Expected ValueError"

    except ValueError:
        pass


def test_add_and_lookup_indicator(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    indicator_id = add_indicator(
        "198.51.100.25",
        "IP",
        "Test Feed",
        confidence=90,
        severity="HIGH"
    )

    assert indicator_id > 0

    results = lookup_indicator("198.51.100.25")

    assert len(results) == 1
    assert results[0]["confidence"] == 90


def test_multiple_sources_preserved(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    add_indicator(
        "198.51.100.25",
        "IP",
        "Feed A"
    )

    add_indicator(
        "198.51.100.25",
        "IP",
        "Feed B"
    )

    results = lookup_indicator("198.51.100.25")

    assert len(results) == 2


def test_event_ip_enrichment(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    add_indicator(
        "198.51.100.25",
        "IP",
        "Test Feed",
        confidence=90,
        severity="HIGH"
    )

    event = {
        "source_ip": "198.51.100.25",
        "destination_ip": "8.8.8.8",
        "image": None,
        "command_line": None,
        "extra_data_json": "{}"
    }

    results = enrich_event(event)

    assert len(results) == 1
    assert results[0]["matched_field"] == "source_ip"


def test_domain_enrichment(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    add_indicator(
        "example-malware.test",
        "DOMAIN",
        "Test Feed"
    )

    event = {
        "source_ip": None,
        "destination_ip": None,
        "image": None,
        "command_line": "curl https://example-malware.test/payload",
        "extra_data_json": "{}"
    }

    results = enrich_event(event)

    assert len(results) == 1


def test_hash_enrichment(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    sample_hash = "a" * 32

    add_indicator(
        sample_hash,
        "MD5",
        "Test Feed"
    )

    event = {
        "source_ip": None,
        "destination_ip": None,
        "image": None,
        "command_line": None,
        "extra_data_json": json.dumps({
            "FileHash": sample_hash
        })
    }

    results = enrich_event(event)

    assert len(results) == 1


def test_feed_import_and_summary(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    result = import_records([
        {
            "indicator": "198.51.100.25",
            "type": "IP",
            "source": "Training Feed",
            "confidence": 80,
            "severity": "HIGH"
        },
        {
            "indicator": "invalid-hash",
            "type": "SHA256",
            "source": "Training Feed"
        }
    ])

    assert result["total"] == 2
    assert result["imported"] == 1
    assert len(result["errors"]) == 1

    summary = get_threat_intel_summary()

    assert summary["active"] == 1
    assert summary["sources"] == 1


def test_duplicate_feed_record_updates_same_source(
    tmp_path,
    monkeypatch
):

    setup_database(tmp_path, monkeypatch)

    first_id = add_indicator(
        "198.51.100.25",
        "IP",
        "Training Feed",
        confidence=60
    )

    second_id = add_indicator(
        "198.51.100.25",
        "IP",
        "Training Feed",
        confidence=95
    )

    results = lookup_indicator("198.51.100.25")

    assert first_id == second_id
    assert len(results) == 1
    assert results[0]["confidence"] == 95


def test_expired_indicator_not_returned(
    tmp_path,
    monkeypatch
):

    setup_database(tmp_path, monkeypatch)

    add_indicator(
        "198.51.100.25",
        "IP",
        "Expired Feed",
        expires_at_utc="2000-01-01T00:00:00+00:00"
    )

    assert expire_indicators() == 1

    assert lookup_indicator("198.51.100.25") == []


def test_bulk_enrichment(tmp_path, monkeypatch):

    setup_database(tmp_path, monkeypatch)

    add_indicator(
        "198.51.100.25",
        "IP",
        "Test Feed"
    )

    events = [
        {
            "normalized_event_id": 1,
            "source_ip": "198.51.100.25",
            "destination_ip": None,
            "image": None,
            "command_line": None,
            "extra_data_json": "{}"
        },
        {
            "normalized_event_id": 2,
            "source_ip": "192.0.2.10",
            "destination_ip": None,
            "image": None,
            "command_line": None,
            "extra_data_json": "{}"
        }
    ]

    results = enrich_events(events)

    assert results[0]["threat_intel_match_count"] == 1
    assert results[0]["threat_intel_status"] == "KNOWN_INDICATOR_MATCH"

    assert results[1]["threat_intel_match_count"] == 0
    assert results[1]["threat_intel_status"] == "NO_MATCHING_INTELLIGENCE"
