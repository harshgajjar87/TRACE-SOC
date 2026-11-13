"""Day 28 tests — System Health and Database Optimizer."""

import pytest
from database.optimizer import (
    get_database_file_metrics,
    get_table_row_counts,
    get_index_list,
    get_system_health,
    run_analyze,
    run_integrity_check,
    run_foreign_key_check,
)


def test_get_database_file_metrics_structure(test_db):
    metrics = get_database_file_metrics()
    assert isinstance(metrics, dict)
    assert "exists" in metrics
    assert "size_bytes" in metrics
    assert "size_mb" in metrics


def test_get_database_file_metrics_exists(test_db):
    metrics = get_database_file_metrics()
    assert metrics["exists"] is True
    assert metrics["size_bytes"] > 0
    assert metrics["size_mb"] >= 0


def test_get_database_file_metrics_page_info(test_db):
    metrics = get_database_file_metrics()
    assert "page_size_bytes" in metrics
    assert "page_count" in metrics
    assert "freelist_pages" in metrics
    assert "fragmentation_pct" in metrics
    assert metrics["page_count"] > 0
    assert metrics["page_size_bytes"] in (1024, 2048, 4096, 8192, 16384, 32768, 65536)


def test_get_table_row_counts_returns_list(test_db):
    counts = get_table_row_counts()
    assert isinstance(counts, list)
    assert len(counts) > 0


def test_get_table_row_counts_sorted(test_db):
    counts = get_table_row_counts()
    for c in counts:
        assert "table" in c
        assert "row_count" in c


def test_get_table_row_counts_core_tables_present(test_db):
    counts = get_table_row_counts()
    table_names = {c["table"] for c in counts}
    # Core tables from database/db.py must exist
    assert "raw_events" in table_names
    assert "normalized_events" in table_names
    assert "alerts" in table_names


def test_get_index_list_returns_list(test_db):
    indexes = get_index_list()
    assert isinstance(indexes, list)


def test_get_index_list_fields(test_db):
    indexes = get_index_list()
    for idx in indexes:
        assert "name" in idx
        assert "table_name" in idx


def test_run_analyze_returns_dict(test_db):
    result = run_analyze()
    assert isinstance(result, dict)
    assert result["operation"] == "ANALYZE"
    assert result["status"] == "OK"
    assert "elapsed_seconds" in result
    assert result["elapsed_seconds"] >= 0


def test_run_integrity_check_ok(test_db):
    result = run_integrity_check()
    assert result["operation"] == "INTEGRITY_CHECK"
    assert result["status"] == "OK"
    assert "ok" in result["results"]


def test_run_foreign_key_check_ok(test_db):
    result = run_foreign_key_check()
    assert result["operation"] == "FOREIGN_KEY_CHECK"
    assert result["status"] in ("OK", "VIOLATIONS_FOUND")
    assert "violation_count" in result


def test_get_system_health_structure(test_db):
    health = get_system_health()
    assert "status" in health
    assert "checked_at_utc" in health
    assert "components" in health
    assert "database" in health
    assert "core_table_counts" in health


def test_get_system_health_status_values(test_db):
    health = get_system_health()
    assert health["status"] in ("HEALTHY", "DEGRADED", "CRITICAL")


def test_get_system_health_components_list(test_db):
    health = get_system_health()
    components = health["components"]
    assert isinstance(components, list)
    assert len(components) > 0
    for c in components:
        assert "component" in c
        assert "status" in c


def test_get_system_health_core_counts_dict(test_db):
    health = get_system_health()
    counts = health["core_table_counts"]
    assert isinstance(counts, dict)
    assert "raw_events" in counts
    assert "normalized_events" in counts


def test_get_system_health_detection_rules_component(test_db):
    health = get_system_health()
    rule_component = next(
        (c for c in health["components"] if c["component"] == "detection_rules"),
        None,
    )
    assert rule_component is not None
    assert rule_component["status"] == "OK"


def test_fragmentation_pct_non_negative(test_db):
    metrics = get_database_file_metrics()
    assert metrics["fragmentation_pct"] >= 0.0
    assert metrics["fragmentation_pct"] <= 100.0
