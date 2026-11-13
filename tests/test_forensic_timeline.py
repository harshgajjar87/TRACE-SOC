"""Day 24 tests — Forensic Timeline Engine."""

import pytest
from forensics.engine import create_forensics_schema, add_artifact
from forensics.timeline import build_forensic_timeline, get_timeline_summary


@pytest.fixture(autouse=True)
def setup_schema(test_db):
    create_forensics_schema()


def test_build_timeline_returns_list(test_db):
    result = build_forensic_timeline()
    assert isinstance(result, list)


def test_build_timeline_includes_artifacts(test_db):
    add_artifact(
        artifact_type="MEMORY_DUMP",
        name="Memory snapshot for host A",
        analyst="analyst1",
        hostname="HOST-A",
    )
    result = build_forensic_timeline(include_artifacts=True, include_telemetry=False, include_alerts=False)
    # At minimum our artifact should appear
    artifact_entries = [e for e in result if e["source"] == "forensic_artifact"]
    assert len(artifact_entries) >= 1


def test_build_timeline_artifacts_have_required_fields(test_db):
    add_artifact(
        artifact_type="LOG_ARCHIVE",
        name="Security logs",
        analyst="a1",
        hostname="HOST-B",
    )
    result = build_forensic_timeline(include_artifacts=True, include_telemetry=False, include_alerts=False)
    for entry in result:
        assert "timestamp_utc" in entry
        assert "source" in entry
        assert "description" in entry


def test_build_timeline_hostname_filter(test_db):
    add_artifact(artifact_type="TRIAGE_PACKAGE", name="Triage HOST-C", analyst="a1", hostname="HOST-C")
    add_artifact(artifact_type="TRIAGE_PACKAGE", name="Triage OTHER", analyst="a1", hostname="DIFFERENT-HOST")

    result = build_forensic_timeline(
        hostname="HOST-C",
        include_artifacts=True,
        include_telemetry=False,
        include_alerts=False,
    )
    for entry in result:
        h = str(entry.get("hostname") or "")
        assert "HOST-C" in h


def test_build_timeline_excludes_sources(test_db):
    result = build_forensic_timeline(
        include_telemetry=False,
        include_artifacts=False,
        include_alerts=False,
    )
    assert result == []


def test_build_timeline_sorted_ascending(test_db):
    add_artifact(artifact_type="DISK_IMAGE", name="Late artifact", analyst="a1",
                 hostname="H1")
    add_artifact(artifact_type="MEMORY_DUMP", name="Early artifact", analyst="a1",
                 hostname="H1")

    result = build_forensic_timeline(
        include_artifacts=True,
        include_telemetry=False,
        include_alerts=False,
    )
    timestamps = [e["timestamp_utc"] for e in result if e.get("timestamp_utc")]
    assert timestamps == sorted(timestamps)


def test_get_timeline_summary_empty():
    summary = get_timeline_summary([])
    assert summary["total_entries"] == 0
    assert summary["by_source"] == {}
    assert summary["earliest"] is None
    assert summary["latest"] is None


def test_get_timeline_summary_counts(test_db):
    add_artifact(artifact_type="FILE_SAMPLE", name="S1", analyst="a1", hostname="H1")
    add_artifact(artifact_type="FILE_SAMPLE", name="S2", analyst="a1", hostname="H2")

    timeline = build_forensic_timeline(
        include_artifacts=True,
        include_telemetry=False,
        include_alerts=False,
    )
    summary = get_timeline_summary(timeline)
    assert summary["total_entries"] == len(timeline)
    assert "forensic_artifact" in summary["by_source"]


def test_get_timeline_summary_unique_hosts(test_db):
    add_artifact(artifact_type="MEMORY_DUMP", name="M1", analyst="a1", hostname="ALPHA")
    add_artifact(artifact_type="MEMORY_DUMP", name="M2", analyst="a1", hostname="BETA")

    timeline = build_forensic_timeline(
        include_artifacts=True,
        include_telemetry=False,
        include_alerts=False,
    )
    summary = get_timeline_summary(timeline)
    assert "ALPHA" in summary["unique_hosts"]
    assert "BETA" in summary["unique_hosts"]


def test_max_entries_cap(test_db):
    for i in range(5):
        add_artifact(artifact_type="FILE_SAMPLE", name=f"Sample {i}", analyst="a1")

    result = build_forensic_timeline(
        include_artifacts=True,
        include_telemetry=False,
        include_alerts=False,
        max_entries=3,
    )
    assert len(result) <= 3
