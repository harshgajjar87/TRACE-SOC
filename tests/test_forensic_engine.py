"""Day 23 tests — Forensic Artifact Engine."""

import pytest
from forensics.engine import (
    create_forensics_schema,
    add_artifact,
    get_artifact,
    list_artifacts,
    update_artifact_status,
    add_artifact_note,
    get_artifacts_by_story,
    get_artifact_summary,
    ARTIFACT_TYPES,
    ARTIFACT_STATUSES,
)


@pytest.fixture(autouse=True)
def setup_schema(test_db):
    create_forensics_schema()


def test_add_artifact_returns_id(test_db):
    aid = add_artifact(
        artifact_type="MEMORY_DUMP",
        name="TestHost memory dump",
        analyst="analyst1",
        hostname="TestHost",
    )
    assert isinstance(aid, int)
    assert aid > 0


def test_get_artifact_full(test_db):
    aid = add_artifact(
        artifact_type="DISK_IMAGE",
        name="Disk image C",
        analyst="analyst2",
        hostname="WORKSTATION01",
        sha256="a" * 64,
        description="Full disk image",
        tags=["incident", "primary"],
        story_id=None,
    )
    art = get_artifact(aid)
    assert art is not None
    assert art["name"] == "Disk image C"
    assert art["artifact_type"] == "DISK_IMAGE"
    assert art["analyst"] == "analyst2"
    assert art["sha256"] == "a" * 64
    assert "incident" in art["tags"]
    assert art["notes"] == []


def test_list_artifacts_filter_by_type(test_db):
    add_artifact(artifact_type="LOG_ARCHIVE", name="Logs", analyst="a1")
    add_artifact(artifact_type="MEMORY_DUMP", name="Mem", analyst="a2")

    logs = list_artifacts(artifact_type="LOG_ARCHIVE")
    assert all(r["artifact_type"] == "LOG_ARCHIVE" for r in logs)

    mems = list_artifacts(artifact_type="MEMORY_DUMP")
    assert any(r["artifact_type"] == "MEMORY_DUMP" for r in mems)


def test_list_artifacts_filter_by_hostname(test_db):
    add_artifact(artifact_type="FILE_SAMPLE", name="Sample", analyst="a1", hostname="TARGET-HOST")
    add_artifact(artifact_type="FILE_SAMPLE", name="Other", analyst="a1", hostname="OTHER-HOST")

    results = list_artifacts(hostname="TARGET")
    assert all("TARGET" in str(r.get("hostname") or "") for r in results)


def test_update_artifact_status(test_db):
    aid = add_artifact(artifact_type="TRIAGE_PACKAGE", name="Triage", analyst="a1")
    ok = update_artifact_status(aid, "VERIFIED", "a2")
    assert ok is True

    art = get_artifact(aid)
    assert art["status"] == "VERIFIED"


def test_add_note_to_artifact(test_db):
    aid = add_artifact(artifact_type="FILE_SAMPLE", name="Sample", analyst="a1")
    note_id = add_artifact_note(aid, "analyst_a", "Initial collection complete.")
    assert isinstance(note_id, int)

    art = get_artifact(aid)
    assert len(art["notes"]) == 1
    assert art["notes"][0]["note"] == "Initial collection complete."


def test_multiple_notes_ordered(test_db):
    aid = add_artifact(artifact_type="MEMORY_DUMP", name="Mem", analyst="a1")
    add_artifact_note(aid, "a1", "First note")
    add_artifact_note(aid, "a2", "Second note")

    art = get_artifact(aid)
    assert len(art["notes"]) == 2
    assert art["notes"][0]["note"] == "First note"
    assert art["notes"][1]["note"] == "Second note"


def test_get_artifact_returns_none_for_missing(test_db):
    art = get_artifact(999999)
    assert art is None


def test_invalid_artifact_type_raises(test_db):
    with pytest.raises(ValueError, match="Unsupported artifact type"):
        add_artifact(artifact_type="INVALID", name="Test", analyst="a1")


def test_missing_analyst_raises(test_db):
    with pytest.raises(ValueError, match="Analyst identity is required"):
        add_artifact(artifact_type="MEMORY_DUMP", name="Test", analyst="")


def test_invalid_sha256_raises(test_db):
    with pytest.raises(ValueError, match="sha256"):
        add_artifact(
            artifact_type="DISK_IMAGE",
            name="Test",
            analyst="a1",
            sha256="not_a_valid_hash",
        )


def test_get_artifact_summary_empty(test_db):
    summary = get_artifact_summary()
    assert isinstance(summary, dict)
    assert summary["total"] >= 0


def test_get_artifact_summary_counts(test_db):
    add_artifact(artifact_type="MEMORY_DUMP", name="M1", analyst="a1")
    add_artifact(artifact_type="MEMORY_DUMP", name="M2", analyst="a1")
    add_artifact(artifact_type="DISK_IMAGE", name="D1", analyst="a1")

    summary = get_artifact_summary()
    type_names = [t["artifact_type"] for t in summary["by_type"]]
    assert "MEMORY_DUMP" in type_names


def test_get_artifacts_by_story(test_db):
    add_artifact(artifact_type="LOG_ARCHIVE", name="Log story 1", analyst="a1", story_id=42)
    add_artifact(artifact_type="LOG_ARCHIVE", name="Log story 2", analyst="a1", story_id=42)
    add_artifact(artifact_type="LOG_ARCHIVE", name="Other story", analyst="a1", story_id=99)

    results = get_artifacts_by_story(42)
    assert len(results) >= 2
    assert all(r["story_id"] == 42 for r in results)


def test_add_note_missing_note_raises(test_db):
    aid = add_artifact(artifact_type="FILE_SAMPLE", name="S", analyst="a")
    with pytest.raises(ValueError, match="Note text is required"):
        add_artifact_note(aid, "a1", "")


def test_add_note_missing_artifact_raises(test_db):
    with pytest.raises(ValueError, match="Artifact 999 not found"):
        add_artifact_note(999, "a1", "Some note")
