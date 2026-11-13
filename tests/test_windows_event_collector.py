
import json
import sqlite3

import pytest

import database.db as db_module

from collectors.windows_event_collector import (
    parse_windows_event,
    store_event,
    collect_windows_events,
    load_state,
    query_windows_event_log,
)


SAMPLE_XML = """<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4625</EventID>
        <Version>0</Version>
        <Level>0</Level>
        <Task>12544</Task>
        <TimeCreated SystemTime="2026-11-10T09:30:00.000Z"/>
        <EventRecordID>1001</EventRecordID>
        <Channel>Security</Channel>
        <Computer>TEST-PC</Computer>
        <Security UserID="S-1-5-18"/>
    </System>
    <EventData>
        <Data Name="TargetUserName">testuser</Data>
        <Data Name="IpAddress">192.0.2.10</Data>
        <Data Name="ProcessId">1234</Data>
        <Data Name="WorkstationName">TEST-WORKSTATION</Data>
    </EventData>
</Event>
"""


@pytest.fixture
def temporary_database(tmp_path, monkeypatch):
    database_path = tmp_path / "test_tracesoc.db"

    monkeypatch.setattr(
        db_module,
        "DATABASE_PATH",
        database_path,
    )

    db_module.create_tables()

    return database_path


def test_parse_windows_event():
    event = parse_windows_event(SAMPLE_XML)

    assert event["event_id"] == "4625"
    assert event["record_id"] == "1001"
    assert event["provider"] == "Microsoft-Windows-Security-Auditing"
    assert event["channel"] == "Security"
    assert event["hostname"] == "TEST-PC"
    assert event["username"] == "testuser"
    assert event["source_ip"] == "192.0.2.10"
    assert event["process_id"] == "1234"
    assert event["event_type"] == "AUTHENTICATION"


def test_invalid_xml_is_rejected():
    with pytest.raises(Exception):
        parse_windows_event("<Invalid>")


def test_store_event_and_preserve_raw_xml(temporary_database):
    inserted = store_event("Security", SAMPLE_XML)

    assert inserted is True

    connection = sqlite3.connect(temporary_database)

    raw_count = connection.execute(
        "SELECT COUNT(*) FROM raw_events"
    ).fetchone()[0]

    normalized_count = connection.execute(
        "SELECT COUNT(*) FROM normalized_events"
    ).fetchone()[0]

    raw_xml = connection.execute(
        "SELECT raw_xml FROM raw_events"
    ).fetchone()[0]

    connection.close()

    assert raw_count == 1
    assert normalized_count == 1
    assert b"EventRecordID" in raw_xml


def test_duplicate_event_is_not_inserted_again(temporary_database):
    first = store_event("Security", SAMPLE_XML)
    second = store_event("Security", SAMPLE_XML)

    assert first is True
    assert second is False

    connection = sqlite3.connect(temporary_database)

    count = connection.execute(
        "SELECT COUNT(*) FROM raw_events"
    ).fetchone()[0]

    connection.close()

    assert count == 1


def test_incremental_collection_updates_state(temporary_database, tmp_path):
    state_file = tmp_path / "collector_state.json"

    def fake_query(channel, last_record_id, max_events):
        assert channel == "Security"
        assert last_record_id == 0
        assert max_events == 10

        return [
            {
                "RecordId": 1001,
                "Xml": SAMPLE_XML,
            }
        ]

    summary = collect_windows_events(
        channels=["Security"],
        max_events=10,
        state_file=state_file,
        query_function=fake_query,
    )

    state = load_state(state_file)

    assert summary["total_received"] == 1
    assert summary["total_inserted"] == 1
    assert state["Security"] == 1001


def test_second_collection_uses_saved_record_id(
    temporary_database,
    tmp_path,
):
    state_file = tmp_path / "collector_state.json"

    def first_query(channel, last_record_id, max_events):
        return [{"RecordId": 1001, "Xml": SAMPLE_XML}]

    collect_windows_events(
        channels=["Security"],
        state_file=state_file,
        query_function=first_query,
    )

    observed_ids = []

    def second_query(channel, last_record_id, max_events):
        observed_ids.append(last_record_id)
        return []

    collect_windows_events(
        channels=["Security"],
        state_file=state_file,
        query_function=second_query,
    )

    assert observed_ids == [1001]


def test_failed_event_does_not_advance_state(
    temporary_database,
    tmp_path,
):
    state_file = tmp_path / "collector_state.json"

    def fake_query(channel, last_record_id, max_events):
        return [{"RecordId": 1002, "Xml": "<Invalid>"}]

    with pytest.raises(Exception):
        collect_windows_events(
            channels=["Security"],
            state_file=state_file,
            query_function=fake_query,
        )

    state = load_state(state_file)

    assert state.get("Security", 0) == 0


def test_no_events_found_returns_empty_list(monkeypatch):
    """
    Get-WinEvent exits with code 1 and prints 'No events were found'
    when the query matches nothing.  The collector should treat this
    as an empty result, not a hard failure.
    """
    import types

    fake_result = types.SimpleNamespace(
        returncode=1,
        stdout="",
        stderr=(
            "No events were found that match the specified "
            "selection criteria."
        ),
    )

    def fake_runner(command, **kwargs):
        return fake_result

    records = query_windows_event_log(
        channel="System",
        last_record_id=0,
        max_events=10,
        runner=fake_runner,
    )

    assert records == []


def test_real_error_still_raises(monkeypatch):
    """
    A genuine PowerShell error (access denied, channel not found, etc.)
    should still raise RuntimeError so callers know the collection
    actually failed.
    """
    import types

    fake_result = types.SimpleNamespace(
        returncode=1,
        stdout="",
        stderr="Attempted to perform an unauthorized operation.",
    )

    def fake_runner(command, **kwargs):
        return fake_result

    with pytest.raises(RuntimeError, match="Could not collect channel"):
        query_windows_event_log(
            channel="Security",
            last_record_id=0,
            max_events=10,
            runner=fake_runner,
        )
