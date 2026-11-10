
import pytest

from pydantic import ValidationError

from normalizer.models import NormalizedEvent
from normalizer.event_schema import (
    convert_pid,
    classify_event,
    create_normalized_event
)


def test_hexadecimal_pid():

    assert convert_pid("0x1234") == 4660


def test_decimal_pid():

    assert convert_pid("4660") == 4660


def test_missing_pid():

    assert convert_pid(None) is None


def test_event_classification():

    assert classify_event("4625") == "authentication_failure"

    assert classify_event("1") == "process_creation"


def test_timestamp_normalization():

    event = NormalizedEvent(
        event_id="4624",
        timestamp_utc="2026-11-07T10:30:00+05:30"
    )

    assert event.timestamp_utc == "2026-11-07T05:00:00Z"


def test_invalid_ip():

    with pytest.raises(ValidationError):

        NormalizedEvent(
            event_id="3",
            source_ip="not-an-ip"
        )


def test_event_mapping():

    system_info = {

        "event_id": "1",

        "provider": "Microsoft-Windows-Sysmon",

        "channel": "Microsoft-Windows-Sysmon/Operational",

        "hostname": "TEST-PC",

        "timestamp": "2026-11-07T10:00:00Z",

        "record_id": "100"

    }

    event_data = {

        "User": "student",

        "ProcessId": "0x1234",

        "ParentProcessId": "0x1000",

        "Image": "C:\\Windows\\System32\\notepad.exe",

        "CommandLine": "notepad.exe"

    }

    result = create_normalized_event(
        system_info,
        event_data
    )

    assert result["event_type"] == "process_creation"

    assert result["username"] == "student"

    assert result["process_id"] == 4660

    assert result["parent_process_id"] == 4096

    assert result["hostname"] == "TEST-PC"


def test_missing_username():

    event = NormalizedEvent(
        event_id="22",
        event_type="dns_query"
    )

    assert event.username is None


if __name__ == "__main__":

    pytest.main([__file__, "-v"])
