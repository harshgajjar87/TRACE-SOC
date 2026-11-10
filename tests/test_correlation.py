
from investigation.correlation import (
    calculate_correlation,
    build_correlation_groups,
    classify_confidence
)


def make_event(
    event_id,
    timestamp,
    hostname="PC-01",
    username="alice",
    source_ip="10.0.0.5",
    process_guid=None,
    parent_process_guid=None
):

    return {

        "id": event_id,

        "event_id": "1",

        "timestamp_utc": timestamp,

        "hostname": hostname,

        "username": username,

        "source_ip": source_ip,

        "process_guid": process_guid,

        "parent_process_guid": parent_process_guid

    }


def test_same_host_and_username():

    event_a = make_event(
        1,
        "2026-11-09T10:00:00+00:00"
    )

    event_b = make_event(
        2,
        "2026-11-09T10:01:00+00:00"
    )

    result = calculate_correlation(
        event_a,
        event_b
    )

    assert result["score"] == 90
    assert "Same source IP and username" in result["reasons"]


def test_parent_child_process_relationship():

    event_a = make_event(
        1,
        "2026-11-09T10:00:00+00:00",
        process_guid="{ABC}"
    )

    event_b = make_event(
        2,
        "2026-11-09T10:01:00+00:00",
        process_guid="{XYZ}",
        parent_process_guid="{ABC}"
    )

    result = calculate_correlation(
        event_a,
        event_b
    )

    assert result["score"] == 95


def test_different_users_and_ips_do_not_correlate():

    event_a = make_event(
        1,
        "2026-11-09T10:00:00+00:00",
        username="alice",
        source_ip="10.0.0.5"
    )

    event_b = make_event(
        2,
        "2026-11-09T10:01:00+00:00",
        username="bob",
        source_ip="10.0.0.9"
    )

    result = calculate_correlation(
        event_a,
        event_b
    )

    assert result["score"] == 0


def test_events_outside_time_window_do_not_correlate():

    event_a = make_event(
        1,
        "2026-11-09T10:00:00+00:00"
    )

    event_b = make_event(
        2,
        "2026-11-09T11:00:00+00:00"
    )

    result = calculate_correlation(
        event_a,
        event_b
    )

    assert result["score"] == 0


def test_build_correlation_groups():

    events = [

        make_event(
            1,
            "2026-11-09T10:00:00+00:00"
        ),

        make_event(
            2,
            "2026-11-09T10:01:00+00:00"
        ),

        make_event(
            3,
            "2026-11-09T10:02:00+00:00"
        )

    ]

    groups = build_correlation_groups(events)

    assert len(groups) == 1

    assert groups[0]["event_count"] == 3

    assert set(groups[0]["event_ids"]) == {1, 2, 3}


def test_confidence_classification():

    assert classify_confidence(90) == "HIGH"

    assert classify_confidence(70) == "MEDIUM"

    assert classify_confidence(40) == "LOW"
