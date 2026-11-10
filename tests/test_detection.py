
from detection.rules import DETECTION_RULES

from detection.engine import (
    evaluate_threshold_rule,
    evaluate_keyword_rule,
    evaluate_single_event_rule
)


def create_test_event(
    event_id,
    event_number,
    username="student",
    source_ip="192.168.1.10",
    image=None,
    command_line=None,
    timestamp=None
):

    return {

        "id": event_number,

        "event_id": event_id,

        "username": username,

        "source_ip": source_ip,

        "hostname": "TEST-PC",

        "image": image,

        "command_line": command_line,

        "timestamp_utc": timestamp,

        "extra_data_json": "{}"

    }


def find_rule(rule_id):

    return next(
        rule for rule in DETECTION_RULES
        if rule["rule_id"] == rule_id
    )


def test_repeated_failed_logins():

    events = [

        create_test_event(
            "4625",
            i,
            timestamp=f"2026-11-09T10:00:0{i}Z"
        )

        for i in range(1, 7)

    ]

    rule = find_rule("TS001")

    alerts = evaluate_threshold_rule(
        events,
        rule
    )

    assert len(alerts) == 1

    assert alerts[0]["event_count"] == 6


def test_suspicious_powershell():

    event = create_test_event(

        "1",

        100,

        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",

        command_line="powershell.exe -EncodedCommand TEST"

    )

    rule = find_rule("TS002")

    alerts = evaluate_keyword_rule(
        [event],
        rule
    )

    assert len(alerts) == 1


def test_security_log_cleared():

    event = create_test_event(
        "1102",
        101
    )

    rule = find_rule("TS003")

    alerts = evaluate_single_event_rule(
        [event],
        rule
    )

    assert len(alerts) == 1

    assert alerts[0]["rule"]["severity"] == "CRITICAL"


def test_no_brute_force_below_threshold():

    events = [

        create_test_event(
            "4625",
            i,
            timestamp=f"2026-11-09T10:00:0{i}Z"
        )

        for i in range(1, 4)

    ]

    rule = find_rule("TS001")

    alerts = evaluate_threshold_rule(
        events,
        rule
    )

    assert len(alerts) == 0


if __name__ == "__main__":

    import pytest

    pytest.main([__file__, "-v"])
