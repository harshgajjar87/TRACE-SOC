
import json
import pytest

from detection.rules import DETECTION_RULES

from detection.engine import (
    evaluate_threshold_rule,
    evaluate_distinct_threshold_rule,
    evaluate_sequence_rule,
    evaluate_keyword_rule,
    evaluate_single_event_rule,
    evaluate_privileged_group_rule,
    evaluate_network_threshold_rule,
    evaluate_dns_rule,
    evaluate_file_rule,
    evaluate_parent_child_rule,
)


# --------------------------------------------------
# COMMON TEST HELPERS
# --------------------------------------------------

def get_rule(rule_id):

    return next(
        rule for rule in DETECTION_RULES
        if rule["rule_id"] == rule_id
    )


def make_event(
    event_id,
    timestamp,
    event_number,
    provider="Microsoft-Windows-Security-Auditing",
    channel="Security",
    **fields
):

    return {
        "id": event_number,
        "event_id": str(event_id),
        "provider": provider,
        "channel": channel,
        "timestamp_utc": timestamp,
        "hostname": "TEST-PC",
        "username": fields.pop("username", "testuser"),
        "source_ip": fields.pop("source_ip", "192.168.1.50"),
        "image": fields.pop("image", None),
        "command_line": fields.pop("command_line", None),
        "extra_data_json": json.dumps(fields),
    }


def make_time(index):

    return f"2026-11-09T10:00:{index:02d}+00:00"


# ==================================================
# 1. AUTHENTICATION TESTS
# ==================================================

def test_brute_force_detection():

    rule = get_rule("TS001")

    events = [
        make_event(
            "4625",
            make_time(i),
            i,
            username="alice",
            source_ip="10.0.0.5"
        )
        for i in range(1, 6)
    ]

    alerts = evaluate_threshold_rule(events, rule)

    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 5
    assert alerts[0]["source_ip"] == "10.0.0.5"


def test_password_spraying_detection():

    rule = get_rule("TS009")

    events = [
        make_event(
            "4625",
            make_time(i),
            i,
            username=f"user{i}",
            source_ip="10.0.0.10"
        )
        for i in range(1, 6)
    ]

    alerts = evaluate_distinct_threshold_rule(events, rule)

    assert len(alerts) == 1
    assert len(
        alerts[0]["additional_data"]["distinct_accounts"]
    ) == 5


def test_successful_login_after_failures():

    rule = get_rule("TS010")

    failures = [
        make_event(
            "4625",
            make_time(i),
            i,
            username="alice",
            source_ip="10.0.0.20"
        )
        for i in range(1, 6)
    ]

    success = make_event(
        "4624",
        "2026-11-09T10:01:00+00:00",
        6,
        username="alice",
        source_ip="10.0.0.20"
    )

    alerts = evaluate_sequence_rule(
        failures + [success],
        rule
    )

    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 6


# ==================================================
# 2. EXECUTION TESTS
# ==================================================

def test_suspicious_powershell_detection():

    rule = get_rule("TS002")

    event = make_event(
        "1",
        make_time(1),
        10,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -EncodedCommand TEST"
    )

    alerts = evaluate_keyword_rule([event], rule)

    assert len(alerts) == 1
    assert "-enc" in alerts[0]["matched_keywords"] or \
           "-encodedcommand" in alerts[0]["matched_keywords"]


def test_parent_child_process_detection():

    rule = get_rule("TS013")

    event = make_event(
        "1",
        make_time(1),
        11,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ParentImage=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    )

    alerts = evaluate_parent_child_rule([event], rule)

    assert len(alerts) == 1


# ==================================================
# 3. PERSISTENCE TESTS
# ==================================================

def test_new_user_creation_detection():

    rule = get_rule("TS004")

    event = make_event(
        "4720",
        make_time(1),
        12,
        TargetUserName="newuser"
    )

    alerts = evaluate_single_event_rule([event], rule)

    assert len(alerts) == 1
    assert alerts[0]["evidence_ids"] == [12]


def test_registry_persistence_detection():

    rule = get_rule("TS015")

    event = make_event(
        "13",
        make_time(1),
        13,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        TargetObject=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        Details="Test value"
    )

    from detection.engine import evaluate_registry_rule

    alerts = evaluate_registry_rule([event], rule)

    assert len(alerts) == 1


# ==================================================
# 4. PRIVILEGE ESCALATION TESTS
# ==================================================

def test_privileged_group_detection():

    rule = get_rule("TS005")

    event = make_event(
        "4732",
        make_time(1),
        14,
        TargetUserName="Administrators",
        TargetSid="S-1-5-32-544",
        MemberName="TEST-PC\\newuser"
    )

    alerts = evaluate_privileged_group_rule([event], rule)

    assert len(alerts) == 1
    assert alerts[0]["additional_data"]["affected_group"] == "administrators"


def test_non_privileged_group_does_not_alert():

    rule = get_rule("TS005")

    event = make_event(
        "4732",
        make_time(1),
        15,
        TargetUserName="Guests",
        TargetSid="S-1-5-32-546",
        MemberName="TEST-PC\\visitor"
    )

    alerts = evaluate_privileged_group_rule([event], rule)

    assert len(alerts) == 0


# ==================================================
# 5. NETWORK TESTS
# ==================================================

def test_possible_port_scan_detection():

    rule = get_rule("TS018")

    events = [
        make_event(
            "3",
            make_time(i),
            100 + i,
            provider="Microsoft-Windows-Sysmon",
            channel="Microsoft-Windows-Sysmon/Operational",
            SourceIp="10.0.0.50",
            DestinationIp="10.0.0.100",
            DestinationPort=port
        )
        for i, port in enumerate(range(1000, 1015), start=1)
    ]

    alerts = evaluate_network_threshold_rule(events, rule)

    assert len(alerts) == 1
    assert len(
        alerts[0]["additional_data"]["distinct_destination_ports"]
    ) == 15


def test_suspicious_dns_detection():

    rule = get_rule("TS020")

    event = make_event(
        "22",
        make_time(1),
        200,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        QueryName="test.ngrok.example"
    )

    alerts = evaluate_dns_rule([event], rule)

    assert len(alerts) == 1
    assert "ngrok" in alerts[0]["matched_keywords"]


# ==================================================
# 6. DATA AND FILE TESTS
# ==================================================

def test_file_creation_detection():

    rule = get_rule("TS021")

    event = make_event(
        "11",
        make_time(1),
        201,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        TargetFilename=r"C:\Temp\test.txt"
    )

    alerts = evaluate_file_rule([event], rule)

    assert len(alerts) == 1


# ==================================================
# 7. DEFENSE EVASION TESTS
# ==================================================

def test_security_log_clearing_detection():

    rule = get_rule("TS003")

    event = make_event(
        "1102",
        make_time(1),
        202,
        provider="Microsoft-Windows-Eventlog",
        channel="Security"
    )

    alerts = evaluate_single_event_rule([event], rule)

    assert len(alerts) == 1
    assert alerts[0]["rule"]["severity"] == "CRITICAL"


# ==================================================
# 8. FALSE-POSITIVE AND PROVIDER TESTS
# ==================================================

def test_wrong_provider_does_not_match():

    rule = get_rule("TS003")

    event = make_event(
        "1102",
        make_time(1),
        203,
        provider="Microsoft-Windows-Sysmon",
        channel="Security"
    )

    alerts = evaluate_single_event_rule([event], rule)

    assert len(alerts) == 0


def test_brute_force_below_threshold_does_not_alert():

    rule = get_rule("TS001")

    events = [
        make_event(
            "4625",
            make_time(i),
            300 + i,
            username="alice",
            source_ip="10.0.0.5"
        )
        for i in range(1, 5)
    ]

    alerts = evaluate_threshold_rule(events, rule)

    assert len(alerts) == 0


# --------------------------------------------------
# TS016 — SPECIAL PRIVILEGES ASSIGNED (SID SUPPRESSION)
# --------------------------------------------------

def _make_4672_event(subject_sid, subject_username, event_id=1):
    """Build a minimal normalized event that matches TS016."""
    return {
        "id": event_id,
        "event_id": "4672",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "timestamp_utc": "2026-11-11T10:00:00+00:00",
        "hostname": "TEST-PC",
        "username": subject_username,
        "extra_data_json": json.dumps({
            "SubjectUserName": subject_username,
            "SubjectUserSid": subject_sid,
            "SubjectLogonId": "0x3e7",
            "PrivilegeList": "SeDebugPrivilege\nSeBackupPrivilege",
        }),
    }


def test_ts016_suppresses_system_account():
    """SYSTEM (S-1-5-18) must not generate a TS016 alert."""
    rule = get_rule("TS016")
    event = _make_4672_event("S-1-5-18", "SYSTEM")
    alerts = evaluate_single_event_rule([event], rule)
    assert alerts == [], "SYSTEM 4672 should be suppressed"


def test_ts016_suppresses_local_service():
    """LOCAL SERVICE (S-1-5-19) must not generate a TS016 alert."""
    rule = get_rule("TS016")
    event = _make_4672_event("S-1-5-19", "LOCAL SERVICE")
    alerts = evaluate_single_event_rule([event], rule)
    assert alerts == [], "LOCAL SERVICE 4672 should be suppressed"


def test_ts016_suppresses_network_service():
    """NETWORK SERVICE (S-1-5-20) must not generate a TS016 alert."""
    rule = get_rule("TS016")
    event = _make_4672_event("S-1-5-20", "NETWORK SERVICE")
    alerts = evaluate_single_event_rule([event], rule)
    assert alerts == [], "NETWORK SERVICE 4672 should be suppressed"


def test_ts016_suppresses_iusr():
    """IUSR (S-1-5-17) must not generate a TS016 alert."""
    rule = get_rule("TS016")
    event = _make_4672_event("S-1-5-17", "IUSR")
    alerts = evaluate_single_event_rule([event], rule)
    assert alerts == [], "IUSR 4672 should be suppressed"


def test_ts016_suppresses_dwm_prefix():
    """DWM accounts (S-1-5-90-*) must not generate a TS016 alert."""
    rule = get_rule("TS016")
    event = _make_4672_event("S-1-5-90-0-1", "DWM-1")
    alerts = evaluate_single_event_rule([event], rule)
    assert alerts == [], "DWM 4672 should be suppressed via SID prefix"


def test_ts016_suppresses_per_service_sid_prefix():
    """Per-service SIDs (S-1-5-80-*) must not generate a TS016 alert."""
    rule = get_rule("TS016")
    event = _make_4672_event(
        "S-1-5-80-863171341-2975503981-1811344707-3769924460-3995132968",
        "IntelTelemetryAgent",
    )
    alerts = evaluate_single_event_rule([event], rule)
    assert alerts == [], "Per-service SID 4672 should be suppressed"


def test_ts016_fires_for_real_user_account():
    """A real user account must still trigger a TS016 alert."""
    rule = get_rule("TS016")
    event = _make_4672_event(
        "S-1-5-21-2036092497-1664975535-1205397107-1001",
        "HP",
    )
    alerts = evaluate_single_event_rule([event], rule)
    assert len(alerts) == 1, "Real user account 4672 must generate an alert"
    assert alerts[0]["rule"]["rule_id"] == "TS016"


def test_ts016_fires_when_no_sid_in_event():
    """
    If the event carries no SubjectUserSid, the suppression check
    cannot match and the alert should still fire (fail-open).
    """
    rule = get_rule("TS016")
    event = {
        "id": 99,
        "event_id": "4672",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "timestamp_utc": "2026-11-11T10:00:00+00:00",
        "hostname": "TEST-PC",
        "username": None,
        "extra_data_json": json.dumps({}),
    }
    alerts = evaluate_single_event_rule([event], rule)
    assert len(alerts) == 1, "Event with no SID must not be silently dropped"
