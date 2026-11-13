
"""
TRACE-SOC - Multi-Category Detection Engine

Supports:
- Authentication detection
- Execution detection
- Persistence detection
- Privilege escalation detection
- Network detection
- File activity detection
- Defense evasion detection

The engine uses normalized SQLite events and preserves
links to the original normalized event IDs.
"""

import json
import hashlib
import sqlite3

from datetime import datetime, timezone

from database.db import get_connection
from detection.rules import DETECTION_RULES


# ==========================================================
# 1. DATA LOADING AND COMMON HELPERS
# ==========================================================

def get_all_events():

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        events = connection.execute("""
            SELECT *
            FROM normalized_events
            ORDER BY timestamp_utc ASC
        """).fetchall()

        return [dict(event) for event in events]

    finally:
        connection.close()


def get_extra_data(event):

    value = event.get("extra_data_json")

    if isinstance(value, dict):
        return value

    if not value:
        return {}

    try:
        result = json.loads(value)
        return result if isinstance(result, dict) else {}

    except (json.JSONDecodeError, TypeError):
        return {}


def get_field(event, *names):

    extra = get_extra_data(event)

    # Prefer normalized fields.
    for name in names:

        value = event.get(name)

        if value not in (None, "", "-"):
            return value

    # Then search original provider-specific event data.
    for name in names:

        value = extra.get(name)

        if value not in (None, "", "-"):
            return value

    return None


def parse_timestamp(value):

    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def get_event_id(event):

    value = event.get("event_id")

    if value is None:
        return None

    return str(value)



def provider_matches(event, rule):

    expected = rule.get("providers") or rule.get("provider")

    if not expected:
        return True

    actual = event.get("provider")

    # Compatibility with older synthetic test events.
    # Real collected events should contain provider metadata.
    if not actual:
        return True

    if isinstance(expected, str):
        expected = [expected]

    return any(
        str(actual).lower() == str(item).lower()
        for item in expected
    )

def channel_matches(event, rule):

    expected = rule.get("channel")

    if not expected:
        return True

    actual = event.get("channel")

    # Allow older synthetic events that lack channel metadata.
    if not actual:
        return True

    return str(actual).lower() == expected.lower()


def event_matches(event, rule, event_ids=None):

    if event_ids is None:
        event_ids = [rule["event_id"]]

    event_ids = {str(item) for item in event_ids}

    return (
        get_event_id(event) in event_ids
        and provider_matches(event, rule)
        and channel_matches(event, rule)
    )


def generate_alert_fingerprint(rule_id, evidence_ids):

    identity = {
        "rule_id": rule_id,
        "evidence_ids": sorted(evidence_ids)
    }

    content = json.dumps(identity, sort_keys=True)

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def make_alert(rule, events, **extra):

    events = sorted(
        events,
        key=lambda item: item.get("timestamp_utc") or ""
    )

    first = events[0] if events else {}

    evidence_ids = [
        event["id"]
        for event in events
        if event.get("id") is not None
    ]

    alert = {
        "rule": rule,
        "username": first.get("username"),
        "source_ip": first.get("source_ip"),
        "hostname": first.get("hostname"),
        "evidence_ids": evidence_ids,
        "event_count": len(events),
        "first_seen": first.get("timestamp_utc"),
        "last_seen": events[-1].get("timestamp_utc") if events else None,
    }

    alert.update(extra)

    return alert


# ==========================================================
# 2. AUTHENTICATION DETECTION
# ==========================================================

def evaluate_threshold_rule(events, rule):

    matching = [
        event for event in events
        if event_matches(event, rule)
    ]

    groups = {}

    for event in matching:

        source_ip = get_field(
            event, "source_ip", "IpAddress", "SourceIp"
        )

        # Do not group unrelated events under an unknown IP.
        if not source_ip:
            continue

        groups.setdefault(str(source_ip), []).append(event)

    alerts = []

    for source_ip, group in groups.items():

        group.sort(
            key=lambda item: item.get("timestamp_utc") or ""
        )

        threshold = rule["threshold"]
        window = rule["time_window"]

        for index, event in enumerate(group):

            start = parse_timestamp(event.get("timestamp_utc"))

            if start is None:
                continue

            window_events = []

            for candidate in group[index:]:

                current = parse_timestamp(
                    candidate.get("timestamp_utc")
                )

                if current is None:
                    continue

                difference = (current - start).total_seconds()

                if 0 <= difference <= window:
                    window_events.append(candidate)

                elif difference > window:
                    break

            if len(window_events) >= threshold:

                alerts.append(
                    make_alert(
                        rule,
                        window_events,
                        source_ip=source_ip,
                        username=None,
                        additional_data={
                            "threshold": threshold,
                            "time_window_seconds": window
                        }
                    )
                )

                break

    return alerts


def evaluate_distinct_threshold_rule(events, rule):

    matching = [
        event for event in events
        if event_matches(event, rule)
    ]

    groups = {}

    for event in matching:

        source_ip = get_field(
            event, "source_ip", "IpAddress"
        )

        username = get_field(
            event, rule["distinct_field"]
        )

        if not source_ip or not username:
            continue

        groups.setdefault(str(source_ip), []).append(
            (str(username).lower(), event)
        )

    alerts = []

    for source_ip, group in groups.items():

        group.sort(
            key=lambda item: item[1].get("timestamp_utc") or ""
        )

        for index, (username, event) in enumerate(group):

            start = parse_timestamp(event.get("timestamp_utc"))

            if start is None:
                continue

            window_events = []
            distinct_users = set()

            for candidate_user, candidate in group[index:]:

                current = parse_timestamp(
                    candidate.get("timestamp_utc")
                )

                if current is None:
                    continue

                difference = (current - start).total_seconds()

                if 0 <= difference <= rule["time_window"]:
                    window_events.append(candidate)
                    distinct_users.add(candidate_user)

                elif difference > rule["time_window"]:
                    break

            if len(distinct_users) >= rule["threshold"]:

                alerts.append(
                    make_alert(
                        rule,
                        window_events,
                        username=None,
                        source_ip=source_ip,
                        additional_data={
                            "distinct_accounts": sorted(distinct_users)
                        }
                    )
                )

                break

    return alerts


def evaluate_sequence_rule(events, rule):

    failures = [
        event for event in events
        if event_matches(
            event, rule, [rule["failure_event_id"]]
        )
    ]

    successes = [
        event for event in events
        if event_matches(
            event, rule, [rule["success_event_id"]]
        )
    ]

    alerts = []

    for success in successes:

        success_time = parse_timestamp(
            success.get("timestamp_utc")
        )

        if success_time is None:
            continue

        success_user = get_field(
            success, "username", "TargetUserName"
        )

        success_ip = get_field(
            success, "source_ip", "IpAddress"
        )

        if not success_user or not success_ip:
            continue

        related_failures = []

        for failure in failures:

            failure_time = parse_timestamp(
                failure.get("timestamp_utc")
            )

            failure_user = get_field(
                failure, "username", "TargetUserName"
            )

            failure_ip = get_field(
                failure, "source_ip", "IpAddress"
            )

            if failure_time is None:
                continue

            elapsed = (success_time - failure_time).total_seconds()

            if (
                failure_user
                and failure_ip
                and str(failure_user).lower() == str(success_user).lower()
                and str(failure_ip) == str(success_ip)
                and 0 <= elapsed <= rule["time_window"]
            ):
                related_failures.append(failure)

        if len(related_failures) >= rule["failure_threshold"]:

            evidence = related_failures + [success]

            alerts.append(
                make_alert(
                    rule,
                    evidence,
                    username=success_user,
                    source_ip=success_ip,
                    additional_data={
                        "failed_attempts": len(related_failures),
                        "successful_login_event_id": success.get("id")
                    }
                )
            )

    return alerts


# ==========================================================
# 3. EXECUTION DETECTION
# ==========================================================

def evaluate_keyword_rule(events, rule):

    alerts = []

    for event in events:

        if not event_matches(event, rule):
            continue

        image = (
            event.get("image") or ""
        ).lower()

        command = (
            event.get("command_line") or ""
        ).lower()

        expected_image = rule.get(
            "process_image_contains", "powershell"
        ).lower()

        if expected_image not in image:
            continue

        matched_keywords = [
            keyword
            for keyword in rule["keywords"]
            if keyword.lower() in command
        ]

        if not matched_keywords:
            continue

        suppress_parents = [
            s.lower()
            for s in rule.get("suppress_parent_cmdline_contains", [])
        ]

        if suppress_parents:
            extra = get_extra_data(event)
            parent_cmdline = str(
                get_field(event, "parent_command_line", "ParentCommandLine")
                or extra.get("ParentCommandLine")
                or ""
            ).lower()
            if any(s in parent_cmdline for s in suppress_parents):
                continue

        alerts.append(
            make_alert(
                rule,
                [event],
                matched_keywords=matched_keywords
            )
        )

    return alerts


def evaluate_process_indicator_rule(events, rule):

    alerts = []

    suspicious_images = [
        item.lower()
        for item in rule.get("suspicious_images", [])
    ]

    for event in events:

        if not event_matches(
            event, rule, rule["event_ids"]
        ):
            continue

        image = (event.get("image") or "").lower()

        if any(image.endswith(name) for name in suspicious_images):

            alerts.append(
                make_alert(
                    rule,
                    [event],
                    extra_data=get_extra_data(event)
                )
            )

    return alerts


def evaluate_parent_child_rule(events, rule):

    alerts = []

    parents = [
        name.lower()
        for name in rule["suspicious_parents"]
    ]

    children = [
        name.lower()
        for name in rule["suspicious_children"]
    ]

    for event in events:

        if not event_matches(event, rule):
            continue

        extra = get_extra_data(event)

        parent = str(
            get_field(
                event,
                "parent_image",
                "ParentImage",
                "ParentProcessName"
            ) or ""
        ).lower()

        child = str(
            event.get("image") or ""
        ).lower()

        if (
            any(parent.endswith(name) for name in parents)
            and any(child.endswith(name) for name in children)
        ):

            alerts.append(
                make_alert(
                    rule,
                    [event],
                    extra_data=extra,
                    additional_data={
                        "parent_image": parent,
                        "child_image": child
                    }
                )
            )

    return alerts


# ==========================================================
# 4. PERSISTENCE AND PRIVILEGE ESCALATION
# ==========================================================

def evaluate_registry_rule(events, rule):

    alerts = []

    for event in events:

        if not event_matches(event, rule, rule["event_ids"]):
            continue

        extra = get_extra_data(event)

        target = str(
            get_field(
                event,
                "TargetObject",
                "TargetFilename"
            ) or ""
        ).lower()

        # Focus on common autorun/persistence locations.
        persistence_locations = [
            r"\currentversion\run",
            r"\currentversion\runonce",
            r"\winlogon",
            r"\services",
            r"\image file execution options"
        ]

        if any(location in target for location in persistence_locations):

            alerts.append(
                make_alert(
                    rule,
                    [event],
                    extra_data=extra,
                    additional_data={
                        "registry_target": target
                    }
                )
            )

    return alerts


def evaluate_privileged_group_rule(events, rule):

    alerts = []

    sensitive_names = {
        name.lower()
        for name in rule["sensitive_group_names"]
    }

    sensitive_sids = {
        sid.lower()
        for sid in rule["sensitive_group_sids"]
    }

    for event in events:

        if not event_matches(event, rule, rule["event_ids"]):
            continue

        group_name = str(
            get_field(
                event,
                "TargetUserName",
                "GroupName",
                "TargetGroupName"
            ) or ""
        ).lower()

        group_sid = str(
            get_field(
                event,
                "TargetSid",
                "GroupSid",
                "TargetGroupSid"
            ) or ""
        ).lower()

        if (
            group_name in sensitive_names
            or group_sid in sensitive_sids
        ):

            alerts.append(
                make_alert(
                    rule,
                    [event],
                    username=get_field(
                        event,
                        "MemberName",
                        "MemberSid",
                        "username"
                    ),
                    extra_data=get_extra_data(event),
                    additional_data={
                        "affected_group": group_name,
                        "affected_group_sid": group_sid
                    }
                )
            )

    return alerts


def evaluate_account_correlation_rule(events, rule):

    creations = [
        event for event in events
        if event_matches(
            event, rule, [rule["creation_event_id"]]
        )
    ]

    group_changes = [
        event for event in events
        if event_matches(
            event, rule, rule["group_event_ids"]
        )
    ]

    alerts = []

    for creation in creations:

        created_user = get_field(
            creation, "TargetUserName", "username"
        )

        creation_time = parse_timestamp(
            creation.get("timestamp_utc")
        )

        if not created_user or creation_time is None:
            continue

        for change in group_changes:

            changed_user = get_field(
                change,
                "MemberName",
                "MemberSid",
                "TargetUserName"
            )

            change_time = parse_timestamp(
                change.get("timestamp_utc")
            )

            if not changed_user or change_time is None:
                continue

            elapsed = (change_time - creation_time).total_seconds()

            if (
                str(created_user).lower() == str(changed_user).lower()
                and 0 <= elapsed <= rule["time_window"]
            ):

                alerts.append(
                    make_alert(
                        rule,
                        [creation, change],
                        username=created_user,
                        additional_data={
                            "correlation": "account_created_then_group_changed"
                        }
                    )
                )

    return alerts


# ==========================================================
# 5. NETWORK DETECTION
# ==========================================================

def evaluate_network_threshold_rule(events, rule):

    matching = [
        event for event in events
        if event_matches(event, rule)
    ]

    groups = {}

    for event in matching:

        source_ip = get_field(event, "SourceIp", "source_ip")
        destination_ip = get_field(
            event, "DestinationIp", "destination_ip"
        )

        destination_port = get_field(
            event, "DestinationPort", "destination_port"
        )

        if not source_ip or not destination_ip or not destination_port:
            continue

        key = (str(source_ip), str(destination_ip))

        groups.setdefault(key, []).append(event)

    alerts = []

    for (source_ip, destination_ip), group in groups.items():

        group.sort(
            key=lambda item: item.get("timestamp_utc") or ""
        )

        for index, event in enumerate(group):

            start = parse_timestamp(event.get("timestamp_utc"))

            if start is None:
                continue

            window_events = []
            ports = set()

            for candidate in group[index:]:

                current = parse_timestamp(
                    candidate.get("timestamp_utc")
                )

                if current is None:
                    continue

                elapsed = (current - start).total_seconds()

                if 0 <= elapsed <= rule["time_window"]:

                    port = get_field(
                        candidate,
                        "DestinationPort",
                        "destination_port"
                    )

                    if port is not None:
                        ports.add(str(port))

                    window_events.append(candidate)

                elif elapsed > rule["time_window"]:
                    break

            if len(ports) >= rule["threshold"]:

                alerts.append(
                    make_alert(
                        rule,
                        window_events,
                        source_ip=source_ip,
                        additional_data={
                            "destination_ip": destination_ip,
                            "distinct_destination_ports": sorted(ports)
                        }
                    )
                )

                break

    return alerts


def evaluate_network_indicator_rule(events, rule):

    alerts = []

    for event in events:

        if not event_matches(event, rule):
            continue

        destination_ip = get_field(
            event, "DestinationIp", "destination_ip"
        )

        if rule.get("require_destination_ip") and not destination_ip:
            continue

        alerts.append(
            make_alert(
                rule,
                [event],
                additional_data={
                    "destination_ip": destination_ip,
                    "destination_port": get_field(
                        event, "DestinationPort", "destination_port"
                    )
                }
            )
        )

    return alerts


def evaluate_dns_rule(events, rule):

    alerts = []

    keywords = [
        item.lower()
        for item in rule["suspicious_keywords"]
    ]

    for event in events:

        if not event_matches(event, rule):
            continue

        query = str(
            get_field(
                event,
                "QueryName",
                "query_name",
                "Query"
            ) or ""
        ).lower()

        matched = [
            keyword for keyword in keywords
            if keyword in query
        ]

        if matched:

            alerts.append(
                make_alert(
                    rule,
                    [event],
                    matched_keywords=matched,
                    additional_data={
                        "dns_query": query
                    }
                )
            )

    return alerts


# ==========================================================
# 6. DATA AND FILE DETECTION
# ==========================================================

def evaluate_file_rule(events, rule):

    alerts = []

    event_ids = rule.get(
        "event_ids",
        [rule.get("event_id")]
    )

    for event in events:

        if not event_matches(event, rule, event_ids):
            continue

        alerts.append(
            make_alert(
                rule,
                [event],
                extra_data=get_extra_data(event)
            )
        )

    return alerts


# ==========================================================
# 7. SINGLE EVENT DETECTION
# ==========================================================

def _is_suppressed_by_sid(event, rule):
    """
    Return True when an event's SubjectUserSid matches one of the
    exact SIDs or SID prefixes listed in the rule's suppression keys.

    This is used by TS016 to skip routine built-in service accounts
    (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, DWM, per-service SIDs)
    while still alerting on real user accounts.
    """
    exact_sids = rule.get("suppress_subject_sids", [])
    sid_prefixes = rule.get("suppress_subject_sid_prefixes", [])

    if not exact_sids and not sid_prefixes:
        return False

    extra = get_extra_data(event)
    subject_sid = (extra.get("SubjectUserSid") or "").strip()

    if not subject_sid:
        return False

    if subject_sid in exact_sids:
        return True

    return any(subject_sid.startswith(p) for p in sid_prefixes)


def evaluate_single_event_rule(events, rule):

    alerts = []

    for event in events:

        if not event_matches(event, rule):
            continue

        if _is_suppressed_by_sid(event, rule):
            continue

        alerts.append(
            make_alert(
                rule,
                [event],
                extra_data=get_extra_data(event)
            )
        )

    return alerts


# ==========================================================
# 8. RULE DISPATCHER
# ==========================================================

EVALUATORS = {
    "threshold": evaluate_threshold_rule,
    "keyword": evaluate_keyword_rule,
    "single_event": evaluate_single_event_rule,
    "distinct_threshold": evaluate_distinct_threshold_rule,
    "sequence": evaluate_sequence_rule,
    "process_indicator": evaluate_process_indicator_rule,
    "parent_child": evaluate_parent_child_rule,
    "registry_event": evaluate_registry_rule,
    "privileged_group": evaluate_privileged_group_rule,
    "account_correlation": evaluate_account_correlation_rule,
    "network_threshold": evaluate_network_threshold_rule,
    "network_indicator": evaluate_network_indicator_rule,
    "dns_indicator": evaluate_dns_rule,
    "file_event": evaluate_file_rule
}


# ==========================================================
# 9. SAVE ALERTS
# ==========================================================

def save_alerts(alerts):

    connection = get_connection()

    inserted = 0

    try:

        for alert in alerts:

            rule = alert["rule"]

            fingerprint = generate_alert_fingerprint(
                rule["rule_id"],
                alert["evidence_ids"]
            )

            evidence = {
                "normalized_event_ids": alert["evidence_ids"],
                "matched_keywords": alert.get(
                    "matched_keywords", []
                ),
                "additional_data": alert.get(
                    "additional_data", {}
                ),
                "extra_data": alert.get(
                    "extra_data", {}
                )
            }

            with connection:

                cursor = connection.execute("""
                    INSERT OR IGNORE INTO alerts (
                        alert_fingerprint,
                        rule_id,
                        rule_name,
                        description,
                        severity,
                        status,
                        hostname,
                        username,
                        source_ip,
                        first_seen,
                        last_seen,
                        event_count,
                        mitre_tactic,
                        mitre_technique,
                        evidence_json,
                        created_at_utc
                    )
                    VALUES (?, ?, ?, ?, ?, 'NEW', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    fingerprint,
                    rule["rule_id"],
                    rule["name"],
                    rule["description"],
                    rule["severity"],
                    alert.get("hostname"),
                    alert.get("username"),
                    alert.get("source_ip"),
                    alert.get("first_seen"),
                    alert.get("last_seen"),
                    alert["event_count"],
                    rule.get("mitre_tactic"),
                    rule.get("mitre_technique"),
                    json.dumps(evidence),
                    datetime.now(timezone.utc).isoformat()
                ))

                inserted += cursor.rowcount

    finally:
        connection.close()

    return inserted


# ==========================================================
# 10. RUN DETECTION ENGINE
# ==========================================================

def run_detection_engine():

    print("\n========== TRACE-SOC DETECTION ENGINE ==========\n")

    events = get_all_events()

    print("Events loaded:", len(events))

    all_alerts = []
    unsupported_rules = []

    for rule in DETECTION_RULES:

        rule_id = rule["rule_id"]
        rule_name = rule["name"]

        rule_type = rule.get(
            "rule_type",
            "threshold" if rule.get("threshold")
            else "keyword" if rule.get("keywords")
            else "single_event"
        )

        print(f"Evaluating {rule_id}: {rule_name}")

        # TS023 requires network transfer-volume telemetry.
        # Sysmon Event 3 alone cannot provide reliable byte counts.
        if rule_id == "TS023":

            unsupported_rules.append({
                "rule_id": rule_id,
                "reason": "Additional network transfer telemetry required"
            })

            print("  COVERAGE GAP: network byte telemetry required")
            continue

        evaluator = EVALUATORS.get(rule_type)

        if evaluator is None:

            unsupported_rules.append({
                "rule_id": rule_id,
                "rule_type": rule_type
            })

            print("  UNSUPPORTED RULE TYPE:", rule_type)
            continue

        detected = evaluator(events, rule)

        print("  Matches:", len(detected))

        all_alerts.extend(detected)

    inserted = save_alerts(all_alerts)

    print("\n========== DETECTION SUMMARY ==========")

    print("Total events analysed:", len(events))
    print("Detection matches:", len(all_alerts))
    print("New alerts stored:", inserted)
    print("Unsupported rules / coverage gaps:", len(unsupported_rules))

    for item in unsupported_rules:
        print("  ", item)

    print("=======================================\n")

    return {
        "events_analysed": len(events),
        "detection_matches": len(all_alerts),
        "new_alerts_stored": inserted,
        "coverage_gaps": unsupported_rules
    }


if __name__ == "__main__":
    run_detection_engine()
