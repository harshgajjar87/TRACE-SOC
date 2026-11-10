
import json
import hashlib
import sqlite3

from datetime import datetime, timezone

from database.db import get_connection
from detection.rules import DETECTION_RULES


def get_all_events():

    connection = get_connection()

    connection.row_factory = sqlite3.Row

    events = connection.execute("""
        SELECT *
        FROM normalized_events
        ORDER BY timestamp_utc ASC
    """).fetchall()

    connection.close()

    return [dict(event) for event in events]


def parse_timestamp(value):

    if not value:
        return None

    try:

        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except ValueError:

        return None


def generate_alert_fingerprint(rule_id, evidence_ids):

    identity = {
        "rule_id": rule_id,
        "evidence_ids": sorted(evidence_ids)
    }

    content = json.dumps(identity, sort_keys=True)

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()


def evaluate_threshold_rule(events, rule):

    matching = [
        event for event in events
        if str(event.get("event_id")) == rule["event_id"]
    ]

    # Group by account and source IP
    groups = {}

    for event in matching:

        extra = json.loads(
            event.get("extra_data_json") or "{}"
        )

        username = (
            event.get("username")
            or extra.get("TargetUserName")
            or "unknown"
        )

        source_ip = (
            event.get("source_ip")
            or extra.get("IpAddress")
            or "unknown"
        )

        key = (username, source_ip)

        groups.setdefault(key, []).append(event)

    alerts = []

    for (username, source_ip), group in groups.items():

        group.sort(
            key=lambda e: e.get("timestamp_utc") or ""
        )

        window = rule["time_window"]
        threshold = rule["threshold"]

        for index, event in enumerate(group):

            start = parse_timestamp(
                event.get("timestamp_utc")
            )

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

                evidence_ids = [
                    item["id"] for item in window_events
                ]

                alerts.append({

                    "rule": rule,

                    "username": username,

                    "source_ip": source_ip,

                    "hostname": event.get("hostname"),

                    "evidence_ids": evidence_ids,

                    "event_count": len(window_events),

                    "first_seen": window_events[0].get(
                        "timestamp_utc"
                    ),

                    "last_seen": window_events[-1].get(
                        "timestamp_utc"
                    )

                })

                # Avoid generating overlapping alerts
                break

    return alerts


def evaluate_keyword_rule(events, rule):

    alerts = []

    for event in events:

        if str(event.get("event_id")) != rule["event_id"]:
            continue

        image = (event.get("image") or "").lower()

        command = (event.get("command_line") or "").lower()

        if "powershell.exe" not in image:
            continue

        matched_keywords = [
            keyword
            for keyword in rule["keywords"]
            if keyword.lower() in command
        ]

        if not matched_keywords:
            continue

        alerts.append({

            "rule": rule,

            "username": event.get("username"),

            "source_ip": event.get("source_ip"),

            "hostname": event.get("hostname"),

            "evidence_ids": [event["id"]],

            "event_count": 1,

            "first_seen": event.get("timestamp_utc"),

            "last_seen": event.get("timestamp_utc"),

            "matched_keywords": matched_keywords

        })

    return alerts


def evaluate_single_event_rule(events, rule):

    alerts = []

    for event in events:

        if str(event.get("event_id")) != rule["event_id"]:
            continue

        extra = json.loads(
            event.get("extra_data_json") or "{}"
        )

        alerts.append({

            "rule": rule,

            "username": event.get("username"),

            "source_ip": event.get("source_ip"),

            "hostname": event.get("hostname"),

            "evidence_ids": [event["id"]],

            "event_count": 1,

            "first_seen": event.get("timestamp_utc"),

            "last_seen": event.get("timestamp_utc"),

            "extra_data": extra

        })

    return alerts


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
                    rule["mitre_tactic"],
                    rule["mitre_technique"],
                    json.dumps(evidence),
                    datetime.now(timezone.utc).isoformat()

                ))

                inserted += cursor.rowcount

    finally:

        connection.close()

    return inserted


def run_detection_engine():

    print("\nTRACE-SOC Detection Engine Starting...\n")

    events = get_all_events()

    print("Events loaded:", len(events))

    all_alerts = []

    for rule in DETECTION_RULES:

        print("Evaluating:", rule["rule_id"], rule["name"])

        if rule.get("threshold"):

            detected = evaluate_threshold_rule(
                events,
                rule
            )

        elif rule.get("keywords"):

            detected = evaluate_keyword_rule(
                events,
                rule
            )

        else:

            detected = evaluate_single_event_rule(
                events,
                rule
            )

        all_alerts.extend(detected)

    inserted = save_alerts(all_alerts)

    print("\n========== DETECTION SUMMARY ==========")

    print("Total events analysed:", len(events))

    print("Detection matches:", len(all_alerts))

    print("New alerts stored:", inserted)

    print("=======================================\n")


if __name__ == "__main__":

    run_detection_engine()
