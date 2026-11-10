
"""
TRACE-SOC - Event Correlation Engine

Identifies potentially related security events using:
- Process GUID
- Parent/child process relationships
- Source IP
- Hostname and username
- Time proximity

This module identifies relationships; it does not prove
that correlated events belong to the same attack.
"""

import json
import sqlite3

from datetime import datetime, timezone

from database.db import get_connection


# Maximum time difference between correlated events.
CORRELATION_WINDOW_MINUTES = 30


# ==================================================
# 1. LOAD EVENTS FROM DATABASE
# ==================================================

def get_all_events():

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:

        rows = connection.execute("""
            SELECT *
            FROM normalized_events
            ORDER BY timestamp_utc ASC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


# ==================================================
# 2. COMMON HELPERS
# ==================================================

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


def get_value(event, *field_names):

    extra = get_extra_data(event)

    for field in field_names:

        value = event.get(field)

        if value not in (None, "", "-"):
            return value

    for field in field_names:

        value = extra.get(field)

        if value not in (None, "", "-"):
            return value

    return None


def normalize_value(value):

    if value is None:
        return None

    return str(value).strip().lower()


# ==================================================
# 3. TIME PROXIMITY
# ==================================================

def events_within_time_window(event_a, event_b):

    time_a = parse_timestamp(
        event_a.get("timestamp_utc")
    )

    time_b = parse_timestamp(
        event_b.get("timestamp_utc")
    )

    if time_a is None or time_b is None:
        return False

    difference = abs(
        (time_a - time_b).total_seconds()
    )

    maximum_seconds = (
        CORRELATION_WINDOW_MINUTES * 60
    )

    return difference <= maximum_seconds


# ==================================================
# 4. CORRELATION ANALYSIS
# ==================================================

def calculate_correlation(event_a, event_b):
    """
    Return correlation score and explanations.

    Scores:
    100 = Same process GUID
    95  = Parent-child process relationship
    90  = Same source IP and username
    80  = Same hostname and username
    65  = Same source IP
    0   = No sufficient relationship
    """

    if event_a.get("id") == event_b.get("id"):
        return {
            "score": 0,
            "reasons": []
        }

    if not events_within_time_window(event_a, event_b):
        return {
            "score": 0,
            "reasons": []
        }

    reasons = []
    scores = []

    # Extract common identifiers.
    host_a = normalize_value(
        get_value(event_a, "hostname")
    )

    host_b = normalize_value(
        get_value(event_b, "hostname")
    )

    user_a = normalize_value(
        get_value(event_a, "username", "TargetUserName")
    )

    user_b = normalize_value(
        get_value(event_b, "username", "TargetUserName")
    )

    ip_a = normalize_value(
        get_value(event_a, "source_ip", "SourceIp", "IpAddress")
    )

    ip_b = normalize_value(
        get_value(event_b, "source_ip", "SourceIp", "IpAddress")
    )

    guid_a = normalize_value(
        get_value(event_a, "process_guid", "ProcessGuid")
    )

    guid_b = normalize_value(
        get_value(event_b, "process_guid", "ProcessGuid")
    )

    parent_a = normalize_value(
        get_value(event_a, "parent_process_guid", "ParentProcessGuid")
    )

    parent_b = normalize_value(
        get_value(event_b, "parent_process_guid", "ParentProcessGuid")
    )

    # Same process GUID.
    if guid_a and guid_a == guid_b:

        scores.append(100)
        reasons.append("Same process GUID")

    # Parent-child process relationship.
    if (
        guid_a and parent_b and guid_a == parent_b
    ) or (
        guid_b and parent_a and guid_b == parent_a
    ):

        scores.append(95)
        reasons.append("Parent-child process relationship")

    # Same source IP and username.
    if (
        ip_a and ip_a == ip_b
        and user_a and user_a == user_b
    ):

        scores.append(90)
        reasons.append("Same source IP and username")

    # Same hostname and username.
    if (
        host_a and host_a == host_b
        and user_a and user_a == user_b
    ):

        scores.append(80)
        reasons.append("Same hostname and username")

    # Same source IP.
    if ip_a and ip_a == ip_b:

        scores.append(65)
        reasons.append("Same source IP")

    if not scores:

        return {
            "score": 0,
            "reasons": []
        }

    return {
        "score": max(scores),
        "reasons": reasons
    }


# ==================================================
# 5. CONFIDENCE CLASSIFICATION
# ==================================================

def classify_confidence(score):

    if score >= 85:
        return "HIGH"

    if score >= 65:
        return "MEDIUM"

    return "LOW"


# ==================================================
# 6. BUILD CORRELATION GROUPS
# ==================================================

def build_correlation_groups(events):
    """
    Build groups of related events.

    Events are joined only when they have a supported
    relationship and fall inside the time window.

    Returns groups with event IDs and explanations.
    """

    events = [
        event for event in events
        if event.get("id") is not None
    ]

    events.sort(
        key=lambda event: event.get("timestamp_utc") or ""
    )

    total = len(events)

    # Each event initially belongs to its own group.
    parent = list(range(total))

    def find(index):

        while parent[index] != index:

            parent[index] = parent[parent[index]]
            index = parent[index]

        return index

    def union(index_a, index_b):

        root_a = find(index_a)
        root_b = find(index_b)

        if root_a != root_b:
            parent[root_b] = root_a

    relationships = []

    # Compare events and create relationship edges.
    for i in range(total):

        for j in range(i + 1, total):

            event_a = events[i]
            event_b = events[j]

            # Events are sorted by time, so we can stop
            # when the later event exceeds the time window.
            time_a = parse_timestamp(
                event_a.get("timestamp_utc")
            )

            time_b = parse_timestamp(
                event_b.get("timestamp_utc")
            )

            if time_a and time_b:

                difference = (
                    time_b - time_a
                ).total_seconds()

                if difference > CORRELATION_WINDOW_MINUTES * 60:
                    break

            result = calculate_correlation(
                event_a,
                event_b
            )

            if result["score"] >= 65:

                union(i, j)

                relationships.append({
                    "event_a_id": event_a["id"],
                    "event_b_id": event_b["id"],
                    "score": result["score"],
                    "reasons": result["reasons"]
                })

    # Collect connected components.
    components = {}

    for index, event in enumerate(events):

        root = find(index)

        components.setdefault(
            root, []
        ).append(event)

    # Keep groups containing at least two events.
    groups = []

    for group_events in components.values():

        if len(group_events) < 2:
            continue

        event_ids = {
            event["id"]
            for event in group_events
        }

        group_relationships = [
            relationship
            for relationship in relationships
            if (
                relationship["event_a_id"] in event_ids
                and relationship["event_b_id"] in event_ids
            )
        ]

        scores = [
            relationship["score"]
            for relationship in group_relationships
        ]

        confidence_score = max(scores) if scores else 0

        group_events.sort(
            key=lambda event: event.get("timestamp_utc") or ""
        )

        first = group_events[0]

        groups.append({

            "event_ids": [
                event["id"]
                for event in group_events
            ],

            "event_count": len(group_events),

            "hostname": first.get("hostname"),

            "username": first.get("username"),

            "source_ip": first.get("source_ip"),

            "first_seen": group_events[0].get(
                "timestamp_utc"
            ),

            "last_seen": group_events[-1].get(
                "timestamp_utc"
            ),

            "confidence_score": confidence_score,

            "confidence_level": classify_confidence(
                confidence_score
            ),

            "relationships": group_relationships

        })

    return groups


# ==================================================
# 7. RUN CORRELATION ENGINE
# ==================================================

def run_correlation_engine():

    print("\n========== TRACE-SOC CORRELATION ENGINE ==========\n")

    events = get_all_events()

    print("Events loaded:", len(events))

    groups = build_correlation_groups(events)

    print("Correlation groups found:", len(groups))

    for index, group in enumerate(groups, start=1):

        print(f"\nStory Candidate #{index}")

        print("Event IDs:", group["event_ids"])
        print("Hostname:", group["hostname"])
        print("Username:", group["username"])
        print("Source IP:", group["source_ip"])

        print(
            "Confidence:",
            group["confidence_score"],
            group["confidence_level"]
        )

        for relationship in group["relationships"]:

            print(
                "Relationship:",
                relationship["reasons"]
            )

    print("\n===============================================\n")

    return groups


if __name__ == "__main__":

    run_correlation_engine()
