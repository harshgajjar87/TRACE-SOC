"""Persist correlation groups as investigation stories (candidates, not proof)."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from database.db import get_connection
from investigation.correlation import get_all_events, build_correlation_groups

SEVERITY_ORDER = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


def generate_story_fingerprint(event_ids):
    payload = json.dumps({"event_ids": sorted(set(event_ids))}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _event_ids_from_evidence(evidence):
    # Support both historical and current evidence JSON key names.
    values = evidence.get("normalized_event_ids", evidence.get("event_ids", []))
    if not isinstance(values, list):
        return []
    result = []
    for value in values:
        try:
            result.append(int(value))
        except (TypeError, ValueError):
            continue
    return result


def load_alert_evidence(connection):
    connection.row_factory = sqlite3.Row
    evidence_map = {}
    rows = connection.execute("""SELECT id, rule_id, rule_name, severity,
        evidence_json, created_at_utc FROM alerts""").fetchall()
    for row in rows:
        try:
            evidence = json.loads(row["evidence_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(evidence, dict):
            continue
        for event_id in _event_ids_from_evidence(evidence):
            evidence_map.setdefault(event_id, []).append(dict(row))
    return evidence_map


def determine_story_severity(alerts):
    if not alerts:
        return "INFO"
    return max((str(a.get("severity") or "INFO").upper() for a in alerts),
               key=lambda value: SEVERITY_ORDER.get(value, 1))


def generate_story_title(group, alerts):
    names = sorted({a["rule_name"] for a in alerts if a.get("rule_name")})
    return "Investigation: " + ", ".join(names[:2]) if names else "Correlated Security Activity"


def save_story(connection, group, evidence_map):
    event_ids = sorted(set(int(x) for x in group.get("event_ids", [])))
    if len(event_ids) < 2:
        return None
    fingerprint = generate_story_fingerprint(event_ids)
    alerts_by_id = {}
    for event_id in event_ids:
        for alert in evidence_map.get(event_id, []):
            alerts_by_id[int(alert["id"])] = alert
    alerts = list(alerts_by_id.values())
    severity = determine_story_severity(alerts)
    now = datetime.now(timezone.utc).isoformat()
    description = ("Correlated security events were grouped using shared identifiers and time proximity. "
                   "This is an investigation candidate, not proof of a single attack.")
    connection.execute("""INSERT OR IGNORE INTO attack_stories (
        story_fingerprint,title,description,severity,status,hostname,username,source_ip,
        first_seen,last_seen,event_count,alert_count,confidence_score,confidence_level,created_at_utc
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (fingerprint, generate_story_title(group, alerts), description, severity, "NEW",
         group.get("hostname"), group.get("username"), group.get("source_ip"),
         group.get("first_seen"), group.get("last_seen"), len(event_ids), len(alerts),
         int(group.get("confidence_score", 0)), group.get("confidence_level", "LOW"), now))
    story = connection.execute("SELECT id FROM attack_stories WHERE story_fingerprint=?",
                               (fingerprint,)).fetchone()
    story_id = story[0]
    for event_id in event_ids:
        event = connection.execute("SELECT timestamp_utc FROM normalized_events WHERE id=?",
                                   (event_id,)).fetchone()
        observed_at = event[0] if event else None
        event_alerts = evidence_map.get(event_id, [])
        connection.execute("""INSERT OR IGNORE INTO story_events
            (story_id,normalized_event_id,alert_id,relationship,evidence_role,observed_at_utc)
            VALUES (?,?,?,?,?,?)""",
            (story_id, event_id, event_alerts[0]["id"] if event_alerts else None,
             "Detection alert evidence" if event_alerts else "Correlation relationship",
             "Observed event linked to detection alert" if event_alerts else "Observed event without matching alert",
             observed_at))
    for alert in alerts:
        connection.execute("INSERT OR IGNORE INTO story_alert_links(story_id,alert_id) VALUES (?,?)",
                           (story_id, alert["id"]))
    for edge in group.get("relationships", []):
        a, b = int(edge["event_a_id"]), int(edge["event_b_id"])
        connection.execute("""INSERT OR IGNORE INTO story_relationships
            (story_id,event_a_id,event_b_id,score,reasons_json) VALUES (?,?,?,?,?)""",
            (story_id, a, b, int(edge.get("score", 0)), json.dumps(edge.get("reasons", []))))
    actual_events = connection.execute("SELECT COUNT(*) FROM story_events WHERE story_id=?", (story_id,)).fetchone()[0]
    actual_alerts = connection.execute("SELECT COUNT(*) FROM story_alert_links WHERE story_id=?", (story_id,)).fetchone()[0]
    connection.execute("""UPDATE attack_stories SET event_count=?,alert_count=?,severity=?,
        confidence_score=?,confidence_level=? WHERE id=?""",
        (actual_events, actual_alerts, severity, int(group.get("confidence_score", 0)),
         group.get("confidence_level", "LOW"), story_id))
    return story_id



def build_and_save_stories(events=None):
    print("\n========== TRACE-SOC STORY BUILDER ==========\n")

    # Use supplied events for bounded automated analysis.
    # Keep the old full-history behavior for manual execution.
    if events is None:
        events = get_all_events()

    print("Events loaded:", len(events))

    groups = build_correlation_groups(events)
    print("Correlation groups found:", len(groups))

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    saved = []

    try:
        evidence_map = load_alert_evidence(connection)

        with connection:
            for group in groups:
                story_id = save_story(
                    connection,
                    group,
                    evidence_map,
                )

                if story_id is not None:
                    saved.append(story_id)

    finally:
        connection.close()

    print("Stories created or updated:", len(saved))
    print("Story IDs:", saved)
    print("\n=============================================\n")

    return saved

if __name__ == "__main__":
    build_and_save_stories()
