"""Chronological, evidence-linked timeline for an investigation story."""
import json
from database.db import get_connection


def get_story_timeline(story_id):
    connection = get_connection()
    connection.row_factory = __import__("sqlite3").Row
    try:
        story = connection.execute("SELECT * FROM attack_stories WHERE id=?", (story_id,)).fetchone()
        if story is None:
            raise ValueError(f"Story {story_id} was not found")
        rows = connection.execute("""SELECT se.id AS story_event_link_id,
            se.relationship AS link_relationship,se.evidence_role,se.observed_at_utc,
            ne.id AS normalized_event_id,ne.event_id,ne.provider,ne.channel,ne.timestamp_utc,
            ne.hostname,ne.username,ne.process_id,ne.parent_process_id,ne.process_guid,
            ne.parent_process_guid,ne.image,ne.command_line,ne.source_ip,ne.destination_ip,
            ne.event_type,ne.extra_data_json,
            re.id AS raw_event_id,re.source_file,re.source_file_sha256,re.raw_xml_sha256,
            a.id AS alert_id,a.rule_id,a.rule_name,a.severity AS alert_severity,a.status AS alert_status
            FROM story_events se
            JOIN normalized_events ne ON ne.id=se.normalized_event_id
            LEFT JOIN raw_events re ON re.id=ne.raw_event_id
            LEFT JOIN alerts a ON a.id=se.alert_id
            WHERE se.story_id=?
            ORDER BY COALESCE(ne.timestamp_utc,se.observed_at_utc) ASC, ne.id ASC""", (story_id,)).fetchall()
        timeline = []
        for row in rows:
            item = dict(row)
            try:
                item["extra_data"] = json.loads(item.pop("extra_data_json") or "{}")
            except (json.JSONDecodeError, TypeError):
                item["extra_data"] = {}
            timeline.append(item)
        edges = connection.execute("""SELECT event_a_id,event_b_id,score,reasons_json
            FROM story_relationships WHERE story_id=? ORDER BY id""", (story_id,)).fetchall()
        relationships = []
        for edge in edges:
            item = dict(edge)
            try: item["reasons"] = json.loads(item.pop("reasons_json"))
            except (json.JSONDecodeError, TypeError): item["reasons"] = []
            relationships.append(item)
        return {"story": dict(story), "timeline": timeline, "relationships": relationships}
    finally:
        connection.close()


def print_story_timeline(story_id):
    result = get_story_timeline(story_id)
    story = result["story"]
    print("\n========== TRACE-SOC ATTACK TIMELINE ==========")
    print(f"Story #{story['id']}: {story['title']}")
    print(f"Severity: {story['severity']} | Status: {story['status']}")
    print(f"Host: {story['hostname'] or 'Unknown'} | User: {story['username'] or 'Unknown'}")
    print(f"Source IP: {story['source_ip'] or 'Unknown'}")
    for event in result["timeline"]:
        print(f"\n{event['timestamp_utc'] or 'Unknown time'} | Event {event['event_id']} | {event['event_type'] or 'Unclassified'}")
        print(f"  Host/User: {event['hostname'] or '-'} / {event['username'] or '-'}")
        print(f"  Source -> Destination: {event['source_ip'] or '-'} -> {event['destination_ip'] or '-'}")
        if event.get("image"): print(f"  Image: {event['image']}")
        if event.get("command_line"): print(f"  Command: {event['command_line']}")
        if event.get("alert_id"): print(f"  Alert: {event['rule_id']} - {event['rule_name']} ({event['alert_severity']})")
        print(f"  Raw evidence ID: {event['raw_event_id'] or 'Unavailable'}")
    print("\nCorrelation relationships:")
    for edge in result["relationships"]:
        print(f"  Event {edge['event_a_id']} <-> Event {edge['event_b_id']}: {edge['score']} ({', '.join(edge['reasons'])})")
    print("\nNOTE: Timeline entries are observed records; relationship edges are analytical inferences.")
    print("===============================================\n")
    return result
