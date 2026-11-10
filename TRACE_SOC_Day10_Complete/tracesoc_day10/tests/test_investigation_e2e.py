import hashlib
import json
import sqlite3

import database.db as db
from database.db import create_tables
from investigation.story_schema import create_story_tables
from investigation.story_builder import build_and_save_stories
from investigation.timeline import get_story_timeline
from investigation.evidence import verify_raw_event_integrity, get_story_evidence
from investigation.investigation_queries import list_stories, get_investigation


def test_complete_investigation_pipeline(tmp_path, monkeypatch):
    test_db = tmp_path / "trace_soc_day10.db"
    monkeypatch.setattr(db, "DATABASE_PATH", test_db)
    create_tables()
    create_story_tables()

    conn = db.get_connection()
    conn.row_factory = sqlite3.Row
    raw_ids = []
    event_ids = []
    try:
        for index, (stamp, record) in enumerate([
            ("2026-11-09T10:00:00Z", "<Event><EventID>4625</EventID></Event>"),
            ("2026-11-09T10:02:00Z", "<Event><EventID>4625</EventID></Event>"),
        ], start=1):
            raw = record.encode("utf-8")
            digest = hashlib.sha256(raw).hexdigest()
            cur = conn.execute("""INSERT INTO raw_events
                (event_fingerprint,source_file,source_file_sha256,raw_xml,event_id,provider,
                 channel,record_id,timestamp_utc,hostname,collected_at_utc,raw_xml_sha256)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (f"raw-fp-{index}", "synthetic.evtx", "source-file-hash", raw,
                 "4625", "Microsoft-Windows-Security-Auditing", "Security", str(index),
                 stamp, "LAB-PC", stamp, digest))
            raw_id = cur.lastrowid
            raw_ids.append(raw_id)
            cur = conn.execute("""INSERT INTO normalized_events
                (raw_event_id,event_id,record_id,provider,channel,timestamp_utc,hostname,
                 username,source_ip,event_type,extra_data_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (raw_id, "4625", str(index), "Microsoft-Windows-Security-Auditing",
                 "Security", stamp, "LAB-PC", "analyst-test", "192.0.2.55",
                 "authentication", json.dumps({"test": True})))
            event_ids.append(cur.lastrowid)

        conn.execute("""INSERT INTO alerts
            (alert_fingerprint,rule_id,rule_name,description,severity,status,hostname,
             username,source_ip,first_seen,last_seen,event_count,mitre_tactic,
             mitre_technique,evidence_json,created_at_utc)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            ("alert-fp-1", "TS001", "Failed Login Detection", "Synthetic failed logins",
             "HIGH", "NEW", "LAB-PC", "analyst-test", "192.0.2.55",
             "2026-11-09T10:00:00Z", "2026-11-09T10:02:00Z", 2,
             "Credential Access", "T1110",
             json.dumps({"normalized_event_ids": [event_ids[0]]}),
             "2026-11-09T10:03:00Z"))
        conn.commit()
    finally:
        conn.close()

    # Build twice; story and links must remain unique.
    first_run_ids = build_and_save_stories()
    second_run_ids = build_and_save_stories()
    assert len(first_run_ids) == 1
    assert first_run_ids == second_run_ids
    story_id = first_run_ids[0]

    timeline = get_story_timeline(story_id)
    assert len(timeline["timeline"]) == 2
    assert timeline["timeline"][0]["timestamp_utc"] <= timeline["timeline"][1]["timestamp_utc"]
    assert timeline["timeline"][0]["raw_event_id"] is not None
    assert timeline["timeline"][0]["alert_id"] is not None
    assert len(timeline["relationships"]) == 1

    evidence = get_story_evidence(story_id)
    assert len(evidence) == 2
    for item in evidence:
        result = verify_raw_event_integrity(item["raw_event_id"])
        assert result["status"] == "VERIFIED"

    stories = list_stories()
    assert len(stories) == 1
    full = get_investigation(story_id)
    assert len(full["alerts"]) == 1
    assert len(full["timeline"]) == 2

    conn = db.get_connection()
    try:
        assert conn.execute("SELECT COUNT(*) FROM story_events").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM story_relationships").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM story_alert_links").fetchone()[0] == 1
    finally:
        conn.close()
