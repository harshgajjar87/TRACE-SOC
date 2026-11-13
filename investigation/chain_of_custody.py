
"""TRACE-SOC Day 22: evidence inventory and chain-of-custody audit trail."""

import hashlib
import json
from datetime import datetime, timezone

from database.db import get_connection


VALID_ACTIONS = {
    "COLLECTED",
    "ACCESSED",
    "VERIFIED",
    "EXPORTED",
    "NOTE_ADDED",
}


def _now_utc():
    return datetime.now(timezone.utc).isoformat()


def create_chain_of_custody_schema():
    """Create the custody audit table. Safe to run repeatedly."""
    connection = get_connection()
    try:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS evidence_custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    raw_event_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT,
                    recorded_at_utc TEXT NOT NULL,
                    sha256 TEXT,
                    details_json TEXT,
                    FOREIGN KEY(raw_event_id)
                        REFERENCES raw_events(id) ON DELETE RESTRICT
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_custody_event
                ON evidence_custody(raw_event_id)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_custody_time
                ON evidence_custody(recorded_at_utc)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_custody_action
                ON evidence_custody(action)
            """)
    finally:
        connection.close()


def record_custody_event(
    raw_event_id,
    action,
    actor,
    reason="",
    sha256=None,
    details=None,
):
    """Append an audit record. Existing audit records are never updated."""
    action = str(action).strip().upper()
    actor = str(actor).strip()

    if action not in VALID_ACTIONS:
        raise ValueError(f"Unsupported custody action: {action}")
    if not actor:
        raise ValueError("Analyst identity is required.")

    create_chain_of_custody_schema()
    connection = get_connection()
    try:
        exists = connection.execute(
            "SELECT id FROM raw_events WHERE id=?",
            (int(raw_event_id),),
        ).fetchone()

        if exists is None:
            raise ValueError(f"Raw event {raw_event_id} was not found.")

        with connection:
            cursor = connection.execute("""
                INSERT INTO evidence_custody (
                    raw_event_id, action, actor, reason,
                    recorded_at_utc, sha256, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                int(raw_event_id),
                action,
                actor,
                str(reason or "").strip(),
                _now_utc(),
                sha256,
                json.dumps(details or {}, sort_keys=True),
            ))
            return cursor.lastrowid
    finally:
        connection.close()


def get_evidence_inventory(limit=500):
    """Return the newest raw evidence records and their latest custody action."""
    create_chain_of_custody_schema()
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT
                re.id AS raw_event_id,
                re.source_file,
                re.source_file_sha256,
                re.raw_xml_sha256,
                re.event_id,
                re.provider,
                re.channel,
                re.record_id,
                re.timestamp_utc,
                re.hostname,
                re.collected_at_utc,
                (
                    SELECT ec.action
                    FROM evidence_custody ec
                    WHERE ec.raw_event_id = re.id
                    ORDER BY ec.id DESC LIMIT 1
                ) AS latest_action,
                (
                    SELECT ec.actor
                    FROM evidence_custody ec
                    WHERE ec.raw_event_id = re.id
                    ORDER BY ec.id DESC LIMIT 1
                ) AS latest_actor
            FROM raw_events re
            ORDER BY re.id DESC
            LIMIT ?
        """, (max(1, min(int(limit), 5000)),)).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_custody_history(raw_event_id):
    """Return the append-only custody history for one raw event."""
    create_chain_of_custody_schema()
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT id, raw_event_id, action, actor, reason,
                   recorded_at_utc, sha256, details_json
            FROM evidence_custody
            WHERE raw_event_id=?
            ORDER BY id ASC
        """, (int(raw_event_id),)).fetchall()

        results = []
        for row in rows:
            item = dict(row)
            try:
                item["details"] = json.loads(item.pop("details_json") or "{}")
            except (TypeError, json.JSONDecodeError):
                item["details"] = {}
            results.append(item)
        return results
    finally:
        connection.close()


def get_raw_event_blob(raw_event_id):
    """Return the stored original XML bytes without modifying them."""
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT raw_xml FROM raw_events WHERE id=?",
            (int(raw_event_id),),
        ).fetchone()

        if row is None:
            raise ValueError(f"Raw event {raw_event_id} was not found.")

        blob = row[0]
        if isinstance(blob, str):
            blob = blob.encode("utf-8")
        return bytes(blob or b"")
    finally:
        connection.close()


def build_evidence_manifest(raw_event_id, verification, actor, reason=""):
    """Build a JSON-serializable export manifest for one evidence item."""
    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT id, source_file, source_file_sha256, raw_xml_sha256,
                   event_id, provider, channel, record_id,
                   timestamp_utc, hostname, collected_at_utc
            FROM raw_events
            WHERE id=?
        """, (int(raw_event_id),)).fetchone()

        if row is None:
            raise ValueError(f"Raw event {raw_event_id} was not found.")

        return {
            "product": "TRACE-SOC",
            "artifact_type": "digital_forensic_evidence_manifest",
            "generated_at_utc": _now_utc(),
            "generated_by": actor,
            "export_reason": reason,
            "evidence": dict(row),
            "integrity_verification": verification,
            "integrity_note": (
                "A matching SHA-256 value confirms that the stored XML bytes "
                "match the recorded baseline. It does not independently prove "
                "source authenticity, acquisition circumstances, or the "
                "accuracy of the original collection timestamp."
            ),
        }
    finally:
        connection.close()
