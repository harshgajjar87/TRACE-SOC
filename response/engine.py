"""TRACE-SOC analyst-approved incident response engine."""

import hashlib
import json
import sqlite3

from datetime import datetime, timezone

from database.db import get_connection
from response.playbooks import get_playbooks, get_playbook


def utc_now():
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def create_response_schema():
    """Create incident response tables."""

    conn = get_connection()

    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS response_playbook_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                playbook_id TEXT NOT NULL,
                playbook_name TEXT NOT NULL,
                status TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                approval_note TEXT,
                started_at_utc TEXT NOT NULL,
                completed_at_utc TEXT,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            );

            CREATE TABLE IF NOT EXISTS response_step_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                step_id TEXT NOT NULL,
                step_name TEXT NOT NULL,
                action_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                executed_at_utc TEXT NOT NULL,
                FOREIGN KEY(run_id)
                    REFERENCES response_playbook_runs(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS response_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                raw_event_id INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                verification_status TEXT NOT NULL,
                preserved_at_utc TEXT NOT NULL,
                UNIQUE(run_id, raw_event_id),
                FOREIGN KEY(run_id)
                    REFERENCES response_playbook_runs(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_response_alert
            ON response_playbook_runs(alert_id);

            CREATE INDEX IF NOT EXISTS idx_response_run
            ON response_step_logs(run_id);

            CREATE INDEX IF NOT EXISTS idx_response_evidence
            ON response_evidence(run_id);
        """)

        conn.commit()

    finally:
        conn.close()


def get_available_alerts():
    """Return alerts that can be investigated."""

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute("""
            SELECT
                id,
                rule_id,
                rule_name,
                severity,
                status,
                hostname,
                username,
                source_ip,
                description,
                created_at_utc
            FROM alerts
            ORDER BY id DESC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_alert_evidence(alert_id):
    """
    Retrieve normalized event IDs associated with an alert.

    Day 9 alert evidence stores normalized_event_ids in evidence_json.
    """

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        row = conn.execute("""
            SELECT evidence_json
            FROM alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        if not row:
            raise ValueError("Alert not found.")

        try:
            evidence = json.loads(row["evidence_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            evidence = {}

        event_ids = evidence.get("normalized_event_ids", [])

        if not isinstance(event_ids, list):
            event_ids = []

        valid_ids = []

        for event_id in event_ids:
            try:
                valid_ids.append(int(event_id))
            except (TypeError, ValueError):
                continue

        if not valid_ids:
            return []

        placeholders = ",".join("?" for _ in valid_ids)

        rows = conn.execute(f"""
            SELECT
                n.id AS normalized_event_id,
                r.id AS raw_event_id,
                r.raw_xml
            FROM normalized_events n
            JOIN raw_events r
                ON r.id = n.raw_event_id
            WHERE n.id IN ({placeholders})
            ORDER BY n.id
        """, valid_ids).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def preserve_alert_evidence(run_id, alert_id):
    """
    Record SHA-256 hashes of raw evidence linked to an alert.

    The original raw evidence is not modified or moved.
    """

    events = get_alert_evidence(alert_id)

    conn = get_connection()

    try:
        preserved_count = 0

        for event in events:
            raw_xml = event.get("raw_xml")

            if raw_xml is None:
                continue

            if isinstance(raw_xml, str):
                raw_bytes = raw_xml.encode("utf-8")
            else:
                raw_bytes = bytes(raw_xml)

            digest = hashlib.sha256(raw_bytes).hexdigest()

            conn.execute("""
                INSERT OR IGNORE INTO response_evidence (
                    run_id,
                    raw_event_id,
                    sha256,
                    verification_status,
                    preserved_at_utc
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                run_id,
                event["raw_event_id"],
                digest,
                "HASH_RECORDED",
                utc_now(),
            ))

            preserved_count += 1

        conn.commit()

        return preserved_count

    finally:
        conn.close()


def create_playbook_run(
    alert_id,
    playbook_id,
    approved_by,
    approval_note="",
):
    """
    Create and execute an analyst-approved playbook.

    No external system or host configuration is modified.
    """

    playbook = get_playbook(playbook_id)

    if not playbook:
        raise ValueError("Unknown playbook.")

    approved_by = str(approved_by).strip()

    if not approved_by:
        raise ValueError("Analyst name is required.")

    if len(approved_by) > 120:
        raise ValueError("Analyst name must be 120 characters or fewer.")

    conn = get_connection()

    try:
        alert = conn.execute("""
            SELECT id
            FROM alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        if not alert:
            raise ValueError("Selected alert does not exist.")

        cursor = conn.execute("""
            INSERT INTO response_playbook_runs (
                alert_id,
                playbook_id,
                playbook_name,
                status,
                approved_by,
                approval_note,
                started_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            playbook_id,
            playbook["name"],
            "RUNNING",
            approved_by,
            str(approval_note).strip(),
            utc_now(),
        ))

        run_id = cursor.lastrowid
        conn.commit()

    finally:
        conn.close()

    try:
        for step in playbook["steps"]:

            details = step["description"]

            if step["action_type"] == "EVIDENCE_PRESERVATION":
                count = preserve_alert_evidence(run_id, alert_id)
                details += (
                    f" Evidence records hashed: {count}. "
                    "Original evidence was not modified."
                )

            elif step["action_type"] == "RECOMMENDATION":
                details += (
                    " Recommendation recorded for analyst review. "
                    "No external action was performed."
                )

            elif step["action_type"] == "ESCALATION":
                details += (
                    " Escalation recommendation recorded. "
                    "No external notification was sent."
                )

            elif step["action_type"] == "SCOPE_ASSESSMENT":
                details += (
                    " Scope assessment guidance recorded. "
                    "No automated system changes were performed."
                )

            else:
                details += " Analyst review step recorded."

            step_conn = get_connection()

            try:
                step_conn.execute("""
                    INSERT INTO response_step_logs (
                        run_id,
                        step_id,
                        step_name,
                        action_type,
                        status,
                        details,
                        executed_at_utc
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    run_id,
                    step["id"],
                    step["name"],
                    step["action_type"],
                    "COMPLETED",
                    details,
                    utc_now(),
                ))

                step_conn.commit()

            finally:
                step_conn.close()

        final_conn = get_connection()

        try:
            final_conn.execute("""
                UPDATE response_playbook_runs
                SET status = ?, completed_at_utc = ?
                WHERE id = ?
            """, (
                "COMPLETED",
                utc_now(),
                run_id,
            ))

            final_conn.commit()

        finally:
            final_conn.close()

        return run_id

    except Exception:
        error_conn = get_connection()

        try:
            error_conn.execute("""
                UPDATE response_playbook_runs
                SET status = ?, completed_at_utc = ?
                WHERE id = ?
            """, (
                "FAILED",
                utc_now(),
                run_id,
            ))

            error_conn.commit()

        finally:
            error_conn.close()

        raise


def get_response_runs(alert_id=None, limit=100):
    """Retrieve response playbook execution history."""

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        if alert_id is None:
            rows = conn.execute("""
                SELECT *
                FROM response_playbook_runs
                ORDER BY id DESC
                LIMIT ?
            """, (limit,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT *
                FROM response_playbook_runs
                WHERE alert_id = ?
                ORDER BY id DESC
                LIMIT ?
            """, (alert_id, limit)).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_run_details(run_id):
    """Retrieve a playbook run and its associated logs and evidence."""

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        run = conn.execute("""
            SELECT *
            FROM response_playbook_runs
            WHERE id = ?
        """, (run_id,)).fetchone()

        if not run:
            return None

        steps = conn.execute("""
            SELECT *
            FROM response_step_logs
            WHERE run_id = ?
            ORDER BY id
        """, (run_id,)).fetchall()

        evidence = conn.execute("""
            SELECT *
            FROM response_evidence
            WHERE run_id = ?
            ORDER BY id
        """, (run_id,)).fetchall()

        return {
            "run": dict(run),
            "steps": [dict(row) for row in steps],
            "evidence": [dict(row) for row in evidence],
        }

    finally:
        conn.close()


def verify_response_evidence(run_id):
    """Recalculate hashes and compare them with recorded evidence hashes."""

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute("""
            SELECT
                e.raw_event_id,
                e.sha256 AS recorded_sha256,
                r.raw_xml
            FROM response_evidence e
            JOIN raw_events r
                ON r.id = e.raw_event_id
            WHERE e.run_id = ?
        """, (run_id,)).fetchall()

        results = []

        for row in rows:
            raw_xml = row["raw_xml"]

            if isinstance(raw_xml, str):
                raw_bytes = raw_xml.encode("utf-8")
            else:
                raw_bytes = bytes(raw_xml or b"")

            current_hash = hashlib.sha256(raw_bytes).hexdigest()

            results.append({
                "raw_event_id": row["raw_event_id"],
                "recorded_sha256": row["recorded_sha256"],
                "current_sha256": current_hash,
                "verified": current_hash == row["recorded_sha256"],
            })

        return results

    finally:
        conn.close()