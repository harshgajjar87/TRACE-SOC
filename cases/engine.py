
"""TRACE-SOC incident case management engine."""

import sqlite3

from datetime import datetime, timezone

from database.db import get_connection


CASE_STATUSES = (
    "OPEN",
    "IN_PROGRESS",
    "ESCALATED",
    "RESOLVED",
    "CLOSED",
)

CASE_PRIORITIES = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
)


def utc_now():
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def create_case_schema():
    """Create case management tables and indexes."""

    conn = get_connection()

    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS incident_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN',
                priority TEXT NOT NULL DEFAULT 'MEDIUM',
                assigned_to TEXT,
                created_by TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                resolved_at_utc TEXT,
                closed_at_utc TEXT
            );

            CREATE TABLE IF NOT EXISTS case_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                linked_at_utc TEXT NOT NULL,
                UNIQUE(case_id, alert_id),
                FOREIGN KEY(case_id)
                    REFERENCES incident_cases(id)
                    ON DELETE CASCADE,
                FOREIGN KEY(alert_id)
                    REFERENCES alerts(id)
            );

            CREATE TABLE IF NOT EXISTS case_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                analyst TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(case_id)
                    REFERENCES incident_cases(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS case_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                activity_type TEXT NOT NULL,
                description TEXT NOT NULL,
                performed_by TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                FOREIGN KEY(case_id)
                    REFERENCES incident_cases(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_cases_status
            ON incident_cases(status);

            CREATE INDEX IF NOT EXISTS idx_cases_priority
            ON incident_cases(priority);

            CREATE INDEX IF NOT EXISTS idx_cases_assigned
            ON incident_cases(assigned_to);

            CREATE INDEX IF NOT EXISTS idx_case_alerts_case
            ON case_alerts(case_id);

            CREATE INDEX IF NOT EXISTS idx_case_notes_case
            ON case_notes(case_id);

            CREATE INDEX IF NOT EXISTS idx_case_activity_case
            ON case_activity(case_id);
        """)

        conn.commit()

    finally:
        conn.close()


def _record_activity(
    conn,
    case_id,
    activity_type,
    description,
    performed_by,
):
    """Record an auditable case activity."""

    conn.execute("""
        INSERT INTO case_activity (
            case_id,
            activity_type,
            description,
            performed_by,
            created_at_utc
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        case_id,
        activity_type,
        description,
        performed_by,
        utc_now(),
    ))


def create_case(
    title,
    description,
    priority,
    created_by,
    assigned_to=None,
    alert_ids=None,
    allow_duplicate=False,
):
    """Create a case and optionally link existing alerts."""

    title = str(title or "").strip()
    description = str(description or "").strip()
    created_by = str(created_by or "").strip()
    assigned_to = str(assigned_to or "").strip() or None
    priority = str(priority or "").upper().strip()

    if not title:
        raise ValueError("Case title is required.")

    if len(title) > 200:
        raise ValueError("Case title must be 200 characters or fewer.")

    if not created_by:
        raise ValueError("Created-by analyst is required.")

    if priority not in CASE_PRIORITIES:
        raise ValueError("Invalid case priority.")

    if len(created_by) > 120:
        raise ValueError("Analyst name must be 120 characters or fewer.")

    if assigned_to and len(assigned_to) > 120:
        raise ValueError("Assigned analyst must be 120 characters or fewer.")

    alert_ids = alert_ids or []

    try:
        alert_ids = list(dict.fromkeys(int(value) for value in alert_ids))
    except (TypeError, ValueError):
        raise ValueError("Alert IDs must be valid integers.")

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        # Prevent creating duplicate active cases with identical title
        if not allow_duplicate:
            existing = conn.execute("""
                SELECT id, case_number, status
                FROM incident_cases
                WHERE LOWER(TRIM(title)) = LOWER(?)
                  AND status IN ('OPEN', 'IN_PROGRESS')
            """, (title,)).fetchone()

            if existing:
                raise ValueError(
                    f"An active case with the title '{title}' already exists ({existing['case_number']}). "
                    "Duplicating active cases is not permitted. Please update the existing case or choose a distinct title."
                )

        # Validate all alerts before creating the case.
        for alert_id in alert_ids:
            alert = conn.execute("""
                SELECT id
                FROM alerts
                WHERE id = ?
            """, (alert_id,)).fetchone()

            if not alert:
                raise ValueError(f"Alert {alert_id} does not exist.")

        now = utc_now()

        cursor = conn.execute("""
            INSERT INTO incident_cases (
                case_number,
                title,
                description,
                status,
                priority,
                assigned_to,
                created_by,
                created_at_utc,
                updated_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "PENDING",
            title,
            description,
            "OPEN",
            priority,
            assigned_to,
            created_by,
            now,
            now,
        ))

        case_id = cursor.lastrowid

        case_number = f"TRACE-CASE-{case_id:05d}"

        conn.execute("""
            UPDATE incident_cases
            SET case_number = ?
            WHERE id = ?
        """, (case_number, case_id))

        _record_activity(
            conn,
            case_id,
            "CASE_CREATED",
            f"Case created: {title}",
            created_by,
        )

        if assigned_to:
            _record_activity(
                conn,
                case_id,
                "CASE_ASSIGNED",
                f"Case assigned to {assigned_to}",
                created_by,
            )

        for alert_id in alert_ids:

            conn.execute("""
                INSERT INTO case_alerts (
                    case_id,
                    alert_id,
                    linked_at_utc
                )
                VALUES (?, ?, ?)
            """, (
                case_id,
                alert_id,
                utc_now(),
            ))

            _record_activity(
                conn,
                case_id,
                "ALERT_LINKED",
                f"Alert #{alert_id} linked to case.",
                created_by,
            )

        conn.commit()

        return case_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_cases(
    status=None,
    priority=None,
    assigned_to=None,
    limit=200,
):
    """Return cases with linked alert counts."""

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        query = """
            SELECT
                c.*,
                COUNT(ca.alert_id) AS alert_count
            FROM incident_cases c
            LEFT JOIN case_alerts ca
                ON ca.case_id = c.id
            WHERE 1 = 1
        """

        params = []

        if status and status != "ALL":
            query += " AND c.status = ?"
            params.append(status)

        if priority and priority != "ALL":
            query += " AND c.priority = ?"
            params.append(priority)

        if assigned_to:
            query += " AND c.assigned_to = ?"
            params.append(assigned_to)

        query += """
            GROUP BY c.id
            ORDER BY c.id DESC
            LIMIT ?
        """

        params.append(max(1, min(int(limit), 1000)))

        rows = conn.execute(query, params).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_case_details(case_id):
    """Return case information, linked alerts, notes and activity."""

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        case = conn.execute("""
            SELECT *
            FROM incident_cases
            WHERE id = ?
        """, (case_id,)).fetchone()

        if not case:
            return None

        alerts = conn.execute("""
            SELECT
                a.id,
                a.rule_id,
                a.rule_name,
                a.severity,
                a.status,
                a.hostname,
                a.username,
                a.source_ip,
                a.description,
                ca.linked_at_utc
            FROM case_alerts ca
            JOIN alerts a
                ON a.id = ca.alert_id
            WHERE ca.case_id = ?
            ORDER BY a.id DESC
        """, (case_id,)).fetchall()

        notes = conn.execute("""
            SELECT *
            FROM case_notes
            WHERE case_id = ?
            ORDER BY id DESC
        """, (case_id,)).fetchall()

        activity = conn.execute("""
            SELECT *
            FROM case_activity
            WHERE case_id = ?
            ORDER BY id DESC
        """, (case_id,)).fetchall()

        return {
            "case": dict(case),
            "alerts": [dict(row) for row in alerts],
            "notes": [dict(row) for row in notes],
            "activity": [dict(row) for row in activity],
        }

    finally:
        conn.close()


def add_alert_to_case(case_id, alert_id, performed_by):
    """Link an existing alert to an existing case."""

    performed_by = str(performed_by or "").strip()

    if not performed_by:
        raise ValueError("Analyst name is required.")

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        case = conn.execute("""
            SELECT id
            FROM incident_cases
            WHERE id = ?
        """, (case_id,)).fetchone()

        if not case:
            raise ValueError("Case does not exist.")

        alert = conn.execute("""
            SELECT id
            FROM alerts
            WHERE id = ?
        """, (alert_id,)).fetchone()

        if not alert:
            raise ValueError("Alert does not exist.")

        existing = conn.execute("""
            SELECT id
            FROM case_alerts
            WHERE case_id = ? AND alert_id = ?
        """, (case_id, alert_id)).fetchone()

        if existing:
            raise ValueError("Alert is already linked to this case.")

        conn.execute("""
            INSERT INTO case_alerts (
                case_id,
                alert_id,
                linked_at_utc
            )
            VALUES (?, ?, ?)
        """, (case_id, alert_id, utc_now()))

        conn.execute("""
            UPDATE incident_cases
            SET updated_at_utc = ?
            WHERE id = ?
        """, (utc_now(), case_id))

        _record_activity(
            conn,
            case_id,
            "ALERT_LINKED",
            f"Alert #{alert_id} linked to case.",
            performed_by,
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def add_case_note(case_id, analyst, note):
    """Add an analyst investigation note."""

    analyst = str(analyst or "").strip()
    note = str(note or "").strip()

    if not analyst:
        raise ValueError("Analyst name is required.")

    if not note:
        raise ValueError("Note cannot be empty.")

    if len(analyst) > 120:
        raise ValueError("Analyst name must be 120 characters or fewer.")

    if len(note) > 10000:
        raise ValueError("Note must be 10,000 characters or fewer.")

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        case = conn.execute("""
            SELECT id
            FROM incident_cases
            WHERE id = ?
        """, (case_id,)).fetchone()

        if not case:
            raise ValueError("Case does not exist.")

        conn.execute("""
            INSERT INTO case_notes (
                case_id,
                analyst,
                note,
                created_at_utc
            )
            VALUES (?, ?, ?, ?)
        """, (
            case_id,
            analyst,
            note,
            utc_now(),
        ))

        conn.execute("""
            UPDATE incident_cases
            SET updated_at_utc = ?
            WHERE id = ?
        """, (utc_now(), case_id))

        _record_activity(
            conn,
            case_id,
            "NOTE_ADDED",
            f"Investigation note added by {analyst}.",
            analyst,
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def update_case(
    case_id,
    performed_by,
    status=None,
    priority=None,
    assigned_to=None,
):
    """Update case status, priority or analyst assignment."""

    performed_by = str(performed_by or "").strip()

    if not performed_by:
        raise ValueError("Analyst name is required.")

    if status is not None:
        status = str(status).upper().strip()

        if status not in CASE_STATUSES:
            raise ValueError("Invalid case status.")

    if priority is not None:
        priority = str(priority).upper().strip()

        if priority not in CASE_PRIORITIES:
            raise ValueError("Invalid case priority.")

    if assigned_to is not None:
        assigned_to = str(assigned_to).strip() or None

        if assigned_to and len(assigned_to) > 120:
            raise ValueError("Assigned analyst must be 120 characters or fewer.")

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        case = conn.execute("""
            SELECT *
            FROM incident_cases
            WHERE id = ?
        """, (case_id,)).fetchone()

        if not case:
            raise ValueError("Case does not exist.")

        changes = {}

        if status is not None and status != case["status"]:
            changes["status"] = status

        if priority is not None and priority != case["priority"]:
            changes["priority"] = priority

        if assigned_to is not None and assigned_to != case["assigned_to"]:
            changes["assigned_to"] = assigned_to

        if not changes:
            return

        now = utc_now()

        for field, value in changes.items():

            old_value = case[field]

            conn.execute(
                f"UPDATE incident_cases SET {field} = ? WHERE id = ?",
                (value, case_id),
            )

            _record_activity(
                conn,
                case_id,
                field.upper() + "_CHANGED",
                f"{field.replace('_', ' ').title()} changed from "
                f"{old_value or 'None'} to {value or 'None'}.",
                performed_by,
            )

        if status == "RESOLVED":
            conn.execute("""
                UPDATE incident_cases
                SET resolved_at_utc = ?
                WHERE id = ?
            """, (now, case_id))

        elif status == "CLOSED":
            conn.execute("""
                UPDATE incident_cases
                SET closed_at_utc = ?
                WHERE id = ?
            """, (now, case_id))

        elif status in ("OPEN", "IN_PROGRESS", "ESCALATED"):
            conn.execute("""
                UPDATE incident_cases
                SET resolved_at_utc = NULL,
                    closed_at_utc = NULL
                WHERE id = ?
            """, (case_id,))

        conn.execute("""
            UPDATE incident_cases
            SET updated_at_utc = ?
            WHERE id = ?
        """, (now, case_id))

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_case_summary():
    """Return case management dashboard statistics."""

    conn = get_connection()
    conn.row_factory = sqlite3.Row

    try:
        total = conn.execute("""
            SELECT COUNT(*) FROM incident_cases
        """).fetchone()[0]

        status_rows = conn.execute("""
            SELECT status, COUNT(*) AS count
            FROM incident_cases
            GROUP BY status
        """).fetchall()

        priority_rows = conn.execute("""
            SELECT priority, COUNT(*) AS count
            FROM incident_cases
            GROUP BY priority
        """).fetchall()

        assigned = conn.execute("""
            SELECT COUNT(*)
            FROM incident_cases
            WHERE assigned_to IS NOT NULL
              AND assigned_to != ''
        """).fetchone()[0]

        return {
            "total": total,
            "assigned": assigned,
            "by_status": {
                row["status"]: row["count"]
                for row in status_rows
            },
            "by_priority": {
                row["priority"]: row["count"]
                for row in priority_rows
            },
        }

    finally:
        conn.close()
