
import sqlite3
from datetime import datetime, timezone

from database.db import get_connection


VALID_STATUSES = {
    "NEW",
    "INVESTIGATING",
    "RESOLVED",
    "FALSE_POSITIVE"
}


def create_alert_management_tables():

    connection = get_connection()

    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alert_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                analyst_note TEXT,
                changed_at_utc TEXT NOT NULL,

                FOREIGN KEY (alert_id)
                    REFERENCES alerts(id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS
            idx_alert_history_alert
            ON alert_status_history(alert_id)
        """)

        connection.commit()

        print("Alert management tables ready!")

    finally:
        connection.close()


def get_alerts(status=None, severity=None, search=None):

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        query = """
            SELECT *
            FROM alerts
            WHERE 1=1
        """

        params = []

        if status and status != "ALL":
            query += " AND UPPER(status) = ?"
            params.append(status.upper())

        if severity and severity != "ALL":
            query += " AND UPPER(severity) = ?"
            params.append(severity.upper())

        if search:
            query += """
                AND (
                    rule_id LIKE ?
                    OR rule_name LIKE ?
                    OR hostname LIKE ?
                    OR username LIKE ?
                    OR source_ip LIKE ?
                )
            """

            value = f"%{search}%"
            params.extend([value] * 5)

        query += " ORDER BY created_at_utc DESC"

        rows = connection.execute(
            query, params
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def update_alert_status(
    alert_id,
    new_status,
    analyst_note=""
):

    new_status = new_status.upper()

    if new_status not in VALID_STATUSES:
        raise ValueError("Invalid alert status")

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        with connection:

            alert = connection.execute("""
                SELECT id, status
                FROM alerts
                WHERE id = ?
            """, (alert_id,)).fetchone()

            if alert is None:
                raise ValueError("Alert not found")

            old_status = alert["status"]

            if old_status.upper() == new_status:
                return False

            now = datetime.now(
                timezone.utc
            ).isoformat()

            connection.execute("""
                UPDATE alerts
                SET status = ?
                WHERE id = ?
            """, (new_status, alert_id))

            connection.execute("""
                INSERT INTO alert_status_history (
                    alert_id,
                    old_status,
                    new_status,
                    analyst_note,
                    changed_at_utc
                )
                VALUES (?, ?, ?, ?, ?)
            """, (
                alert_id,
                old_status,
                new_status,
                analyst_note.strip() or None,
                now
            ))

        return True

    finally:
        connection.close()


def get_alert_history(alert_id):

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute("""
            SELECT *
            FROM alert_status_history
            WHERE alert_id = ?
            ORDER BY changed_at_utc DESC
        """, (alert_id,)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()
