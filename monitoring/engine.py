
"""TRACE-SOC monitoring history and health engine."""

from datetime import datetime, timezone

from database.db import create_tables, get_connection


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def create_monitoring_schema():
    """Create tables used by the continuous monitoring service."""
    create_tables()

    connection = get_connection()

    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS monitoring_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at_utc TEXT NOT NULL,
                completed_at_utc TEXT,
                status TEXT NOT NULL,
                total_received INTEGER DEFAULT 0,
                total_inserted INTEGER DEFAULT 0,
                total_duplicates INTEGER DEFAULT 0,
                channels_json TEXT,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS monitoring_status (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                service_status TEXT NOT NULL DEFAULT 'STOPPED',
                started_at_utc TEXT,
                last_run_at_utc TEXT,
                last_success_at_utc TEXT,
                last_error TEXT,
                polling_interval_seconds INTEGER DEFAULT 60,
                updated_at_utc TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_monitoring_runs_started
            ON monitoring_runs(started_at_utc);

            CREATE INDEX IF NOT EXISTS idx_monitoring_runs_status
            ON monitoring_runs(status);
            """
        )

        connection.execute(
            """
            INSERT OR IGNORE INTO monitoring_status (
                id,
                service_status,
                updated_at_utc
            )
            VALUES (1, 'STOPPED', ?)
            """,
            (utc_now(),),
        )

        connection.commit()

    finally:
        connection.close()


def update_service_status(
    status,
    polling_interval_seconds=None,
    last_error=None,
):
    """Update the current service status."""
    allowed = {"RUNNING", "STOPPED", "ERROR"}

    if status not in allowed:
        raise ValueError("Invalid monitoring service status.")

    connection = get_connection()

    try:
        connection.execute(
            """
            UPDATE monitoring_status
            SET service_status = ?,
                polling_interval_seconds = COALESCE(
                    ?, polling_interval_seconds
                ),
                last_error = ?,
                updated_at_utc = ?
            WHERE id = 1
            """,
            (
                status,
                polling_interval_seconds,
                last_error,
                utc_now(),
            ),
        )

        connection.commit()

    finally:
        connection.close()


def start_service(polling_interval_seconds):
    """Mark the monitoring service as running."""
    if polling_interval_seconds < 1:
        raise ValueError("Polling interval must be at least 1 second.")

    connection = get_connection()

    try:
        now = utc_now()

        connection.execute(
            """
            UPDATE monitoring_status
            SET service_status = 'RUNNING',
                started_at_utc = ?,
                polling_interval_seconds = ?,
                last_error = NULL,
                updated_at_utc = ?
            WHERE id = 1
            """,
            (now, polling_interval_seconds, now),
        )

        connection.commit()

    finally:
        connection.close()


def record_monitoring_run(
    status,
    summary=None,
    error_message=None,
    started_at=None,
):
    """Save one polling cycle and update service health."""
    if status not in {"SUCCESS", "FAILED"}:
        raise ValueError("Run status must be SUCCESS or FAILED.")

    summary = summary or {}
    started_at = started_at or utc_now()
    completed_at = utc_now()

    total_received = int(summary.get("total_received", 0))
    total_inserted = int(summary.get("total_inserted", 0))
    total_duplicates = int(summary.get("total_duplicates", 0))

    channels = summary.get("channels", {})

    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO monitoring_runs (
                started_at_utc,
                completed_at_utc,
                status,
                total_received,
                total_inserted,
                total_duplicates,
                channels_json,
                error_message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                started_at,
                completed_at,
                status,
                total_received,
                total_inserted,
                total_duplicates,
                __import__("json").dumps(channels),
                error_message,
            ),
        )

        if status == "SUCCESS":
            connection.execute(
                """
                UPDATE monitoring_status
                SET last_run_at_utc = ?,
                    last_success_at_utc = ?,
                    last_error = NULL,
                    updated_at_utc = ?
                WHERE id = 1
                """,
                (completed_at, completed_at, completed_at),
            )
        else:
            connection.execute(
                """
                UPDATE monitoring_status
                SET last_run_at_utc = ?,
                    last_error = ?,
                    updated_at_utc = ?
                WHERE id = 1
                """,
                (completed_at, error_message, completed_at),
            )

        connection.commit()

    finally:
        connection.close()


def get_monitoring_status():
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT service_status, started_at_utc,
                   last_run_at_utc, last_success_at_utc,
                   last_error, polling_interval_seconds,
                   updated_at_utc
            FROM monitoring_status
            WHERE id = 1
            """
        ).fetchone()

        if row is None:
            return {}

        return {
            "service_status": row[0],
            "started_at_utc": row[1],
            "last_run_at_utc": row[2],
            "last_success_at_utc": row[3],
            "last_error": row[4],
            "polling_interval_seconds": row[5],
            "updated_at_utc": row[6],
        }

    finally:
        connection.close()


def get_monitoring_runs(limit=50):
    if limit < 1:
        raise ValueError("Limit must be at least 1.")

    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT id, started_at_utc, completed_at_utc,
                   status, total_received, total_inserted,
                   total_duplicates, channels_json, error_message
            FROM monitoring_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [
            {
                "id": row[0],
                "started_at_utc": row[1],
                "completed_at_utc": row[2],
                "status": row[3],
                "total_received": row[4],
                "total_inserted": row[5],
                "total_duplicates": row[6],
                "channels_json": row[7],
                "error_message": row[8],
            }
            for row in rows
        ]

    finally:
        connection.close()


def get_monitoring_summary():
    connection = get_connection()

    try:
        totals = connection.execute(
            """
            SELECT
                COUNT(*),
                SUM(CASE WHEN status = 'SUCCESS' THEN 1 ELSE 0 END),
                SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END),
                COALESCE(SUM(total_received), 0),
                COALESCE(SUM(total_inserted), 0),
                COALESCE(SUM(total_duplicates), 0)
            FROM monitoring_runs
            """
        ).fetchone()

        return {
            "total_runs": totals[0] or 0,
            "successful_runs": totals[1] or 0,
            "failed_runs": totals[2] or 0,
            "total_received": totals[3] or 0,
            "total_inserted": totals[4] or 0,
            "total_duplicates": totals[5] or 0,
        }

    finally:
        connection.close()
