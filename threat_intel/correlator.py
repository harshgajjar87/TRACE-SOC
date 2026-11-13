"""
TRACE-SOC Day 26 — IOC-to-Event Correlation Engine

Scans stored normalized events against active IOC indicators and builds
a persistent correlation result table. Each match records which event
matched which IOC, what field triggered the match, and a confidence
score derived from the IOC confidence and indicator type.

This is a best-effort correlation using local telemetry and locally
stored IOC intelligence. A match is a signal for analyst review; it
is not proof of compromise.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone

from database.db import get_connection
from threat_intel.engine import expire_indicators, _domain_or_hash_match


# Confidence multipliers per IOC type
_TYPE_CONFIDENCE_WEIGHT = {
    "IP": 1.0,
    "SHA256": 1.0,
    "MD5": 0.95,
    "SHA1": 0.95,
    "DOMAIN": 0.85,
    "URL": 0.80,
}

# Minimum IOC confidence to include in correlation runs
MIN_IOC_CONFIDENCE = 30


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _dict_rows(rows):
    return [dict(row) for row in rows]


def create_ioc_correlation_schema() -> None:
    """Create the IOC correlation results table. Safe to run repeatedly."""
    connection = get_connection()
    try:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS ioc_event_correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    normalized_event_id INTEGER NOT NULL,
                    ioc_id INTEGER NOT NULL,
                    ioc_type TEXT NOT NULL,
                    indicator TEXT NOT NULL,
                    matched_field TEXT NOT NULL,
                    match_confidence INTEGER NOT NULL,
                    ioc_severity TEXT NOT NULL,
                    ioc_source TEXT NOT NULL,
                    correlated_at_utc TEXT NOT NULL,
                    analyst_note TEXT,
                    UNIQUE(normalized_event_id, ioc_id)
                )
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_ioc_corr_event
                ON ioc_event_correlations(normalized_event_id)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_ioc_corr_ioc
                ON ioc_event_correlations(ioc_id)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_ioc_corr_indicator
                ON ioc_event_correlations(indicator)
            """)
            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_ioc_corr_severity
                ON ioc_event_correlations(ioc_severity)
            """)
    finally:
        connection.close()


def _extract_event_text(event: dict) -> str:
    """Build a searchable text blob from an event's key fields."""
    parts = []
    for key in ("image", "command_line", "extra_data_json"):
        v = event.get(key)
        if v:
            parts.append(str(v))
    return " ".join(parts).lower()


def _match_event_against_ioc(event: dict, ioc: dict) -> tuple[bool, str]:
    """
    Test one event against one IOC. Returns (matched, matched_field).
    matched_field is the name of the event field that triggered the match.
    """
    ioc_type = ioc["ioc_type"]
    indicator = ioc["indicator"]

    if ioc_type == "IP":
        src = str(event.get("source_ip") or "").strip()
        dst = str(event.get("destination_ip") or "").strip()
        if src == indicator:
            return True, "source_ip"
        if dst == indicator:
            return True, "destination_ip"
        return False, ""

    # For hash and domain/URL types, search event text fields
    text = _extract_event_text(event)
    if _domain_or_hash_match(indicator, text):
        return True, "event_text"

    return False, ""


def run_ioc_correlation(
    *,
    event_limit: int = 5000,
    ioc_limit: int = 2000,
) -> dict:
    """
    Scan stored normalized events against active IOCs and persist matches.

    Returns a summary of the run:
      events_scanned, iocs_checked, new_correlations, duplicate_correlations
    """
    create_ioc_correlation_schema()
    expire_indicators()

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        # Load active IOCs above minimum confidence threshold
        ioc_rows = connection.execute("""
            SELECT id, ioc_type, indicator, confidence, severity, source_name
            FROM ioc_indicators
            WHERE is_active = 1
              AND confidence >= ?
            ORDER BY confidence DESC
            LIMIT ?
        """, (MIN_IOC_CONFIDENCE, int(ioc_limit))).fetchall()

        iocs = _dict_rows(ioc_rows)

        if not iocs:
            return {
                "events_scanned": 0,
                "iocs_checked": 0,
                "new_correlations": 0,
                "duplicate_correlations": 0,
                "run_at_utc": _utc_now(),
            }

        # Load recent normalized events
        event_rows = connection.execute("""
            SELECT id AS normalized_event_id,
                   event_id, timestamp_utc, hostname, username,
                   source_ip, destination_ip,
                   image, command_line, extra_data_json
            FROM normalized_events
            ORDER BY id DESC
            LIMIT ?
        """, (int(event_limit),)).fetchall()

        events = _dict_rows(event_rows)

    finally:
        connection.close()

    new_count = 0
    dup_count = 0
    now = _utc_now()

    write_conn = get_connection()
    try:
        for event in events:
            eid = event["normalized_event_id"]
            for ioc in iocs:
                matched, matched_field = _match_event_against_ioc(event, ioc)
                if not matched:
                    continue

                # Compute weighted confidence
                weight = _TYPE_CONFIDENCE_WEIGHT.get(ioc["ioc_type"], 0.75)
                match_confidence = int(ioc["confidence"] * weight)

                try:
                    with write_conn:
                        write_conn.execute("""
                            INSERT INTO ioc_event_correlations (
                                normalized_event_id, ioc_id, ioc_type,
                                indicator, matched_field, match_confidence,
                                ioc_severity, ioc_source, correlated_at_utc
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            eid,
                            ioc["id"],
                            ioc["ioc_type"],
                            ioc["indicator"],
                            matched_field,
                            match_confidence,
                            ioc["severity"],
                            ioc["source_name"],
                            now,
                        ))
                    new_count += 1

                except sqlite3.IntegrityError:
                    # UNIQUE constraint: already correlated this pair
                    dup_count += 1

    finally:
        write_conn.close()

    return {
        "events_scanned": len(events),
        "iocs_checked": len(iocs),
        "new_correlations": new_count,
        "duplicate_correlations": dup_count,
        "run_at_utc": now,
    }


def get_correlations(
    *,
    ioc_severity: str | None = None,
    ioc_type: str | None = None,
    indicator: str | None = None,
    limit: int = 500,
) -> list[dict]:
    """Return stored IOC correlation results, optionally filtered."""
    create_ioc_correlation_schema()

    limit = max(1, min(int(limit), 5000))
    sql = """
        SELECT
            c.id,
            c.normalized_event_id,
            ne.timestamp_utc,
            ne.hostname,
            ne.username,
            ne.source_ip,
            ne.destination_ip,
            ne.event_id AS windows_event_id,
            ne.image,
            ne.command_line,
            c.ioc_type,
            c.indicator,
            c.matched_field,
            c.match_confidence,
            c.ioc_severity,
            c.ioc_source,
            c.correlated_at_utc,
            c.analyst_note
        FROM ioc_event_correlations c
        JOIN normalized_events ne
            ON ne.id = c.normalized_event_id
        WHERE 1=1
    """
    params: list = []

    if ioc_severity and ioc_severity != "ALL":
        sql += " AND c.ioc_severity = ?"
        params.append(ioc_severity.upper())

    if ioc_type and ioc_type != "ALL":
        sql += " AND c.ioc_type = ?"
        params.append(ioc_type.upper())

    if indicator and indicator.strip():
        sql += " AND c.indicator LIKE ?"
        params.append(f"%{indicator.strip()}%")

    sql += " ORDER BY c.correlated_at_utc DESC, c.match_confidence DESC LIMIT ?"
    params.append(limit)

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        return _dict_rows(connection.execute(sql, params).fetchall())
    finally:
        connection.close()


def get_correlation_summary() -> dict:
    """Return aggregate statistics about stored correlations."""
    create_ioc_correlation_schema()

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        total = connection.execute(
            "SELECT COUNT(*) AS cnt FROM ioc_event_correlations"
        ).fetchone()["cnt"]

        by_severity = connection.execute("""
            SELECT ioc_severity AS severity, COUNT(*) AS count
            FROM ioc_event_correlations
            GROUP BY ioc_severity
            ORDER BY count DESC
        """).fetchall()

        by_type = connection.execute("""
            SELECT ioc_type, COUNT(*) AS count
            FROM ioc_event_correlations
            GROUP BY ioc_type
            ORDER BY count DESC
        """).fetchall()

        affected_events = connection.execute("""
            SELECT COUNT(DISTINCT normalized_event_id) AS cnt
            FROM ioc_event_correlations
        """).fetchone()["cnt"]

        top_indicators = connection.execute("""
            SELECT indicator, ioc_type, COUNT(*) AS event_hits
            FROM ioc_event_correlations
            GROUP BY indicator, ioc_type
            ORDER BY event_hits DESC
            LIMIT 10
        """).fetchall()

        return {
            "total_correlations": total,
            "affected_events": affected_events,
            "by_severity": _dict_rows(by_severity),
            "by_type": _dict_rows(by_type),
            "top_indicators": _dict_rows(top_indicators),
        }

    finally:
        connection.close()


def add_analyst_note_to_correlation(correlation_id: int, note: str) -> bool:
    """Attach an analyst note to an existing correlation record."""
    create_ioc_correlation_schema()
    connection = get_connection()
    try:
        with connection:
            cursor = connection.execute("""
                UPDATE ioc_event_correlations
                SET analyst_note = ?
                WHERE id = ?
            """, (str(note).strip(), int(correlation_id)))
        return cursor.rowcount > 0
    finally:
        connection.close()
