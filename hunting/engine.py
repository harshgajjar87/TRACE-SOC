
"""TRACE-SOC Advanced Threat Hunting Engine."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from database.db import get_connection


HUNT_TYPES = (
    "GENERAL",
    "IP",
    "DOMAIN",
    "HASH",
    "PROCESS",
    "COMMAND_LINE",
)


def create_hunting_schema() -> None:
    """Create saved-hunt storage without modifying existing records."""
    connection = get_connection()

    try:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS saved_hunts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    hunt_type TEXT NOT NULL,
                    query_json TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_saved_hunts_name
                ON saved_hunts(name)
            """)

    finally:
        connection.close()


def _dict_rows(rows):
    return [dict(row) for row in rows]


def _normalize_text(value):
    if value is None:
        return None

    value = str(value).strip()
    return value if value else None


def search_hunt(
    *,
    hunt_type="GENERAL",
    indicator=None,
    hostname=None,
    username=None,
    event_id=None,
    event_type=None,
    start_time=None,
    end_time=None,
    limit=300,
):
    """
    Search normalized telemetry.

    IP searches check source_ip and destination_ip.
    Domain/hash searches inspect stored event text and extra_data_json.
    Process searches inspect image and command_line.
    """

    hunt_type = str(hunt_type).upper()

    if hunt_type not in HUNT_TYPES:
        raise ValueError(
            f"Unsupported hunt type. Choose: {', '.join(HUNT_TYPES)}"
        )

    limit = max(1, min(int(limit), 2000))
    indicator = _normalize_text(indicator)

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        sql = """
            SELECT
                ne.id AS normalized_event_id,
                ne.raw_event_id,
                ne.event_id,
                ne.provider,
                ne.channel,
                ne.record_id,
                ne.timestamp_utc,
                ne.hostname,
                ne.username,
                ne.process_id,
                ne.parent_process_id,
                ne.process_guid,
                ne.parent_process_guid,
                ne.image,
                ne.command_line,
                ne.source_ip,
                ne.destination_ip,
                ne.event_type,
                ne.extra_data_json,
                re.source_file,
                re.raw_xml_sha256
            FROM normalized_events ne
            LEFT JOIN raw_events re
                ON re.id = ne.raw_event_id
            WHERE 1=1
        """

        params: list[Any] = []

        if hostname:
            sql += " AND ne.hostname LIKE ?"
            params.append(f"%{hostname.strip()}%")

        if username:
            sql += " AND ne.username LIKE ?"
            params.append(f"%{username.strip()}%")

        if event_id:
            sql += " AND ne.event_id = ?"
            params.append(str(event_id).strip())

        if event_type:
            sql += " AND ne.event_type LIKE ?"
            params.append(f"%{event_type.strip()}%")

        if start_time:
            sql += " AND ne.timestamp_utc >= ?"
            params.append(start_time)

        if end_time:
            sql += " AND ne.timestamp_utc <= ?"
            params.append(end_time)

        if indicator:
            pattern = f"%{indicator}%"

            if hunt_type == "IP":
                sql += """
                    AND (
                        ne.source_ip = ?
                        OR ne.destination_ip = ?
                    )
                """
                params.extend([indicator, indicator])

            elif hunt_type == "PROCESS":
                sql += """
                    AND (
                        ne.image LIKE ?
                        OR ne.command_line LIKE ?
                    )
                """
                params.extend([pattern, pattern])

            elif hunt_type == "COMMAND_LINE":
                sql += " AND ne.command_line LIKE ?"
                params.append(pattern)

            elif hunt_type in ("DOMAIN", "HASH"):
                # These values are searched in available event text.
                # They are not assumed to be dedicated schema fields.
                sql += """
                    AND (
                        ne.extra_data_json LIKE ?
                        OR ne.image LIKE ?
                        OR ne.command_line LIKE ?
                    )
                """
                params.extend([pattern, pattern, pattern])

            else:
                sql += """
                    AND (
                        ne.source_ip LIKE ?
                        OR ne.destination_ip LIKE ?
                        OR ne.image LIKE ?
                        OR ne.command_line LIKE ?
                        OR ne.extra_data_json LIKE ?
                        OR ne.provider LIKE ?
                        OR ne.channel LIKE ?
                    )
                """
                params.extend([pattern] * 7)

        sql += """
            ORDER BY ne.timestamp_utc DESC, ne.id DESC
            LIMIT ?
        """
        params.append(limit)

        rows = connection.execute(sql, params).fetchall()

        return _dict_rows(rows)

    finally:
        connection.close()


def get_event_detail(normalized_event_id: int):
    """Retrieve normalized details and the associated raw XML evidence."""

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        row = connection.execute("""
            SELECT
                ne.*,
                re.source_file,
                re.source_file_sha256,
                re.raw_xml_sha256,
                re.raw_xml
            FROM normalized_events ne
            LEFT JOIN raw_events re
                ON re.id = ne.raw_event_id
            WHERE ne.id = ?
        """, (int(normalized_event_id),)).fetchone()

        if row is None:
            return None

        result = dict(row)

        raw_xml = result.get("raw_xml")

        if raw_xml is not None:
            if isinstance(raw_xml, str):
                raw_bytes = raw_xml.encode("utf-8")
            else:
                raw_bytes = bytes(raw_xml)

            actual_hash = hashlib.sha256(raw_bytes).hexdigest()
            expected_hash = result.get("raw_xml_sha256")

            result["actual_raw_xml_sha256"] = actual_hash

            result["integrity_status"] = (
                "VERIFIED"
                if expected_hash and actual_hash == expected_hash
                else "MISMATCH"
                if expected_hash
                else "NO_BASELINE_HASH"
            )

            result["raw_xml_text"] = raw_bytes.decode(
                "utf-8",
                errors="replace"
            )

            result.pop("raw_xml", None)

        else:
            result["actual_raw_xml_sha256"] = None
            result["integrity_status"] = "NO_RAW_EVIDENCE"
            result["raw_xml_text"] = None

        return result

    finally:
        connection.close()


def _extract_alert_event_ids(evidence_json):
    """Read normalized event IDs from the existing detection evidence format."""

    if not evidence_json:
        return set()

    try:
        evidence = (
            json.loads(evidence_json)
            if isinstance(evidence_json, str)
            else evidence_json
        )
    except (json.JSONDecodeError, TypeError):
        return set()

    if not isinstance(evidence, dict):
        return set()

    values = evidence.get("normalized_event_ids", [])

    # Compatibility with older synthetic or manually created records.
    if not values:
        values = evidence.get("event_ids", [])

    if not isinstance(values, list):
        return set()

    result = set()

    for value in values:
        try:
            result.add(int(value))
        except (TypeError, ValueError):
            continue

    return result


def analyze_detection_gaps(events):
    """
    Mark events that do not appear in any alert's evidence.

    This is an alert-linkage comparison, not proof of malicious activity
    or proof that a detection rule failed.
    """

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        alert_rows = connection.execute("""
            SELECT evidence_json
            FROM alerts
        """).fetchall()

        alerted_ids = set()

        for row in alert_rows:
            alerted_ids.update(
                _extract_alert_event_ids(row["evidence_json"])
            )

        results = []

        for event in events:
            event_id = event.get("normalized_event_id")

            try:
                event_id = int(event_id)
            except (TypeError, ValueError):
                continue

            item = dict(event)

            item["detection_linkage"] = (
                "LINKED_TO_ALERT"
                if event_id in alerted_ids
                else "NO_LINKED_ALERT"
            )

            results.append(item)

        return results

    finally:
        connection.close()


def save_hunt(
    name,
    hunt_type,
    query,
    description="",
):
    """Save reusable hunt parameters as JSON."""

    name = _normalize_text(name)
    hunt_type = str(hunt_type).upper()

    if not name:
        raise ValueError("Hunt name is required")

    if hunt_type not in HUNT_TYPES:
        raise ValueError("Unsupported hunt type")

    if not isinstance(query, dict):
        raise ValueError("Query must be a dictionary")

    now = datetime.now(timezone.utc).isoformat()

    query_json = json.dumps(
        query,
        sort_keys=True,
        ensure_ascii=False
    )

    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute("""
                INSERT INTO saved_hunts (
                    name,
                    description,
                    hunt_type,
                    query_json,
                    created_at_utc,
                    updated_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                name,
                (description or "").strip() or None,
                hunt_type,
                query_json,
                now,
                now,
            ))

            return cursor.lastrowid

    finally:
        connection.close()


def list_saved_hunts():
    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute("""
            SELECT
                id,
                name,
                description,
                hunt_type,
                query_json,
                created_at_utc,
                updated_at_utc
            FROM saved_hunts
            ORDER BY updated_at_utc DESC, id DESC
        """).fetchall()

        results = _dict_rows(rows)

        for item in results:
            try:
                item["query"] = json.loads(item.pop("query_json"))
            except (json.JSONDecodeError, TypeError):
                item["query"] = {}

        return results

    finally:
        connection.close()


def delete_saved_hunt(hunt_id):
    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute(
                "DELETE FROM saved_hunts WHERE id = ?",
                (int(hunt_id),)
            )

            return cursor.rowcount > 0

    finally:
        connection.close()
