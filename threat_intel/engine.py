
"""TRACE-SOC Threat Intelligence and IOC Enrichment Engine."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
import sqlite3

from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from database.db import get_connection


IOC_TYPES = ("IP", "DOMAIN", "URL", "MD5", "SHA1", "SHA256")

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_ioc(value: str, ioc_type: str) -> str:
    """Validate and normalize an IOC according to its type."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("IOC value cannot be empty")

    value = value.strip()
    ioc_type = str(ioc_type).upper().strip()

    if ioc_type not in IOC_TYPES:
        raise ValueError("Unsupported IOC type")

    if ioc_type == "IP":
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc

    if ioc_type == "DOMAIN":
        value = value.rstrip(".").lower()

        if len(value) > 253:
            raise ValueError("Domain is too long")

        labels = value.split(".")

        if len(labels) < 2:
            raise ValueError("Domain must contain at least two labels")

        label_pattern = re.compile(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )

        if any(not label_pattern.fullmatch(label) for label in labels):
            raise ValueError("Invalid domain name")

        return value

    if ioc_type == "URL":
        parsed = urlsplit(value)

        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("URL must use HTTP or HTTPS")

        if not parsed.hostname:
            raise ValueError("URL hostname is missing")

        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("Invalid URL port") from exc

        return value.rstrip()

    hash_lengths = {
        "MD5": 32,
        "SHA1": 40,
        "SHA256": 64,
    }

    if ioc_type in hash_lengths:
        value = value.lower()

        if not re.fullmatch(r"[a-f0-9]+", value):
            raise ValueError("Hash must contain hexadecimal characters")

        if len(value) != hash_lengths[ioc_type]:
            raise ValueError(f"Invalid {ioc_type} hash length")

        return value

    raise ValueError("Unsupported IOC type")


def infer_ioc_type(value: str) -> str:
    """Infer common IOC types from a supplied value."""

    value = str(value).strip()

    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "MD5"

    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA1"

    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA256"

    try:
        ipaddress.ip_address(value)
        return "IP"
    except ValueError:
        pass

    if value.lower().startswith(("http://", "https://")):
        return "URL"

    return "DOMAIN"


def create_threat_intel_schema():
    """Create local IOC storage and indexes."""

    connection = get_connection()

    try:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS ioc_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    ioc_type TEXT NOT NULL,
                    indicator TEXT NOT NULL,

                    source_name TEXT NOT NULL,
                    source_reference TEXT,

                    confidence INTEGER NOT NULL DEFAULT 50,
                    severity TEXT NOT NULL DEFAULT 'MEDIUM',

                    description TEXT,
                    tags_json TEXT,

                    first_seen_utc TEXT,
                    last_seen_utc TEXT,
                    expires_at_utc TEXT,

                    is_active INTEGER NOT NULL DEFAULT 1,

                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL,

                    UNIQUE(ioc_type, indicator, source_name)
                )
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_ioc_indicator
                ON ioc_indicators(ioc_type, indicator)
            """)

            connection.execute("""
                CREATE INDEX IF NOT EXISTS idx_ioc_active
                ON ioc_indicators(is_active, expires_at_utc)
            """)

    finally:
        connection.close()


def _dict_rows(rows):
    return [dict(row) for row in rows]


def add_indicator(
    indicator,
    ioc_type,
    source_name,
    *,
    source_reference=None,
    confidence=50,
    severity="MEDIUM",
    description=None,
    tags=None,
    first_seen_utc=None,
    last_seen_utc=None,
    expires_at_utc=None,
):
    """Insert or update an IOC while preserving source provenance."""

    normalized = normalize_ioc(indicator, ioc_type)

    source_name = str(source_name or "").strip()

    if not source_name:
        raise ValueError("Source name is required")

    confidence = int(confidence)

    if not 0 <= confidence <= 100:
        raise ValueError("Confidence must be between 0 and 100")

    severity = str(severity).upper().strip()

    if severity not in SEVERITIES:
        raise ValueError("Invalid severity")

    if tags is None:
        tags = []

    if not isinstance(tags, list):
        raise ValueError("Tags must be a list")

    tags_json = json.dumps(
        sorted(set(str(tag).strip() for tag in tags if str(tag).strip())),
        ensure_ascii=False
    )

    now = utc_now()

    connection = get_connection()

    try:
        with connection:
            connection.execute("""
                INSERT INTO ioc_indicators (
                    ioc_type,
                    indicator,
                    source_name,
                    source_reference,
                    confidence,
                    severity,
                    description,
                    tags_json,
                    first_seen_utc,
                    last_seen_utc,
                    expires_at_utc,
                    is_active,
                    created_at_utc,
                    updated_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)

                ON CONFLICT(ioc_type, indicator, source_name)
                DO UPDATE SET
                    source_reference = excluded.source_reference,
                    confidence = excluded.confidence,
                    severity = excluded.severity,
                    description = excluded.description,
                    tags_json = excluded.tags_json,
                    first_seen_utc = COALESCE(
                        excluded.first_seen_utc,
                        ioc_indicators.first_seen_utc
                    ),
                    last_seen_utc = COALESCE(
                        excluded.last_seen_utc,
                        ioc_indicators.last_seen_utc
                    ),
                    expires_at_utc = excluded.expires_at_utc,
                    is_active = 1,
                    updated_at_utc = excluded.updated_at_utc
            """, (
                ioc_type.upper(),
                normalized,
                source_name,
                source_reference,
                confidence,
                severity,
                description,
                tags_json,
                first_seen_utc,
                last_seen_utc,
                expires_at_utc,
                now,
                now,
            ))

            row = connection.execute("""
                SELECT id
                FROM ioc_indicators
                WHERE ioc_type = ?
                  AND indicator = ?
                  AND source_name = ?
            """, (
                ioc_type.upper(),
                normalized,
                source_name,
            )).fetchone()

            return row[0]

    finally:
        connection.close()


def expire_indicators():
    """Deactivate indicators whose expiry timestamp has passed."""

    now = utc_now()

    connection = get_connection()

    try:
        with connection:
            cursor = connection.execute("""
                UPDATE ioc_indicators
                SET is_active = 0,
                    updated_at_utc = ?
                WHERE is_active = 1
                  AND expires_at_utc IS NOT NULL
                  AND expires_at_utc <= ?
            """, (now, now))

            return cursor.rowcount

    finally:
        connection.close()


def get_indicators(
    *,
    ioc_type=None,
    severity=None,
    search=None,
    active_only=True,
    limit=500,
):
    limit = max(1, min(int(limit), 2000))

    sql = "SELECT * FROM ioc_indicators WHERE 1=1"
    params = []

    if active_only:
        sql += " AND is_active = 1"

    if ioc_type and ioc_type != "ALL":
        sql += " AND ioc_type = ?"
        params.append(str(ioc_type).upper())

    if severity and severity != "ALL":
        sql += " AND severity = ?"
        params.append(str(severity).upper())

    if search and search.strip():
        sql += """
            AND (
                indicator LIKE ?
                OR source_name LIKE ?
                OR description LIKE ?
            )
        """
        value = f"%{search.strip()}%"
        params.extend([value] * 3)

    sql += " ORDER BY confidence DESC, updated_at_utc DESC LIMIT ?"
    params.append(limit)

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        return _dict_rows(
            connection.execute(sql, params).fetchall()
        )

    finally:
        connection.close()


def lookup_indicator(indicator, ioc_type=None):
    """Find an indicator across its recorded intelligence sources."""

    if not ioc_type:
        ioc_type = infer_ioc_type(indicator)

    normalized = normalize_ioc(indicator, ioc_type)

    expire_indicators()

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute("""
            SELECT *
            FROM ioc_indicators
            WHERE ioc_type = ?
              AND indicator = ?
              AND is_active = 1
            ORDER BY confidence DESC
        """, (ioc_type, normalized)).fetchall()

        return _dict_rows(rows)

    finally:
        connection.close()


def _extract_text_fields(event):
    values = []

    for key in (
        "image",
        "command_line",
        "extra_data_json",
    ):
        value = event.get(key)

        if value:
            values.append(str(value))

    return " ".join(values).lower()


def _domain_or_hash_match(indicator, text):
    """Avoid matching a domain or hash as an arbitrary substring."""

    escaped = re.escape(indicator.lower())

    if re.fullmatch(r"[a-f0-9]{32,64}", indicator.lower()):
        return re.search(
            rf"(?<![a-f0-9]){escaped}(?![a-f0-9])",
            text
        ) is not None

    return re.search(
        rf"(?<![a-z0-9.-]){escaped}(?![a-z0-9.-])",
        text
    ) is not None


def enrich_event(event, active_iocs=None):
    """Return matching active IOC records for one normalized event."""

    if active_iocs is None:
        expire_indicators()

        connection = get_connection()
        connection.row_factory = sqlite3.Row

        try:
            active_iocs = [dict(row) for row in connection.execute("""
                SELECT *
                FROM ioc_indicators
                WHERE is_active = 1
            """).fetchall()]
        finally:
            connection.close()

    text = _extract_text_fields(event)

    source_ip = str(event.get("source_ip") or "").strip()
    destination_ip = str(event.get("destination_ip") or "").strip()

    matches = []

    for item_raw in active_iocs:
        item = dict(item_raw)

        ioc_type = item["ioc_type"]
        indicator = item["indicator"]

        matched = False
        matched_field = None

        if ioc_type == "IP":
            if source_ip == indicator:
                matched = True
                matched_field = "source_ip"

            elif destination_ip == indicator:
                matched = True
                matched_field = "destination_ip"

        elif ioc_type == "URL":
            matched = _domain_or_hash_match(
                indicator,
                text
            )
            matched_field = "event_text"

        else:
            matched = _domain_or_hash_match(
                indicator,
                text
            )
            matched_field = "event_text"

        if matched:
            item["matched_field"] = matched_field
            matches.append(item)

    return matches


def enrich_events(events):
    """Enrich a list of normalized events."""

    expire_indicators()

    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        active_iocs = [dict(row) for row in connection.execute("""
            SELECT *
            FROM ioc_indicators
            WHERE is_active = 1
        """).fetchall()]
    finally:
        connection.close()

    results = []

    for event in events:
        item = dict(event)
        matches = enrich_event(event, active_iocs=active_iocs)

        item["threat_intel_matches"] = matches
        item["threat_intel_match_count"] = len(matches)

        item["threat_intel_status"] = (
            "KNOWN_INDICATOR_MATCH"
            if matches
            else "NO_MATCHING_INTELLIGENCE"
        )

        results.append(item)

    return results


def import_json_feed(path):
    """Import a JSON array of indicators."""

    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        records = json.load(file)

    if not isinstance(records, list):
        raise ValueError("JSON feed must contain a list of indicators")

    return import_records(records)


def import_csv_feed(path):
    """Import indicators from a CSV feed."""

    path = Path(path)

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as file:
        records = list(csv.DictReader(file))

    return import_records(records)


def import_records(records):
    """Import a list of normalized or feed-style IOC records."""

    imported = 0
    errors = []

    for index, record in enumerate(records, start=1):

        try:
            indicator = (
                record.get("indicator")
                or record.get("value")
            )

            ioc_type = (
                record.get("ioc_type")
                or record.get("type")
                or infer_ioc_type(indicator)
            )

            tags = record.get("tags", [])

            if isinstance(tags, str):
                tags = [
                    tag.strip()
                    for tag in tags.split(",")
                    if tag.strip()
                ]

            if isinstance(tags, dict):
                tags = list(tags.keys())

            if not isinstance(tags, list):
                tags = []

            confidence = record.get("confidence", 50)

            if confidence in (None, ""):
                confidence = 50

            add_indicator(
                indicator=indicator,
                ioc_type=ioc_type,
                source_name=(
                    record.get("source_name")
                    or record.get("source")
                    or "Imported Feed"
                ),
                source_reference=record.get("source_reference"),
                confidence=confidence,
                severity=record.get("severity") or "MEDIUM",
                description=record.get("description"),
                tags=tags,
                first_seen_utc=record.get("first_seen_utc"),
                last_seen_utc=record.get("last_seen_utc"),
                expires_at_utc=record.get("expires_at_utc"),
            )

            imported += 1

        except (ValueError, TypeError, sqlite3.Error) as exc:
            errors.append({
                "record": index,
                "error": str(exc),
            })

    return {
        "total": len(records),
        "imported": imported,
        "errors": errors,
    }


def get_threat_intel_summary():
    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        total = connection.execute("""
            SELECT COUNT(*) AS count
            FROM ioc_indicators
        """).fetchone()["count"]

        active = connection.execute("""
            SELECT COUNT(*) AS count
            FROM ioc_indicators
            WHERE is_active = 1
        """).fetchone()["count"]

        by_type = connection.execute("""
            SELECT ioc_type, COUNT(*) AS count
            FROM ioc_indicators
            WHERE is_active = 1
            GROUP BY ioc_type
            ORDER BY count DESC
        """).fetchall()

        by_severity = connection.execute("""
            SELECT severity, COUNT(*) AS count
            FROM ioc_indicators
            WHERE is_active = 1
            GROUP BY severity
            ORDER BY count DESC
        """).fetchall()

        sources = connection.execute("""
            SELECT COUNT(DISTINCT source_name) AS count
            FROM ioc_indicators
            WHERE is_active = 1
        """).fetchone()["count"]

        return {
            "total": total,
            "active": active,
            "sources": sources,
            "by_type": _dict_rows(by_type),
            "by_severity": _dict_rows(by_severity),
        }

    finally:
        connection.close()
