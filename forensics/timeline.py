"""
TRACE-SOC Day 24 — Forensic Timeline Engine

Reconstructs chronological forensic timelines by merging events from
multiple sources: normalized endpoint telemetry, forensic artifact
collection records and investigation story events. The result is a
unified, analyst-readable timeline suitable for incident reconstruction.

Each timeline entry carries a source label so the analyst can judge
confidence and provenance. Entries are sorted by UTC timestamp.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from database.db import get_connection
from forensics.engine import create_forensics_schema


# Source labels for timeline entries
SOURCE_ENDPOINT_TELEMETRY = "endpoint_telemetry"
SOURCE_FORENSIC_ARTIFACT = "forensic_artifact"
SOURCE_INVESTIGATION_STORY = "investigation_story"
SOURCE_ALERT = "alert"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dict_rows(rows):
    return [dict(row) for row in rows]


def _safe_ts(value: Any) -> str:
    """Return a sortable string timestamp, empty string if None."""
    return str(value or "")


# ---------------------------------------------------------------------------
# Individual source queries
# ---------------------------------------------------------------------------

def _get_telemetry_entries(
    hostname: str | None,
    start_time: str | None,
    end_time: str | None,
    limit: int,
) -> list[dict]:
    """Fetch normalized event entries for the timeline."""
    sql = """
        SELECT
            ne.id AS source_id,
            ne.timestamp_utc,
            ne.event_id,
            ne.hostname,
            ne.username,
            ne.source_ip,
            ne.destination_ip,
            ne.image,
            ne.command_line,
            ne.event_type,
            ne.extra_data_json
        FROM normalized_events ne
        WHERE 1=1
    """
    params: list = []

    if hostname and hostname.strip():
        sql += " AND ne.hostname LIKE ?"
        params.append(f"%{hostname.strip()}%")

    if start_time:
        sql += " AND ne.timestamp_utc >= ?"
        params.append(start_time)

    if end_time:
        sql += " AND ne.timestamp_utc <= ?"
        params.append(end_time)

    sql += " ORDER BY ne.timestamp_utc ASC LIMIT ?"
    params.append(limit)

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(sql, params).fetchall()
    finally:
        connection.close()

    entries = []
    for row in rows:
        item = dict(row)
        entry = {
            "timestamp_utc": item["timestamp_utc"] or "",
            "source": SOURCE_ENDPOINT_TELEMETRY,
            "source_id": item["source_id"],
            "event_id": item["event_id"],
            "hostname": item["hostname"],
            "username": item["username"],
            "source_ip": item["source_ip"],
            "destination_ip": item["destination_ip"],
            "image": item["image"],
            "command_line": item["command_line"],
            "description": item["event_type"] or f"Event {item['event_id']}",
            "detail": None,
        }
        # Annotate with any extra data
        raw_extra = item.get("extra_data_json")
        if raw_extra:
            try:
                extra = json.loads(raw_extra)
                if isinstance(extra, dict) and extra:
                    entry["detail"] = "; ".join(
                        f"{k}={v}" for k, v in list(extra.items())[:4]
                    )
            except (json.JSONDecodeError, TypeError):
                pass
        entries.append(entry)

    return entries


def _get_artifact_entries(
    hostname: str | None,
    start_time: str | None,
    end_time: str | None,
    story_id: int | None,
    limit: int,
) -> list[dict]:
    """Fetch forensic artifact collection records for the timeline."""
    create_forensics_schema()

    sql = """
        SELECT id, artifact_type, name, description,
               hostname, analyst, status, story_id,
               sha256, collected_at_utc
        FROM forensic_artifacts
        WHERE 1=1
    """
    params: list = []

    if hostname and hostname.strip():
        sql += " AND hostname LIKE ?"
        params.append(f"%{hostname.strip()}%")

    if start_time:
        sql += " AND collected_at_utc >= ?"
        params.append(start_time)

    if end_time:
        sql += " AND collected_at_utc <= ?"
        params.append(end_time)

    if story_id is not None:
        sql += " AND story_id = ?"
        params.append(int(story_id))

    sql += " ORDER BY collected_at_utc ASC LIMIT ?"
    params.append(limit)

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(sql, params).fetchall()
    finally:
        connection.close()

    entries = []
    for row in rows:
        item = dict(row)
        entries.append({
            "timestamp_utc": item["collected_at_utc"] or "",
            "source": SOURCE_FORENSIC_ARTIFACT,
            "source_id": item["id"],
            "event_id": None,
            "hostname": item["hostname"],
            "username": None,
            "source_ip": None,
            "destination_ip": None,
            "image": None,
            "command_line": None,
            "description": f"[{item['artifact_type']}] {item['name']}",
            "detail": (
                f"Status: {item['status']} | Analyst: {item['analyst']}"
                + (f" | SHA256: {item['sha256'][:16]}…" if item["sha256"] else "")
            ),
        })

    return entries


def _get_story_alert_entries(
    story_id: int,
    limit: int,
) -> list[dict]:
    """Fetch alert records linked to an investigation story for the timeline."""
    sql = """
        SELECT a.id, a.rule_id, a.rule_name, a.severity,
               a.status, a.hostname, a.username, a.source_ip,
               a.first_seen AS timestamp_utc, a.mitre_tactic, a.mitre_technique
        FROM alerts a
        JOIN story_alerts sa ON sa.alert_id = a.id
        WHERE sa.story_id = ?
        ORDER BY a.first_seen ASC
        LIMIT ?
    """
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(sql, (int(story_id), limit)).fetchall()
    except sqlite3.OperationalError:
        # story_alerts table may not exist yet in some environments
        return []
    finally:
        connection.close()

    entries = []
    for row in rows:
        item = dict(row)
        entries.append({
            "timestamp_utc": item["timestamp_utc"] or "",
            "source": SOURCE_ALERT,
            "source_id": item["id"],
            "event_id": item["rule_id"],
            "hostname": item["hostname"],
            "username": item["username"],
            "source_ip": item["source_ip"],
            "destination_ip": None,
            "image": None,
            "command_line": None,
            "description": f"ALERT [{item['severity']}] {item['rule_name']}",
            "detail": (
                f"Tactic: {item.get('mitre_tactic', '')} | "
                f"Technique: {item.get('mitre_technique', '')} | "
                f"Status: {item['status']}"
            ),
        })

    return entries


# ---------------------------------------------------------------------------
# Unified timeline builder
# ---------------------------------------------------------------------------

def build_forensic_timeline(
    *,
    hostname: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    story_id: int | None = None,
    include_telemetry: bool = True,
    include_artifacts: bool = True,
    include_alerts: bool = True,
    max_entries: int = 2000,
) -> list[dict]:
    """
    Build a merged, chronologically sorted forensic timeline.

    Parameters
    ----------
    hostname       : Filter events and artifacts to this hostname.
    start_time     : ISO-8601 UTC lower bound (inclusive).
    end_time       : ISO-8601 UTC upper bound (inclusive).
    story_id       : Include artifact and alert entries for this story.
    include_*      : Toggle individual source categories.
    max_entries    : Per-source entry cap before merging.

    Returns
    -------
    List of timeline entry dicts sorted by timestamp_utc ascending.
    Each entry has: timestamp_utc, source, source_id, event_id,
    hostname, username, source_ip, destination_ip, image,
    command_line, description, detail.
    """
    entries: list[dict] = []

    if include_telemetry:
        entries.extend(
            _get_telemetry_entries(hostname, start_time, end_time, max_entries)
        )

    if include_artifacts:
        entries.extend(
            _get_artifact_entries(hostname, start_time, end_time, story_id, max_entries)
        )

    if include_alerts and story_id is not None:
        entries.extend(
            _get_story_alert_entries(story_id, max_entries)
        )

    # Sort: entries without timestamps sort to the bottom
    entries.sort(key=lambda e: (_safe_ts(e["timestamp_utc"]) or "9999"))

    return entries


def get_timeline_summary(timeline: list[dict]) -> dict:
    """
    Return aggregate summary statistics for a built timeline.
    """
    if not timeline:
        return {
            "total_entries": 0,
            "by_source": {},
            "earliest": None,
            "latest": None,
            "unique_hosts": [],
            "unique_users": [],
        }

    by_source: dict[str, int] = {}
    timestamps = []
    hosts = set()
    users = set()

    for entry in timeline:
        src = entry.get("source", "unknown")
        by_source[src] = by_source.get(src, 0) + 1

        ts = entry.get("timestamp_utc")
        if ts:
            timestamps.append(ts)

        h = entry.get("hostname")
        if h:
            hosts.add(h)

        u = entry.get("username")
        if u:
            users.add(u)

    timestamps.sort()

    return {
        "total_entries": len(timeline),
        "by_source": by_source,
        "earliest": timestamps[0] if timestamps else None,
        "latest": timestamps[-1] if timestamps else None,
        "unique_hosts": sorted(hosts),
        "unique_users": sorted(users),
    }
