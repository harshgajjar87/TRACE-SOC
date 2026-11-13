"""
TRACE-SOC Day 23 — Forensic Artifact Engine

Manages forensic artifact records: metadata about disk images,
memory dumps, process snapshots, registry exports and log archives
collected during an investigation. Each artifact is content-addressed
by its SHA-256 hash and linked to an optional investigation story.

Design principles:
- Artifact records describe evidence; they do not store actual file bytes.
- The hash is the primary integrity anchor.
- All operations are append-only or non-destructive.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from database.db import get_connection


ARTIFACT_TYPES = (
    "DISK_IMAGE",
    "MEMORY_DUMP",
    "PROCESS_SNAPSHOT",
    "REGISTRY_EXPORT",
    "LOG_ARCHIVE",
    "NETWORK_CAPTURE",
    "FILE_SAMPLE",
    "TRIAGE_PACKAGE",
    "OTHER",
)

ARTIFACT_STATUSES = (
    "COLLECTED",
    "VERIFIED",
    "PENDING_ANALYSIS",
    "ANALYSED",
    "EXPORTED",
    "ARCHIVED",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dict_rows(rows):
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def create_forensics_schema() -> None:
    """Create forensic artifact storage tables. Safe to run repeatedly."""
    connection = get_connection()
    try:
        with connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS forensic_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_type TEXT NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    hostname TEXT,
                    analyst TEXT NOT NULL,
                    sha256 TEXT,
                    file_path TEXT,
                    file_size_bytes INTEGER,
                    status TEXT NOT NULL DEFAULT 'COLLECTED',
                    story_id INTEGER,
                    tags_json TEXT,
                    metadata_json TEXT,
                    collected_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS forensic_artifact_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_id INTEGER NOT NULL,
                    analyst TEXT NOT NULL,
                    note TEXT NOT NULL,
                    recorded_at_utc TEXT NOT NULL,
                    FOREIGN KEY(artifact_id)
                        REFERENCES forensic_artifacts(id) ON DELETE RESTRICT
                )
            """)

            for idx_sql in [
                "CREATE INDEX IF NOT EXISTS idx_fa_hostname ON forensic_artifacts(hostname)",
                "CREATE INDEX IF NOT EXISTS idx_fa_story ON forensic_artifacts(story_id)",
                "CREATE INDEX IF NOT EXISTS idx_fa_type ON forensic_artifacts(artifact_type)",
                "CREATE INDEX IF NOT EXISTS idx_fa_sha256 ON forensic_artifacts(sha256)",
                "CREATE INDEX IF NOT EXISTS idx_fan_artifact ON forensic_artifact_notes(artifact_id)",
            ]:
                connection.execute(idx_sql)

    finally:
        connection.close()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def add_artifact(
    *,
    artifact_type: str,
    name: str,
    analyst: str,
    hostname: str = "",
    description: str = "",
    sha256: str | None = None,
    file_path: str | None = None,
    file_size_bytes: int | None = None,
    status: str = "COLLECTED",
    story_id: int | None = None,
    tags: list[str] | None = None,
    metadata: dict | None = None,
) -> int:
    """Register a new forensic artifact. Returns the artifact ID."""
    artifact_type = str(artifact_type).upper().strip()
    if artifact_type not in ARTIFACT_TYPES:
        raise ValueError(
            f"Unsupported artifact type. Choose: {', '.join(ARTIFACT_TYPES)}"
        )

    name = str(name).strip()
    if not name:
        raise ValueError("Artifact name is required")

    analyst = str(analyst).strip()
    if not analyst:
        raise ValueError("Analyst identity is required")

    status = str(status).upper().strip()
    if status not in ARTIFACT_STATUSES:
        raise ValueError(f"Invalid status. Choose: {', '.join(ARTIFACT_STATUSES)}")

    if sha256:
        sha256 = sha256.lower().strip()
        if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
            raise ValueError("sha256 must be a 64-character hex string")

    tags_json = json.dumps(
        sorted({str(t).strip() for t in (tags or []) if str(t).strip()}),
        ensure_ascii=False,
    )

    now = _utc_now()
    create_forensics_schema()
    connection = get_connection()
    try:
        with connection:
            cursor = connection.execute("""
                INSERT INTO forensic_artifacts (
                    artifact_type, name, description, hostname, analyst,
                    sha256, file_path, file_size_bytes, status, story_id,
                    tags_json, metadata_json, collected_at_utc, updated_at_utc
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact_type,
                name,
                description.strip() or None,
                hostname.strip() or None,
                analyst,
                sha256,
                file_path,
                file_size_bytes,
                status,
                story_id,
                tags_json,
                json.dumps(metadata or {}, sort_keys=True),
                now,
                now,
            ))
            return cursor.lastrowid
    finally:
        connection.close()


def update_artifact_status(artifact_id: int, status: str, analyst: str) -> bool:
    """Update the status of an artifact. Status must be a valid ARTIFACT_STATUSES value."""
    status = str(status).upper().strip()
    if status not in ARTIFACT_STATUSES:
        raise ValueError(f"Invalid status: {status}")

    create_forensics_schema()
    connection = get_connection()
    try:
        with connection:
            cursor = connection.execute("""
                UPDATE forensic_artifacts
                SET status = ?, updated_at_utc = ?
                WHERE id = ?
            """, (status, _utc_now(), int(artifact_id)))
        return cursor.rowcount > 0
    finally:
        connection.close()


def get_artifact(artifact_id: int) -> dict | None:
    """Return full details for one artifact, including its notes."""
    create_forensics_schema()
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM forensic_artifacts WHERE id = ?",
            (int(artifact_id),),
        ).fetchone()

        if row is None:
            return None

        result = dict(row)
        # Deserialise JSON fields
        for field in ("tags_json", "metadata_json"):
            try:
                result[field.replace("_json", "")] = json.loads(result.pop(field) or "null")
            except (TypeError, json.JSONDecodeError):
                result[field.replace("_json", "")] = None

        # Attach notes
        note_rows = connection.execute("""
            SELECT id, analyst, note, recorded_at_utc
            FROM forensic_artifact_notes
            WHERE artifact_id = ?
            ORDER BY id ASC
        """, (int(artifact_id),)).fetchall()
        result["notes"] = _dict_rows(note_rows)

        return result
    finally:
        connection.close()


def list_artifacts(
    *,
    artifact_type: str | None = None,
    hostname: str | None = None,
    status: str | None = None,
    story_id: int | None = None,
    limit: int = 500,
) -> list[dict]:
    """Return artifact records, optionally filtered."""
    create_forensics_schema()
    limit = max(1, min(int(limit), 5000))

    sql = "SELECT * FROM forensic_artifacts WHERE 1=1"
    params: list = []

    if artifact_type and artifact_type != "ALL":
        sql += " AND artifact_type = ?"
        params.append(artifact_type.upper())

    if hostname and hostname.strip():
        sql += " AND hostname LIKE ?"
        params.append(f"%{hostname.strip()}%")

    if status and status != "ALL":
        sql += " AND status = ?"
        params.append(status.upper())

    if story_id is not None:
        sql += " AND story_id = ?"
        params.append(int(story_id))

    sql += " ORDER BY collected_at_utc DESC LIMIT ?"
    params.append(limit)

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(sql, params).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            for field in ("tags_json", "metadata_json"):
                try:
                    item[field.replace("_json", "")] = json.loads(item.pop(field) or "null")
                except (TypeError, json.JSONDecodeError):
                    item[field.replace("_json", "")] = None
            results.append(item)
        return results
    finally:
        connection.close()


def add_artifact_note(artifact_id: int, analyst: str, note: str) -> int:
    """Append a note to an artifact record. Returns the note ID."""
    analyst = str(analyst).strip()
    note = str(note).strip()

    if not analyst:
        raise ValueError("Analyst identity is required")
    if not note:
        raise ValueError("Note text is required")

    create_forensics_schema()
    connection = get_connection()
    try:
        # Verify artifact exists
        exists = connection.execute(
            "SELECT id FROM forensic_artifacts WHERE id = ?",
            (int(artifact_id),),
        ).fetchone()
        if exists is None:
            raise ValueError(f"Artifact {artifact_id} not found")

        with connection:
            cursor = connection.execute("""
                INSERT INTO forensic_artifact_notes (artifact_id, analyst, note, recorded_at_utc)
                VALUES (?, ?, ?, ?)
            """, (int(artifact_id), analyst, note, _utc_now()))
            return cursor.lastrowid
    finally:
        connection.close()


def get_artifacts_by_story(story_id: int) -> list[dict]:
    """Shortcut: return all artifacts linked to an investigation story."""
    return list_artifacts(story_id=story_id, limit=1000)


def compute_file_sha256(file_path: str | Path) -> str:
    """Compute SHA-256 of a local file. Returns lowercase hex string."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def get_artifact_summary() -> dict:
    """Return aggregate statistics about stored forensic artifacts."""
    create_forensics_schema()
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        total = connection.execute(
            "SELECT COUNT(*) AS cnt FROM forensic_artifacts"
        ).fetchone()["cnt"]

        by_type = connection.execute("""
            SELECT artifact_type, COUNT(*) AS count
            FROM forensic_artifacts
            GROUP BY artifact_type
            ORDER BY count DESC
        """).fetchall()

        by_status = connection.execute("""
            SELECT status, COUNT(*) AS count
            FROM forensic_artifacts
            GROUP BY status
            ORDER BY count DESC
        """).fetchall()

        by_host = connection.execute("""
            SELECT hostname, COUNT(*) AS count
            FROM forensic_artifacts
            WHERE hostname IS NOT NULL
            GROUP BY hostname
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()

        return {
            "total": total,
            "by_type": _dict_rows(by_type),
            "by_status": _dict_rows(by_status),
            "by_hostname": _dict_rows(by_host),
        }
    finally:
        connection.close()
