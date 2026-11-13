"""
TRACE-SOC Day 28 — System Health and Database Optimizer

Provides database health metrics, maintenance operations (ANALYZE,
VACUUM, index rebuild) and a system-wide component health check.
All operations are non-destructive unless explicitly documented.

VACUUM creates a new database file and replaces the original — this
is safe but rewrites the full database. Only call it on user request.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from database.db import get_connection, DATABASE_PATH


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _dict_rows(rows):
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Database size and structure metrics
# ---------------------------------------------------------------------------

def get_database_file_metrics() -> dict:
    """Return file-level database metrics (size, page info)."""
    path = Path(DATABASE_PATH)

    if not path.exists():
        return {
            "exists": False,
            "path": str(path),
            "size_bytes": 0,
            "size_mb": 0.0,
        }

    size_bytes = path.stat().st_size

    connection = get_connection()
    try:
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        freelist_count = connection.execute("PRAGMA freelist_count").fetchone()[0]
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        cache_size = connection.execute("PRAGMA cache_size").fetchone()[0]
    finally:
        connection.close()

    fragmentation_pct = (
        round(freelist_count / page_count * 100, 2)
        if page_count > 0 else 0.0
    )

    return {
        "exists": True,
        "path": str(path.resolve()),
        "size_bytes": size_bytes,
        "size_mb": round(size_bytes / (1024 * 1024), 3),
        "page_size_bytes": page_size,
        "page_count": page_count,
        "freelist_pages": freelist_count,
        "fragmentation_pct": fragmentation_pct,
        "journal_mode": journal_mode,
        "cache_size_pages": cache_size,
    }


def get_table_row_counts() -> list[dict]:
    """Return row counts for every user table in the database."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        tables = connection.execute("""
            SELECT name
            FROM sqlite_master
            WHERE type='table'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """).fetchall()

        results = []
        for table_row in tables:
            table_name = table_row["name"]
            try:
                count_row = connection.execute(
                    f"SELECT COUNT(*) AS cnt FROM \"{table_name}\""
                ).fetchone()
                row_count = count_row["cnt"]
            except sqlite3.Error:
                row_count = -1

            results.append({
                "table": table_name,
                "row_count": row_count,
            })

        return sorted(results, key=lambda r: r["row_count"], reverse=True)

    finally:
        connection.close()


def get_index_list() -> list[dict]:
    """Return all indexes with their target tables."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row

    try:
        rows = connection.execute("""
            SELECT name, tbl_name AS table_name, sql
            FROM sqlite_master
            WHERE type = 'index'
              AND name NOT LIKE 'sqlite_%'
            ORDER BY tbl_name, name
        """).fetchall()
        return _dict_rows(rows)

    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Maintenance operations
# ---------------------------------------------------------------------------

def run_analyze() -> dict:
    """
    Run ANALYZE to update SQLite query planner statistics.
    Non-destructive. Recommended after bulk inserts.
    """
    start = datetime.now(timezone.utc)
    connection = get_connection()
    try:
        connection.execute("ANALYZE")
        connection.commit()
    finally:
        connection.close()

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    return {
        "operation": "ANALYZE",
        "status": "OK",
        "elapsed_seconds": round(elapsed, 3),
        "run_at_utc": _utc_now(),
        "note": "Query planner statistics updated.",
    }


def run_vacuum() -> dict:
    """
    Run VACUUM to reclaim free pages and defragment the database file.
    This rewrites the database file — it is safe but can take time on
    large databases. Only call on explicit user request.
    """
    start = datetime.now(timezone.utc)
    size_before = Path(DATABASE_PATH).stat().st_size if Path(DATABASE_PATH).exists() else 0

    connection = get_connection()
    try:
        # VACUUM cannot run inside a transaction
        connection.isolation_level = None
        connection.execute("VACUUM")
    finally:
        connection.close()

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    size_after = Path(DATABASE_PATH).stat().st_size if Path(DATABASE_PATH).exists() else 0

    reclaimed = max(0, size_before - size_after)
    return {
        "operation": "VACUUM",
        "status": "OK",
        "elapsed_seconds": round(elapsed, 3),
        "size_before_bytes": size_before,
        "size_after_bytes": size_after,
        "reclaimed_bytes": reclaimed,
        "reclaimed_mb": round(reclaimed / (1024 * 1024), 3),
        "run_at_utc": _utc_now(),
        "note": "Database file has been rewritten and defragmented.",
    }


def run_integrity_check() -> dict:
    """
    Run SQLite PRAGMA integrity_check. Returns OK or lists problems found.
    Read-only operation — does not modify the database.
    """
    connection = get_connection()
    try:
        rows = connection.execute("PRAGMA integrity_check").fetchall()
        results = [row[0] for row in rows]
    finally:
        connection.close()

    is_ok = results == ["ok"]
    return {
        "operation": "INTEGRITY_CHECK",
        "status": "OK" if is_ok else "ISSUES_FOUND",
        "results": results,
        "run_at_utc": _utc_now(),
    }


def run_foreign_key_check() -> dict:
    """
    Run PRAGMA foreign_key_check to detect orphaned references.
    Read-only operation.
    """
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("PRAGMA foreign_key_check").fetchall()
        violations = _dict_rows(rows)
    finally:
        connection.close()

    return {
        "operation": "FOREIGN_KEY_CHECK",
        "status": "OK" if not violations else "VIOLATIONS_FOUND",
        "violation_count": len(violations),
        "violations": violations,
        "run_at_utc": _utc_now(),
    }


# ---------------------------------------------------------------------------
# Component health check
# ---------------------------------------------------------------------------

_CORE_TABLES = [
    "raw_events",
    "normalized_events",
    "alerts",
    "attack_stories",
    "story_events",
    "ioc_indicators",
    "incident_cases",
    "saved_hunts",
    "monitoring_runs",
    "evidence_custody",
    "ioc_event_correlations",
]


def get_system_health() -> dict:
    """
    Check the health of TRACE-SOC components.

    Returns a summary dict with:
      status        — HEALTHY / DEGRADED / CRITICAL
      components    — per-component health records
      database      — file-level DB metrics
      table_counts  — row counts for core tables
    """
    db_metrics = get_database_file_metrics()
    table_counts = {r["table"]: r["row_count"] for r in get_table_row_counts()}

    components = []
    all_ok = True

    # Check each core table is accessible
    for table in _CORE_TABLES:
        count = table_counts.get(table)
        if count is None:
            # Table doesn't exist yet
            status = "MISSING"
            all_ok = False
        elif count < 0:
            status = "ERROR"
            all_ok = False
        else:
            status = "OK"

        components.append({
            "component": table,
            "type": "table",
            "status": status,
            "row_count": count if count is not None else 0,
        })

    # Check detection rules are loadable
    try:
        from detection.rules import DETECTION_RULES
        rule_count = len(DETECTION_RULES)
        components.append({
            "component": "detection_rules",
            "type": "module",
            "status": "OK",
            "detail": f"{rule_count} rules loaded",
        })
    except Exception as exc:
        all_ok = False
        components.append({
            "component": "detection_rules",
            "type": "module",
            "status": "ERROR",
            "detail": str(exc),
        })

    # Fragmentation warning
    frag = db_metrics.get("fragmentation_pct", 0)
    frag_status = "OK" if frag < 20 else "WARN"
    if frag_status != "OK":
        all_ok = False
    components.append({
        "component": "db_fragmentation",
        "type": "metric",
        "status": frag_status,
        "detail": f"{frag}% free pages (VACUUM recommended above 20%)",
    })

    overall_status = "HEALTHY" if all_ok else "DEGRADED"

    return {
        "status": overall_status,
        "checked_at_utc": _utc_now(),
        "components": components,
        "database": db_metrics,
        "core_table_counts": {
            t: table_counts.get(t, 0)
            for t in _CORE_TABLES
        },
    }
