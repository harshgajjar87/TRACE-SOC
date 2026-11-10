"""Database access for the TRACE-SOC analyst dashboard.

All user-supplied filters are parameterized. This module has no Streamlit
 dependency so its behavior can be tested independently.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from database.db import get_connection

ALERT_STATUSES = ("NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def ensure_dashboard_schema() -> None:
    """Create the alert status audit table without changing existing alert rows."""
    connection = get_connection()
    try:
        with connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS alert_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                note TEXT,
                changed_at_utc TEXT NOT NULL,
                FOREIGN KEY(alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            )""")
            connection.execute("""CREATE INDEX IF NOT EXISTS idx_alert_history_alert
                ON alert_status_history(alert_id, changed_at_utc)""")
    finally:
        connection.close()


def _dict_rows(rows):
    return [dict(row) for row in rows]


def get_dashboard_summary() -> dict[str, Any]:
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        counts = connection.execute("""SELECT
            (SELECT COUNT(*) FROM normalized_events) AS total_events,
            (SELECT COUNT(*) FROM raw_events) AS raw_events,
            (SELECT COUNT(*) FROM alerts) AS total_alerts,
            (SELECT COUNT(*) FROM alerts WHERE UPPER(status) IN ('NEW','INVESTIGATING')) AS open_alerts,
            (SELECT COUNT(*) FROM alerts WHERE UPPER(severity)='CRITICAL' AND UPPER(status) NOT IN ('RESOLVED','FALSE_POSITIVE')) AS critical_alerts,
            (SELECT COUNT(*) FROM attack_stories) AS total_stories,
            (SELECT COUNT(*) FROM attack_stories WHERE UPPER(status) IN ('NEW','INVESTIGATING')) AS active_stories
        """).fetchone()
        severity_rows = connection.execute("""SELECT UPPER(severity) AS severity, COUNT(*) AS count
            FROM alerts GROUP BY UPPER(severity) ORDER BY count DESC""").fetchall()
        status_rows = connection.execute("""SELECT UPPER(status) AS status, COUNT(*) AS count
            FROM alerts GROUP BY UPPER(status) ORDER BY count DESC""").fetchall()
        category_rows = connection.execute("""SELECT COALESCE(NULLIF(event_type,''),'Unclassified') AS category,
            COUNT(*) AS count FROM normalized_events GROUP BY category ORDER BY count DESC LIMIT 10""").fetchall()
        recent_alerts = connection.execute("""SELECT id,rule_id,rule_name,severity,status,hostname,username,source_ip,
            last_seen,created_at_utc FROM alerts ORDER BY created_at_utc DESC,id DESC LIMIT 8""").fetchall()
        return {
            "counts": dict(counts),
            "severity": _dict_rows(severity_rows),
            "status": _dict_rows(status_rows),
            "event_categories": _dict_rows(category_rows),
            "recent_alerts": _dict_rows(recent_alerts),
        }
    finally:
        connection.close()


def get_alerts(*, status=None, severity=None, search=None, limit=200):
    limit = max(1, min(int(limit), 1000))
    sql = """SELECT id,alert_fingerprint,rule_id,rule_name,description,severity,status,hostname,
        username,source_ip,first_seen,last_seen,event_count,mitre_tactic,mitre_technique,
        evidence_json,created_at_utc FROM alerts WHERE 1=1"""
    params: list[Any] = []
    if status and str(status).upper() != "ALL":
        sql += " AND UPPER(status)=?"; params.append(str(status).upper())
    if severity and str(severity).upper() != "ALL":
        sql += " AND UPPER(severity)=?"; params.append(str(severity).upper())
    if search and search.strip():
        term = f"%{search.strip()}%"
        sql += " AND (rule_id LIKE ? OR rule_name LIKE ? OR hostname LIKE ? OR username LIKE ? OR source_ip LIKE ?)"
        params.extend([term] * 5)
    sql += " ORDER BY CASE UPPER(severity) WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, created_at_utc DESC LIMIT ?"
    params.append(limit)
    connection = get_connection(); connection.row_factory = sqlite3.Row
    try:
        return _dict_rows(connection.execute(sql, params).fetchall())
    finally:
        connection.close()


def update_alert_status(alert_id: int, new_status: str, note: str = "") -> bool:
    """Update an alert status and append an immutable transition record."""
    status = str(new_status).strip().upper()
    if status not in ALERT_STATUSES:
        raise ValueError(f"Invalid status. Choose one of: {', '.join(ALERT_STATUSES)}")
    connection = get_connection()
    try:
        with connection:
            row = connection.execute("SELECT status FROM alerts WHERE id=?", (int(alert_id),)).fetchone()
            if row is None:
                return False
            old_status = str(row[0] or "NEW").upper()
            if old_status == status:
                return True
            changed_at = datetime.now(timezone.utc).isoformat()
            connection.execute("UPDATE alerts SET status=? WHERE id=?", (status, int(alert_id)))
            connection.execute("""INSERT INTO alert_status_history
                (alert_id,old_status,new_status,note,changed_at_utc) VALUES (?,?,?,?,?)""",
                (int(alert_id), old_status, status, (note or "").strip() or None, changed_at))
        return True
    finally:
        connection.close()


def get_alert_status_history(alert_id: int):
    connection = get_connection(); connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("""SELECT id,alert_id,old_status,new_status,note,changed_at_utc
            FROM alert_status_history WHERE alert_id=? ORDER BY changed_at_utc,id""", (int(alert_id),)).fetchall()
        return _dict_rows(rows)
    finally:
        connection.close()


def get_stories(*, status=None, severity=None, search=None, limit=200):
    limit = max(1, min(int(limit), 1000))
    sql = "SELECT * FROM attack_stories WHERE 1=1"; params: list[Any] = []
    if status and str(status).upper() != "ALL":
        sql += " AND UPPER(status)=?"; params.append(str(status).upper())
    if severity and str(severity).upper() != "ALL":
        sql += " AND UPPER(severity)=?"; params.append(str(severity).upper())
    if search and search.strip():
        term=f"%{search.strip()}%"
        sql += " AND (title LIKE ? OR hostname LIKE ? OR username LIKE ? OR source_ip LIKE ?)"
        params.extend([term]*4)
    sql += " ORDER BY last_seen DESC,id DESC LIMIT ?"; params.append(limit)
    connection=get_connection(); connection.row_factory=sqlite3.Row
    try: return _dict_rows(connection.execute(sql,params).fetchall())
    finally: connection.close()


def search_events(*, hostname=None, username=None, source_ip=None, event_id=None,
                  event_type=None, start_time=None, end_time=None, search=None, limit=300):
    """Search normalized events using exact filters and a general text search."""
    limit=max(1,min(int(limit),2000))
    sql="""SELECT ne.id,ne.event_id,ne.provider,ne.channel,ne.timestamp_utc,ne.hostname,ne.username,
        ne.source_ip,ne.destination_ip,ne.event_type,ne.image,ne.command_line,ne.raw_event_id,
        re.source_file,re.raw_xml_sha256 FROM normalized_events ne
        LEFT JOIN raw_events re ON re.id=ne.raw_event_id WHERE 1=1"""
    params: list[Any]=[]
    for column,value in (("ne.hostname",hostname),("ne.username",username),("ne.source_ip",source_ip),
                         ("ne.event_id",event_id),("ne.event_type",event_type)):
        if value and str(value).strip(): sql+=f" AND {column} LIKE ?"; params.append(f"%{str(value).strip()}%")
    if start_time: sql+=" AND ne.timestamp_utc>=?"; params.append(start_time)
    if end_time: sql+=" AND ne.timestamp_utc<=?"; params.append(end_time)
    if search and search.strip():
        term=f"%{search.strip()}%"
        sql+=" AND (ne.image LIKE ? OR ne.command_line LIKE ? OR ne.provider LIKE ? OR ne.channel LIKE ?)"
        params.extend([term]*4)
    sql+=" ORDER BY ne.timestamp_utc DESC,ne.id DESC LIMIT ?"; params.append(limit)
    connection=get_connection(); connection.row_factory=sqlite3.Row
    try: return _dict_rows(connection.execute(sql,params).fetchall())
    finally: connection.close()


def get_distinct_values(column: str):
    allowed={"hostname":"hostname","username":"username","event_type":"event_type","severity":"severity","status":"status"}
    if column not in allowed: raise ValueError("Unsupported distinct-value column")
    table="alerts" if column in {"severity","status"} else "normalized_events"
    connection=get_connection()
    try:
        rows=connection.execute(f"SELECT DISTINCT {allowed[column]} FROM {table} WHERE {allowed[column]} IS NOT NULL AND {allowed[column]}!='' ORDER BY 1").fetchall()
        return [row[0] for row in rows]
    finally: connection.close()
