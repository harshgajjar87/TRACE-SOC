"""Read-only investigation search and summary queries."""
import sqlite3
from database.db import get_connection
from investigation.timeline import get_story_timeline


def list_stories(limit=50, severity=None, status=None):
    limit = max(1, min(int(limit), 500))
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM attack_stories WHERE 1=1"
        params = []
        if severity:
            sql += " AND severity=?"; params.append(str(severity).upper())
        if status:
            sql += " AND status=?"; params.append(str(status).upper())
        sql += " ORDER BY last_seen DESC, id DESC LIMIT ?"; params.append(limit)
        return [dict(row) for row in connection.execute(sql, params).fetchall()]
    finally:
        connection.close()


def search_stories(hostname=None, username=None, source_ip=None):
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM attack_stories WHERE 1=1"; params = []
        for column, value in (("hostname", hostname), ("username", username), ("source_ip", source_ip)):
            if value:
                sql += f" AND {column}=?"; params.append(value)
        sql += " ORDER BY last_seen DESC"
        return [dict(row) for row in connection.execute(sql, params).fetchall()]
    finally:
        connection.close()


def get_investigation(story_id):
    result = get_story_timeline(story_id)
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    try:
        alerts = connection.execute("""SELECT a.* FROM story_alert_links sal
            JOIN alerts a ON a.id=sal.alert_id WHERE sal.story_id=? ORDER BY a.created_at_utc""",
            (story_id,)).fetchall()
        result["alerts"] = [dict(row) for row in alerts]
        return result
    finally:
        connection.close()
