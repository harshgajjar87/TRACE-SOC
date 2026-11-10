"""TRACE-SOC Day 10 investigation schema and safe SQLite migrations."""
import hashlib
from database.db import get_connection


def _ensure_column(connection, table, column, definition):
    columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def create_story_tables():
    connection = get_connection()
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS attack_stories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                story_fingerprint TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL DEFAULT 'INFO',
                status TEXT NOT NULL DEFAULT 'NEW',
                hostname TEXT, username TEXT, source_ip TEXT,
                first_seen TEXT, last_seen TEXT,
                event_count INTEGER NOT NULL DEFAULT 0,
                alert_count INTEGER NOT NULL DEFAULT 0,
                confidence_score INTEGER NOT NULL DEFAULT 0,
                confidence_level TEXT NOT NULL DEFAULT 'LOW',
                created_at_utc TEXT NOT NULL
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS story_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                story_id INTEGER NOT NULL,
                normalized_event_id INTEGER NOT NULL,
                alert_id INTEGER,
                relationship TEXT NOT NULL,
                evidence_role TEXT,
                observed_at_utc TEXT,
                FOREIGN KEY(story_id) REFERENCES attack_stories(id) ON DELETE CASCADE,
                FOREIGN KEY(normalized_event_id) REFERENCES normalized_events(id),
                FOREIGN KEY(alert_id) REFERENCES alerts(id),
                UNIQUE(story_id, normalized_event_id)
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS story_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                story_id INTEGER NOT NULL,
                event_a_id INTEGER NOT NULL,
                event_b_id INTEGER NOT NULL,
                score INTEGER NOT NULL,
                reasons_json TEXT NOT NULL,
                FOREIGN KEY(story_id) REFERENCES attack_stories(id) ON DELETE CASCADE,
                FOREIGN KEY(event_a_id) REFERENCES normalized_events(id),
                FOREIGN KEY(event_b_id) REFERENCES normalized_events(id),
                UNIQUE(story_id, event_a_id, event_b_id)
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS story_alert_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                story_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                FOREIGN KEY(story_id) REFERENCES attack_stories(id) ON DELETE CASCADE,
                FOREIGN KEY(alert_id) REFERENCES alerts(id),
                UNIQUE(story_id, alert_id)
            )""")
            # Hash each stored event XML blob separately. The existing source_file_sha256
            # hashes the original source file and is NOT a hash of this individual XML blob.
            _ensure_column(connection, "raw_events", "raw_xml_sha256", "TEXT")
            rows = connection.execute("SELECT id, raw_xml FROM raw_events WHERE raw_xml_sha256 IS NULL").fetchall()
            for row in rows:
                blob = row[1] or b""
                if isinstance(blob, str):
                    blob = blob.encode("utf-8")
                connection.execute("UPDATE raw_events SET raw_xml_sha256=? WHERE id=?",
                                   (hashlib.sha256(blob).hexdigest(), row[0]))
            for sql in [
                "CREATE INDEX IF NOT EXISTS idx_story_hostname ON attack_stories(hostname)",
                "CREATE INDEX IF NOT EXISTS idx_story_username ON attack_stories(username)",
                "CREATE INDEX IF NOT EXISTS idx_story_source_ip ON attack_stories(source_ip)",
                "CREATE INDEX IF NOT EXISTS idx_story_events_story ON story_events(story_id)",
                "CREATE INDEX IF NOT EXISTS idx_story_events_alert ON story_events(alert_id)",
                "CREATE INDEX IF NOT EXISTS idx_story_relationships_story ON story_relationships(story_id)",
            ]:
                connection.execute(sql)
        print("TRACE-SOC attack investigation tables ready!")
    finally:
        connection.close()
