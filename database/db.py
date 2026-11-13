
import sqlite3

from pathlib import Path


# Database location
DATABASE_PATH = Path("data/tracesoc.db")


def get_connection():

    # Ensure database folder exists
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(DATABASE_PATH)

    # Return rows as sqlite3.Row objects so dict(row) works correctly
    connection.row_factory = sqlite3.Row

    # Enable foreign key constraints
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def create_tables():

    connection = get_connection()

    cursor = connection.cursor()

    # Table 1: Raw Events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_fingerprint TEXT NOT NULL UNIQUE,

            source_file TEXT NOT NULL,

            source_file_sha256 TEXT NOT NULL,

            raw_xml BLOB NOT NULL,

            event_id TEXT,

            provider TEXT,

            channel TEXT,

            record_id TEXT,

            timestamp_utc TEXT,

            hostname TEXT,

            collected_at_utc TEXT NOT NULL

        )
    """)

    # Table 2: Normalized Events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS normalized_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            raw_event_id INTEGER NOT NULL UNIQUE,

            event_id TEXT,

            record_id TEXT,

            provider TEXT,

            channel TEXT,

            timestamp_utc TEXT,

            hostname TEXT,

            username TEXT,

            process_id INTEGER,

            parent_process_id INTEGER,

            process_guid TEXT,

            parent_process_guid TEXT,

            image TEXT,

            command_line TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            event_type TEXT,

            extra_data_json TEXT,

            FOREIGN KEY (raw_event_id)
                REFERENCES raw_events(id)

        )
    """)

    # Indexes for faster searching
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_event_id
        ON normalized_events(event_id)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_username
        ON normalized_events(username)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_hostname
        ON normalized_events(hostname)
    """)

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_timestamp
        ON normalized_events(timestamp_utc)
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            alert_fingerprint TEXT NOT NULL UNIQUE,

            rule_id TEXT NOT NULL,

            rule_name TEXT NOT NULL,

            description TEXT,

            severity TEXT NOT NULL,

            status TEXT NOT NULL DEFAULT 'NEW',

            hostname TEXT,

            username TEXT,

            source_ip TEXT,

            first_seen TEXT,

            last_seen TEXT,

            event_count INTEGER DEFAULT 1,

            mitre_tactic TEXT,

            mitre_technique TEXT,

            evidence_json TEXT,

            created_at_utc TEXT NOT NULL

        )
    """)

    connection.commit()

    connection.close()

    print("TRACE-SOC database created successfully!")


if __name__ == "__main__":

    create_tables()
