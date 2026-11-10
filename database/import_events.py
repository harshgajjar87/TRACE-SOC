
import json
import hashlib
import sqlite3

from pathlib import Path
from datetime import datetime, timezone

from database.db import get_connection, create_tables
from investigation.story_schema import create_story_tables


# Input and output locations
JSONL_PATH = Path("data/processed/events.jsonl")
SAMPLES_PATH = Path("data/samples")


def calculate_sha256(content):
    """Calculate SHA-256 hash of bytes."""
    return hashlib.sha256(content).hexdigest()


def import_events():

    if not JSONL_PATH.exists():
        print("JSONL file not found:", JSONL_PATH)
        return

    # Create base database tables first.
    create_tables()

    # Apply Day 10 schema migration.
    # This ensures raw_xml_sha256 exists before importing.
    create_story_tables()

    connection = get_connection()

    total = 0
    imported = 0
    duplicates = 0
    errors = 0

    try:

        with open(
            JSONL_PATH,
            "r",
            encoding="utf-8"
        ) as file:

            for line_number, line in enumerate(file, start=1):

                if not line.strip():
                    continue

                total += 1

                try:

                    event = json.loads(line)

                    source_file = event.get("source_file")
                    source_hash = event.get("source_file_sha256")
                    fingerprint = event.get("event_fingerprint")

                    if not source_file or not source_hash or not fingerprint:
                        raise ValueError(
                            "Required source metadata missing"
                        )

                    # Locate original XML.
                    xml_path = SAMPLES_PATH / source_file

                    if not xml_path.exists():
                        raise FileNotFoundError(
                            f"Original XML missing: {xml_path}"
                        )

                    # Read original XML bytes.
                    raw_xml = xml_path.read_bytes()

                    # Calculate hash of the complete source XML file.
                    actual_hash = calculate_sha256(raw_xml)

                    # Verify original source file integrity.
                    if actual_hash.lower() != source_hash.lower():

                        raise ValueError(
                            "Source file SHA-256 mismatch. "
                            "Source file may have changed."
                        )

                    # Individual event XML hash.
                    raw_xml_hash = calculate_sha256(raw_xml)

                    now = datetime.now(timezone.utc).isoformat()

                    # One transaction per event.
                    with connection:

                        cursor = connection.cursor()

                        # Insert original event evidence.
                        cursor.execute("""
                            INSERT OR IGNORE INTO raw_events (

                                event_fingerprint,
                                source_file,
                                source_file_sha256,
                                raw_xml,
                                raw_xml_sha256,
                                event_id,
                                provider,
                                channel,
                                record_id,
                                timestamp_utc,
                                hostname,
                                collected_at_utc

                            )

                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                        """, (

                            fingerprint,
                            source_file,
                            source_hash,
                            sqlite3.Binary(raw_xml),
                            raw_xml_hash,
                            event.get("event_id"),
                            event.get("provider"),
                            event.get("channel"),
                            str(event.get("record_id"))
                                if event.get("record_id") is not None else None,
                            event.get("timestamp_utc"),
                            event.get("hostname"),
                            event.get("collected_at_utc") or now

                        ))

                        # Duplicate event check.
                        if cursor.rowcount == 0:

                            duplicates += 1
                            continue

                        # Get raw event database ID.
                        raw_event = cursor.execute("""

                            SELECT id
                            FROM raw_events
                            WHERE event_fingerprint = ?

                        """, (fingerprint,)).fetchone()

                        if raw_event is None:
                            raise sqlite3.Error(
                                "Could not retrieve inserted raw event"
                            )

                        raw_event_id = raw_event[0]

                        # Insert normalized event.
                        cursor.execute("""

                            INSERT INTO normalized_events (

                                raw_event_id,
                                event_id,
                                record_id,
                                provider,
                                channel,
                                timestamp_utc,
                                hostname,
                                username,
                                process_id,
                                parent_process_id,
                                process_guid,
                                parent_process_guid,
                                image,
                                command_line,
                                source_ip,
                                destination_ip,
                                event_type,
                                extra_data_json

                            )

                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

                        """, (

                            raw_event_id,
                            event.get("event_id"),
                            str(event.get("record_id"))
                                if event.get("record_id") is not None else None,
                            event.get("provider"),
                            event.get("channel"),
                            event.get("timestamp_utc"),
                            event.get("hostname"),
                            event.get("username"),
                            event.get("process_id"),
                            event.get("parent_process_id"),
                            event.get("process_guid"),
                            event.get("parent_process_guid"),
                            event.get("image"),
                            event.get("command_line"),
                            event.get("source_ip"),
                            event.get("destination_ip"),
                            event.get("event_type"),
                            json.dumps(
                                event.get("extra_data", {}),
                                ensure_ascii=False
                            )

                        ))

                    imported += 1

                    print(
                        f"Imported event {event.get('event_id')} "
                        f"from {source_file}"
                    )

                except (
                    json.JSONDecodeError,
                    ValueError,
                    OSError,
                    sqlite3.Error,
                    TypeError
                ) as error:

                    errors += 1

                    print(
                        f"Error on JSONL line {line_number}: {error}"
                    )

    finally:

        connection.close()

    print("\n========== DATABASE IMPORT SUMMARY ==========")

    print("Total events:", total)
    print("Imported:", imported)
    print("Duplicates:", duplicates)
    print("Errors:", errors)

    print("===============================================")


if __name__ == "__main__":

    import_events()
