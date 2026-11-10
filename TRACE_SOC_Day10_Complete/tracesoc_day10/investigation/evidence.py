"""Evidence access and integrity checks for raw XML event blobs."""
import hashlib
from database.db import get_connection
from investigation.story_schema import create_story_tables


def verify_raw_event_integrity(raw_event_id):
    # Ensure the migration has added/backfilled raw_xml_sha256.
    create_story_tables()
    connection = get_connection()
    try:
        row = connection.execute("SELECT id,raw_xml,raw_xml_sha256,source_file_sha256,source_file FROM raw_events WHERE id=?",
                                 (raw_event_id,)).fetchone()
        if row is None:
            raise ValueError(f"Raw event {raw_event_id} was not found")
        blob = row[1] or b""
        if isinstance(blob, str): blob = blob.encode("utf-8")
        actual = hashlib.sha256(blob).hexdigest()
        expected = row[2]
        return {
            "raw_event_id": row[0],
            "status": "VERIFIED" if expected and actual == expected else "MISMATCH" if expected else "NO_BASELINE_HASH",
            "expected_raw_xml_sha256": expected,
            "actual_raw_xml_sha256": actual,
            "source_file": row[4],
            "source_file_sha256": row[3],
            "note": "source_file_sha256 hashes the original source file; raw_xml_sha256 hashes this stored event XML blob."
        }
    finally:
        connection.close()


def get_story_evidence(story_id):
    connection = get_connection()
    connection.row_factory = __import__("sqlite3").Row
    try:
        rows = connection.execute("""SELECT DISTINCT re.id AS raw_event_id,re.source_file,
            re.source_file_sha256,re.raw_xml_sha256,re.event_id,re.record_id,re.timestamp_utc
            FROM story_events se JOIN normalized_events ne ON ne.id=se.normalized_event_id
            JOIN raw_events re ON re.id=ne.raw_event_id
            WHERE se.story_id=? ORDER BY re.timestamp_utc""", (story_id,)).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()
