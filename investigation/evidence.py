
"""Evidence access and integrity checks for raw XML event blobs."""

import hashlib

from database.db import get_connection
from investigation.story_schema import create_story_tables


def verify_raw_event_integrity(raw_event_id):
    # This migration creates/backfills raw_xml_sha256 when necessary.
    create_story_tables()

    connection = get_connection()
    try:
        row = connection.execute("""
            SELECT id, raw_xml, raw_xml_sha256,
                   source_file_sha256, source_file
            FROM raw_events
            WHERE id=?
        """, (int(raw_event_id),)).fetchone()

        if row is None:
            raise ValueError(f"Raw event {raw_event_id} was not found.")

        blob = row["raw_xml"] or b""
        if isinstance(blob, str):
            blob = blob.encode("utf-8")

        actual = hashlib.sha256(blob).hexdigest()
        expected = row["raw_xml_sha256"]

        if expected and actual == expected:
            status = "VERIFIED"
        elif expected:
            status = "MISMATCH"
        else:
            status = "NO_BASELINE_HASH"

        return {
            "raw_event_id": row["id"],
            "status": status,
            "expected_raw_xml_sha256": expected,
            "actual_raw_xml_sha256": actual,
            "source_file": row["source_file"],
            "source_file_sha256": row["source_file_sha256"],
            "note": (
                "source_file_sha256 hashes the original source file; "
                "raw_xml_sha256 hashes this stored event XML blob."
            ),
        }
    finally:
        connection.close()


def get_story_evidence(story_id):
    connection = get_connection()
    try:
        rows = connection.execute("""
            SELECT DISTINCT
                re.id AS raw_event_id,
                re.source_file,
                re.source_file_sha256,
                re.raw_xml_sha256,
                re.event_id,
                re.record_id,
                re.timestamp_utc,
                re.hostname,
                re.collected_at_utc
            FROM story_events se
            JOIN normalized_events ne
                ON ne.id = se.normalized_event_id
            JOIN raw_events re
                ON re.id = ne.raw_event_id
            WHERE se.story_id=?
            ORDER BY re.timestamp_utc
        """, (int(story_id),)).fetchall()

        return [dict(row) for row in rows]
    finally:
        connection.close()
