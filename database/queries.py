
from database.db import get_connection


def get_event_count():

    connection = get_connection()

    result = connection.execute("""
        SELECT COUNT(*)
        FROM normalized_events
    """).fetchone()

    connection.close()

    return result[0]


def get_events_by_id(event_id):

    connection = get_connection()

    results = connection.execute("""

        SELECT
            id,
            event_id,
            username,
            hostname,
            timestamp_utc,
            event_type

        FROM normalized_events

        WHERE event_id = ?

        ORDER BY timestamp_utc DESC

    """, (str(event_id),)).fetchall()

    connection.close()

    return results


def get_events_by_username(username):

    connection = get_connection()

    results = connection.execute("""

        SELECT
            id,
            event_id,
            username,
            hostname,
            timestamp_utc,
            event_type

        FROM normalized_events

        WHERE username = ?

        ORDER BY timestamp_utc DESC

    """, (username,)).fetchall()

    connection.close()

    return results


def get_recent_events(limit=10):

    connection = get_connection()

    results = connection.execute("""

        SELECT
            id,
            event_id,
            username,
            hostname,
            timestamp_utc,
            event_type

        FROM normalized_events

        ORDER BY timestamp_utc DESC

        LIMIT ?

    """, (limit,)).fetchall()

    connection.close()

    return results


def get_raw_event(normalized_id):

    connection = get_connection()

    result = connection.execute("""

        SELECT
            raw_events.id,
            raw_events.source_file,
            raw_events.source_file_sha256,
            raw_events.raw_xml

        FROM normalized_events

        JOIN raw_events

        ON normalized_events.raw_event_id = raw_events.id

        WHERE normalized_events.id = ?

    """, (normalized_id,)).fetchone()

    connection.close()

    return result


if __name__ == "__main__":

    print("\nTotal normalized events:")

    print(get_event_count())

    print("\nRecent events:")

    for event in get_recent_events():

        print(event)

    print("\nAuthentication success events:")

    for event in get_events_by_id("4624"):

        print(event)
