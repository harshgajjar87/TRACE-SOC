
"""
TRACE-SOC - Windows Event Log Collector

Collects Windows Event Logs using PowerShell, normalizes selected
fields, and stores both raw XML and normalized events in SQLite.

This collector uses incremental EventRecordID tracking per channel.
"""

import argparse
import hashlib
import json
import subprocess
import sys

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET

from database.db import create_tables, get_connection


DEFAULT_CHANNELS = [
    "System",
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
]

STATE_FILE = Path("data/collector_state/windows_event_state.json")

SYSTEM_TAG = "{http://schemas.microsoft.com/win/2004/08/events/event}System"
EVENT_DATA_TAG = "{http://schemas.microsoft.com/win/2004/08/events/event}EventData"


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_state(state_file: Path) -> dict:
    """Load last processed Record ID for each event channel."""
    if not state_file.exists():
        return {}

    try:
        with state_file.open("r", encoding="utf-8") as file:
            state = json.load(file)
        return state if isinstance(state, dict) else {}
    except (json.JSONDecodeError, OSError):
        raise RuntimeError(
            f"Could not read collector state file: {state_file}"
        )


def save_state(state: dict, state_file: Path):
    """Save state atomically to avoid partially written JSON."""
    state_file.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = state_file.with_suffix(
        state_file.suffix + ".tmp"
    )

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(state, file, indent=4)

    temporary_file.replace(state_file)


def query_windows_event_log(
    channel: str,
    last_record_id: int,
    max_events: int = 500,
    runner=None,
) -> list:
    """
    Query Windows Event Log using PowerShell.

    First collection: retrieve the newest max_events.
    Later collections: retrieve records with RecordID greater
    than the previously saved RecordID.
    """
    if sys.platform != "win32":
        raise RuntimeError(
            "Windows Event Log collection must run on Windows."
        )

    if max_events < 1:
        raise ValueError("max_events must be at least 1.")

    # Safely escape a PowerShell single-quoted string.
    safe_channel = channel.replace("'", "''")

    if last_record_id > 0:
        query = (
            f"*[System[EventRecordID > {int(last_record_id)}]]"
        )

        retrieval = (
            f"$events = @(Get-WinEvent -LogName '{safe_channel}' "
            f"-FilterXPath '{query}' -Oldest "
            f"-MaxEvents {int(max_events)})"
        )
    else:
        retrieval = (
            f"$events = @(Get-WinEvent -LogName '{safe_channel}' "
            f"-MaxEvents {int(max_events)})"
        )

    script = f"""
$ErrorActionPreference = 'Stop'
try {{
    {retrieval}
    $events = @($events | Sort-Object RecordId)

    $result = @(
        $events | ForEach-Object {{
            [PSCustomObject]@{{
                RecordId = [long]$_.RecordId
                Xml = $_.ToXml()
            }}
        }}
    )

    if ($result.Count -eq 0) {{
        '[]'
    }}
    else {{
        ConvertTo-Json -InputObject $result -Compress -Depth 3
    }}
}}
catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}}
"""

    encoded_script = (
        __import__("base64").b64encode(
            script.encode("utf-16le")
        ).decode("ascii")
    )

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-EncodedCommand",
        encoded_script,
    ]

    execute = runner or subprocess.run

    result = execute(
        command,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    if result.returncode != 0:
        error = (result.stderr or result.stdout).strip()

        # Get-WinEvent exits with code 1 when the query matches zero
        # events.  This is a normal "no results" condition, not a real
        # error, so return an empty list instead of raising.
        no_events_phrases = (
            "no events were found",
            "no matching events",
        )
        if any(phrase in error.lower() for phrase in no_events_phrases):
            return []

        raise RuntimeError(
            f"Could not collect channel '{channel}': {error}"
        )

    output = result.stdout.strip()

    if not output:
        return []

    try:
        records = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid PowerShell JSON for channel '{channel}'."
        ) from exc

    # PowerShell may serialize one result as a JSON object.
    if isinstance(records, dict):
        records = [records]

    if not isinstance(records, list):
        raise RuntimeError(
            f"Unexpected PowerShell output for '{channel}'."
        )

    return records


def _event_fields(root: ET.Element) -> dict:
    """Extract Windows System and EventData fields from XML."""
    system = root.find(SYSTEM_TAG)

    if system is None:
        raise ValueError("Windows event XML has no System section.")

    # Use namespace-independent child lookup for System fields.
    children = {
        child.tag.split("}")[-1]: child
        for child in list(system)
    }

    provider_element = children.get("Provider")
    time_element = children.get("TimeCreated")
    security_element = children.get("Security")

    provider = ""
    if provider_element is not None:
        provider = provider_element.attrib.get("Name", "")

    timestamp = ""
    if time_element is not None:
        timestamp = time_element.attrib.get("SystemTime", "")

    event_data = {}
    event_data_element = root.find(EVENT_DATA_TAG)

    if event_data_element is not None:
        for item in list(event_data_element):
            name = item.attrib.get("Name")
            if name:
                event_data[name] = item.text or ""

    # Also support event XML that uses a different namespace prefix.
    if event_data_element is None:
        for element in root.iter():
            if element.tag.split("}")[-1] == "Data":
                name = element.attrib.get("Name")
                if name:
                    event_data[name] = element.text or ""

    security_user = ""
    if security_element is not None:
        security_user = security_element.attrib.get("UserID", "")

    def first_value(*names):
        for name in names:
            value = event_data.get(name)
            if value and value not in ("-", "N/A"):
                return value
        return None

    return {
        "event_id": children.get("EventID").text
        if children.get("EventID") is not None else None,
        "record_id": children.get("EventRecordID").text
        if children.get("EventRecordID") is not None else None,
        "provider": provider,
        "channel": children.get("Channel").text
        if children.get("Channel") is not None else None,
        "timestamp": timestamp,
        "hostname": children.get("Computer").text
        if children.get("Computer") is not None else None,
        "username": first_value(
            "TargetUserName",
            "SubjectUserName",
            "User",
            "AccountName",
        ) or security_user or None,
        "process_id": first_value("ProcessId", "ProcessID"),
        "parent_process_id": first_value(
            "ParentProcessId", "ParentProcessID"
        ),
        "process_guid": first_value("ProcessGuid"),
        "parent_process_guid": first_value("ParentProcessGuid"),
        "image": first_value("Image", "NewProcessName"),
        "command_line": first_value(
            "CommandLine", "ProcessCommandLine"
        ),
        "source_ip": first_value(
            "SourceIp",
            "SourceIP",
            "IpAddress",
            "ClientAddress",
            "WorkstationAddress",
        ),
        "destination_ip": first_value(
            "DestinationIp",
            "DestinationIP",
            "DestAddress",
            "DestinationAddress",
        ),
        "event_data": event_data,
    }


def parse_windows_event(xml_text: str) -> dict:
    """Convert one Windows Event XML document to a normalized record."""
    root = ET.fromstring(xml_text)
    fields = _event_fields(root)

    timestamp = fields["timestamp"]

    if timestamp:
        try:
            parsed_time = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
            if parsed_time.tzinfo is None:
                parsed_time = parsed_time.replace(
                    tzinfo=timezone.utc
                )
            timestamp = parsed_time.astimezone(
                timezone.utc
            ).isoformat()
        except ValueError:
            pass

    event_id = fields["event_id"]
    event_type = "WINDOWS_EVENT"

    if event_id in ("4624", "4625", "4634", "4648"):
        event_type = "AUTHENTICATION"
    elif event_id in ("4688", "1"):
        event_type = "PROCESS_EXECUTION"
    elif event_id in ("1102",):
        event_type = "LOG_CLEARED"
    elif event_id in ("3",):
        event_type = "NETWORK_CONNECTION"

    return {
        "event_id": event_id,
        "record_id": fields["record_id"],
        "provider": fields["provider"],
        "channel": fields["channel"],
        "timestamp_utc": timestamp,
        "hostname": fields["hostname"],
        "username": fields["username"],
        "process_id": fields["process_id"],
        "parent_process_id": fields["parent_process_id"],
        "process_guid": fields["process_guid"],
        "parent_process_guid": fields["parent_process_guid"],
        "image": fields["image"],
        "command_line": fields["command_line"],
        "source_ip": fields["source_ip"],
        "destination_ip": fields["destination_ip"],
        "event_type": event_type,
        "extra_data_json": json.dumps(
            fields["event_data"],
            ensure_ascii=False,
        ),
    }


def store_event(channel: str, xml_text: str) -> bool:
    """
    Store original XML and normalized fields.

    Returns True when a new raw event is inserted.
    Duplicate fingerprints are ignored.
    """
    raw_xml = xml_text.encode("utf-8")
    fingerprint = sha256_bytes(raw_xml)
    normalized = parse_windows_event(xml_text)

    source_file = f"windows_eventlog:{channel}"
    collected_at = utc_now()

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT OR IGNORE INTO raw_events (
                event_fingerprint,
                source_file,
                source_file_sha256,
                raw_xml,
                event_id,
                provider,
                channel,
                record_id,
                timestamp_utc,
                hostname,
                collected_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                source_file,
                fingerprint,
                raw_xml,
                normalized["event_id"],
                normalized["provider"],
                normalized["channel"],
                normalized["record_id"],
                normalized["timestamp_utc"],
                normalized["hostname"],
                collected_at,
            ),
        )

        inserted = cursor.rowcount == 1

        cursor.execute(
            """
            SELECT id FROM raw_events
            WHERE event_fingerprint = ?
            """,
            (fingerprint,),
        )
        raw_row = cursor.fetchone()

        if raw_row is None:
            raise RuntimeError("Could not retrieve stored raw event.")

        raw_event_id = raw_row[0]

        cursor.execute(
            """
            INSERT OR IGNORE INTO normalized_events (
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
            """,
            (
                raw_event_id,
                normalized["event_id"],
                normalized["record_id"],
                normalized["provider"],
                normalized["channel"],
                normalized["timestamp_utc"],
                normalized["hostname"],
                normalized["username"],
                normalized["process_id"],
                normalized["parent_process_id"],
                normalized["process_guid"],
                normalized["parent_process_guid"],
                normalized["image"],
                normalized["command_line"],
                normalized["source_ip"],
                normalized["destination_ip"],
                normalized["event_type"],
                normalized["extra_data_json"],
            ),
        )

        connection.commit()
        return inserted

    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def collect_windows_events(
    channels: Optional[list] = None,
    max_events: int = 500,
    state_file: Path = STATE_FILE,
    query_function=None,
) -> dict:
    """
    Collect events from configured channels and save progress.

    The saved Record ID is updated only after all returned records
    for that channel have been stored successfully.
    """
    if max_events < 1:
        raise ValueError("max_events must be at least 1.")

    create_tables()

    channels = channels or DEFAULT_CHANNELS
    state_file = Path(state_file)
    state = load_state(state_file)
    query = query_function or query_windows_event_log

    summary = {
        "channels": {},
        "total_received": 0,
        "total_inserted": 0,
        "total_duplicates": 0,
    }

    for channel in channels:
        last_id = int(state.get(channel, 0))

        records = query(
            channel=channel,
            last_record_id=last_id,
            max_events=max_events,
        )

        valid_records = []

        for record in records:
            xml_text = record.get("Xml")
            record_id = int(record.get("RecordId", 0))

            if not xml_text or record_id <= 0:
                continue

            valid_records.append((record_id, xml_text))

        valid_records.sort(key=lambda item: item[0])

        inserted_count = 0
        duplicate_count = 0
        highest_id = last_id

        for record_id, xml_text in valid_records:
            inserted = store_event(channel, xml_text)

            if inserted:
                inserted_count += 1
            else:
                duplicate_count += 1

            highest_id = max(highest_id, record_id)

        # Persist progress after this channel has been processed.
        state[channel] = highest_id
        save_state(state, state_file)

        summary["channels"][channel] = {
            "received": len(valid_records),
            "inserted": inserted_count,
            "duplicates": duplicate_count,
            "last_record_id": highest_id,
        }

        summary["total_received"] += len(valid_records)
        summary["total_inserted"] += inserted_count
        summary["total_duplicates"] += duplicate_count

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="TRACE-SOC Windows Event Log Collector"
    )

    parser.add_argument(
        "--channels",
        nargs="+",
        default=DEFAULT_CHANNELS,
        help="Windows Event Log channels to collect.",
    )

    parser.add_argument(
        "--max-events",
        type=int,
        default=500,
        help="Maximum events to retrieve per channel.",
    )

    parser.add_argument(
        "--state-file",
        default=str(STATE_FILE),
        help="Path to incremental collection state JSON.",
    )

    args = parser.parse_args()

    try:
        summary = collect_windows_events(
            channels=args.channels,
            max_events=args.max_events,
            state_file=Path(args.state_file),
        )

        print("\n========== TRACE-SOC COLLECTION ==========")

        for channel, details in summary["channels"].items():
            print(f"\nChannel: {channel}")
            print(f"Received: {details['received']}")
            print(f"Inserted: {details['inserted']}")
            print(f"Duplicates: {details['duplicates']}")
            print(f"Last Record ID: {details['last_record_id']}")

        print("\nTotal received:", summary["total_received"])
        print("Total inserted:", summary["total_inserted"])
        print("Total duplicates:", summary["total_duplicates"])
        print("\nCollection completed.")

    except Exception as exc:
        print(f"\nCollection failed: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
