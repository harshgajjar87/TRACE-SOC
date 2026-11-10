import sys
import os
import json
import hashlib

from pathlib import Path

from datetime import datetime, timezone

# Ensure the project root is on sys.path when running this file directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from normalizer.event_parser import (
    read_xml,
    extract_system_info,
    extract_event_data
)

from pydantic import ValidationError

from normalizer.event_schema import (
    create_normalized_event
)

def calculate_file_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        for chunk in iter(
            lambda: file.read(65536),
            b""
        ):

            sha256.update(chunk)

    return sha256.hexdigest()

def create_event_fingerprint(system_info, event_data):

    record_id = system_info.get("record_id")

    if record_id is not None:

        identity = {

            "provider": system_info.get("provider"),

            "channel": system_info.get("channel"),

            "hostname": system_info.get("hostname"),

            "record_id": record_id,

            "timestamp": system_info.get("timestamp")

        }

    else:

        identity = {

            "system": system_info,

            "event_data": event_data

        }

    content = json.dumps(
        identity,
        sort_keys=True,
        default=str
    )

    return hashlib.sha256(
        content.encode("utf-8")
    ).hexdigest()

def load_manifest(manifest_path):

    if not manifest_path.exists():

        return {
            "processed_files": {}
        }

    try:

        with open(manifest_path, "r", encoding="utf-8") as file:

            return json.load(file)

    except (json.JSONDecodeError, OSError):

        print("Warning: Could not read manifest.")

        return {
            "processed_files": {}
        }

def load_existing_fingerprints(output_path):

    fingerprints = set()

    if not output_path.exists():
        return fingerprints

    with open(output_path, "r", encoding="utf-8") as file:

        for line in file:

            if not line.strip():
                continue

            try:

                event = json.loads(line)

                fingerprint = event.get("event_fingerprint")

                if fingerprint:
                    fingerprints.add(fingerprint)

            except json.JSONDecodeError:

                print("Warning: Invalid JSONL record skipped.")

    return fingerprints

def collect_xml_files(input_dir, output_path, manifest_path):

    input_dir = Path(input_dir)
    output_path = Path(output_path)
    manifest_path = Path(manifest_path)

    # Check input directory
    if not input_dir.exists():

        print("Input directory does not exist:", input_dir)
        return

    # Create output directory
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    manifest_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Load previous collection history
    manifest = load_manifest(manifest_path)

    processed_files = manifest.get("processed_files", {})

    existing_fingerprints = load_existing_fingerprints(
        output_path
    )

    xml_files = sorted(input_dir.glob("*.xml"))

    total_files = len(xml_files)
    processed_count = 0
    skipped_count = 0
    duplicate_count = 0
    error_count = 0

    new_events = []

    print(f"\nFound {total_files} XML files.\n")

    for file_path in xml_files:

        print("Processing:", file_path.name)

        try:

            # Calculate source file hash
            file_hash = calculate_file_hash(file_path)

            # Check whether file was already imported
            if file_hash in processed_files:

                print("Already processed. Skipping.")
                skipped_count += 1
                continue

            # Read XML
            root = read_xml(file_path)

            if root is None:

                print("Could not parse XML.")
                error_count += 1
                continue

            # Extract information
            system_info = extract_system_info(root)

            event_data = extract_event_data(root)

            if not system_info.get("event_id"):

                print("Event ID missing. Skipping.")
                error_count += 1
                continue

            # Create normalized event
            normalized_event = create_normalized_event(
                system_info,
                event_data
            )

            # Generate event fingerprint
            fingerprint = create_event_fingerprint(
                system_info,
                event_data
            )

            # Check duplicate event
            if fingerprint in existing_fingerprints:

                print("Duplicate event detected.")
                duplicate_count += 1

            else:

                normalized_event["event_fingerprint"] = fingerprint

                normalized_event["source_file"] = file_path.name

                normalized_event["source_file_sha256"] = file_hash

                normalized_event["collected_at_utc"] = (
                    datetime.now(timezone.utc).isoformat()
                )

                new_events.append(normalized_event)

                existing_fingerprints.add(fingerprint)

                print("Event successfully collected.")

            # Mark file as processed
            processed_files[file_hash] = (
                datetime.now(timezone.utc).isoformat()
            )

            processed_count += 1

        except (
            OSError,
            ValueError,
            TypeError,
            ValidationError
        ) as error:

            print(f"Error processing {file_path.name}: {error}")

            error_count += 1

    # Append new events to JSONL
    if new_events:

        with open(
            output_path,
            "a",
            encoding="utf-8"
        ) as file:

            for event in new_events:

                file.write(
                    json.dumps(event, ensure_ascii=False) + "\n"
                )

    # Update manifest only after event output is written
    manifest["processed_files"] = processed_files

    temp_manifest = manifest_path.with_suffix(".tmp")

    temp_manifest.write_text(
        json.dumps(manifest, indent=4),
        encoding="utf-8"
    )

    temp_manifest.replace(manifest_path)

    # Final summary
    print("\n========== COLLECTION SUMMARY ==========")

    print("Total XML files:", total_files)

    print("Files processed:", processed_count)

    print("Already processed files:", skipped_count)

    print("Duplicate events:", duplicate_count)

    print("New events collected:", len(new_events))

    print("Errors:", error_count)

    print("Output:", output_path)

    print("========================================\n")

if __name__ == "__main__":

    collect_xml_files(

        input_dir="data/samples",

        output_path="data/processed/events.jsonl",

        manifest_path="data/processed/collector_manifest.json"

    )