import json
import os

from normalizer.event_parser import (
    read_xml,
    extract_system_info,
    extract_event_data
)

from normalizer.event_schema import create_normalized_event

# Resolve sample paths relative to this file, not the working directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(BASE_DIR, "data", "samples")


def process_event(file_path):

    print("\nReading:", file_path)

    root = read_xml(file_path)

    if root is None:
        return

    system_info = extract_system_info(root)

    event_data = extract_event_data(root)

    normalized_event = create_normalized_event(
        system_info,
        event_data
    )

    print("\nNormalized Event:\n")

    print(
        json.dumps(
            normalized_event,
            indent=4
        )
    )


if __name__ == "__main__":

    process_event(os.path.join(SAMPLES_DIR, "security_4624.xml"))

    process_event(os.path.join(SAMPLES_DIR, "security_4688.xml"))

    process_event(os.path.join(SAMPLES_DIR, "sysmon_1.xml"))