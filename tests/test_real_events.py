
import pytest

from pathlib import Path

from normalizer.event_parser import (
    read_xml,
    extract_system_info,
    extract_event_data
)

from normalizer.event_schema import create_normalized_event


SAMPLES = Path(__file__).parent.parent / "data" / "samples"


@pytest.mark.parametrize("file_name", [
    "security_4624.xml",
    "security_4688.xml",
    "sysmon_1.xml",
])
def test_real_xml_file(file_name):

    file_path = SAMPLES / file_name

    print(f"\nTesting: {file_name}")

    root = read_xml(file_path)

    assert root is not None, "XML parsing failed"

    system_info = extract_system_info(root)

    event_data = extract_event_data(root)

    result = create_normalized_event(
        system_info,
        event_data
    )

    print("\nNormalized Event:")

    for key, value in result.items():

        print(f"{key}: {value}")

    assert result["event_id"] is not None

    assert result["provider"] is not None

    assert result["hostname"] is not None

    assert isinstance(result["extra_data"], dict)

    print("\nValidation successful!")


if __name__ == "__main__":

    files = [
        "security_4624.xml",
        "security_4688.xml",
        "sysmon_1.xml"
    ]

    for file_name in files:

        if (SAMPLES / file_name).exists():

            test_real_xml_file(file_name)

        else:

            print("Sample unavailable:", file_name)
