
import xml.etree.ElementTree as ET


def find_tag(element, tag_name):

    for child in element.iter():
        if child.tag.split("}")[-1] == tag_name:
            return child

    return None


def read_xml(file_path):

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        return root

    except ET.ParseError as error:
        print("XML parsing error:", error)

    except FileNotFoundError:
        print("File not found:", file_path)

    return None


def extract_event_id(root):

    system = find_tag(root, "System")

    if system is None:
        return None

    event_id = find_tag(system, "EventID")

    if event_id is not None:
        return event_id.text

    return None


def extract_system_info(root):

    system = find_tag(root, "System")

    if system is None:
        return {}

    info = {}

    provider = find_tag(system, "Provider")

    if provider is not None:
        info["provider"] = provider.get("Name")

    event_id = find_tag(system, "EventID")

    if event_id is not None:
        info["event_id"] = event_id.text

    computer = find_tag(system, "Computer")

    if computer is not None:
        info["hostname"] = computer.text

    time_created = find_tag(system, "TimeCreated")

    if time_created is not None:
        info["timestamp"] = time_created.get("SystemTime")

    channel = find_tag(system, "Channel")

    if channel is not None:
        info["channel"] = channel.text

    return info


def extract_event_data(root):

    event_data = {}

    # Extract traditional EventData fields.
    for data in root.iter():

        if data.tag.split("}")[-1] == "Data":

            field_name = data.get("Name")

            if field_name:
                event_data[field_name] = data.text

    # Extract UserData fields from Windows events.
    user_data = find_tag(root, "UserData")

    if user_data is not None:

        for element in user_data.iter():

            # Extract leaf elements only.
            if len(element) == 0:

                field_name = element.tag.split("}")[-1]

                if field_name and field_name not in event_data:
                    event_data[field_name] = element.text

    return event_data
