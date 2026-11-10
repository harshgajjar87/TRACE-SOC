
from normalizer.models import NormalizedEvent


def convert_pid(value):

    if value is None or value in ("", "-"):
        return None

    try:
        return int(str(value), 0)

    except (ValueError, TypeError):
        return None


def classify_event(event_id):

    event_types = {

        "4624": "authentication_success",
        "4625": "authentication_failure",
        "4634": "logoff",
        "4648": "explicit_credentials",
        "4672": "privileged_logon",
        "4688": "process_creation",
        "4698": "scheduled_task_created",
        "4719": "audit_policy_changed",
        "1102": "security_log_cleared",
        "4720": "user_account_created",
        "4728": "group_membership_changed",
        "4732": "group_membership_changed",

        "1": "process_creation",
        "2": "file_timestamp_changed",
        "3": "network_connection",
        "5": "process_terminated",
        "7": "image_loaded",
        "10": "process_access",
        "11": "file_creation",
        "12": "registry_object_changed",
        "13": "registry_value_changed",
        "14": "registry_value_renamed",
        "22": "dns_query",
        "25": "process_tampering"

    }

    return event_types.get(str(event_id), "unknown")


def create_normalized_event(system_info, event_data):

    event_id = str(system_info.get("event_id", ""))

    if not event_id:
        raise ValueError("Event ID is missing")

    provider = system_info.get("provider") or ""

    # Username mapping
    username = (
        event_data.get("TargetUserName")
        or event_data.get("SubjectUserName")
        or event_data.get("User")
    )

    # Process ID mapping
    process_id = (
        event_data.get("ProcessId")
        or event_data.get("NewProcessId")
    )

    parent_process_id = (
        event_data.get("ParentProcessId")
        or event_data.get("CreatorProcessId")
    )

    # Image mapping
    image = (
        event_data.get("Image")
        or event_data.get("NewProcessName")
    )

    # Network mapping
    source_ip = (
        event_data.get("SourceIp")
        or event_data.get("IpAddress")
    )

    destination_ip = event_data.get("DestinationIp")

    candidate = {

        "event_id": event_id,

        "record_id": (
            str(system_info["record_id"])
            if system_info.get("record_id") is not None
            else None
        ),

        "provider": provider,

        "channel": system_info.get("channel"),

        "timestamp_utc": system_info.get("timestamp"),

        "hostname": system_info.get("hostname"),

        "username": username,

        "process_id": convert_pid(process_id),

        "parent_process_id": convert_pid(parent_process_id),

        "process_guid": event_data.get("ProcessGuid"),

        "parent_process_guid": event_data.get("ParentProcessGuid"),

        "image": image,

        "command_line": (
            event_data.get("CommandLine")
            or event_data.get("ProcessCommandLine")
        ),

        "source_ip": source_ip,

        "destination_ip": destination_ip,

        "event_type": classify_event(event_id),

        "extra_data": event_data

    }

    validated_event = NormalizedEvent.model_validate(candidate)

    return validated_event.model_dump(mode="json")
