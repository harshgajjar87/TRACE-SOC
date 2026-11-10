
"""
TRACE-SOC: Detection Coverage Registry

Purpose:
Maintain a central registry of attack categories,
detection rules, required telemetry and limitations.
"""

DETECTION_COVERAGE = {

    "authentication": {
        "name": "Authentication Attacks",

        "attacks": [
            "Brute Force",
            "Password Spraying",
            "Repeated Login Failures",
            "Successful Login After Repeated Failures",
            "Account Lockout",
            "Suspicious Remote Login"
        ],

        "required_events": {
            "Security": [4624, 4625, 4740]
        },

        "required_fields": [
            "timestamp_utc",
            "username",
            "source_ip",
            "event_id"
        ],

        "rules": [
            "TS001",
            "TS009",
            "TS010",
            "TS011"
        ],

        "limitations": [
            "Source IP may be unavailable.",
            "Successful login alone does not prove malicious activity.",
            "Missing authentication logs reduce detection capability."
        ]
    },

    "execution": {
        "name": "Execution Attacks",

        "attacks": [
            "Suspicious PowerShell",
            "Encoded PowerShell Commands",
            "Suspicious Process Execution",
            "Unusual Parent-Child Processes",
            "Script Interpreter Abuse"
        ],

        "required_events": {
            "Sysmon": [1],
            "Security": [4688]
        },

        "required_fields": [
            "timestamp_utc",
            "image",
            "command_line",
            "process_id",
            "parent_process_id"
        ],

        "rules": [
            "TS002",
            "TS012",
            "TS013"
        ],

        "limitations": [
            "Command-line logging must be enabled.",
            "Process creation telemetry is required.",
            "Obfuscated commands may evade simple keyword rules."
        ]
    },

    "persistence": {
        "name": "Persistence Attacks",

        "attacks": [
            "New User Creation",
            "Scheduled Task Creation",
            "Suspicious Service Creation",
            "Registry Persistence",
            "Startup Folder Modification"
        ],

        "required_events": {
            "Security": [4698, 4697, 4720],
            "Sysmon": [12, 13, 14]
        },

        "required_fields": [
            "timestamp_utc",
            "event_id",
            "hostname",
            "username"
        ],

        "rules": [
            "TS004",
            "TS006",
            "TS014",
            "TS015"
        ],

        "limitations": [
            "Registry monitoring requires suitable Sysmon configuration.",
            "Some persistence methods require additional telemetry."
        ]
    },

    "privilege_escalation": {
        "name": "Privilege Escalation",

        "attacks": [
            "Privileged Group Membership Changes",
            "Suspicious Account Privileges",
            "Unexpected Administrator Account Creation",
            "Privilege Assignment Changes"
        ],

        "required_events": {
            "Security": [4720, 4728, 4732, 4756, 4672]
        },

        "required_fields": [
            "timestamp_utc",
            "username",
            "event_id",
            "hostname"
        ],

        "rules": [
            "TS005",
            "TS016",
            "TS017"
        ],

        "limitations": [
            "Group name or group SID is needed to identify sensitive groups.",
            "Special privileges do not automatically indicate malicious activity."
        ]
    },

    "network": {
        "name": "Network Attacks",

        "attacks": [
            "Port Scanning Indicators",
            "Suspicious Outbound Connections",
            "Unusual Network Connections",
            "Suspicious DNS Activity",
            "Potential Command and Control Communication"
        ],

        "required_events": {
            "Sysmon": [3, 22]
        },

        "required_fields": [
            "timestamp_utc",
            "source_ip",
            "destination_ip",
            "hostname"
        ],

        "rules": [
            "TS018",
            "TS019",
            "TS020"
        ],

        "limitations": [
            "Sysmon network and DNS logging must be enabled.",
            "Encrypted traffic limits payload visibility.",
            "A single network connection is not proof of an attack."
        ]
    },

    "data_file": {
        "name": "Data and File Attacks",

        "attacks": [
            "Suspicious File Creation",
            "File Modification",
            "File Deletion Indicators",
            "Unusual File Activity",
            "Potential Data Exfiltration"
        ],

        "required_events": {
            "Sysmon": [11, 23, 26]
        },

        "required_fields": [
            "timestamp_utc",
            "hostname",
            "image",
            "event_id"
        ],

        "rules": [
            "TS021",
            "TS022",
            "TS023"
        ],

        "limitations": [
            "File monitoring must be configured.",
            "File creation does not prove malicious intent.",
            "Exfiltration detection requires network or other data-transfer telemetry."
        ]
    },

    "defense_evasion": {
        "name": "Defense Evasion",

        "attacks": [
            "Security Log Clearing",
            "Audit Policy Modification",
            "Sysmon Configuration Changes",
            "Logging Interruption",
            "Suspicious Security Configuration Changes"
        ],

        "required_events": {
            "Security": [1102, 4719],
            "Sysmon": [16],
            "System": [104]
        },

        "required_fields": [
            "timestamp_utc",
            "event_id",
            "provider",
            "hostname"
        ],

        "rules": [
            "TS003",
            "TS007",
            "TS008",
            "TS024"
        ],

        "limitations": [
            "Log clearing can remove evidence.",
            "External monitoring helps detect logging interruptions.",
            "Event 104 must be distinguished from Security Event 1102."
        ]
    }
}


def get_all_categories():
    """Return all registered attack categories."""
    return list(DETECTION_COVERAGE.keys())


def get_category_details(category):
    """Return details for one attack category."""
    return DETECTION_COVERAGE.get(category)


def get_all_detection_rules():
    """Return all unique rule IDs."""
    rule_ids = set()

    for category in DETECTION_COVERAGE.values():
        rule_ids.update(category["rules"])

    return sorted(rule_ids)


def print_coverage_summary():
    """Print a readable coverage summary."""

    print("\n========== TRACE-SOC DETECTION COVERAGE ==========\n")

    for category_id, details in DETECTION_COVERAGE.items():

        print(f"Category: {details['name']}")
        print(f"Attacks covered: {len(details['attacks'])}")
        print(f"Detection rules: {', '.join(details['rules'])}")
        print("-" * 55)

    print(f"\nTotal categories: {len(DETECTION_COVERAGE)}")
    print(f"Total unique planned rules: {len(get_all_detection_rules())}")


if __name__ == "__main__":
    print_coverage_summary()
