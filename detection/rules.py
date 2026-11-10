
"""
TRACE-SOC - Multi-Category Detection Rules

Rule definitions for seven attack categories.

IMPORTANT:
The upgraded engine must support each rule_type before
all these rules are activated.
"""

DETECTION_RULES = [

    # ==================================================
    # 1. AUTHENTICATION ATTACKS
    # ==================================================

    {
        "rule_id": "TS001",
        "name": "Repeated Failed Logins",
        "description": "Multiple failed authentication attempts from one source.",
        "category": "authentication",
        "rule_type": "threshold",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4625",
        "threshold": 5,
        "time_window": 300,
        "group_by": ["source_ip"],
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110"
    },

    {
        "rule_id": "TS009",
        "name": "Password Spraying Indicators",
        "description": "One source IP produces failed logins against multiple accounts.",
        "category": "authentication",
        "rule_type": "distinct_threshold",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4625",
        "threshold": 5,
        "time_window": 600,
        "group_by": ["source_ip"],
        "distinct_field": "username",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.003"
    },

    {
        "rule_id": "TS010",
        "name": "Successful Login After Repeated Failures",
        "description": "A successful login follows repeated failures for the same account and source.",
        "category": "authentication",
        "rule_type": "sequence",
        "severity": "HIGH",
        "providers": ["Microsoft-Windows-Security-Auditing"],
        "channel": "Security",
        "failure_event_id": "4625",
        "success_event_id": "4624",
        "failure_threshold": 5,
        "time_window": 600,
        "correlation_fields": ["username", "source_ip"],
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110"
    },

    {
        "rule_id": "TS011",
        "name": "Account Lockout",
        "description": "A Windows account was locked after repeated authentication failures.",
        "category": "authentication",
        "rule_type": "single_event",
        "severity": "MEDIUM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4740",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110"
    },

    # ==================================================
    # 2. EXECUTION ATTACKS
    # ==================================================

    {
        "rule_id": "TS002",
        "name": "Suspicious PowerShell Execution",
        "description": "PowerShell executed with suspicious command patterns.",
        "category": "execution",
        "rule_type": "keyword",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "1",
        "process_image_contains": "powershell",
        "keywords": [
            "-enc",
            "-encodedcommand",
            "downloadstring",
            "frombase64string",
            "invoke-expression",
            "iex",
            " -hidden"
        ],
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001"
    },

    {
        "rule_id": "TS012",
        "name": "Suspicious Process Execution",
        "description": "A potentially suspicious process or script interpreter was executed.",
        "category": "execution",
        "rule_type": "process_indicator",
        "severity": "MEDIUM",
        "providers": [
            "Microsoft-Windows-Sysmon",
            "Microsoft-Windows-Security-Auditing"
        ],
        "event_ids": ["1", "4688"],
        "suspicious_images": [
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe"
        ],
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059"
    },

    {
        "rule_id": "TS013",
        "name": "Unusual Parent-Child Process Relationship",
        "description": "A potentially unusual parent process launched a sensitive child process.",
        "category": "execution",
        "rule_type": "parent_child",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "1",
        "suspicious_parents": [
            "winword.exe",
            "excel.exe",
            "outlook.exe"
        ],
        "suspicious_children": [
            "powershell.exe",
            "cmd.exe",
            "wscript.exe",
            "cscript.exe"
        ],
        "mitre_tactic": "Execution",
        "mitre_technique": "T1204"
    },

    # ==================================================
    # 3. PERSISTENCE ATTACKS
    # ==================================================

    {
        "rule_id": "TS004",
        "name": "New User Account Created",
        "description": "A new Windows user account was created.",
        "category": "persistence",
        "rule_type": "single_event",
        "severity": "MEDIUM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4720",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.001"
    },

    {
        "rule_id": "TS006",
        "name": "Scheduled Task Created",
        "description": "A new Windows scheduled task was registered.",
        "category": "persistence",
        "rule_type": "single_event",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4698",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.005"
    },

    {
        "rule_id": "TS014",
        "name": "Service Installation",
        "description": "A new Windows service was installed.",
        "category": "persistence",
        "rule_type": "single_event",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4697",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1543.003"
    },

    {
        "rule_id": "TS015",
        "name": "Registry Persistence Modification",
        "description": "A monitored registry key was created or modified.",
        "category": "persistence",
        "rule_type": "registry_event",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_ids": ["12", "13", "14"],
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1112"
    },

    # ==================================================
    # 4. PRIVILEGE ESCALATION
    # ==================================================

    {
        "rule_id": "TS005",
        "name": "Account Added to Privileged Group",
        "description": "An account was added to a sensitive local group.",
        "category": "privilege_escalation",
        "rule_type": "privileged_group",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_ids": ["4732", "4728", "4756"],
        "sensitive_group_names": [
            "administrators",
            "domain admins",
            "enterprise admins",
            "schema admins",
            "backup operators",
            "account operators",
            "server operators",
            "remote desktop users"
        ],
        "sensitive_group_sids": [
            "S-1-5-32-544",
            "S-1-5-32-551",
            "S-1-5-32-548",
            "S-1-5-32-549",
            "S-1-5-32-550"
        ],
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098"
    },

    {
        "rule_id": "TS016",
        "name": "Special Privileges Assigned",
        "description": "A logon session received special privileges.",
        "category": "privilege_escalation",
        "rule_type": "single_event",
        "severity": "MEDIUM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4672",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1078"
    },

    {
        "rule_id": "TS017",
        "name": "Privileged Account Creation",
        "description": "A newly created account may require privileged-account investigation.",
        "category": "privilege_escalation",
        "rule_type": "account_correlation",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "creation_event_id": "4720",
        "group_event_ids": ["4728", "4732", "4756"],
        "time_window": 1800,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098"
    },

    # ==================================================
    # 5. NETWORK ATTACKS
    # ==================================================

    {
        "rule_id": "TS018",
        "name": "Possible Port Scanning",
        "description": "One source host connects to many destination ports.",
        "category": "network",
        "rule_type": "network_threshold",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "3",
        "threshold": 15,
        "time_window": 60,
        "group_by": ["source_ip", "destination_ip"],
        "distinct_field": "destination_port",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046"
    },

    {
        "rule_id": "TS019",
        "name": "Unusual Outbound Network Connections",
        "description": "A host makes connections that may require network investigation.",
        "category": "network",
        "rule_type": "network_indicator",
        "severity": "MEDIUM",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "3",
        "require_destination_ip": True,
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071"
    },

    {
        "rule_id": "TS020",
        "name": "Suspicious DNS Activity",
        "description": "DNS queries with potentially suspicious characteristics were observed.",
        "category": "network",
        "rule_type": "dns_indicator",
        "severity": "MEDIUM",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "22",
        "suspicious_keywords": [
            "pastebin",
            "ngrok",
            "duckdns",
            "no-ip"
        ],
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.004"
    },

    # ==================================================
    # 6. DATA AND FILE ATTACKS
    # ==================================================

    {
        "rule_id": "TS021",
        "name": "Suspicious File Creation",
        "description": "A file was created in a monitored location.",
        "category": "data_file",
        "rule_type": "file_event",
        "severity": "MEDIUM",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "11",
        "mitre_tactic": "Collection",
        "mitre_technique": "T1005"
    },

    {
        "rule_id": "TS022",
        "name": "File Deletion Activity",
        "description": "File deletion telemetry was observed.",
        "category": "data_file",
        "rule_type": "file_event",
        "severity": "MEDIUM",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_ids": ["23", "26"],
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070"
    },

    {
        "rule_id": "TS023",
        "name": "Potential Data Exfiltration",
        "description": "High-volume outbound transfer indicators require investigation.",
        "category": "data_file",
        "rule_type": "data_transfer_threshold",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "3",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1041",
        "note": "Connection events alone do not provide transferred-byte counts. Additional network telemetry is required."
    },

    # ==================================================
    # 7. DEFENSE EVASION
    # ==================================================

    {
        "rule_id": "TS003",
        "name": "Security Log Cleared",
        "description": "Windows Security audit log was cleared.",
        "category": "defense_evasion",
        "rule_type": "single_event",
        "severity": "CRITICAL",
        "provider": "Microsoft-Windows-Eventlog",
        "channel": "Security",
        "event_id": "1102",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001"
    },

    {
        "rule_id": "TS007",
        "name": "Audit Policy Changed",
        "description": "Windows audit policy configuration changed.",
        "category": "defense_evasion",
        "rule_type": "single_event",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "event_id": "4719",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.002"
    },

    {
        "rule_id": "TS008",
        "name": "Sysmon Configuration Changed",
        "description": "Sysmon monitoring configuration changed.",
        "category": "defense_evasion",
        "rule_type": "single_event",
        "severity": "HIGH",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "event_id": "16",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.001"
    },

    {
        "rule_id": "TS024",
        "name": "System Event Log Cleared",
        "description": "The Windows System event log was cleared.",
        "category": "defense_evasion",
        "rule_type": "single_event",
        "severity": "CRITICAL",
        "provider": "Microsoft-Windows-Eventlog",
        "channel": "System",
        "event_id": "104",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001"
    }
]
