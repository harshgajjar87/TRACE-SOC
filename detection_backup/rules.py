
DETECTION_RULES = [

    {
        "rule_id": "TS001",
        "name": "Repeated Failed Logins",
        "description": "Multiple failed authentication attempts",
        "severity": "HIGH",
        "event_id": "4625",
        "threshold": 5,
        "time_window": 300,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110"
    },

    {
        "rule_id": "TS002",
        "name": "Suspicious PowerShell Execution",
        "description": "PowerShell executed with suspicious command patterns",
        "severity": "HIGH",
        "event_id": "1",
        "keywords": [
            "-enc",
            "-encodedcommand",
            "downloadstring",
            "frombase64string",
            "invoke-expression",
            "iex",
            "hidden"
        ],
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059.001"
    },

    {
        "rule_id": "TS003",
        "name": "Security Log Cleared",
        "description": "Windows Security audit log was cleared",
        "severity": "CRITICAL",
        "event_id": "1102",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1070.001"
    },

    {
        "rule_id": "TS004",
        "name": "New User Account Created",
        "description": "A new Windows user account was created",
        "severity": "MEDIUM",
        "event_id": "4720",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1136.001"
    },

    {
        "rule_id": "TS005",
        "name": "Account Added to Privileged Group",
        "description": "An account was added to a sensitive local group",
        "severity": "HIGH",
        "event_id": "4732",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1098"
    },

    {
        "rule_id": "TS006",
        "name": "Scheduled Task Created",
        "description": "A new scheduled task was registered",
        "severity": "HIGH",
        "event_id": "4698",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1053.005"
    },

    {
        "rule_id": "TS007",
        "name": "Audit Policy Changed",
        "description": "Windows audit policy configuration changed",
        "severity": "HIGH",
        "event_id": "4719",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.002"
    },

    {
        "rule_id": "TS008",
        "name": "Sysmon Configuration Changed",
        "description": "Sysmon monitoring configuration changed",
        "severity": "HIGH",
        "event_id": "16",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562.001"
    }

]
