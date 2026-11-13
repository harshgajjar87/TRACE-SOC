"""Built-in analyst-approved incident response playbooks."""

PLAYBOOKS = {
    "general_alert_triage": {
        "name": "General Alert Triage",
        "description": "Investigate an alert, preserve evidence and prepare a response.",
        "severity": "ALL",
        "steps": [
            {
                "id": "review_alert",
                "name": "Review alert details",
                "description": "Review the alert description, severity, host and associated user.",
                "action_type": "ANALYST_REVIEW",
            },
            {
                "id": "preserve_evidence",
                "name": "Preserve available evidence",
                "description": "Calculate SHA-256 hashes of available raw event evidence and record its references.",
                "action_type": "EVIDENCE_PRESERVATION",
            },
            {
                "id": "assess_scope",
                "name": "Assess incident scope",
                "description": "Review associated events and determine whether additional systems or users may be affected.",
                "action_type": "SCOPE_ASSESSMENT",
            },
            {
                "id": "recommend_containment",
                "name": "Prepare containment recommendation",
                "description": "Recommend suitable containment for analyst review. No machine or account changes are performed.",
                "action_type": "RECOMMENDATION",
            },
            {
                "id": "escalate",
                "name": "Prepare escalation",
                "description": "Record whether the incident should be escalated for further investigation.",
                "action_type": "ESCALATION",
            },
        ],
    },

    "authentication_response": {
        "name": "Suspicious Authentication Response",
        "description": "Triage repeated login failures and suspicious authentication activity.",
        "severity": "ALL",
        "steps": [
            {
                "id": "review_authentication",
                "name": "Review authentication activity",
                "description": "Examine the account, source IP, hostname and authentication-related evidence.",
                "action_type": "ANALYST_REVIEW",
            },
            {
                "id": "preserve_evidence",
                "name": "Preserve authentication evidence",
                "description": "Calculate and record hashes of available raw event evidence.",
                "action_type": "EVIDENCE_PRESERVATION",
            },
            {
                "id": "check_account",
                "name": "Assess account activity",
                "description": "Recommend reviewing recent successful and failed logins for the affected account.",
                "action_type": "SCOPE_ASSESSMENT",
            },
            {
                "id": "recommend_account_protection",
                "name": "Recommend account protection",
                "description": "Recommend account protection measures for an authorized administrator to review.",
                "action_type": "RECOMMENDATION",
            },
            {
                "id": "escalate",
                "name": "Escalate authentication incident",
                "description": "Prepare the incident for escalation if suspicious activity is confirmed.",
                "action_type": "ESCALATION",
            },
        ],
    },

    "suspicious_execution_response": {
        "name": "Suspicious Process Execution Response",
        "description": "Investigate potentially suspicious process execution.",
        "severity": "ALL",
        "steps": [
            {
                "id": "review_process",
                "name": "Review process information",
                "description": "Review process name, executable path, command line and parent process.",
                "action_type": "ANALYST_REVIEW",
            },
            {
                "id": "preserve_evidence",
                "name": "Preserve process evidence",
                "description": "Calculate and record hashes of available raw event evidence.",
                "action_type": "EVIDENCE_PRESERVATION",
            },
            {
                "id": "assess_execution",
                "name": "Assess process behaviour",
                "description": "Recommend reviewing parent-child relationships and related execution events.",
                "action_type": "SCOPE_ASSESSMENT",
            },
            {
                "id": "recommend_isolation",
                "name": "Recommend host isolation",
                "description": "If compromise is confirmed, recommend host isolation through an authorized administrator. No isolation is performed.",
                "action_type": "RECOMMENDATION",
            },
            {
                "id": "escalate",
                "name": "Escalate process incident",
                "description": "Prepare the incident for further malware or forensic investigation.",
                "action_type": "ESCALATION",
            },
        ],
    },

    "network_ioc_response": {
        "name": "Network IOC Response",
        "description": "Investigate an alert involving suspicious network indicators.",
        "severity": "ALL",
        "steps": [
            {
                "id": "review_network",
                "name": "Review network activity",
                "description": "Review source IP, destination IP, hostname and related network events.",
                "action_type": "ANALYST_REVIEW",
            },
            {
                "id": "preserve_evidence",
                "name": "Preserve network evidence",
                "description": "Calculate and record hashes of available raw event evidence.",
                "action_type": "EVIDENCE_PRESERVATION",
            },
            {
                "id": "check_intelligence",
                "name": "Review threat intelligence",
                "description": "Recommend checking associated indicators against the local threat intelligence inventory.",
                "action_type": "SCOPE_ASSESSMENT",
            },
            {
                "id": "recommend_block",
                "name": "Prepare network containment recommendation",
                "description": "Recommend reviewing firewall or network controls. No blocking rule is applied.",
                "action_type": "RECOMMENDATION",
            },
            {
                "id": "escalate",
                "name": "Escalate network incident",
                "description": "Prepare the incident for further network investigation.",
                "action_type": "ESCALATION",
            },
        ],
    },
}


def get_playbooks():
    """Return all available playbooks."""
    return PLAYBOOKS


def get_playbook(playbook_id):
    """Return a playbook by its identifier."""
    return PLAYBOOKS.get(playbook_id)