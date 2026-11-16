"""
TRACE-SOC - Real-World Attack EVTX Validation Test Suite

Validates CYFROG's normalization and detection engine against
actual adversarial Windows Event Log captures from D:\\EVTX-ATTACK-SAMPLES.
"""

import os
import json
import pytest
from pathlib import Path
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

from normalizer.event_parser import extract_system_info, extract_event_data
from normalizer.event_schema import create_normalized_event
from detection.rules import DETECTION_RULES
import detection.engine as eng

SAMPLES_DIR = Path(r"D:\EVTX-ATTACK-SAMPLES")
pytestmark = pytest.mark.skipif(
    not SAMPLES_DIR.exists(),
    reason="D:\\EVTX-ATTACK-SAMPLES not accessible on this system"
)

def load_evtx_events(evtx_relative_path):
    full_path = SAMPLES_DIR / evtx_relative_path
    assert full_path.exists(), f"Sample not found: {full_path}"
    events = []
    with evtx.Evtx(str(full_path)) as log:
        for idx, record in enumerate(log.records()):
            try:
                root = ET.fromstring(record.xml())
                sys_info = extract_system_info(root)
                ev_data = extract_event_data(root)
                norm = create_normalized_event(sys_info, ev_data)
                norm["id"] = idx + 1
                norm["extra_data_json"] = json.dumps(norm.get("extra_data", {}))
                events.append(norm)
            except Exception:
                pass
    return events

def get_rule_by_id(rule_id):
    for rule in DETECTION_RULES:
        if rule.get("rule_id") == rule_id:
            return rule
    raise ValueError(f"Rule {rule_id} not found in DETECTION_RULES")


def test_real_evtx_ts006_scheduled_task_persistence():
    """Validates TS006 against real Event 4698 scheduled task creation captures."""
    events = load_evtx_events(r"Execution\temp_scheduled_task_4698_4699.evtx")
    rule = get_rule_by_id("TS006")
    alerts = eng.evaluate_single_event_rule(events, rule)
    assert len(alerts) >= 1
    assert alerts[0]["rule"]["rule_id"] == "TS006"
    assert alerts[0]["event_count"] >= 1


def test_real_evtx_ts006_privesc_task():
    """Validates TS006 against real SeImpersonatePriv scheduled task persistence."""
    events = load_evtx_events(r"Privilege Escalation\PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx")
    rule = get_rule_by_id("TS006")
    alerts = eng.evaluate_single_event_rule(events, rule)
    assert len(alerts) >= 1
    assert alerts[0]["rule"]["rule_id"] == "TS006"


def test_real_evtx_ts016_pass_the_hash_special_privileges():
    """Validates TS016 against real Mimikatz Pass-The-Hash Event 4672 capture."""
    events = load_evtx_events(r"Lateral Movement\LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx")
    rule = get_rule_by_id("TS016")
    alerts = eng.evaluate_single_event_rule(events, rule)
    assert len(alerts) >= 1
    assert alerts[0]["rule"]["rule_id"] == "TS016"


def test_real_evtx_psexec_multi_stage_detection():
    """Validates multi-stage real PsExec lateral movement detection."""
    events = load_evtx_events(r"Lateral Movement\LM_sysmon_psexec_smb_meterpreter.evtx")
    
    # 1. TS002 Encoded PowerShell
    ts002 = get_rule_by_id("TS002")
    alerts_002 = eng.evaluate_keyword_rule(events, ts002)
    assert len(alerts_002) >= 1

    # 2. TS015 Registry Persistence
    ts015 = get_rule_by_id("TS015")
    alerts_015 = eng.evaluate_registry_rule(events, ts015)
    assert len(alerts_015) >= 1

    # 3. TS019 Outbound Network Connection
    ts019 = get_rule_by_id("TS019")
    alerts_019 = eng.evaluate_network_indicator_rule(events, ts019)
    assert len(alerts_019) >= 1


def test_real_evtx_comsvcs_lsass_dump_collateral():
    """Validates collateral detection on Comsvcs LSASS memory dumping."""
    events = load_evtx_events(r"Credential Access\sysmon_10_1_memdump_comsvcs_minidump.evtx")
    
    # TS012 Process indicator (rundll32)
    ts012 = get_rule_by_id("TS012")
    alerts_012 = eng.evaluate_process_indicator_rule(events, ts012)
    assert len(alerts_012) >= 1

    # TS021 Suspicious file creation (.dmp)
    ts021 = get_rule_by_id("TS021")
    alerts_021 = eng.evaluate_file_rule(events, ts021)
    assert len(alerts_021) >= 1


def test_real_evtx_ts003_defense_evasion_log_clearing():
    """Validates TS003 against real Event 1102 logs cleared during Kerberos spray."""
    events = load_evtx_events(r"Credential Access\kerberos_pwd_spray_4771.evtx")
    rule = get_rule_by_id("TS003")
    alerts = eng.evaluate_single_event_rule(events, rule)
    assert len(alerts) >= 1
    assert alerts[0]["rule"]["rule_id"] == "TS003"

