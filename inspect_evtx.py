import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET
from normalizer.event_parser import extract_system_info, extract_event_data
from normalizer.event_schema import create_normalized_event
from detection.rules import DETECTION_RULES

samples = [
    ('LSASS Sysmon 10 (Mimikatz)', r'D:\EVTX-ATTACK-SAMPLES\Credential Access\sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx'),
    ('LSASS Sysmon 10 (Memdump)', r'D:\EVTX-ATTACK-SAMPLES\Credential Access\sysmon_10_11_lsass_memdump.evtx'),
    ('LSASS Sysmon 10 (Comsvcs)', r'D:\EVTX-ATTACK-SAMPLES\Credential Access\sysmon_10_1_memdump_comsvcs_minidump.evtx'),
    ('Mimikatz BabyShark PowerShell', r'D:\EVTX-ATTACK-SAMPLES\Credential Access\babyshark_mimikatz_powershell.evtx'),
    ('Mimikatz Invoke-Mimikatz', r'D:\EVTX-ATTACK-SAMPLES\Credential Access\sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx'),
    ('DCSync 4662', r'D:\EVTX-ATTACK-SAMPLES\Credential Access\CA_DCSync_4662.evtx'),
    ('Kerberos Password Spray 4771', r'D:\EVTX-ATTACK-SAMPLES\Credential Access\kerberos_pwd_spray_4771.evtx'),
    ('Scheduled Task 4698', r'D:\EVTX-ATTACK-SAMPLES\Execution\temp_scheduled_task_4698_4699.evtx'),
    ('Service Install 7045', r'D:\EVTX-ATTACK-SAMPLES\Privilege Escalation\System_7045_namedpipe_privesc.evtx'),
    ('Lateral Movement Service 7045', r'D:\EVTX-ATTACK-SAMPLES\Lateral Movement\LM_Remote_Service02_7045.evtx'),
    ('Lateral Movement WMIExec', r'D:\EVTX-ATTACK-SAMPLES\Lateral Movement\LM_wmiexec_impacket_sysmon_whoami.evtx'),
    ('Lateral Movement PsExec', r'D:\EVTX-ATTACK-SAMPLES\Lateral Movement\LM_sysmon_psexec_smb_meterpreter.evtx'),
    ('Lateral Movement WinRM', r'D:\EVTX-ATTACK-SAMPLES\Lateral Movement\LM_winrm_exec_sysmon_1_winrshost.evtx'),
    ('Process Injection Sysmon 8', r'D:\EVTX-ATTACK-SAMPLES\Defense Evasion\sysmon_8_process_injection_create_remote_thread.evtx'),
    ('Process Injection Mimikatz', r'D:\EVTX-ATTACK-SAMPLES\Defense Evasion\sysmon_8_create_remote_thread_mimikatz_powersploit.evtx'),
    ('Scheduled Task SeImpersonate', r'D:\EVTX-ATTACK-SAMPLES\Privilege Escalation\PrivEsc_SeImpersonatePriv_enabled_back_for_upnp_localsvc_4698.evtx')
]

for label, path in samples:
    try:
        with evtx.Evtx(path) as log:
            eids = {}
            total = 0
            for record in log.records():
                total += 1
                root = ET.fromstring(record.xml())
                sys_info = extract_system_info(root)
                eid = sys_info.get('event_id', 'unknown')
                eids[eid] = eids.get(eid, 0) + 1
            print(f'{label}: Total={total}, EventIDs={eids}')
    except Exception as e:
        print(f'{label}: ERROR {e}')

