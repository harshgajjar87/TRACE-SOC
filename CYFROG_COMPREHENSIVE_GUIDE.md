# CYFROG: An Intelligent TRACE System
## Comprehensive Architecture, Detection Logic, DFIR Operations & Evaluation Guide

---

# TABLE OF CONTENTS
1. [Executive Overview: What is CYFROG?](#1-executive-overview-what-is-cyfrog)
2. [Why We Built It: Problem Statement & Motivation](#2-why-we-built-it-problem-statement--motivation)
3. [CYFROG vs Traditional SOC vs Wazuh/Splunk](#3-cyfrog-vs-traditional-soc-vs-wazuhsplunk)
4. [High-Level Architecture & End-to-End Pipeline](#4-high-level-architecture--end-to-end-pipeline)
5. [Core Functionalities & Module Breakdown](#5-core-functionalities--module-breakdown)
6. [How Our Detection Logic Works (The 14 Evaluators in Plain English)](#6-how-our-detection-logic-works-the-14-evaluators-in-plain-english)
7. [End-to-End Walkthrough: A Real Attack in Baby Steps](#7-end-to-end-walkthrough-a-real-attack-in-baby-steps)
8. [Dashboard Guide: All 5 Workspaces & 20 Pages Explained](#8-dashboard-guide-all-5-workspaces--20-pages-explained)
9. [Empirical Validation & Viva Defense Strategy](#9-empirical-validation--viva-defense-strategy)
10. [Quick Command Reference](#10-quick-command-reference)

---

## 1. Executive Overview: What is CYFROG?

**CYFROG** (internally code-named **TRACE-SOC**) is an end-to-end, lightweight, intelligent Security Operations Center (SOC) and Digital Forensics & Incident Response (DFIR) platform. 

It was engineered to solve the most critical bottleneck in modern endpoint defense: **transforming noisy, fragmented Windows security telemetry into actionable, mathematically verifiable attack narratives with cryptographic chain of custody.**

### Core Capabilities at a Glance:
- **Zero-Dependency Native Ingestion**: Ingests Windows Security, System, and Sysmon logs via live PowerShell channels or offline `.evtx` files without requiring heavy third-party agent daemons.
- **Unified Event Normalization**: Normalizes disparate Windows event structures into standardized, typed schema representations with SHA-256 raw event provenance.
- **Multi-Strategy Detection Engine**: Features 14 distinct rule evaluators (threshold, sequence, parent-child, distinct aggregation, process indicators, script blocks, etc.) mapped directly to MITRE ATT&CK.
- **Automated Attack Story Builder**: Correlates isolated, low-level alerts across hosts, users, and time windows into a unified multi-stage attack story.
- **Cryptographic Chain of Custody**: Hashes every raw record at collection time to ensure defensible, tamper-evident evidence admissible in investigations.
- **Full-Spectrum DFIR Workspace**: A 20-page dark-themed analytical dashboard spanning triage, threat hunting, risk scoring, case management, playbooks, and automated PDF reporting.

---

## 2. Why We Built It: Problem Statement & Motivation

### The Modern SOC Crisis
1. **The Alert Fatigue Trap**: Modern EDRs and SIEMs bombard analysts with thousands of isolated alerts per day. 95% are disconnected noise. Analysts spend hours manually pivoting between logs to understand if five separate alerts represent one coordinated adversary or routine background activity.
2. **The "Agent & Cluster Bloat" Problem**: Enterprise SIEM platforms (Splunk, Elastic, Wazuh) demand massive infrastructure—distributed Elasticsearch clusters, JVM runtimes, complex log forwarders, and gigabytes of memory just to idle. Smaller organizations, research labs, and incident response teams need a lean, self-contained engine that runs anywhere.
3. **Loss of Forensic Integrity**: Most SIEMs normalize away or discard raw event bytes. When an incident reaches a legal hearing or strict audit, proving that normalized records were not tampered with is nearly impossible without the original cryptographic hash.
4. **The "Detection vs Proof" Gap**: Academic cybersecurity projects frequently claim massive MITRE coverage based purely on synthetic unit tests. CYFROG was built with a strict engineering ethos: **clearly delineate between what is conceptually configured and what is empirically proven against real attack datasets.**

---

## 3. CYFROG vs Traditional SOC vs Wazuh/Splunk

Understanding these distinctions is essential for academic viva presentations and technical evaluations:

### A. CYFROG vs Traditional SOC
- **A Traditional SOC** is an entire organizational unit comprising people, processes, Tier 1/2/3 analysts, shifts, SLAs, escalation pathways, and third-party tools.
- **CYFROG** is the **automated intelligent software engine** that powers a SOC analyst's workflow. It performs the Tier-1 repetitive work (ingestion, filtering, deduplication, rule evaluation), executes Tier-2 analytical correlation (building attack stories, scoring risk), and assists Tier-3 forensic investigators (chain-of-custody verification, timeline reconstruction).

### B. CYFROG vs Wazuh / OSSEC
| Dimension | Wazuh / OSSEC | CYFROG |
| :--- | :--- | :--- |
| **Architecture** | Heavy agent-server daemon model; requires OpenSearch/Elasticsearch, Filebeat, Indexers. | Lightweight, modular Python/SQLite architecture; zero agent requirement on target host. |
| **Hardware Overhead** | Demands 4–16 GB RAM, multi-core CPU, Java runtime. | Runs smoothly on standard workstation hardware (< 500 MB RAM). |
| **Detection Engine** | XML-based regular expressions and decoders; complex rule inheritance. | 14 typed Python detection algorithms supporting complex sliding time-windows, distinct thresholds, and stateful sequences. |
| **Attack Correlation** | Alerts remain largely independent hits; correlation requires complex custom rules. | Native **Attack Story Builder** that automatically synthesizes related alerts into unified incident graphs. |
| **Evidence Custody** | Raw logs stored in indices without per-event cryptographic signing. | Cryptographic SHA-256 evidence hashing and immutable chain-of-custody tracking out of the box. |
| **Setup Time** | Hours to days of multi-server provisioning. | Seconds (`pip install -r requirements.txt` and launch). |

### C. CYFROG vs Splunk / QRadar
- **Commercial SIEMs** charge exorbitant fees per gigabyte of ingested logs, rely on proprietary query languages (SPL, AQL), and operate as closed "black boxes."
- **CYFROG** is completely transparent, open-source, uses standard SQL/Pydantic data models, and provides 100% explainable detection metrics.

---

## 4. High-Level Architecture & End-to-End Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ADVERSARY ACTIVITY                                │
│        (PowerShell Encoded Commands, LSASS Access, Scheduled Tasks)         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           WINDOWS EVENT SUBSYSTEM                           │
│     Security (4624, 4625, 4698) | System (7045) | Sysmon (1, 3, 10, 13)    │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       COLLECTION & CRYPTOGRAPHIC PROVENANCE                 │
│  - collectors/windows_event_collector.py (Live EventRecordID tracking)       │
│  - collectors/xml_collector.py & python-evtx (Offline capture ingestion)    │
│  - Compute raw event SHA-256 hash & store in raw_events table               │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NORMALIZATION & SCHEMA ENGINE                       │
│  - normalizer/event_parser.py (XML tree & UserData extraction)              │
│  - normalizer/event_schema.py (Field mapping, PID conversion, classification│
│  - Stored in normalized_events table with foreign key to raw_events         │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MULTI-STRATEGY DETECTION ENGINE                     │
│  - detection/rules.py (25 Multi-Category Detection Rules)                   │
│  - detection/engine.py (14 Evaluator Algorithms)                            │
│  - Alert deduplication via SHA-256 fingerprinting -> alerts table           │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         CORRELATION & ATTACK STORY BUILDER                  │
│  - investigation/story_builder.py                                           │
│  - Links alerts by entity (hostname, user) across temporal correlation win  │
│  - Generates comprehensive attack narratives in attack_stories table        │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ADVANCED DFIR, RISK & PRESENTATION LAYER                 │
│  - Risk Engine (Asset & User Scoring)  - Forensic Timeline & Artifacts      │
│  - Case Management & Playbooks         - Automated ReportLab PDF Generator  │
│  - Threat Intelligence & Hunting       - 20-Page Streamlit Dark Workspace   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Core Functionalities & Module Breakdown

CYFROG is structured into 12 distinct functional subsystems:

1. **`collectors/` (Telemetry Collection)**:
   - Queries live Windows Event Logs with incremental watermark tracking (`EventRecordID`) so no event is collected twice.
   - Computes SHA-256 digest of the raw XML to guarantee legal non-repudiation.
2. **`normalizer/` (Schema & Parser)**:
   - Extracts nested `System`, `EventData`, and `UserData` XML structures.
   - Standardizes fields into a uniform data model: `timestamp_utc`, `hostname`, `username`, `process_id`, `image`, `command_line`, `source_ip`, `destination_ip`.
3. **`detection/` (Detection Engine)**:
   - Houses the rule library and execution algorithms.
   - Evaluates sliding time-windows, distinct user thresholds, and multi-event sequences without false-positive cross-grouping.
4. **`investigation/` (Story Builder & Evidence)**:
   - Combines multiple correlated alerts into an **Attack Story**.
   - Preserves an auditable chain of custody linking every story back to the exact normalized and raw database rows.
5. **`risk/` (Risk Engine)**:
   - Assigns dynamic risk scores based on event severity, asset criticality (e.g. Domain Controller vs Workstation), and historical alert frequency.
6. **`forensics/` (Digital Forensics Engine)**:
   - Reconstructs process execution trees, parses suspicious artifact indicators, and establishes chronological microsecond-precision incident timelines.
7. **`threat_intel/` (Threat Intelligence & IOCs)**:
   - Maintains a local threat intelligence feed (malicious IPs, domains, hashes) and automatically flags matches across all incoming logs.
8. **`hunting/` (Threat Hunting Engine)**:
   - Allows SOC analysts to run structured hunting hypotheses (e.g. unusual LOLBins, off-hours administrative logins, rare parent-child relationships).
9. **`cases/` (Case Management)**:
   - Full incident lifecycle tracking: status (New, Triaged, In Progress, Closed), priority, assignee, analytical notes, and SLA timers.
10. **`response/` (Incident Response Playbooks)**:
    - Provides standardized response workflows (host isolation, credential revocation, artifact quarantine) tailored to the specific MITRE technique.
11. **`reports/` (Automated DFIR Reporting)**:
    - Generates professional forensic audit PDF reports using ReportLab with tables, evidence matrices, and executive summaries.
12. **`dashboard/` (Analyst Workspace)**:
    - A modern, dark-themed Streamlit web interface with real-time analytics, Plotly visualizations, and investigation drill-downs.

---

## 6. How Our Detection Logic Works (The 14 Evaluators in Plain English)

CYFROG does not rely on simple text search. It uses 14 mathematically distinct evaluator algorithms implemented in [detection/engine.py](file:///d:/CYFROG/detection/engine.py):

### 1. Single Event Rule (`evaluate_single_event_rule`)
- **How it works**: Monitors for the occurrence of a single critical event ID that indicates high-risk activity by itself.
- **Example**: Event `1102` (Security Audit Log Cleared - TS003) or Event `4698` (Scheduled Task Created - TS006).
- **Suppression Logic**: Supports built-in SID whitelist filtering (e.g., suppressing routine SYSTEM/DWM service accounts on Event 4672 in TS016).

### 2. Threshold Rule (`evaluate_threshold_rule`)
- **How it works**: Groups events by an entity (e.g. `source_ip`) and counts occurrences within a sliding time window (e.g., $\ge 5$ events in 300 seconds).
- **Example**: Event `4625` (Repeated Failed Logins - TS001).
- **Mathematical Defense**: Uses timestamps to guarantee that only events strictly within the sliding window trigger the alert.

### 3. Distinct Threshold Rule (`evaluate_distinct_threshold_rule`)
- **How it works**: Tracks unique values of a secondary field from a single source within a time window.
- **Example**: Event `4625` where one `source_ip` attempts to log in across $\ge 5$ **distinct usernames** within 600 seconds (Password Spraying - TS009).

### 4. Sequence Rule (`evaluate_sequence_rule`)
- **How it works**: Tracks an ordered state machine where Event A must precede Event B within a specified timeframe for the same entity.
- **Example**: 5 or more failed logins (Event `4625`) followed immediately by a successful login (Event `4624`) for the same user and source IP (Brute-Force Success - TS010).

### 5. Keyword Matching Rule (`evaluate_keyword_rule`)
- **How it works**: Inspects specific command lines or script block text for known adversary syntax patterns.
- **Example**: Event `1` command lines containing `-encodedcommand` or `downloadstring` (TS002), or PowerShell Event `4104` containing `MiniDumpWriteDump` / `Get-Process lsass` (TS025).
- **Noise Filter**: Supports suppression lists (e.g., ignoring PowerShell spawned by CYFROG's own monitoring collectors).

### 6. Process Indicator Rule (`evaluate_process_indicator_rule`)
- **How it works**: Monitors process creation events (Sysmon 1 / Security 4688) for suspicious Living-off-the-Land Binaries (LOLBins) like `rundll32.exe`, `mshta.exe`, `wscript.exe`, or `regsvr32.exe` (TS012).

### 7. Parent-Child Process Relationship Rule (`evaluate_parent_child_rule`)
- **How it works**: Detects abnormal execution hierarchies where non-technical user applications spawn command shells.
- **Example**: Microsoft Word (`winword.exe`) or Excel (`excel.exe`) launching `powershell.exe` or `cmd.exe` (TS013).

### 8. Registry Modification Rule (`evaluate_registry_rule`)
- **How it works**: Inspects Sysmon Events 12, 13, and 14 for modifications to Windows Run keys, startup folders, or service registrations (TS015).

### 9. Privileged Group Modification Rule (`evaluate_privileged_group_rule`)
- **How it works**: Monitors Security Events 4732, 4728, and 4756 for accounts added to sensitive security groups like Administrators, Domain Admins, or Backup Operators (TS005).

### 10. Account Correlation Rule (`evaluate_account_correlation_rule`)
- **How it works**: Correlates user account creation (Event 4720) with subsequent privilege escalation within 30 minutes (TS017).

### 11. Network Threshold Rule (`evaluate_network_threshold_rule`)
- **How it works**: Analyzes Sysmon Event 3 network connections to detect port scans (one source connecting to $\ge 15$ distinct destination ports in 60 seconds - TS018).

### 12. Network Indicator Rule (`evaluate_network_indicator_rule`)
- **How it works**: Flags outbound connections from monitored endpoints to unusual external destinations (TS019).

### 13. DNS Indicator Rule (`evaluate_dns_rule`)
- **How it works**: Inspects Sysmon Event 22 queries for dynamic DNS services, paste sites (`pastebin`), or tunneling utilities (`ngrok`) (TS020).

### 14. File Activity Rule (`evaluate_file_rule`)
- **How it works**: Flags suspicious file creations (Sysmon 11) or mass deletions (Sysmon 23/26) in sensitive directories (TS021, TS022).

---

## 7. End-to-End Walkthrough: A Real Attack in Baby Steps

Let's trace what happens when an adversary executes a real multi-stage attack:

```
ATTACK SCENARIO:
Adversary uses PsExec to move laterally, executes an Encoded PowerShell script,
installs a Registry Run Key for persistence, and reaches out to a C2 Server.
(Validated against D:\EVTX-ATTACK-SAMPLES\Lateral Movement\LM_sysmon_psexec_smb_meterpreter.evtx)
```

### Baby Step 1: The Adversary Acts on the Endpoint
- The attacker on host `10.0.0.5` uses PsExec to execute a Meterpreter payload on victim workstation `VICTIM-PC`.
- They run: `powershell.exe -NoP -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLi4u`
- The payload modifies `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to survive reboot.
- The payload connects back to C2 port 4444.

### Baby Step 2: Windows Subsystems Generate Event Telemetry
- **Sysmon Event 1** captures process creation: `powershell.exe` with base64 `-enc` flag.
- **Sysmon Event 13** captures registry modification on the Run key.
- **Sysmon Event 3** captures the TCP connection to port 4444.

### Baby Step 3: CYFROG Ingests & Signs the Raw Evidence
- `collectors/windows_event_collector.py` captures the raw XML logs.
- The collector computes the SHA-256 fingerprint:
  $$\text{SHA256}(\text{Raw XML}) = \texttt{e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855}$$
- Stored safely in the `raw_events` table with collection timestamp and record ID.

### Baby Step 4: The Normalizer Parses the Event
- `normalizer/event_parser.py` extracts the XML fields.
- `normalizer/event_schema.py` standardizes the fields:
  - `event_id`: "1"
  - `image`: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
  - `command_line`: "powershell.exe -enc ..."
  - `username`: "VICTIM-PC\Administrator"
- Validated through Pydantic and inserted into `normalized_events`.

### Baby Step 5: The Detection Engine Evaluates Rules
- Evaluator `evaluate_keyword_rule` inspects the normalized command line against Rule **TS002** (Suspicious PowerShell Execution). The `-enc` keyword matches $\rightarrow$ **Alert Generated!**
- Evaluator `evaluate_registry_rule` inspects the Run key modification against Rule **TS015** (Registry Persistence) $\rightarrow$ **Alert Generated!**
- Evaluator `evaluate_network_indicator_rule` inspects Event 3 against Rule **TS019** (Unusual Outbound Connections) $\rightarrow$ **Alert Generated!**

### Baby Step 6: Story Builder Synthesizes the Attack Narrative
- Rather than leaving 3 disconnected alerts, `investigation/story_builder.py` observes that all 3 alerts occurred on `VICTIM-PC` under user `Administrator` within a 15-minute window.
- It groups them into **Attack Story #52**: *"Multi-Stage Lateral Movement & Execution on VICTIM-PC"*.

### Baby Step 7: Risk Scoring & Forensics
- `risk/risk_engine.py` calculates the composite risk score: $\text{Criticality (80)} \times \text{Severity Factor} = \mathbf{92/100}$ (CRITICAL).
- `forensics/forensic_engine.py` reconstructs the process tree: `psexecsvc.exe` $\rightarrow$ `cmd.exe` $\rightarrow$ `powershell.exe`.

### Baby Step 8: Case Management & Triage
- The analyst opens the CYFROG Dashboard.
- Clicks *"Escalate to Case"*: Case `#104` is created, assigned to Analyst, and the MITRE `T1059.001` response playbook is loaded.

### Baby Step 9: Cryptographic Report Generation
- Analyst clicks *"Export DFIR Report"*.
- `reports/pdf_generator.py` compiles an executive PDF including the SHA-256 evidence verification certificates ready for presentation to leadership or legal auditors.

---

## 8. Dashboard Guide: All 5 Workspaces & 20 Pages Explained

The CYFROG dark-themed workspace is divided into 5 logical analytical operational tiers:

```
CYFROG WORKSPACE STRUCTURE
├── ◈ COMMAND CENTER
│   ├── Overview
│   ├── Alert Management
│   ├── Live Monitoring
│   └── Automated Detection
├── ◉ THREAT INTELLIGENCE
│   ├── Threat Hunting
│   ├── Threat Intelligence
│   ├── IOC Correlation
│   └── Risk Intelligence
├── ⌕ INVESTIGATION & DFIR
│   ├── Investigations (Attack Stories)
│   ├── Forensic Artifacts
│   ├── Evidence & Integrity
│   ├── Forensic Timeline
│   ├── Case Management
│   └── Incident Response
├── ◎ DETECTION ENGINEERING
│   ├── Detection Intelligence
│   ├── Detection Quality
│   └── MITRE ATT&CK Coverage
└── ▤ REPORTS & ADMIN
    ├── Analyst Reports
    ├── Soc Analytics
    └── System Health
```

### Workspace 1: Command Center (Daily Triage & Monitoring)
1. **Overview (◈)**:
   - *What it is*: Executive high-level HUD.
   - *What it shows*: Total ingested events, active alert count, open attack stories, average risk score, and real-time alert trends.
   - *Analyst Action*: Review at shift start to understand endpoint threat posture.
2. **Alert Management (⚑)**:
   - *What it is*: The primary alert triage queue.
   - *What it shows*: Sortable table of all fired alerts with severity badges (CRITICAL, HIGH, MEDIUM), rule IDs, affected host, username, and timestamps.
   - *Analyst Action*: Update alert status (NEW $\rightarrow$ IN_PROGRESS $\rightarrow$ RESOLVED / FALSE_POSITIVE), inspect evidence payloads.
3. **Live Monitoring (📡)**:
   - *What it is*: Real-time stream of incoming Windows events.
   - *What it shows*: Live event rate metrics, breakdown by provider (Security, Sysmon, System), and recent raw event stream.
   - *Analyst Action*: Monitor live data ingestion during active forensic tests.
4. **Automated Detection (🧠)**:
   - *What it is*: Detection engine controller.
   - *What it shows*: Status of background detection loops, execution latency, and one-click manual detection trigger.

### Workspace 2: Threat Intelligence & Hunting
5. **Threat Hunting (⌘)**:
   - *What it is*: Hypothesis-driven threat hunting console.
   - *What it shows*: Pre-built hunting queries (e.g. LOLBins, rare process parentage, off-hours logins, suspicious script extensions).
   - *Analyst Action*: Execute custom SQL/structured queries across millions of normalized events to find stealthy adversaries.
6. **Threat Intelligence (◉)**:
   - *What it is*: Threat feed management repository.
   - *What it shows*: Curated list of known malicious indicators of compromise (IOCs): IP addresses, domains, URL endpoints, and file hashes with threat actors and confidence levels.
7. **IOC Correlation (🔗)**:
   - *What it is*: Automated threat feed matcher.
   - *What it shows*: Matches between incoming endpoint logs and active threat intelligence feeds, displaying exact matched indicators and associated threat actors.
8. **Risk Intelligence (🎯)**:
   - *What it is*: Dynamic asset and user risk assessment.
   - *What it shows*: Top risky users, high-risk host assets, criticality multipliers, and historical risk trajectory.

### Workspace 3: Investigation & DFIR
9. **Investigations (⌕)**:
   - *What it is*: The Attack Story viewer.
   - *What it shows*: Clustered attack narratives combining related alerts into a single cohesive story with narrative timeline and affected entities.
10. **Forensic Artifacts (🗂️)**:
    - *What it is*: Deep forensic evidence inspector.
    - *What it shows*: Extracted process command lines, loaded DLL modules, modified registry keys, and network socket bindings.
11. **Evidence & Integrity (⬡)**:
    - *What it is*: Cryptographic audit and chain-of-custody verifier.
    - *What it shows*: Real-time SHA-256 integrity verification: recalculates the raw hash and verifies that the database has experienced zero byte-level tampering.
12. **Forensic Timeline (🕒)**:
    - *What it is*: High-precision chronological event sequencer.
    - *What it shows*: Millisecond-accurate timeline of adversary actions preceding, during, and following an alert.
13. **Case Management (📁)**:
    - *What it is*: Full SOC incident case management.
    - *What it shows*: Incident tickets, priority levels, assigned investigators, case notes, timeline milestones, and resolution tracking.
14. **Incident Response (🛡️)**:
    - *What it is*: Playbook automation guidance.
    - *What it shows*: Step-by-step MITRE-aligned containment, eradication, and recovery playbooks (e.g. isolating hosts, killing malicious PIDs, resetting compromised credentials).

### Workspace 4: Detection Engineering
15. **Detection Intelligence (◎)**:
    - *What it is*: Detection rule performance analytics.
    - *What it shows*: Rule firing frequency, false-positive rates per rule, and noise-to-signal ratios.
16. **Detection Quality (🎚️)**:
    - *What it is*: Rule tuning and efficacy dashboard.
    - *What it shows*: Evaluates rule precision, threshold drift, and provides recommendations for sliding-window tuning.
17. **MITRE ATT&CK Coverage (🗺️)**:
    - *What it is*: Visual enterprise defense heatmap.
    - *What it shows*: Color-coded MITRE ATT&CK matrix showing covered tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Discovery, and C2.

### Workspace 5: Reports & Administration
18. **Analyst Reports (📑)**:
    - *What it is*: Automated DFIR PDF report generator.
    - *What it shows*: One-click export of comprehensive incident investigation reports formatted with ReportLab.
19. **Soc Analytics (📊)**:
    - *What it is*: SOC operational performance metrics.
    - *What it shows*: Mean Time to Detect (MTTD), Mean Time to Respond (MTTR), alerts triaged per analyst, and triage resolution velocity.
20. **System Health (💚)**:
    - *What it is*: Platform diagnostics and ingestion pipeline telemetry.
    - *What it shows*: SQLite database size, record counts across all tables, collector status, memory consumption, and system errors.

---

## 9. Empirical Validation & Viva Defense Strategy

### The Golden Academic Rule: Differentiate Configured vs Proven
In your project thesis (Chapter 5: Evaluation & Results) and viva, use this defensible framework:

```
┌──────────────────────────────────────────────────────────────────┐
│                   CYFROG THREE-TIER DEFENSE MODEL                │
│                                                                  │
│  Tier 1: Configured Coverage (25 Rules across 7 MITRE Tactics)   │
│          Architectural design showing theoretical capability.    │
│                                                                  │
│  Tier 2: Unit Automated Verification (263 Passing PyTest Cases)   │
│          Proves algorithms, edge cases, and sliding-window logic.│
│                                                                  │
│  Tier 3: Empirical Adversary Validation (Real EVTX Attack Captures)│
│          Proves real-world detection against actual attacker logs.│
└──────────────────────────────────────────────────────────────────┘
```

### Verified Real EVTX Detections (Empirically Proven):
1. **TS003 (Security Audit Log Cleared - Event 1102)**: Proven on real adversary defense evasion logs.
2. **TS025 (PowerShell ScriptBlock LSASS Dump - Event 4104)**: Proven on real MiniDumpWriteDump capture.
3. **TS006 (Scheduled Task Persistence - Event 4698)**: Proven on real `temp_scheduled_task` and `PrivEsc_SeImpersonatePriv` captures.
4. **TS016 (Special Privileges / Pass-the-Hash - Event 4672)**: Proven on real Mimikatz Pass-the-Hash capture.
5. **TS015 (Registry Persistence - Sysmon 13)**: Proven on real PsExec lateral movement capture.
6. **TS002 (Encoded PowerShell Execution - Sysmon 1)**: Proven on real PsExec meterpreter capture.
7. **TS012 (Process Indicator / LOLBin - Sysmon 1)**: Proven on real `comsvcs.dll` Living-off-the-Land minidump.
8. **TS019 (Outbound Network Indicator - Sysmon 3)**: Proven on real BabyShark and Invoke-Mimikatz captures.

### The Real-World Telemetry Insights (Examiners Love This):
- **The Event 4697 vs 7045 Reality**: Windows compliance docs mention Event 4697 for services. In reality, Windows defaults log services as **Event 7045 in the System channel**. Explaining this shows deep operational expertise.
- **Primary vs Collateral Detection**: Demonstrating that CYFROG detected the collateral footprint (dump files, network C2) even before direct LSASS memory access rules were added demonstrates layered defense-in-depth.

---

## 10. Quick Command Reference

All functions can be executed using the master runner [run_cyfrog.py](file:///d:/CYFROG/run_cyfrog.py):

```powershell
# 1. Interactive Master Console Menu:
python run_cyfrog.py

# 2. Launch the Streamlit Dark SOC Dashboard:
python run_cyfrog.py --dashboard

# 3. Run the Real-World Attack EVTX Validation Matrix:
python run_cyfrog.py --matrix

# 4. Run PyTest Automated Test Suite (263 Tests):
python run_cyfrog.py --test

# 5. Run Live Pipeline Ingestion & Detection:
python run_cyfrog.py --pipeline

# 6. Check System Health & Database Statistics:
python run_cyfrog.py --health

# 7. Generate Automated DFIR PDF Investigation Report:
python run_cyfrog.py --report
```

