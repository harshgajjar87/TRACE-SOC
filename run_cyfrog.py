#!/usr/bin/env python3
"""
CYFROG - Master Project Orchestrator & CLI Runner
================================================================================
Unified launcher for tests, live detection pipeline, real attack validation,
dashboard server, database diagnostics, and DFIR reporting.

Usage:
    python run_cyfrog.py               # Launch interactive menu
    python run_cyfrog.py --dashboard   # Launch Streamlit Analyst Workspace
    python run_cyfrog.py --matrix      # Run Real Attack EVTX Validation Matrix
    python run_cyfrog.py --test        # Run Automated PyTest Suite (263 tests)
    python run_cyfrog.py --pipeline    # Run Detection & Attack Story Pipeline
    python run_cyfrog.py --health      # Display Database & Subsystem Diagnostics
    python run_cyfrog.py --report      # Generate DFIR PDF Investigation Report
"""

import os
import sys
import subprocess
import argparse
import sqlite3
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
DB_PATH = ROOT_DIR / "data" / "tracesoc.db"
PYTHON_EXE = sys.executable

def banner():
    print("""
================================================================================
  ██████╗██╗   ██╗███████╗██████╗  ██████╗  ██████╗ 
 ██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔═══██╗██╔════╝ 
 ██║      ╚████╔╝ █████╗  ██████╔╝██║   ██║██║  ███╗
 ██║       ╚██╔╝  ██╔══╝  ██╔══██╗██║   ██║██║   ██║
 ╚██████╗   ██║   ██║     ██║  ██║╚██████╔╝╚██████╔╝
  ╚═════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ 
        AN INTELLIGENT TRACE SYSTEM FOR SOC & DIGITAL FORENSICS
================================================================================
""")

def run_cmd(cmd_list, description="Executing command"):
    print(f"\n[*] {description}...")
    print(f"    Command: {' '.join(cmd_list)}\n" + "-" * 76)
    try:
        subprocess.run(cmd_list, cwd=str(ROOT_DIR), check=True)
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Error during execution: exited with code {e.returncode}")
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")

def launch_dashboard():
    banner()
    print("[*] Starting CYFROG SOC Analyst Workspace on Streamlit...")
    print("    URL: http://localhost:8501")
    print("    Press Ctrl+C in this terminal to stop the dashboard server.\n")
    run_cmd([PYTHON_EXE, "-m", "streamlit", "run", "dashboard/app.py"], "Launching Streamlit Dashboard")

def run_tests():
    banner()
    print("[*] Running full automated test suite (PyTest)...")
    run_cmd([PYTHON_EXE, "-m", "pytest", "tests/", "-v"], "Running Automated Test Suite")

def run_attack_matrix(scenario=None):
    banner()
    cmd = [PYTHON_EXE, "evaluate_attack_matrix.py"]
    if scenario:
        cmd.extend(["--scenario", str(scenario)])
    run_cmd(cmd, "Evaluating Detection Engine against Real Attack EVTX Samples")

def run_pipeline():
    banner()
    print("[*] Executing Ingestion, Detection Engine & Story Builder Pipeline...")
    try:
        from monitoring.analysis_pipeline import run_analysis_pipeline
        result = run_analysis_pipeline()
        print("\n[+] Analysis Pipeline Execution Completed Successfully!")
        print(f"    Total Events Analyzed : {result.get('total_events', 'N/A')}")
        print(f"    Alerts Generated      : {result.get('alerts_generated', 'N/A')}")
        print(f"    Stories Built         : {result.get('stories_built', 'N/A')}")
        print(f"    Pipeline Latency      : {result.get('duration_seconds', 'N/A')} seconds")
    except Exception as e:
        print(f"\n[!] Pipeline error: {e}")

def check_health():
    banner()
    print("[*] Inspecting CYFROG Subsystem Health & Database Telemetry...")
    if not DB_PATH.exists():
        print(f"[!] Database file not found at: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()]

    print(f"\n[+] Database Location : {DB_PATH}")
    print(f"[+] Database Size     : {DB_PATH.stat().st_size / (1024*1024):.2f} MB")
    print("\n" + "=" * 60)
    print(f" {'TABLE NAME':<35} | {'RECORD COUNT':>15} ")
    print("=" * 60)

    for tbl in tables:
        try:
            cnt = cursor.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            print(f"  {tbl:<33} | {cnt:>15,} ")
        except Exception:
            pass

    print("=" * 60)

    # Key SOC Metrics
    try:
        raw_cnt = cursor.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
        norm_cnt = cursor.execute("SELECT COUNT(*) FROM normalized_events").fetchone()[0]
        alert_cnt = cursor.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        story_cnt = cursor.execute("SELECT COUNT(*) FROM attack_stories").fetchone()[0]
        case_cnt = cursor.execute("SELECT COUNT(*) FROM incident_cases").fetchone()[0]

        print("\n  CORE SOC TELEMETRY SUMMARY:")
        print(f"  - Raw Cryptographic Events Ingested : {raw_cnt:,}")
        print(f"  - Normalized Pydantic Records       : {norm_cnt:,}")
        print(f"  - Security Alerts Fired             : {alert_cnt:,}")
        print(f"  - Correlated Attack Stories         : {story_cnt:,}")
        print(f"  - Managed Incident Cases            : {case_cnt:,}")
    except Exception as e:
        print(f"[!] Error reading summary metrics: {e}")
    finally:
        conn.close()

def generate_pdf_report():
    banner()
    print("[*] Generating Automated DFIR Forensic Investigation PDF Report...")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Find the most recent attack story
    story = cursor.execute("SELECT id, title, severity FROM attack_stories ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()

    if not story:
        print("[!] No attack stories found in database to generate report for.")
        print("    Run option 4 (Analysis Pipeline) first to correlate alerts into stories.")
        return

    story_id = story["id"]
    print(f"[+] Found Attack Story #{story_id}: '{story['title']}' (Severity: {story['severity']})")

    try:
        from reports.pdf_generator import generate_investigation_pdf
        pdf_bytes = generate_investigation_pdf(story_id)
        out_file = ROOT_DIR / f"CYFROG_Investigation_Story_{story_id}.pdf"
        with open(out_file, "wb") as f:
            f.write(pdf_bytes)
        print(f"[+] PDF Investigation Report Generated Successfully!")
        print(f"    Saved to: {out_file} ({len(pdf_bytes) / 1024:.1f} KB)")
    except Exception as e:
        print(f"[!] Error generating PDF: {e}")

def initialize_database():
    banner()
    print("[*] Initializing CYFROG Database Schemas...")
    from database.db import create_tables
    from investigation.story_schema import create_story_tables
    from dashboard.data_access import ensure_dashboard_schema
    from threat_intel.engine import create_threat_intel_schema
    from response.engine import create_response_schema
    from cases.engine import create_case_schema
    from risk.engine import create_risk_schema
    from attack.engine import create_attack_schema
    from monitoring.engine import create_monitoring_schema
    from monitoring.analysis_pipeline import create_analysis_schema
    from investigation.chain_of_custody import create_chain_of_custody_schema
    from forensics.engine import create_forensics_schema
    from threat_intel.correlator import create_ioc_correlation_schema

    create_tables()
    create_story_tables()
    ensure_dashboard_schema()
    create_threat_intel_schema()
    create_response_schema()
    create_case_schema()
    create_risk_schema()
    create_attack_schema()
    create_monitoring_schema()
    create_analysis_schema()
    create_chain_of_custody_schema()
    create_forensics_schema()
    create_ioc_correlation_schema()
    print("[+] All database tables and schemas successfully created and verified!")

def interactive_menu():
    while True:
        banner()
        print("Select an operation to execute:")
        print("  [1] 🛡️  Launch CYFROG SOC Analyst Workspace (Streamlit Web UI)")
        print("  [2] 🎯  Run Real Attack EVTX Validation Matrix (D:\\EVTX-ATTACK-SAMPLES)")
        print("  [3] 🧪  Run Automated PyTest Suite (263 Unit & Real Event Tests)")
        print("  [4] ⚙️  Run End-to-End Pipeline (Ingest, Detect, Correlate Stories)")
        print("  [5] 📊  Inspect System Health & Database Telemetry")
        print("  [6] 📑  Generate Automated DFIR Investigation PDF Report")
        print("  [7] 🔍  Run Specific Attack Scenario Validation (1 to 6)")
        print("  [8] 🗄️  Initialize / Verify Database Tables")
        print("  [9] ❌  Exit")
        print("-" * 80)

        choice = input("Enter choice (1-9): ").strip()

        if choice == "1":
            launch_dashboard()
            break
        elif choice == "2":
            run_attack_matrix()
            input("\nPress Enter to return to menu...")
        elif choice == "3":
            run_tests()
            input("\nPress Enter to return to menu...")
        elif choice == "4":
            run_pipeline()
            input("\nPress Enter to return to menu...")
        elif choice == "5":
            check_health()
            input("\nPress Enter to return to menu...")
        elif choice == "6":
            generate_pdf_report()
            input("\nPress Enter to return to menu...")
        elif choice == "7":
            print("\nSelect Scenario:")
            print("  1: LSASS Memory Access (Sysmon 10)")
            print("  2: Mimikatz Execution & Staging")
            print("  3: Active Directory DCSync Attacks")
            print("  4: Password Spraying & Brute Force")
            print("  5: Persistence via Scheduled Tasks & Services")
            print("  6: Process Injection & Lateral Movement (PsExec/PTH)")
            sc_choice = input("Enter scenario (1-6): ").strip()
            if sc_choice in ["1", "2", "3", "4", "5", "6"]:
                run_attack_matrix(int(sc_choice))
            else:
                print("[!] Invalid scenario choice.")
            input("\nPress Enter to return to menu...")
        elif choice == "8":
            initialize_database()
            input("\nPress Enter to return to menu...")
        elif choice == "9":
            print("\nExiting CYFROG Master Runner. Happy Defending!\n")
            sys.exit(0)
        else:
            print("[!] Invalid selection. Please enter 1-9.")

def main():
    parser = argparse.ArgumentParser(description="CYFROG Master CLI Runner")
    parser.add_argument("--dashboard", action="store_true", help="Launch Streamlit SOC Analyst Workspace")
    parser.add_argument("--matrix", action="store_true", help="Run Real Attack EVTX Validation Matrix")
    parser.add_argument("--scenario", type=int, choices=range(1, 7), help="Specific attack scenario to run (1-6)")
    parser.add_argument("--test", action="store_true", help="Run Automated PyTest Suite")
    parser.add_argument("--pipeline", action="store_true", help="Run Detection & Story Builder Pipeline")
    parser.add_argument("--health", action="store_true", help="Inspect System Health & Database Metrics")
    parser.add_argument("--report", action="store_true", help="Generate DFIR PDF Investigation Report")
    parser.add_argument("--init-db", action="store_true", help="Initialize Database Tables")

    args = parser.parse_args()

    if args.dashboard:
        launch_dashboard()
    elif args.matrix or args.scenario:
        run_attack_matrix(args.scenario)
    elif args.test:
        run_tests()
    elif args.pipeline:
        run_pipeline()
    elif args.health:
        check_health()
    elif args.report:
        generate_pdf_report()
    elif args.init_db:
        initialize_database()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
