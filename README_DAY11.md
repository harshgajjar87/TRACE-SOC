# TRACE-SOC Day 11 — SOC Analyst Workspace

Day 11 adds a Streamlit analyst workspace on top of the existing TRACE-SOC SQLite, detection and investigation modules. It does not replace the custom detection engine and does not require Wazuh.

## Features

- Security overview with event, alert, severity, workflow and story metrics.
- Alert search/filter and analyst status updates (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).
- Append-only status transition history in `alert_status_history`.
- Investigation story list with linked timeline, correlation edges and alerts.
- Threat hunting across normalized events with parameterized filters.
- Evidence hash verification for raw XML records linked to a story.
- Detection rule inventory grouped by category.
- Downloadable PDF investigation reports.

## Install

From the project root in PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, use the interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Start the dashboard

Run from `D:\TRACE-SOC` (the project root):

```powershell
python -m streamlit run dashboard/app.py
```

Streamlit will print a local URL, normally `http://localhost:8501`.

## Database behavior

The dashboard uses the existing `data/tracesoc.db`. On startup it calls the existing base-table initializer and Day 10 investigation schema initializer, then creates `alert_status_history` if absent. It does not clear or replace existing events, alerts, stories or evidence.

Alert status updates are validated and recorded with old status, new status, optional analyst note and UTC timestamp. Re-saving the same status does not create a duplicate history entry.

## Tests

```powershell
python -m pytest tests/ -v
```

The new dashboard data-access tests use a temporary SQLite database and do not modify the user's real database. PDF report generation requires ReportLab.

## Notes and limitations

- Dashboard figures are database snapshots refreshed when the page reruns; they are not a claim of live endpoint telemetry.
- Threat hunting searches the normalized fields currently stored by TRACE-SOC.
- Evidence `VERIFIED` means the stored raw XML blob matches its recorded SHA-256 baseline. It does not independently prove original acquisition authenticity.
- Correlation confidence is a heuristic relationship-strength score, not a probability that an attack occurred.
- Dashboard status history records transitions made through this dashboard. It cannot reconstruct status changes that happened before the history table existed.
