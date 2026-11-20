# REWS — Ransomware Early Warning System

A local academic prototype for monitoring a user-selected folder, inventorying files, computing SHA-256 fingerprints, detecting selected suspicious indicators, reviewing alerts, and exporting audit reports.

## Run on Windows
1. Install Python 3.10 or newer.
2. Extract this folder.
3. Double-click `run.bat`.
4. The browser opens at `http://127.0.0.1:5000`.

Or run manually:
```bash
python -m pip install -r requirements.txt
python app.py
```

## Main modules
- Overview: current monitoring state, alert metrics and recent activity.
- Live Monitor: choose a folder, start/stop polling, inspect observed file events.
- File Inventory: scan the selected folder, search and inspect file metadata and SHA-256.
- Security Alerts: filter by severity/status, inspect details and acknowledge alerts.
- Scan History: review previous scans and their summaries.
- Threat Guide: ransomware indicators and defensive guidance.
- Reports: export JSON, CSV and print-friendly HTML reports.
- Settings: adjust change-burst threshold and polling interval.

## Safe demo workspace
`data/demo_workspace/` contains harmless sample files. Select this folder to test scanning and monitoring without pointing the app at personal or system folders. Use the Demo Lab action in the interface to create a clearly labelled test event and sample file activity.

## Scope and limitations
REWS is an educational folder-monitoring prototype. It only observes the folder explicitly selected by the user. It does not scan the whole computer, inspect process memory, stop processes, quarantine files, decrypt data, or guarantee malware detection. Extension and burst-activity rules can produce false positives and false negatives. A warning is not proof of ransomware; a clean result is not proof that a file is safe. Keep backups and use established endpoint protection.
