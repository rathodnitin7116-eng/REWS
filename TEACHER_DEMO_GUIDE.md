# REWS — Ransomware Early Warning System
## Complete Viva, Presentation & Teacher Demonstration Guide

---

## 1. What is REWS and What Cybersecurity Problem Does It Solve?

### The Core Problem: Modern Ransomware Attacks
- **How Ransomware Works**: Cybercriminals deploy malicious payloads (e.g., *LockBit, WannaCry, BlackCat, Akira*) that silently sweep through user or server storage.
- **The Attack Vector**: Once inside, the ransomware automated loop rapidly opens documents (`.docx`, `.xlsx`, `.pdf`), encrypts their contents using strong ciphers (AES-256 / ChaCha20), renames them with appended extensions (e.g., `.locked`, `.crypt`), deletes original copies, and drops extortion ransom notes (`HOW_TO_RESTORE_FILES.txt`) demanding cryptocurrency.
- **Why Traditional Antivirus Fails**: Standard antivirus relies heavily on known file signatures (hashes of known viruses). Attackers constantly recompile or obfuscate payloads (zero-day malware), allowing them to bypass traditional antivirus until hundreds of gigabytes of critical data are already destroyed.

### The Solution: REWS (Host-Based Behavioral Early Warning)
REWS operates as an active **Host-Based Intrusion Detection System (HIDS)** that focuses on **behavioral heuristics** and **filesystem velocity** rather than just static file signatures:
1. **Cryptographic Integrity (SHA-256)**: Baselines all assets and checks for unauthorized content alterations.
2. **Behavioral Velocity (Burst Detection)**: Tracks how many file modifications happen per time tick. Ransomware encrypts in rapid automated bursts; if changes exceed the burst threshold within 2–3 seconds, REWS raises an immediate **Critical Alert**.
3. **Suspicious Suffix & Double-Extension Matching**: Detects known ransomware extensions (`.locked`, `.crypt`, `.enc`, etc.) and double suffixes (`report.docx.locked`).
4. **Ransom Extortion Note Detection**: Scans for known ransom note patterns (`HOW_TO_DECRYPT`, `RESTORE_FILES`) dropped into target directories.
5. **Real-time Incident Response & Forensic Audit Trail**: Instant triage console, alert acknowledgment, and exportable forensic reports (JSON, CSV, and Printable Executive PDF).

---

## 2. What Does the "Folder" Do? (What You Need to Know)

- **Target Directory Concept**: REWS monitors a user-specified folder and its subdirectories. In enterprise security, this can be a user's critical data vault, or a **Canary / Honeypot folder** intentionally placed to bait ransomware.
- **The Safe Demo Workspace**: The project includes a dedicated safe folder:
  ```
  data/demo_workspace/
  ├── demo_note.txt
  ├── meeting_notes.txt
  ├── Finance/
  │   ├── budget_notes.txt
  │   └── quarterly_summary.txt
  ├── Legal/
  │   └── compliance_policy.txt
  └── Projects/
      ├── project_readme.txt
      └── readme.txt
  ```
- **You do NOT need to type anything manually**: The system automatically detects and pre-fills this safe demo path (`data/demo_workspace`) on launch!
- **Zero Risk**: All testing happens strictly inside this sandbox folder without ever touching your Windows or personal files.

---

## 3. Step-by-Step 5-Minute Teacher Demonstration Script

Follow these exact steps when presenting to your teacher:

### Step 1: Launch the System
1. Double-click `run.bat` in the project folder.
2. The browser opens automatically at `http://127.0.0.1:5000`.
3. Point out the **Hacker SOC (Security Operations Center)** dark theme:
   - *“Teacher, this is the REWS Sentinel Command Center. It displays our real-time threat posture, DEFCON threat levels, and active host surveillance telemetry.”*

### Step 2: Show the Monitored Target
1. Look at the top cyan target banner:
   - Notice it shows `C:\...\data\demo_workspace`.
   - Explain: *“The system automatically binds to our safe demonstration repository containing mock enterprise documents (Finance, Legal, Projects).”*

### Step 3: Demonstrate SHA-256 Forensics
1. Click **SHA-256 Forensics** (or **File Inventory**) in the left sidebar.
2. Click the **Run Deep Inspection** button.
3. Show the table:
   - Explain: *“REWS has audited every single file, calculated its SHA-256 cryptographic digest, and verified that no unauthorized encryption has occurred. The status shows VERIFIED CLEAN.”*

### Step 4: Arm the Live Surveillance Daemon
1. Click **Live Monitor** in the left sidebar.
2. Click **Start Monitoring**.
3. Point out:
   - The glowing green **ARMED** status badge.
   - The **Rotating Surveillance Radar** sweeping across the target folder.
   - The **Real-Time Telemetry Console** at the bottom listening for filesystem events.

### Step 5: The Climax — Simulate a Ransomware Strike!
1. In the **Red Team Live Simulation Lab** panel (right on the Live Monitor page), click:
   👉 **`[ ☣ Simulate Attack ]`**
2. Within 2-3 seconds, watch the magic happen:
   - The cyber audio alarm chirps.
   - The **Incident Register** triggers **Critical** and **High** alerts!
   - The real-time console prints: `[INODE_CREATED] ... Payroll_2026.xlsx.locked`, `[INODE_CREATED] ... HOW_TO_RESTORE_YOUR_FILES.txt`.
   - Go back to **Command Center**: The Threat Gauge spikes to **DEFCON 1 // CRITICAL BREACH**, and the Risk Score jumps!
3. Explain to the teacher:
   - *“Notice how REWS instantly flagged 3 key ransomware behaviors: first, the rapid burst of modifications; second, the suspicious `.locked` and `.crypt` extensions; and third, the ransom extortion note `HOW_TO_RESTORE_YOUR_FILES.txt`.”*

### Step 6: Triage & Incident Response
1. Click **Incident Register** (Security Alerts) in the sidebar.
2. Click any incident to open the **Forensic Incident Detail** modal showing affected file path and timestamp.
3. Click **Acknowledge All Open** to triage the alarms.
4. Click **Sanitize & Restore Clean Baseline** (`[ 🛡️ Reset Folder ]`) to clean up the attack artifacts and restore the clean files!

### Step 7: Export Forensic Evidence
1. Click **Forensic Reports** in the sidebar.
2. Click **Open Printable Report ↗**:
   - A clean, executive-grade SOC Audit Report opens with timestamps, alert breakdown, and non-repudiation note.
   - Explain: *“In enterprise security, incident responders require auditable logs for digital forensics and compliance audits. REWS provides structured JSON, CSV, and printable PDF reports.”*

---

## 4. Likely Teacher / Viva Questions & Exact Answers

#### Q1: "What is the difference between signature-based and heuristic-based detection?"
> **Answer**:
> - **Signature-based detection** compares known file hashes against a blacklist. If an attacker modifies even a single byte or uses a new variant, the hash changes completely and signature detection fails.
> - **Heuristic-based detection** (which REWS uses) monitors **behavior**: rapid velocity of file modifications (bursts), suspicious naming patterns (`.locked`), and ransom notes. Even if the malware binary is brand new, its behavior on disk gives it away.

#### Q2: "How does the burst detection algorithm work?"
> **Answer**:
> REWS takes periodic filesystem snapshots (every 3 seconds). It compares the current state against the previous baseline snapshot. If the count of modified, created, or renamed files in a single polling interval exceeds the threshold (e.g. 8 files), REWS detects an automated encryption process and raises a Critical Burst Alert.

#### Q3: "What is the purpose of SHA-256 hashing in this project?"
> **Answer**:
> SHA-256 provides cryptographic file integrity verification. Before any attack, we have an immutable baseline digest. If ransomware alters a document, even without changing its extension, its SHA-256 hash immediately changes, proving data tampering.

#### Q4: "What is MITRE ATT&CK T1486?"
> **Answer**:
> MITRE ATT&CK technique **T1486** is titled **'Data Encrypted for Impact'**. It documents adversary techniques for encrypting data on target systems to interrupt availability and extort ransom. REWS is specifically designed as a countermeasure against T1486.

#### Q5: "What are the limitations of this prototype?"
> **Answer**:
> - It is an educational host-based monitoring prototype operating in user space.
> - It does not block kernel-level file drivers or kill processes directly (to avoid false-positive termination of legitimate system tools).
> - In a full enterprise EDR (Endpoint Detection and Response), REWS would be paired with process termination (API hooks) and volume shadow copy protection.

---

## 5. Technology Stack Summary
- **Backend**: Python 3.10+ with Flask (REST API, multi-threaded polling daemon).
- **Database**: SQLite 3 (`data/rews.db`) for persistent alert registers, scan history, and settings.
- **Frontend**: Vanilla JavaScript (ES6+), responsive CSS3 with Dark Cyberpunk SOC styling, and Web Audio API for synthetic audio telemetry.
- **Security Protocols**: SHA-256 cryptographic hashing (`hashlib`), regex pattern matching, and file stat timestamp analysis.
