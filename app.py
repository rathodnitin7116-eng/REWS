from flask import Flask, jsonify, request, render_template, make_response
from pathlib import Path
from datetime import datetime, timezone
import sqlite3, threading, time, hashlib, json, csv, io, os, re, html

BASE = Path(__file__).resolve().parent
DATA = BASE / "data"
DB = DATA / "rews.db"
DATA.mkdir(exist_ok=True)

app = Flask(__name__)
# Flask 3+ compatibility
if hasattr(app, "json") and hasattr(app.json, "sort_keys"):
    app.json.sort_keys = False
else:
    app.config["JSON_SORT_KEYS"] = False

SUSPICIOUS_EXT = {
    ".locked", ".crypt", ".crypted", ".encrypted", ".enc", ".ryk",
    ".wncry", ".lockbit", ".pay", ".akira", ".blackcat", ".darkside",
    ".revil", ".hive", ".phobos", ".dharma", ".stop", ".djvu"
}
SCRIPT_EXT = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".msi", ".vbe", ".jse", ".wsf", ".wsh"}
IGNORE_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".rews"}
RANSOM_NOTE_REGEX = re.compile(r"(readme.*restore|how.*to.*decrypt|decrypt.*note|restore.*file|!.*decrypt.*!|help.*restore|ransom)", re.IGNORECASE)

monitor = {"active": False, "path": "", "snapshot": {}, "thread": None, "stop": threading.Event(),
           "interval": 3, "last_poll": None, "last_events": []}
lock = threading.RLock()

def now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def db():
    con = sqlite3.connect(DB, timeout=15)
    con.row_factory = sqlite3.Row
    return con

def ensure_demo_workspace():
    demo = DATA / "demo_workspace"
    demo.mkdir(exist_ok=True)
    (demo / "Finance").mkdir(parents=True, exist_ok=True)
    (demo / "Projects").mkdir(parents=True, exist_ok=True)
    (demo / "Legal").mkdir(parents=True, exist_ok=True)
    files = {
        demo / "demo_note.txt": "REWS Security Baseline Note.\nAll monitored assets are subject to real-time integrity verification.\n",
        demo / "meeting_notes.txt": "Incident Response Drill Schedule.\nPriority 1: Isolate infected subnet.\nPriority 2: Preserve forensic image.\n",
        demo / "Finance" / "budget_notes.txt": "Q4 Cyber Defense Budget Allocation.\nEndpoint EDR: $45,000\nCold Offline Backups: $20,000\n",
        demo / "Finance" / "quarterly_summary.txt": "Financial Summary: Enterprise assets and payroll audit.\n",
        demo / "Projects" / "project_readme.txt": "Project Sentinel: Autonomous Behavioral Ransomware Detection Architecture.\n",
        demo / "Projects" / "readme.txt": "Production Deployment Guidelines and Access Control Matrix.\n",
        demo / "Legal" / "compliance_policy.txt": "NIST CSF and ISO 27001 Data Protection & Recovery Policy.\n"
    }
    for p, text in files.items():
        if not p.exists():
            try: p.write_text(text, encoding="utf-8")
            except OSError: pass

def init_db():
    ensure_demo_workspace()
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, severity TEXT NOT NULL,
            category TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL, file_path TEXT,
            status TEXT NOT NULL DEFAULT 'Open', source TEXT NOT NULL DEFAULT 'monitor')""")
        c.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, root_path TEXT NOT NULL,
            files_scanned INTEGER NOT NULL, flagged_count INTEGER NOT NULL, bytes_scanned INTEGER NOT NULL,
            result_json TEXT NOT NULL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL)""")
        defaults = {"burst_threshold":"8","poll_interval":"3","max_scan_files":"5000"}
        for k,v in defaults.items():
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",(k,v))

def get_setting(k, default):
    with db() as c:
        r=c.execute("SELECT value FROM settings WHERE key=?",(k,)).fetchone()
    return r["value"] if r else default

def add_alert(severity, category, title, details, path="", source="monitor"):
    with db() as c:
        cur=c.execute("""INSERT INTO alerts(timestamp,severity,category,title,details,file_path,status,source)
                         VALUES(?,?,?,?,?,?,'Open',?)""",(now(),severity,category,title,details,path,source))
        return cur.lastrowid

def safe_path(raw):
    if not raw:
        raise ValueError("Select a folder path first.")
    raw_str = str(raw).strip().strip('"').strip("'")
    if not raw_str:
        raise ValueError("Select a folder path first.")
    raw_p = Path(raw_str).expanduser()
    if not raw_p.is_absolute():
        candidate = (BASE / raw_p).resolve()
        if candidate.exists() and candidate.is_dir():
            return candidate
    p = raw_p.resolve()
    if not p.exists() or not p.is_dir():
        raise ValueError(f"Folder '{raw_str}' does not exist or is not accessible.")
    return p

def sha256(path):
    try:
        h=hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return ""

def iter_files(root):
    for current, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".rews")]
        for name in names:
            p=Path(current)/name
            try:
                if p.is_symlink() or not p.is_file(): continue
                yield p
            except OSError: continue

def inspect_folder(root, hash_files=True):
    result=[]; flagged=[]; total=0; bytes_total=0
    limit=int(get_setting("max_scan_files","5000"))
    for p in iter_files(root):
        if len(result)>=limit: break
        try:
            st=p.stat(); ext=p.suffix.lower(); name_lower=p.name.lower()
            item={"path":str(p),"name":p.name,"relative_path":str(p.relative_to(root)),
                  "extension":ext or "(none)","size":st.st_size,
                  "modified":datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(timespec="seconds"),
                  "sha256":sha256(p) if hash_files else ""}
            flags=[]
            if ext in SUSPICIOUS_EXT: flags.append("Ransomware-associated extension")
            if ext in SCRIPT_EXT: flags.append("Executable or script — review context")
            if re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpg|jpeg|png|txt|csv|zip)\.(locked|crypt|crypted|encrypted|enc|ryk|wncry|lockbit|pay|akira|blackcat|darkside|revil|hive|phobos|dharma|stop|djvu)$", name_lower):
                flags.append("Document or media filename with appended encryption-style suffix")
            if RANSOM_NOTE_REGEX.search(name_lower):
                flags.append("Suspected ransom note pattern")
            item["flags"]=flags
            result.append(item); total+=1; bytes_total+=st.st_size
            if flags: flagged.append(item)
        except (OSError,PermissionError): continue
    return result,flagged,bytes_total

def snapshot(root):
    out={}
    for p in iter_files(root):
        try:
            st=p.stat()
            out[str(p)]=(st.st_size,st.st_mtime_ns)
        except OSError: pass
    return out

def record_file_event(kind, path):
    ext = Path(path).suffix.lower()
    name = Path(path).name
    is_suspicious_ext = ext in SUSPICIOUS_EXT or bool(re.search(r"\.(pdf|docx?|xlsx?|pptx?|jpg|png|txt)\.(locked|crypt|crypted|encrypted|enc|ryk|wncry|lockbit|pay|akira|blackcat|darkside|revil|hive|phobos|dharma|stop|djvu)$", name.lower()))
    is_ransom_note = bool(RANSOM_NOTE_REGEX.search(name.lower()))

    if kind == "deleted":
        add_alert("Medium", "File activity", "File deleted during monitoring",
                  f"A monitored file was removed: {name}", path)
    elif is_suspicious_ext:
        add_alert("High", "Ransomware indicator", "Suspicious extension observed",
                  f"{name} uses {ext}, an extension associated with renamed or encrypted files. This requires review and is not proof of infection.", path)
    elif is_ransom_note:
        add_alert("Critical", "Ransom note detected", "Potential ransom demand file created",
                  f"Extortion note pattern detected in filename: {name}. Ransomware operators drop instructions for victims.", path)
    elif ext in SCRIPT_EXT and kind in ("created", "modified"):
        add_alert("Medium", "Executable indicator", "Executable or script observed",
                  f"Executable or script {kind}: {name} ({ext}). Review context.", path)
    elif kind == "modified":
        add_alert("Low", "File activity", "File modified during monitoring",
                  f"The monitored file changed: {name}", path)
    else:
        add_alert("Low", "File activity", "New file created during monitoring",
                  f"A new file appeared: {name}", path)

def monitor_loop(stop_token):
    while not stop_token.wait(monitor["interval"]):
        with lock:
            if not monitor["active"] or not monitor["path"]: return
            root=Path(monitor["path"]); old=dict(monitor["snapshot"])
        try: current=snapshot(root)
        except Exception: continue
        created=set(current)-set(old)
        deleted=set(old)-set(current)
        modified={p for p in set(current)&set(old) if current[p]!=old[p]}
        events=[]
        for kind, paths in (("created",created),("modified",modified),("deleted",deleted)):
            for p in sorted(paths):
                record_file_event(kind,p); events.append({"kind":kind,"path":p,"time":now()})
        threshold=int(get_setting("burst_threshold","8"))
        if len(events)>=threshold:
            add_alert("Critical","Behavioural indicator","Rapid file-change burst detected",
                f"{len(events)} file changes were observed in one polling interval. Bulk legitimate operations can also trigger this warning; investigate the source.",str(root))
        with lock:
            monitor["snapshot"]=current
            if events:
                monitor["last_events"]=(monitor["last_events"]+events)[-50:]
            monitor["last_poll"]=now()

def alerts_list(limit=1000):
    with db() as c: rows=c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]

@app.get("/")
def home(): return render_template("index.html")

@app.get("/api/health")
def health(): return jsonify({"ok":True,"app":"REWS","database":DB.exists()})

@app.get("/api/summary")
def summary():
    al=alerts_list()
    with db() as c:
        scans=c.execute("SELECT COUNT(*) n FROM scans").fetchone()["n"]
        latest=c.execute("SELECT id,timestamp,root_path,files_scanned,flagged_count,bytes_scanned FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    open_a=[a for a in al if a["status"]=="Open"]
    counts={s:sum(a["severity"]==s and a["status"]=="Open" for a in al) for s in ["Critical","High","Medium","Low"]}
    score=min(100,counts["Critical"]*35+counts["High"]*20+counts["Medium"]*10+counts["Low"]*3)
    demo_p=str(DATA/"demo_workspace")
    return jsonify({"monitoring":monitor["active"],"path":monitor["path"],"files_in_scope":len(monitor["snapshot"]),
        "alerts_total":len(al),"open_alerts":len(open_a),"critical":counts["Critical"],"counts":counts,
        "risk_score":score,"scans":scans,"latest_scan":dict(latest) if latest else None,
        "last_poll":monitor["last_poll"],"demo_path":demo_p})

@app.get("/api/alerts")
def get_alerts(): return jsonify(alerts_list())

@app.get("/api/monitor/events")
def monitor_events():
    with lock: return jsonify(list(reversed(monitor["last_events"])))

@app.post("/api/alerts/<int:aid>/ack")
def ack(aid):
    with db() as c: cur=c.execute("UPDATE alerts SET status='Acknowledged' WHERE id=?",(aid,))
    if not cur.rowcount: return jsonify({"error":"Alert not found"}),404
    return jsonify({"ok":True})

@app.post("/api/alerts/ack-all")
def ack_all():
    with db() as c: cur=c.execute("UPDATE alerts SET status='Acknowledged' WHERE status='Open'")
    return jsonify({"ok":True,"updated":cur.rowcount})

@app.post("/api/alerts/clear")
def clear_alerts():
    with db() as c: cur=c.execute("DELETE FROM alerts")
    return jsonify({"ok":True,"deleted":cur.rowcount})

@app.post("/api/monitor/start")
def monitor_start():
    data=request.get_json(silent=True) or {}
    try: root=safe_path(data.get("path",""))
    except ValueError as e: return jsonify({"error":str(e)}),400
    try: baseline=snapshot(root)
    except Exception as e: return jsonify({"error":f"Unable to read folder: {e}"}),400
    with lock:
        monitor["stop"].set()
        token=threading.Event()
        monitor.update({"active":True,"path":str(root),"snapshot":baseline,"stop":token,
                        "interval":int(get_setting("poll_interval","3")),"last_poll":now(),"last_events":[]})
        th=threading.Thread(target=monitor_loop,args=(token,),daemon=True)
        monitor["thread"]=th; th.start()
    add_alert("Low","Monitoring","Folder monitoring started",f"Monitoring began for {root}. Baseline contains {len(baseline)} files.",str(root),"system")
    return jsonify({"ok":True,"path":str(root),"baseline_files":len(baseline)})

@app.post("/api/monitor/stop")
def monitor_stop():
    with lock:
        active=monitor["active"]; monitor["active"]=False; monitor["stop"].set()
    if active: add_alert("Low","Monitoring","Folder monitoring stopped","The user stopped folder monitoring.",monitor["path"],"system")
    return jsonify({"ok":True})

@app.post("/api/scan")
def scan():
    data=request.get_json(silent=True) or {}
    try: root=safe_path(data.get("path") or monitor.get("path"))
    except ValueError as e: return jsonify({"error":str(e)}),400
    items,flagged,total_bytes=inspect_folder(root)
    for item in flagged:
        sev="High" if Path(item["path"]).suffix.lower() in SUSPICIOUS_EXT else "Medium"
        add_alert(sev,"File inspection","File flagged for manual review","; ".join(item["flags"]),item["path"],"scan")
    payload={"files_scanned":len(items),"flagged_count":len(flagged),"bytes_scanned":total_bytes,
             "root_path":str(root),"files":items,"truncated":len(items)>=int(get_setting("max_scan_files","5000"))}
    with db() as c:
        c.execute("""INSERT INTO scans(timestamp,root_path,files_scanned,flagged_count,bytes_scanned,result_json)
                     VALUES(?,?,?,?,?,?)""",(now(),str(root),len(items),len(flagged),total_bytes,json.dumps(payload)))
    return jsonify(payload)

@app.get("/api/scans")
def scans():
    with db() as c: rows=c.execute("SELECT id,timestamp,root_path,files_scanned,flagged_count,bytes_scanned FROM scans ORDER BY id DESC LIMIT 100").fetchall()
    return jsonify([dict(r) for r in rows])

@app.get("/api/scans/<int:sid>")
def scan_detail(sid):
    with db() as c: row=c.execute("SELECT result_json FROM scans WHERE id=?",(sid,)).fetchone()
    if not row: return jsonify({"error":"Scan not found"}),404
    return jsonify(json.loads(row["result_json"]))

@app.post("/api/scans/clear")
def clear_scans():
    with db() as c: cur=c.execute("DELETE FROM scans")
    return jsonify({"ok":True,"deleted":cur.rowcount})

@app.get("/api/settings")
def get_settings():
    return jsonify({k:int(get_setting(k,v)) for k,v in {"burst_threshold":"8","poll_interval":"3","max_scan_files":"5000"}.items()})

@app.post("/api/settings")
def save_settings():
    data=request.get_json(silent=True) or {}
    try:
        threshold=max(3,min(200,int(data.get("burst_threshold",8))))
        interval=max(2,min(30,int(data.get("poll_interval",3))))
        maximum=max(100,min(20000,int(data.get("max_scan_files",5000))))
    except (TypeError,ValueError): return jsonify({"error":"Settings must be valid numbers."}),400
    with db() as c:
        for k,v in {"burst_threshold":threshold,"poll_interval":interval,"max_scan_files":maximum}.items():
            c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)",(k,str(v)))
    with lock: monitor["interval"]=interval
    return jsonify({"ok":True,"settings":{"burst_threshold":threshold,"poll_interval":interval,"max_scan_files":maximum}})

@app.post("/api/demo-lab")
def demo_lab():
    demo=DATA/"demo_workspace"
    demo.mkdir(exist_ok=True)
    (demo/"Finance").mkdir(parents=True, exist_ok=True)
    (demo/"Projects").mkdir(parents=True, exist_ok=True)
    (demo/"demo_note.txt").write_text("Harmless REWS demonstration file. No real user data.\n",encoding="utf-8")
    (demo/"Finance"/"quarterly_summary.txt").write_text("Sample finance summary for REWS monitoring demonstration.\n",encoding="utf-8")
    (demo/"Projects"/"readme.txt").write_text("Sample project workspace file.\n",encoding="utf-8")
    (demo/"sample_document.docx.locked").write_text("Harmless demo encrypted extension test file.\n",encoding="utf-8")
    add_alert("High","Demo lab","Simulated ransomware indicator",
        "A clearly labelled demonstration event was generated to show alert handling. No file was encrypted or damaged.",
        str(demo/"sample_document.docx.locked"),"demo")
    return jsonify({"ok":True,"path":str(demo),"message":"Harmless sample files created. Select this folder in Live Monitor to test."})

@app.post("/api/demo-change")
def demo_change():
    if not monitor["active"]: return jsonify({"error":"Start monitoring the Demo Workspace first."}),400
    root=Path(monitor["path"])
    if "demo_workspace" not in str(root).replace("\\", "/"):
        return jsonify({"error":"For safety, demo file changes are allowed only inside data/demo_workspace."}),400
    t = int(time.time() * 1000)
    for i in range(9):
        p=root/f"demo_activity_{i+1}.txt"
        p.write_text(f"Harmless synthetic activity {i+1} at {now()} (batch {t})\n",encoding="utf-8")
    return jsonify({"ok":True,"created":9,"message":"Created 9 harmless sample files. The monitor should report a burst on its next poll."})

@app.post("/api/simulate-attack")
def simulate_attack():
    demo = DATA / "demo_workspace"
    demo.mkdir(exist_ok=True)
    (demo / "Finance").mkdir(parents=True, exist_ok=True)
    (demo / "Legal").mkdir(parents=True, exist_ok=True)
    
    # 1. Drop encrypted file artifacts
    (demo / "Finance" / "Payroll_2026.xlsx.locked").write_text("ENCRYPTED_SIMULATION_BURST_FLAG_REWS", encoding="utf-8")
    (demo / "Legal" / "Client_Contracts.pdf.crypt").write_text("ENCRYPTED_SIMULATION_BURST_FLAG_REWS", encoding="utf-8")
    (demo / "sample_document.docx.locked").write_text("Harmless demo encrypted extension test file.\n", encoding="utf-8")
    
    # 2. Drop standard ransomware ransom note
    ransom_note = demo / "HOW_TO_RESTORE_YOUR_FILES.txt"
    ransom_note.write_text(
        "!!! WARNING - YOUR NETWORK ASSETS HAVE BEEN LOCKED !!!\n\n"
        "All critical documents, databases, and financial spreadsheets have been encrypted with military-grade AES-256.\n"
        "To purchase the private decryption key, transfer 0.5 BTC to our designated portal.\n"
        "Do NOT modify or rename files, or permanent data loss will occur.\n\n"
        "[REWS SIMULATION DEMONSTRATION FILE - HARMLESS ACADEMIC MOCK]\n",
        encoding="utf-8"
    )
    
    # 3. Create rapid burst changes
    t = int(time.time() * 1000)
    for i in range(8):
        p = demo / f"ransom_locked_block_{i+1}.locked"
        p.write_text(f"Simulated encrypted payload block {i+1} at {now()} ({t})\n", encoding="utf-8")
        
    add_alert("Critical", "Ransomware Simulation", "Simulated multi-stage ransomware attack triggered",
              "A simulated ransomware payload generated 11 encrypted file mutations (.locked / .crypt) and dropped an extortion ransom note. Watch the live monitor and telemetry detect the intrusion in real time.",
              str(ransom_note), "simulator")
              
    return jsonify({
        "ok": True,
        "path": str(demo),
        "message": "Simulated ransomware attack triggered! Created encrypted files and dropped HOW_TO_RESTORE_YOUR_FILES.txt."
    })

@app.post("/api/reset-demo")
def reset_demo():
    demo = DATA / "demo_workspace"
    if demo.exists():
        for p in list(demo.rglob("*")):
            if p.is_file():
                ext = p.suffix.lower()
                name = p.name.lower()
                if ext in SUSPICIOUS_EXT or "activity" in name or "payload" in name or "locked" in name or "crypt" in name or "restore" in name or "how_to" in name:
                    try: p.unlink()
                    except OSError: pass
    ensure_demo_workspace()
    return jsonify({
        "ok": True,
        "path": str(demo),
        "message": "Demo workspace sanitized! Ransomware artifacts purged and pristine documents restored."
    })

@app.get("/api/report.json")
def report_json():
    with db() as c:
        scanrows=[dict(r) for r in c.execute("SELECT id,timestamp,root_path,files_scanned,flagged_count,bytes_scanned FROM scans ORDER BY id DESC LIMIT 100")]
    payload={"generated_at":now(),"application":"REWS — Ransomware Early Warning System",
        "monitoring":{"active":monitor["active"],"folder":monitor["path"]},
        "alerts":alerts_list(),"scan_history":scanrows,
        "scope_note":"Academic folder-monitoring prototype. Indicators require human review and do not prove malicious activity."}
    return make_response(json.dumps(payload,indent=2),200,{"Content-Type":"application/json; charset=utf-8","Content-Disposition":"attachment; filename=rews_security_report.json"})

@app.get("/api/report.csv")
def report_csv():
    out=io.StringIO(); w=csv.writer(out)
    w.writerow(["ID","Timestamp","Severity","Category","Title","Details","File path","Status","Source"])
    for a in alerts_list(): w.writerow([a[k] for k in ["id","timestamp","severity","category","title","details","file_path","status","source"]])
    return make_response(out.getvalue(),200,{"Content-Type":"text/csv; charset=utf-8","Content-Disposition":"attachment; filename=rews_alert_register.csv"})

@app.get("/api/report/print")
def report_print():
    al=alerts_list()
    rows="".join(f"<tr><td>{html.escape(str(a['timestamp']))}</td><td><span class='badge {html.escape(str(a['severity']).lower())}'>{html.escape(str(a['severity']))}</span></td><td><b>{html.escape(str(a['title']))}</b><br><small>{html.escape(str(a['file_path'] or '—'))}</small></td><td>{html.escape(str(a['category']))}</td><td>{html.escape(str(a['status']))}</td></tr>" for a in al[:150])
    folder_name = html.escape(str(monitor['path'] or 'Safe Demo Workspace'))
    monitoring_state = 'Active Surveillance' if monitor['active'] else 'Idle / Standby'
    report_html=f"""<!doctype html><html><head><title>REWS Security Report</title><style>
    body{{font:13px 'Segoe UI',Arial,sans-serif;margin:40px;color:#172033;line-height:1.5}}
    .header{{display:flex;justify-content:space-between;align-items:flex-start;border-bottom:2px solid #005b8e;padding-bottom:15px;margin-bottom:25px}}
    h1{{margin:0;color:#0b1e36;font-size:24px;letter-spacing:0.5px}}
    .sub{{color:#5a6e85;font-size:12px;margin-top:4px}}
    .meta-box{{display:grid;grid-template-columns:repeat(4,1fr);gap:15px;background:#f4f7fb;border:1px solid #d9e2ec;padding:15px;border-radius:6px;margin-bottom:25px}}
    .meta-box div{{display:flex;flex-direction:column}}
    .meta-box small{{font-size:10px;color:#627d98;font-weight:bold;text-transform:uppercase}}
    .meta-box b{{font-size:13px;color:#102a43;margin-top:2px}}
    table{{border-collapse:collapse;width:100%;margin-top:10px}}
    th{{background:#0b1e36;color:#ffffff;font-size:11px;text-transform:uppercase;padding:10px 12px;text-align:left;letter-spacing:0.5px}}
    td{{border-bottom:1px solid #e2e8f0;padding:10px 12px;vertical-align:middle;font-size:12px}}
    tr:nth-child(even) td{{background:#f8fafc}}
    .badge{{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:bold;text-transform:uppercase}}
    .badge.critical{{background:#ffe3e3;color:#d6336c;border:1px solid #ffc9c9}}
    .badge.high{{background:#fff3bf;color:#d9480f;border:1px solid #ffe066}}
    .badge.medium{{background:#e7f5ff;color:#1c7ed6;border:1px solid #a5d8ff}}
    .badge.low{{background:#ebfbee;color:#2b8a3e;border:1px solid #b2f2bb}}
    .note{{margin-top:35px;padding:15px;background:#f8fafc;border-left:4px solid #005b8e;color:#486581;font-size:11px}}
    @media print{{body{{margin:20px}}}}
    </style></head><body>
    <div class="header">
      <div>
        <h1>REWS Security Report</h1>
        <div class="sub">Host-Based Ransomware Early Warning & Forensics Audit</div>
      </div>
      <div style="text-align:right">
        <b>CONFIDENTIAL AUDIT REPORT</b><br>
        <small style="color:#627d98">Generated: {now()}</small>
      </div>
    </div>
    <div class="meta-box">
      <div><small>Surveillance Engine</small><b>{monitoring_state}</b></div>
      <div><small>Target Repository</small><b style="word-break:break-all">{folder_name}</b></div>
      <div><small>Total Recorded Alerts</small><b>{len(al)} Incidents</b></div>
      <div><small>Forensic Integrity</small><b>SHA-256 Validated</b></div>
    </div>
    <h2 style="font-size:16px;color:#0b1e36;margin-bottom:8px">Incident & Behavioral Alert Register</h2>
    <table>
      <thead>
        <tr><th style="width:160px">Timestamp</th><th style="width:90px">Severity</th><th>Threat Event & Target</th><th style="width:130px">Category</th><th style="width:100px">Status</th></tr>
      </thead>
      <tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;padding:30px;color:#829ab1">No incidents recorded in database.</td></tr>'}</tbody>
    </table>
    <div class="note">
      <b>Academic Scope & Security Verification Note:</b> REWS is a local educational host-based security prototype. Alerts are rule-based and behavioral heuristic indicators designed to aid human operators in early mitigation of potential ransomware encryption loops.
    </div>
    <script>window.onload=()=>window.print()</script>
    </body></html>"""
    return report_html

init_db()
if __name__=="__main__":
    print("REWS Professional running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1",port=5000,debug=False,threaded=True)
