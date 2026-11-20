/* ==========================================================================
   REWS // SENTINEL-X - CYBER THREAT OPERATIONS CLIENT LOGIC
   ========================================================================== */

const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];

let alertsCache = [], filesCache = [], summaryCache = {};
const viewNames = {
  overview: "Command Center",
  monitor: "Live Monitor",
  inventory: "File Inventory",
  alerts: "Security Alerts",
  history: "Scan History",
  guide: "Threat Guide",
  reports: "Forensic Reports",
  settings: "Heuristic Settings"
};

let toastTimer;
function toast(msg, type = "ok") {
  const t = $("#toast");
  if (!t) return;
  t.textContent = msg;
  t.className = "toast show " + (type === "error" ? "error" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = "toast"; }, 3600);
}

// ==========================================================================
// CYBER AUDIO SYNTHESIZER (Web Audio API - Zero External Files)
// ==========================================================================
let audioEnabled = localStorage.getItem("rews_sfx") !== "false";
let audioCtx = null;

function getAudioContext() {
  if (!audioCtx) {
    const AudioContext = window.AudioContext || window.webkitAudioContext;
    if (AudioContext) audioCtx = new AudioContext();
  }
  if (audioCtx && audioCtx.state === "suspended") {
    audioCtx.resume();
  }
  return audioCtx;
}

function playCyberSound(type = "click") {
  if (!audioEnabled) return;
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    const now = ctx.currentTime;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === "click") {
      osc.type = "sine";
      osc.frequency.setValueAtTime(800, now);
      osc.frequency.exponentialRampToValueAtTime(400, now + 0.05);
      gain.gain.setValueAtTime(0.04, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
      osc.start(now);
      osc.stop(now + 0.05);
    } else if (type === "alert") {
      osc.type = "sawtooth";
      osc.frequency.setValueAtTime(880, now);
      osc.frequency.setValueAtTime(659, now + 0.08);
      gain.gain.setValueAtTime(0.08, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.22);
      osc.start(now);
      osc.stop(now + 0.22);
    } else if (type === "scan") {
      osc.type = "sine";
      osc.frequency.setValueAtTime(300, now);
      osc.frequency.exponentialRampToValueAtTime(1200, now + 0.18);
      gain.gain.setValueAtTime(0.05, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.2);
      osc.start(now);
      osc.stop(now + 0.2);
    } else if (type === "success") {
      osc.type = "triangle";
      osc.frequency.setValueAtTime(523, now);
      osc.frequency.setValueAtTime(659, now + 0.07);
      osc.frequency.setValueAtTime(783, now + 0.14);
      gain.gain.setValueAtTime(0.05, now);
      gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
      osc.start(now);
      osc.stop(now + 0.25);
    }
  } catch (e) {
    // Audio context not allowed until user interaction
  }
}

function updateSoundButton() {
  const btn = $("#soundToggle");
  const icon = $("#soundIcon");
  if (!btn || !icon) return;
  icon.textContent = audioEnabled ? "🔊" : "🔇";
  btn.title = audioEnabled ? "Audio SFX: ON (Click to mute)" : "Audio SFX: MUTED (Click to unmute)";
}

// ==========================================================================
// CORE API HELPERS
// ==========================================================================
async function api(url, opts = {}) {
  const r = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...opts
  });
  let data;
  try { data = await r.json(); } catch { data = {}; }
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}

function fmtSize(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

function shortTime(s) {
  if (!s) return "—";
  return new Date(s).toLocaleString();
}

function sev(s) {
  return `<span class="severity ${s.toLowerCase()}">${s}</span>`;
}

function status(s) {
  return `<span class="status-text ${s.toLowerCase()}">${s}</span>`;
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ==========================================================================
// NAVIGATION
// ==========================================================================
function navigate(view) {
  if (!viewNames[view]) return;
  playCyberSound("click");
  $$(".view").forEach(v => v.classList.toggle("active", v.id === `view-${view}`));
  $$(".nav-item").forEach(b => b.classList.toggle("active", b.dataset.view === view));
  if ($("#crumbTitle")) $("#crumbTitle").textContent = viewNames[view];
  if ($("#sidebar")) $("#sidebar").classList.remove("open");
  history.replaceState(null, "", `#${view}`);

  if (view === "alerts") renderAlerts();
  if (view === "history") loadHistory();
  if (view === "settings") loadSettings();
  if (view === "inventory" && summaryCache.path) {
    if ($("#scanPath")) $("#scanPath").value = summaryCache.path;
  }
  window.scrollTo({ top: 0, behavior: "instant" });
}

// Register Listeners
$$(".nav-item").forEach(b => b.addEventListener("click", () => navigate(b.dataset.view)));
$$("[data-go]").forEach(b => b.addEventListener("click", () => navigate(b.dataset.go)));
$("#menuBtn")?.addEventListener("click", () => $("#sidebar")?.classList.toggle("open"));
$("#refreshBtn")?.addEventListener("click", () => { playCyberSound("click"); refreshAll(); });
$("#soundToggle")?.addEventListener("click", () => {
  audioEnabled = !audioEnabled;
  localStorage.setItem("rews_sfx", audioEnabled ? "true" : "false");
  updateSoundButton();
  if (audioEnabled) playCyberSound("success");
});

$("#overviewStop")?.addEventListener("click", stopMonitor);
$("#startMonitor")?.addEventListener("click", startMonitor);
$("#stopMonitor")?.addEventListener("click", stopMonitor);
$("#runScan")?.addEventListener("click", runScan);
$("#fileSearch")?.addEventListener("input", renderFiles);
$("#alertSearch")?.addEventListener("input", renderAlerts);
$("#severityFilter")?.addEventListener("change", renderAlerts);
$("#statusFilter")?.addEventListener("change", renderAlerts);
$("#ackAll")?.addEventListener("click", ackAll);
$("#clearAlerts")?.addEventListener("click", clearAlerts);
$("#clearHistory")?.addEventListener("click", clearHistory);

function fillDefaultDemo() {
  const p = summaryCache.demo_path || "";
  if (p) {
    if ($("#monitorPath")) $("#monitorPath").value = p;
    if ($("#scanPath")) $("#scanPath").value = p;
    updateScopeBanner(p);
  }
}

$("#fillDemoMonitor")?.addEventListener("click", fillDefaultDemo);
$("#fillDemoScan")?.addEventListener("click", fillDefaultDemo);
$("#bannerUseDemo")?.addEventListener("click", () => { fillDefaultDemo(); toast("Loaded Safe Demo Workspace"); playCyberSound("click"); });

$("#closeDetail")?.addEventListener("click", () => $("#alertDetail")?.classList.add("hidden"));
$("#closeHistory")?.addEventListener("click", () => $("#historyDetail")?.classList.add("hidden"));

// Demo & Red Team Simulation
$("#demoChange")?.addEventListener("click", demoChange);
$("#quickDemoChange")?.addEventListener("click", demoChange);
$("#quickDemo")?.addEventListener("click", demoLab);

async function triggerSimulateAttack() {
  playCyberSound("alert");
  try {
    const r = await api("/api/simulate-attack", { method: "POST", body: "{}" });
    toast(r.message, "error");
    if ($("#monitorPath") && !$("#monitorPath").value) $("#monitorPath").value = r.path;
    if ($("#scanPath") && !$("#scanPath").value) $("#scanPath").value = r.path;
    await refreshAll();
    setTimeout(poll, 1000);
    setTimeout(poll, 3000);
  } catch (e) {
    toast(e.message, "error");
  }
}

async function triggerResetDemo() {
  playCyberSound("success");
  try {
    const r = await api("/api/reset-demo", { method: "POST", body: "{}" });
    toast(r.message);
    await refreshAll();
  } catch (e) {
    toast(e.message, "error");
  }
}

$("#quickSimulateAttack")?.addEventListener("click", triggerSimulateAttack);
$("#monitorSimulateAttack")?.addEventListener("click", triggerSimulateAttack);
$("#bannerSimulate")?.addEventListener("click", triggerSimulateAttack);

$("#quickResetLab")?.addEventListener("click", triggerResetDemo);
$("#monitorResetDemo")?.addEventListener("click", triggerResetDemo);

$("#saveSettings")?.addEventListener("click", saveSettings);
$("#scanPath")?.addEventListener("keydown", e => { if (e.key === "Enter") runScan(); });
window.addEventListener("hashchange", () => {
  const v = location.hash.slice(1);
  if (viewNames[v]) navigate(v);
});

function updateScopeBanner(p) {
  const el = $("#scopeBannerPath");
  if (el) {
    el.textContent = p ? p : "No folder locked in yet. Click 'Use Safe Demo Folder' or input path below.";
  }
}

// ==========================================================================
// REFRESH & TELEMETRY
// ==========================================================================
async function refreshAll() {
  try {
    const [s, a] = await Promise.all([api("/api/summary"), api("/api/alerts")]);
    summaryCache = s;
    alertsCache = a;

    const conn = $("#connection");
    if (conn) conn.textContent = "CONNECTED // HOST ONLINE";
    const connDot = $("#connDot");
    if (connDot) connDot.style.background = "var(--neon-green)";

    // Update Banner & Inputs if blank
    const activeOrDemo = s.path || s.demo_path;
    updateScopeBanner(activeOrDemo);
    if (!$("#monitorPath")?.value && activeOrDemo) $("#monitorPath").value = activeOrDemo;
    if (!$("#scanPath")?.value && activeOrDemo) $("#scanPath").value = activeOrDemo;

    // Metrics
    if ($("#mFiles")) $("#mFiles").textContent = s.files_in_scope.toLocaleString();
    if ($("#mScope")) $("#mScope").textContent = s.path ? s.path : "Safe Demo Workspace Ready";
    if ($("#mOpen")) $("#mOpen").textContent = s.open_alerts;
    if ($("#mCritical")) $("#mCritical").textContent = s.critical;
    if ($("#mRisk")) $("#mRisk").textContent = s.risk_score;
    if ($("#navAlertCount")) $("#navAlertCount").textContent = s.open_alerts;

    // Threat Level Badge & DEFCON
    const tBadge = $("#threatLevelBadge");
    const tBar = $("#threatBarFill");
    if (tBadge) {
      if (s.risk_score >= 75 || s.critical > 0) {
        tBadge.textContent = "DEFCON 1 // CRITICAL BREACH";
        tBadge.className = "threat-level critical";
      } else if (s.risk_score >= 45) {
        tBadge.textContent = "DEFCON 2 // HIGH RISK ALERT";
        tBadge.className = "threat-level critical";
      } else if (s.risk_score >= 20) {
        tBadge.textContent = "DEFCON 3 // GUARDED ALERT";
        tBadge.className = "threat-level";
      } else {
        tBadge.textContent = "DEFCON 5 // NORMAL POSTURE";
        tBadge.className = "threat-level";
      }
    }
    if (tBar) {
      tBar.style.width = Math.min(100, Math.max(8, s.risk_score)) + "%";
    }

    // Monitoring Status
    const isMon = !!s.monitoring;
    if ($("#navLive")) $("#navLive").classList.toggle("visible", isMon);
    if ($("#topState")) $("#topState").textContent = isMon ? "SURVEILLANCE ACTIVE" : "MONITORING STOPPED";
    if ($("#topStateDot")) $("#topStateDot").classList.toggle("active", isMon);
    if ($("#survState")) {
      $("#survState").textContent = isMon ? "ARMED" : "IDLE";
      $("#survState").className = isMon ? "neon-green" : "neon-amber";
    }

    if ($("#overviewStatus")) {
      $("#overviewStatus").textContent = isMon ? "ARMED" : "STOPPED";
      $("#overviewStatus").className = "status-chip " + (isMon ? "running" : "stopped");
    }
    if ($("#monitorPageStatus")) {
      $("#monitorPageStatus").textContent = isMon ? "ARMED" : "STOPPED";
      $("#monitorPageStatus").className = "status-chip " + (isMon ? "running" : "stopped");
    }

    // Radar Animation Control
    const sweep = $("#radarSweep");
    if (sweep) {
      sweep.style.animationPlayState = isMon ? "running" : "paused";
      sweep.style.opacity = isMon ? "1" : "0.3";
    }

    if ($("#monitorEmpty")) $("#monitorEmpty").classList.toggle("hidden", isMon);
    if ($("#monitorActive")) $("#monitorActive").classList.toggle("hidden", !isMon);

    if ($("#activePath")) $("#activePath").textContent = s.path || "—";
    if ($("#activeFiles")) $("#activeFiles").textContent = s.files_in_scope;
    if ($("#lastPoll")) $("#lastPoll").textContent = shortTime(s.last_poll);
    if ($("#monFiles")) $("#monFiles").textContent = s.files_in_scope;
    if ($("#monLastPoll")) $("#monLastPoll").textContent = shortTime(s.last_poll);

    if ($("#startMonitor")) $("#startMonitor").disabled = isMon;
    if ($("#stopMonitor")) $("#stopMonitor").disabled = !isMon;

    // Ticker Text
    const ticker = $("#telemetryTicker");
    if (ticker) {
      ticker.textContent = isMon 
        ? `DAEMON ACTIVE ON ${s.path} · SAMPLING EVERY ${s.polling_interval || 3}s · ASSETS: ${s.files_in_scope}`
        : "HEURISTIC ENGINES ARMED · REAL-TIME VELOCITY SENTINEL READY";
    }

    // Donut Chart
    const c = s.counts || {};
    ["Critical", "High", "Medium", "Low"].forEach(k => {
      const el = $("#c" + k);
      if (el) el.textContent = c[k] || 0;
    });
    if ($("#donutTotal")) $("#donutTotal").textContent = s.open_alerts;

    const vals = [c.Critical || 0, c.High || 0, c.Medium || 0, c.Low || 0];
    const total = vals.reduce((x, y) => x + y, 0) || 1;
    const colors = ["#ff0055", "#ffb703", "#3b82f6", "#00ff88"];
    const donutEl = $("#donut");
    if (donutEl) {
      if (s.open_alerts === 0) {
        donutEl.style.background = "#14233c";
      } else {
        let grad = [], pos = 0;
        vals.forEach((v, i) => {
          if (v > 0) {
            const end = pos + (v / total) * 100;
            grad.push(`${colors[i]} ${pos}% ${end}%`);
            pos = end;
          }
        });
        donutEl.style.background = `conic-gradient(${grad.join(",")})`;
      }
    }

    renderRecent();
    renderAlerts();
    renderEvents();
  } catch (e) {
    const conn = $("#connection");
    if (conn) conn.textContent = "DISCONNECTED // HOST OFFLINE";
    const connDot = $("#connDot");
    if (connDot) connDot.style.background = "var(--neon-red)";
    toast(e.message, "error");
  }
}

// ==========================================================================
// RENDERERS
// ==========================================================================
function renderRecent() {
  const el = $("#recentRows");
  if (!el) return;
  const rows = alertsCache.slice(0, 5);
  el.innerHTML = rows.length ? rows.map(a => `
    <tr>
      <td>
        <b>${escapeHtml(a.title)}</b>
        <small class="cell-sub">${escapeHtml(a.file_path || "—")}</small>
      </td>
      <td><span class="code-tag">${escapeHtml(a.category)}</span></td>
      <td>${sev(a.severity)}</td>
      <td><span class="cell-sub">${shortTime(a.timestamp)}</span></td>
      <td>${status(a.status)}</td>
    </tr>
  `).join("") : `<tr><td colspan="5" class="empty">No events recorded. Start surveillance or run the Red Team Attack Simulator.</td></tr>`;
}

function renderAlerts() {
  const el = $("#alertRows");
  if (!el) return;
  const q = ($("#alertSearch")?.value || "").toLowerCase();
  const sv = $("#severityFilter")?.value || "all";
  const st = $("#statusFilter")?.value || "all";

  const rows = alertsCache.filter(a =>
    (sv === "all" || a.severity === sv) &&
    (st === "all" || a.status === st) &&
    [a.title, a.category, a.details, a.file_path].join(" ").toLowerCase().includes(q)
  );

  el.innerHTML = rows.length ? rows.map(a => `
    <tr>
      <td>
        <b>#${a.id}</b>
        <small class="cell-sub">${shortTime(a.timestamp)}</small>
      </td>
      <td>
        <button class="link-button" data-detail="${a.id}">${escapeHtml(a.title)}</button>
        <small class="cell-sub">${escapeHtml(a.source)}</small>
      </td>
      <td><span class="code-tag">${escapeHtml(a.category)}</span></td>
      <td>${sev(a.severity)}</td>
      <td>${status(a.status)}</td>
      <td>
        ${a.status === "Open" ? `<button class="table-action" data-ack="${a.id}">Acknowledge</button>` : "—"}
      </td>
    </tr>
  `).join("") : `<tr><td colspan="6" class="empty">No security alerts match query filters.</td></tr>`;

  $$("[data-ack]").forEach(b => b.addEventListener("click", () => ackOne(b.dataset.ack)));
  $$("[data-detail]").forEach(b => b.addEventListener("click", () => showAlert(+b.dataset.detail)));
}

async function showAlert(id) {
  playCyberSound("click");
  const a = alertsCache.find(x => x.id === id);
  if (!a) return;
  $("#alertDetail")?.classList.remove("hidden");
  if ($("#detailTitle")) $("#detailTitle").textContent = a.title;
  if ($("#detailSub")) $("#detailSub").textContent = `INCIDENT #${a.id} · SEVERITY: ${a.severity.toUpperCase()} · ${shortTime(a.timestamp)}`;
  if ($("#detailText")) $("#detailText").textContent = a.details;
  if ($("#detailPath")) $("#detailPath").textContent = a.file_path || "No file target recorded";
  $("#alertDetail")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function ackOne(id) {
  try {
    await api(`/api/alerts/${id}/ack`, { method: "POST", body: "{}" });
    playCyberSound("success");
    toast("Incident marked as acknowledged");
    await refreshAll();
  } catch (e) {
    toast(e.message, "error");
  }
}

async function ackAll() {
  try {
    const r = await api("/api/alerts/ack-all", { method: "POST", body: "{}" });
    playCyberSound("success");
    toast(`${r.updated} incident alerts acknowledged`);
    await refreshAll();
  } catch (e) {
    toast(e.message, "error");
  }
}

async function clearAlerts() {
  try {
    const r = await api("/api/alerts/clear", { method: "POST", body: "{}" });
    playCyberSound("click");
    toast(`Purged ${r.deleted} alerts from database`);
    await refreshAll();
  } catch (e) {
    toast(e.message, "error");
  }
}

// ==========================================================================
// MONITOR CONTROLS
// ==========================================================================
async function startMonitor() {
  playCyberSound("click");
  const path = $("#monitorPath")?.value.trim() || summaryCache.demo_path;
  if (!path) {
    toast("Specify a target folder path to monitor", "error");
    return;
  }
  try {
    const r = await api("/api/monitor/start", {
      method: "POST",
      body: JSON.stringify({ path })
    });
    playCyberSound("success");
    toast(`Surveillance Armed · ${r.baseline_files} Baseline Files Registered`);
    await refreshAll();
    navigate("monitor");
  } catch (e) {
    toast(e.message, "error");
  }
}

async function stopMonitor() {
  playCyberSound("click");
  try {
    await api("/api/monitor/stop", { method: "POST", body: "{}" });
    toast("Surveillance daemon disarmed");
    await refreshAll();
  } catch (e) {
    toast(e.message, "error");
  }
}

// ==========================================================================
// SCAN & FORENSICS
// ==========================================================================
async function runScan() {
  const path = $("#scanPath")?.value.trim() || summaryCache.path || summaryCache.demo_path;
  if (!path) {
    toast("Specify a target folder path to scan", "error");
    return;
  }
  const scanBtn = $("#runScan");
  if (scanBtn) {
    scanBtn.disabled = true;
    scanBtn.textContent = "Auditing Inodes...";
  }
  playCyberSound("scan");

  try {
    const r = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({ path })
    });
    filesCache = r.files || [];
    if ($("#scanFiles")) $("#scanFiles").textContent = r.files_scanned;
    if ($("#scanFlagged")) $("#scanFlagged").textContent = r.flagged_count;
    if ($("#scanSize")) $("#scanSize").textContent = fmtSize(r.bytes_scanned);
    if ($("#scanResultCaption")) {
      $("#scanResultCaption").textContent = `${r.root_path} · ${r.truncated ? "Index capped" : "Verification completed"} · ${shortTime(new Date().toISOString())}`;
    }
    renderFiles();
    playCyberSound("success");
    toast(`Scan Complete · ${r.files_scanned} files hashed & audited`);
    await refreshAll();
  } catch (e) {
    toast(e.message, "error");
  } finally {
    if (scanBtn) {
      scanBtn.disabled = false;
      scanBtn.textContent = "Run Deep Inspection";
    }
  }
}

function renderFiles() {
  const el = $("#fileRows");
  if (!el) return;
  const q = ($("#fileSearch")?.value || "").toLowerCase();
  const rows = filesCache.filter(f =>
    (f.name + " " + f.relative_path + " " + f.extension).toLowerCase().includes(q)
  );

  el.innerHTML = rows.length ? rows.map(f => `
    <tr>
      <td>
        <b>${escapeHtml(f.name)}</b>
        <small class="cell-sub">${escapeHtml(f.extension)}</small>
      </td>
      <td><span class="cell-sub">${escapeHtml(f.relative_path)}</span></td>
      <td>${fmtSize(f.size)}</td>
      <td>
        <code class="hash">${f.sha256 ? escapeHtml(f.sha256.slice(0, 18)) + "…" : "Unavailable"}</code>
        <button class="copy-hash" data-copy="${f.sha256 || ""}" ${!f.sha256 ? "disabled" : ""}>Copy</button>
      </td>
      <td>
        ${f.flags && f.flags.length 
          ? `<span class="flagged">ANOMALY</span><small class="cell-sub">${escapeHtml(f.flags.join("; "))}</small>` 
          : `<span class="clean">VERIFIED CLEAN</span>`}
      </td>
    </tr>
  `).join("") : `<tr><td colspan="5" class="empty">No files match search filters.</td></tr>`;

  $$("[data-copy]").forEach(b => b.addEventListener("click", async () => {
    const text = b.dataset.copy || "";
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      playCyberSound("click");
      toast("SHA-256 copied to clipboard");
    } catch {
      toast("Clipboard access denied", "error");
    }
  }));
}

// ==========================================================================
// HISTORY
// ==========================================================================
async function loadHistory() {
  try {
    const rows = await api("/api/scans");
    const el = $("#historyRows");
    if (!el) return;
    el.innerHTML = rows.length ? rows.map(s => `
      <tr>
        <td><b>#${s.id}</b></td>
        <td><small class="cell-sub">${shortTime(s.timestamp)}</small></td>
        <td class="path-cell"><code class="code-tag">${escapeHtml(s.root_path)}</code></td>
        <td><b>${s.files_scanned}</b></td>
        <td><span class="${s.flagged_count > 0 ? "flagged" : "clean"}">${s.flagged_count}</span></td>
        <td>${fmtSize(s.bytes_scanned)}</td>
        <td><button class="table-action" data-scan="${s.id}">Forensics</button></td>
      </tr>
    `).join("") : `<tr><td colspan="7" class="empty">No historical inspection audits recorded.</td></tr>`;

    $$("[data-scan]").forEach(b => b.addEventListener("click", () => showScan(+b.dataset.scan)));
  } catch (e) {
    toast(e.message, "error");
  }
}

async function clearHistory() {
  try {
    const r = await api("/api/scans/clear", { method: "POST", body: "{}" });
    toast(`Purged ${r.deleted} historical scans`);
    $("#historyDetail")?.classList.add("hidden");
    await loadHistory();
  } catch (e) {
    toast(e.message, "error");
  }
}

async function showScan(id) {
  playCyberSound("click");
  try {
    const r = await api(`/api/scans/${id}`);
    $("#historyDetail")?.classList.remove("hidden");
    if ($("#historyCaption")) {
      $("#historyCaption").textContent = `${r.root_path} · ${r.files_scanned} objects · ${r.flagged_count} flagged`;
    }
    const hFiles = $("#historyFiles");
    if (hFiles) {
      hFiles.innerHTML = (r.files || []).map(f => {
        const hash = f.sha256 ? `${escapeHtml(f.sha256.slice(0, 20))}…` : "Unavailable";
        const flags = (f.flags && f.flags.length) ? escapeHtml(f.flags.join("; ")) : "—";
        return `
          <tr>
            <td>${escapeHtml(f.relative_path)}</td>
            <td>${fmtSize(f.size)}</td>
            <td><code class="hash">${hash}</code></td>
            <td>${flags !== "—" ? `<span class="flagged">${flags}</span>` : `<span class="clean">Nominal</span>`}</td>
          </tr>
        `;
      }).join("");
    }
    $("#historyDetail")?.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    toast(e.message, "error");
  }
}

// ==========================================================================
// LIVE INODE CONSOLE STREAM
// ==========================================================================
let monitorEvents = [];
function renderEvents() {
  const el = $("#liveEvents");
  if (!el) return;
  const isMon = summaryCache.monitoring;

  if (isMon && monitorEvents.length) {
    el.innerHTML = monitorEvents.map(x => `
      <div class="feed-item">
        <span class="feed-symbol ${x.kind}">${x.kind === "created" ? "＋" : x.kind === "deleted" ? "−" : "↻"}</span>
        <div>
          <b>[INODE_${x.kind.toUpperCase()}]</b>
          <p>${escapeHtml(x.path)}</p>
        </div>
        <small>${shortTime(x.time)}</small>
      </div>
    `).join("");
  } else if (isMon) {
    el.innerHTML = `<div class="empty-state">Surveillance armed. Listening for filesystem mutations in target repository...</div>`;
  } else {
    el.innerHTML = `<div class="empty-state">No file events observed yet. Start monitoring and make changes in the target directory.</div>`;
  }
}

// ==========================================================================
// DEMO LAB & SETTINGS
// ==========================================================================
async function demoLab() {
  playCyberSound("click");
  try {
    const r = await api("/api/demo-lab", { method: "POST", body: "{}" });
    toast(r.message);
    if ($("#monitorPath")) $("#monitorPath").value = r.path;
    if ($("#scanPath")) $("#scanPath").value = r.path;
    updateScopeBanner(r.path);
    await refreshAll();
    navigate("monitor");
  } catch (e) {
    toast(e.message, "error");
  }
}

async function demoChange() {
  playCyberSound("alert");
  try {
    const r = await api("/api/demo-change", { method: "POST", body: "{}" });
    toast(r.message);
    setTimeout(poll, 1000);
    setTimeout(poll, 3000);
  } catch (e) {
    toast(e.message, "error");
  }
}

async function loadSettings() {
  try {
    const s = await api("/api/settings");
    if ($("#thresholdSetting")) $("#thresholdSetting").value = s.burst_threshold;
    if ($("#intervalSetting")) $("#intervalSetting").value = String(s.poll_interval);
    if ($("#maxFilesSetting")) $("#maxFilesSetting").value = String(s.max_scan_files);
  } catch (e) {
    toast(e.message, "error");
  }
}

async function saveSettings() {
  playCyberSound("click");
  try {
    const t = $("#thresholdSetting")?.value;
    const i = $("#intervalSetting")?.value;
    const m = $("#maxFilesSetting")?.value;
    await api("/api/settings", {
      method: "POST",
      body: JSON.stringify({ burst_threshold: t, poll_interval: i, max_scan_files: m })
    });
    if ($("#settingsMessage")) $("#settingsMessage").textContent = "Heuristic configuration committed to SQLite.";
    if ($("#monInterval")) $("#monInterval").textContent = i + " sec";
    if ($("#activeInterval")) $("#activeInterval").textContent = i + " sec";
    playCyberSound("success");
    toast("Heuristic parameters updated");
  } catch (e) {
    toast(e.message, "error");
  }
}

async function poll() {
  try {
    monitorEvents = await api("/api/monitor/events");
    await refreshAll();
  } catch {}
}

// ==========================================================================
// INITIALIZATION
// ==========================================================================
async function init() {
  updateSoundButton();
  const health = await api("/api/health");
  if (health.ok) {
    await refreshAll();
    if (location.hash && viewNames[location.hash.slice(1)]) {
      navigate(location.hash.slice(1));
    }
  }
  setInterval(poll, 3000);
  setInterval(async () => {
    if ($("#view-history")?.classList.contains("active")) loadHistory();
  }, 10000);
}

init().catch(e => toast(e.message, "error"));
