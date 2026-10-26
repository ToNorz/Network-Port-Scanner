const PRESETS = {
  common: "21,22,23,25,53,80,110,139,143,443,445,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017",
  wellknown: "1-1024",
  sensitive: "21,22,23,25,69,80,110,111,135,139,143,445,512,513,514,1433,1521,2049,2375,3306,3389,5432,5900,6379,9200,11211,27017",
  all: "1-65535",
};

const PREFS_KEY = "port-scanner-prefs";

const form = document.querySelector("#scan-form");
const hostEl = document.querySelector("#host");
const portsEl = document.querySelector("#ports");
const threadsEl = document.querySelector("#threads");
const timeoutEl = document.querySelector("#timeout");
const scanBtn = document.querySelector("#scan");
const errorEl = document.querySelector("#error");
const statusEl = document.querySelector("#status");
const detailEl = document.querySelector("#detail");
const progressEl = document.querySelector("#progress");
const barEl = document.querySelector("#bar");
const rowsEl = document.querySelector("#rows");
const tableWrap = document.querySelector("#table-wrap");
const emptyEl = document.querySelector("#empty");
const filterEl = document.querySelector("#filter");
const copyBtn = document.querySelector("#copy");
const jsonBtn = document.querySelector("#json");
const csvBtn = document.querySelector("#csv");
const countEl = document.querySelector("#port-count");
const colHost = document.querySelector("#col-host");
const riskCard = document.querySelector("#risk-card");
const riskBadge = document.querySelector("#risk-badge");
const riskScore = document.querySelector("#risk-score");
const pillCritical = document.querySelector("#pill-critical");
const pillHigh = document.querySelector("#pill-high");
const pillMedium = document.querySelector("#pill-medium");
const pillLow = document.querySelector("#pill-low");
const recommendationsBox = document.querySelector("#recommendations-box");
const recommendationsList = document.querySelector("#recommendations-list");
const presetButtons = [...document.querySelectorAll("[data-preset]")];

const state = {
  running: false,
  generation: 0,
  id: null,
  rows: [],
  host: "",
  ip: "",
  total: 0,
  checked: 0,
  open: 0,
  elapsed: 0,
  isMultiHost: false,
};

function parseBound(text) {
  const trimmed = text.trim();
  if (!/^\d+$/.test(trimmed)) return null;
  const value = Number(trimmed);
  if (!Number.isSafeInteger(value)) return null;
  return value;
}

function countPorts(text) {
  const seen = new Set();
  for (const raw of text.split(",")) {
    const part = raw.trim();
    if (!part) continue;
    if (part.includes("-")) {
      const [startText, endText] = part.split("-", 2);
      const start = parseBound(startText);
      const end = parseBound(endText);
      if (start == null || end == null) return null;
      const first = Math.max(start, 1);
      const last = Math.min(end, 65535);
      if (first <= last) {
        for (let port = first; port <= last; port += 1) seen.add(port);
      }
    } else {
      const port = parseBound(part);
      if (port == null) return null;
      if (port >= 1 && port <= 65535) seen.add(port);
    }
  }
  return seen.size;
}

function formatElapsed(seconds) {
  const value = Math.max(0, Number(seconds) || 0);
  if (value < 60) return `${value.toFixed(1)}s`;
  const minutes = Math.floor(value / 60);
  const rest = Math.round(value % 60);
  return `${minutes}m ${String(rest).padStart(2, "0")}s`;
}

function portLabel(count) {
  if (count == null) return "Invalid port list";
  if (count === 0) return "No valid ports";
  if (count === 1) return "1 port";
  return `${count.toLocaleString()} ports`;
}

function showError(message) {
  if (!message) {
    errorEl.hidden = true;
    errorEl.textContent = "";
    return;
  }
  errorEl.hidden = false;
  errorEl.textContent = message;
}

function setLocked(locked) {
  hostEl.readOnly = locked;
  portsEl.readOnly = locked;
  threadsEl.readOnly = locked;
  timeoutEl.readOnly = locked;
  for (const button of presetButtons) button.disabled = locked;
}

function updatePresetPress() {
  const value = portsEl.value.trim();
  for (const button of presetButtons) {
    button.setAttribute("aria-pressed", PRESETS[button.dataset.preset] === value ? "true" : "false");
  }
}

function updatePortCount() {
  const count = countPorts(portsEl.value);
  countEl.textContent = portLabel(count);
  if (!state.running) {
    scanBtn.textContent = count > 0 ? `Scan ${portLabel(count)}` : "Scan";
  }
}

function savePrefs() {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify({
      host: hostEl.value,
      ports: portsEl.value,
      threads: threadsEl.value,
      timeout: timeoutEl.value,
    }));
  } catch {
    // Storage access might be restricted in some browser modes
  }
}

function loadPrefs() {
  try {
    const saved = JSON.parse(localStorage.getItem(PREFS_KEY) || "null");
    if (!saved) return;
    if (typeof saved.host === "string" && saved.host) hostEl.value = saved.host;
    if (typeof saved.ports === "string" && saved.ports) portsEl.value = saved.ports;
    if (saved.threads) threadsEl.value = saved.threads;
    if (saved.timeout) timeoutEl.value = saved.timeout;
  } catch {
    // Keep defaults on failure
  }
}

function matches(hit, query) {
  if (!query) return true;
  const target = `${hit.host || ""} ${hit.ip || ""} ${hit.port} ${hit.service || ""} ${hit.risk || ""} ${hit.banner || ""} ${hit.recommendation || ""} ${(hit.evidence || []).join(" ")}`.toLowerCase();
  return target.includes(query);
}

function computeRiskSummary(rows) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  let maxScore = 0.0;
  for (const r of rows) {
    const risk = (r.risk || "INFO").toUpperCase();
    counts[risk] = (counts[risk] || 0) + 1;
    const score = Number(r.score) || 0;
    if (score > maxScore) maxScore = score;
  }

  let overallLevel = "SAFE";
  if (counts.CRITICAL > 0 || maxScore >= 9.0) overallLevel = "CRITICAL";
  else if (counts.HIGH > 0 || maxScore >= 7.0) overallLevel = "HIGH";
  else if (counts.MEDIUM > 0 || maxScore >= 4.0) overallLevel = "MEDIUM";
  else if (counts.LOW > 0 || maxScore >= 2.0) overallLevel = "LOW";
  else if (rows.length > 0) overallLevel = "INFO";

  return {
    overallLevel,
    maxScore: maxScore.toFixed(1),
    counts,
  };
}

function renderRiskAndRecommendations() {
  if (state.rows.length === 0) {
    riskCard.hidden = true;
    recommendationsBox.hidden = true;
    return;
  }

  const summary = computeRiskSummary(state.rows);
  riskCard.hidden = false;

  riskBadge.textContent = summary.overallLevel;
  riskBadge.className = `badge badge-${summary.overallLevel.toLowerCase()}`;
  riskScore.textContent = `(Max Score: ${summary.maxScore}/10)`;

  pillCritical.textContent = `${summary.counts.CRITICAL} Critical`;
  pillCritical.classList.toggle("has-findings", summary.counts.CRITICAL > 0);
  pillCritical.style.color = summary.counts.CRITICAL > 0 ? "var(--danger)" : "var(--muted)";

  pillHigh.textContent = `${summary.counts.HIGH} High`;
  pillHigh.classList.toggle("has-findings", summary.counts.HIGH > 0);
  pillHigh.style.color = summary.counts.HIGH > 0 ? "var(--warn)" : "var(--muted)";

  pillMedium.textContent = `${summary.counts.MEDIUM} Medium`;
  pillMedium.classList.toggle("has-findings", summary.counts.MEDIUM > 0);
  pillMedium.style.color = summary.counts.MEDIUM > 0 ? "#fde047" : "var(--muted)";

  pillLow.textContent = `${summary.counts.LOW} Low`;
  pillLow.classList.toggle("has-findings", summary.counts.LOW > 0);
  pillLow.style.color = summary.counts.LOW > 0 ? "#93c5fd" : "var(--muted)";

  // Recommendations
  const sorted = [...state.rows]
    .filter((r) => r.recommendation)
    .sort((a, b) => (Number(b.score) || 0) - (Number(a.score) || 0));

  const seen = new Set();
  const uniqueRecs = [];
  for (const item of sorted) {
    const key = `${item.port}-${item.service}`;
    if (!seen.has(key)) {
      seen.add(key);
      uniqueRecs.push(item);
    }
  }

  if (uniqueRecs.length > 0) {
    recommendationsBox.hidden = false;
    const fragment = document.createDocumentFragment();
    for (const rec of uniqueRecs) {
      const card = document.createElement("div");
      const riskClass = (rec.risk || "info").toLowerCase();
      card.className = `rec-item rec-${riskClass}`;

      const header = document.createElement("div");
      header.className = "rec-header";

      const badge = document.createElement("span");
      badge.className = `badge badge-${riskClass}`;
      badge.textContent = rec.risk || "INFO";

      const title = document.createElement("span");
      title.className = "rec-title";
      title.textContent = `Port ${rec.port}/TCP (${rec.service || "unknown"})`;

      const scoreSpan = document.createElement("span");
      scoreSpan.style.color = "var(--dim)";
      scoreSpan.style.fontSize = "0.78rem";
      scoreSpan.textContent = `· Score: ${rec.score || "2.0"}/10`;

      header.append(badge, title, scoreSpan);

      const text = document.createElement("p");
      text.className = "rec-text";
      text.textContent = rec.recommendation;

      card.append(header, text);

      // Evidence — dynamic findings from the live probe
      const evidence = rec.evidence || [];
      if (evidence.length > 0) {
        const evSection = document.createElement("div");
        evSection.className = "rec-evidence";

        const evLabel = document.createElement("span");
        evLabel.className = "rec-evidence-label";
        evLabel.textContent = "🔍 Dynamic Findings";
        evSection.append(evLabel);

        const ul = document.createElement("ul");
        ul.className = "rec-evidence-list";
        for (const finding of evidence) {
          const li = document.createElement("li");
          li.textContent = finding;
          ul.append(li);
        }
        evSection.append(ul);
        card.append(evSection);
      }

      // TLS info badge if present
      if (rec.tls_version) {
        const tlsBadge = document.createElement("span");
        tlsBadge.className = "tls-badge";
        tlsBadge.textContent = `🔒 ${rec.tls_version}`;
        card.append(tlsBadge);
      }

      fragment.append(card);
    }
    recommendationsList.replaceChildren(fragment);
  } else {
    recommendationsBox.hidden = true;
  }
}

function renderRows() {
  const query = filterEl.value.trim().toLowerCase();
  const fragment = document.createDocumentFragment();
  let shown = 0;

  colHost.hidden = !state.isMultiHost;

  for (const hit of state.rows) {
    const row = document.createElement("tr");

    if (state.isMultiHost) {
      const hostTd = document.createElement("td");
      hostTd.className = "td-host";
      hostTd.textContent = hit.ip || hit.host || "—";
      row.append(hostTd);
    }

    const port = document.createElement("td");
    port.className = "td-port";
    port.textContent = String(hit.port);

    const service = document.createElement("td");
    service.className = "td-service";
    service.textContent = hit.service || "unknown";

    const riskTd = document.createElement("td");
    riskTd.className = "td-risk";
    const badge = document.createElement("span");
    const riskLevel = (hit.risk || "INFO").toUpperCase();
    badge.className = `badge badge-${riskLevel.toLowerCase()}`;
    badge.textContent = riskLevel;
    riskTd.append(badge);

    const banner = document.createElement("td");
    banner.className = "td-banner";
    let bannerText = hit.banner || "—";
    if (hit.tls_version) bannerText = `[${hit.tls_version}] ${bannerText}`;
    banner.textContent = bannerText;
    if (hit.banner) banner.title = hit.full_banner || hit.banner;
    // Show evidence as tooltip on the risk badge
    if (hit.evidence && hit.evidence.length > 0) {
      badge.title = hit.evidence.join("\n");
      badge.style.cursor = "help";
    }

    row.append(port, service, riskTd, banner);

    if (matches(hit, query)) shown += 1;
    else row.hidden = true;

    fragment.append(row);
  }

  rowsEl.replaceChildren(fragment);
  const filtering = query && state.rows.length > 0 && shown === 0;
  tableWrap.hidden = shown === 0;

  if (state.rows.length === 0) {
    emptyEl.hidden = false;
    emptyEl.textContent = state.running ? "No open ports yet." : "No open ports.";
  } else if (filtering) {
    emptyEl.hidden = false;
    emptyEl.textContent = "No open ports match that filter.";
  } else {
    emptyEl.hidden = true;
  }

  renderRiskAndRecommendations();
}

function renderStatus() {
  const host = state.host ? `${state.host} (${state.ip})` : "";
  if (state.running) {
    statusEl.textContent = "Scanning";
    detailEl.textContent = `${host} · ${state.checked.toLocaleString()} / ${state.total.toLocaleString()} checked · ${state.open.toLocaleString()} open · ${formatElapsed(state.elapsed)}`;
    document.title = `${Math.floor(state.total ? (state.checked / state.total) * 100 : 0)}% · Port Scanner`;
  }
  const fraction = state.total ? Math.min(100, (state.checked / state.total) * 100) : 0;
  barEl.style.width = `${fraction}%`;
  const hasRows = state.rows.length > 0;
  copyBtn.disabled = !hasRows;
  jsonBtn.disabled = !hasRows;
  csvBtn.disabled = !hasRows;
  filterEl.disabled = !hasRows;
}

function resetResults(host, ip, total, isMultiHost) {
  state.rows = [];
  state.host = host;
  state.ip = ip;
  state.total = total;
  state.checked = 0;
  state.open = 0;
  state.elapsed = 0;
  state.isMultiHost = Boolean(isMultiHost);
  filterEl.value = "";
  progressEl.hidden = false;
  riskCard.hidden = true;
  recommendationsBox.hidden = true;
  rowsEl.replaceChildren();
  emptyEl.hidden = false;
  emptyEl.textContent = "No open ports yet.";
  renderStatus();
}

function finishScan(data) {
  state.running = false;
  state.checked = data.checked ?? state.checked;
  state.open = data.open ?? state.open;
  state.elapsed = data.elapsed ?? state.elapsed;
  setLocked(false);
  scanBtn.classList.remove("stop");
  scanBtn.disabled = false;
  updatePortCount();
  const host = `${state.host} (${state.ip})`;
  if (data.cancelled) {
    statusEl.textContent = "Stopped";
    detailEl.textContent = `${host} · ${state.open.toLocaleString()} open · ${state.checked.toLocaleString()} of ${state.total.toLocaleString()} checked · ${formatElapsed(state.elapsed)}`;
  } else {
    statusEl.textContent = state.open === 0
      ? "No open ports"
      : state.open === 1
        ? "1 open port"
        : `${state.open.toLocaleString()} open ports`;
    detailEl.textContent = `${host} · finished in ${formatElapsed(state.elapsed)}`;
    state.checked = state.total;
  }
  document.title = "Port Scanner";
  renderStatus();
  renderRows();
}

function failScan(message) {
  state.running = false;
  setLocked(false);
  scanBtn.classList.remove("stop");
  scanBtn.disabled = false;
  updatePortCount();
  statusEl.textContent = "Scan failed";
  detailEl.textContent = message;
  document.title = "Port Scanner";
  showError(message);
  renderStatus();
}

async function poll(generation, id, since) {
  let failures = 0;
  while (generation === state.generation) {
    let response;
    try {
      response = await fetch(`/api/scans/${id}?since=${since}`);
    } catch {
      failures += 1;
      if (failures > 3 || generation !== state.generation) {
        if (generation === state.generation) failScan("Lost contact with the scanner.");
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 400));
      continue;
    }
    if (generation !== state.generation) return;
    if (!response.ok) {
      failScan("The scanner lost this scan.");
      return;
    }
    const body = await response.json();
    failures = 0;
    for (const event of body.events) applyEvent(event);
    if (body.done && !state.running) return;
    if (body.done && state.running) {
      finishScan({
        open: state.open,
        checked: state.checked,
        elapsed: state.elapsed,
        cancelled: state.checked < state.total,
      });
      return;
    }
    since = body.next;
  }
}

function applyEvent(event) {
  const data = event.data || {};
  if (event.name === "started") {
    state.host = data.host || state.host;
    state.ip = data.ip || state.ip;
    state.total = data.total || state.total;
    state.isMultiHost = (data.hosts_count || 1) > 1;
    renderStatus();
    return;
  }
  if (event.name === "progress") {
    state.checked = data.checked;
    state.total = data.total;
    state.open = data.open;
    state.elapsed = data.elapsed;
    if (data.hit) {
      state.rows.push(data.hit);
      state.rows.sort((a, b) => {
        if (a.ip !== b.ip) return String(a.ip).localeCompare(String(b.ip));
        return a.port - b.port;
      });
      renderRows();
    }
    renderStatus();
    return;
  }
  if (event.name === "finished") {
    finishScan(data);
    return;
  }
  if (event.name === "failed") {
    failScan(data.message || "Scan failed");
  }
}

async function startScan() {
  showError("");
  const count = countPorts(portsEl.value);
  if (count == null) {
    showError("Ports must look like 1-1024 or 22,80,443.");
    return;
  }
  if (count === 0) {
    showError("No valid ports in that range.");
    return;
  }
  state.running = true;
  state.generation += 1;
  const generation = state.generation;
  setLocked(true);
  scanBtn.disabled = true;
  scanBtn.classList.remove("stop");
  scanBtn.textContent = "Starting…";
  statusEl.textContent = "Preparing scan";
  detailEl.textContent = hostEl.value.trim();
  savePrefs();

  let response;
  try {
    response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host: hostEl.value.trim(),
        ports: portsEl.value.trim(),
        threads: Number(threadsEl.value),
        timeout: Number(timeoutEl.value),
      }),
    });
  } catch {
    failScan("Could not reach the scanner.");
    return;
  }
  if (generation !== state.generation) return;

  let payload = {};
  try {
    payload = await response.json();
  } catch {
    payload = {};
  }
  if (!response.ok) {
    failScan(payload.error || "Could not start the scan.");
    return;
  }

  state.id = payload.id;
  const isMulti = (payload.hosts_count || 1) > 1;
  resetResults(payload.host, payload.ip, payload.total, isMulti);
  scanBtn.disabled = false;
  scanBtn.classList.add("stop");
  scanBtn.textContent = "Stop";
  poll(generation, payload.id, 0);
}

async function stopScan() {
  const id = state.id;
  scanBtn.disabled = true;
  if (!id) return;
  try {
    await fetch(`/api/scans/${id}/cancel`, { method: "POST" });
  } catch {
    showError("Could not reach the scanner to stop the scan.");
    scanBtn.disabled = false;
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  if (state.running) stopScan();
  else startScan();
});

portsEl.addEventListener("input", () => {
  updatePortCount();
  updatePresetPress();
});

for (const button of presetButtons) {
  button.addEventListener("click", () => {
    portsEl.value = PRESETS[button.dataset.preset];
    updatePortCount();
    updatePresetPress();
    portsEl.focus();
  });
}

filterEl.addEventListener("input", renderRows);

copyBtn.addEventListener("click", async () => {
  const text = state.rows.map((hit) => {
    const host = hit.ip ? `${hit.ip}\t` : "";
    return `${host}${hit.port}\t${hit.service}\t${hit.risk}\t${hit.banner || "—"}`;
  }).join("\n");
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = "Copied";
    setTimeout(() => { copyBtn.textContent = "Copy"; }, 1200);
  } catch {
    showError("Could not copy the results.");
  }
});

// JSON Export
jsonBtn.addEventListener("click", () => {
  const summary = computeRiskSummary(state.rows);
  const report = {
    scanner: "Network Port Scanner",
    version: "2.0",
    target: state.host,
    ip: state.ip,
    timestamp: new Date().toISOString(),
    total_checks: state.total,
    open_ports_count: state.rows.length,
    elapsed_seconds: state.elapsed,
    risk_summary: summary,
    results: state.rows,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  const name = (state.host || "scan").replace(/[^A-Za-z0-9._-]+/g, "_");
  link.href = URL.createObjectURL(blob);
  link.download = `${name}-ports-report.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

// CSV Export
csvBtn.addEventListener("click", () => {
  const lines = ["host,ip,port,service,risk_level,risk_score,banner,recommendation"];
  for (const hit of state.rows) {
    const esc = (val) => `"${String(val ?? "").replaceAll('"', '""')}"`;
    lines.push([
      esc(hit.host || state.host),
      esc(hit.ip || state.ip),
      esc(hit.port),
      esc(hit.service),
      esc(hit.risk),
      esc(hit.score),
      esc(hit.banner),
      esc(hit.recommendation)
    ].join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8;" });
  const link = document.createElement("a");
  const name = (state.host || "scan").replace(/[^A-Za-z0-9._-]+/g, "_");
  link.href = URL.createObjectURL(blob);
  link.download = `${name}-ports-report.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
});

window.addEventListener("pagehide", () => {
  if (state.running && state.id) {
    navigator.sendBeacon(`/api/scans/${state.id}/cancel`);
  }
});

loadPrefs();
updatePortCount();
updatePresetPress();
