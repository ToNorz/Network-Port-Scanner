const PRESETS = {
  common: "21,22,23,25,53,80,110,139,143,443,445,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017",
  wellknown: "1-1024",
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
const csvBtn = document.querySelector("#csv");
const countEl = document.querySelector("#port-count");
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
    // Private mode can block storage. The scan still runs.
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
    // Ignore unreadable prefs and keep the defaults.
  }
}

function matches(hit, query) {
  if (!query) return true;
  return `${hit.port} ${hit.service} ${hit.banner}`.toLowerCase().includes(query);
}

function renderRows() {
  const query = filterEl.value.trim().toLowerCase();
  const fragment = document.createDocumentFragment();
  let shown = 0;
  for (const hit of state.rows) {
    const row = document.createElement("tr");
    const port = document.createElement("td");
    const service = document.createElement("td");
    const banner = document.createElement("td");
    port.textContent = String(hit.port);
    service.textContent = hit.service || "unknown";
    banner.textContent = hit.banner || "—";
    if (hit.banner) banner.title = hit.banner;
    row.append(port, service, banner);
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
  csvBtn.disabled = !hasRows;
  filterEl.disabled = !hasRows;
}

function resetResults(host, ip, total) {
  state.rows = [];
  state.host = host;
  state.ip = ip;
  state.total = total;
  state.checked = 0;
  state.open = 0;
  state.elapsed = 0;
  filterEl.value = "";
  progressEl.hidden = false;
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
      state.rows.sort((a, b) => a.port - b.port);
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
  statusEl.textContent = "Resolving host";
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
  resetResults(payload.host, payload.ip, payload.total);
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
  const text = state.rows.map((hit) => `${hit.port}\t${hit.service}\t${hit.banner}`).join("\n");
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = "Copied";
    setTimeout(() => { copyBtn.textContent = "Copy"; }, 1200);
  } catch {
    showError("Could not copy the results.");
  }
});

csvBtn.addEventListener("click", () => {
  const lines = ["port,service,banner"];
  for (const hit of state.rows) {
    const banner = `"${String(hit.banner || "").replaceAll('"', '""')}"`;
    const service = `"${String(hit.service || "").replaceAll('"', '""')}"`;
    lines.push(`${hit.port},${service},${banner}`);
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const link = document.createElement("a");
  const name = (state.host || "scan").replace(/[^A-Za-z0-9._-]+/g, "_");
  link.href = URL.createObjectURL(blob);
  link.download = `${name}-ports.csv`;
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
