/* Deep Scan dashboard - vanilla JS, no build step. */
"use strict";

const FAMILIES = ["sast", "sca", "secret", "iac", "license", "pipeline", "malware"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const POLL_ACTIVE_MS = 3000;
const MAX_UPLOAD_BYTES = 200 * 1024 * 1024;  // matches the server limit
// VCS / dependency / build dirs never worth uploading for a scan.
const SKIP_DIRS = new Set([
  ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
  ".tox", ".nox", "dist", "build", ".mypy_cache", ".pytest_cache", ".ruff_cache",
  ".idea", "target",
]);

const $ = (id) => document.getElementById(id);

const state = {
  tab: "new",         // "new" | "history"
  currentId: null,    // the scan just launched (tracked on the New-scan tab)
  selectedId: null,   // the scan currently shown in the detail panel
  history: { items: [], total: 0, offset: 0, limit: 50 },
  detailTimer: null,  // polls the open scan's detail while it is active
  listTimer: null,    // polls the history page while it holds active scans
  mode: "static",     // "static" | "dynamic"
  source: "archive",  // static source: "archive" (folder/zip) | "repo"
  archive: { mode: null, file: null, files: [], name: "" },  // mode: "zip" | "folder"
  // open report's tables (sort/filter state lives here so re-renders preserve it)
  findings: [],
  tools: [],
  findingsView: { sort: "severity", dir: "desc", q: "", sev: "", tool: "" },
  toolsView: { sort: "scanner", dir: "asc", q: "", status: "" },
};

const HISTORY_PAGE_SIZE = 50;  // hard cap - no page ever shows more than 50 rows

/* ---------- helpers ---------- */

const ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

function esc(value) {
  // HTML-encodes &, <, >, " and ' so escaped values are safe in both
  // element and (quoted) attribute contexts.
  return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

function num(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body && body.detail) {
        message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch (_) { /* non-JSON error body */ }
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}

// A paginated GET: returns { items, total } where total comes from the
// X-Total-Count header the API sets on list endpoints.
async function apiPaged(path) {
  const response = await fetch(path);
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body && body.detail) {
        message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch (_) { /* non-JSON error body */ }
    throw new Error(message);
  }
  const items = await response.json();
  const total = Number(response.headers.get("X-Total-Count"));
  return { items, total: Number.isFinite(total) ? total : items.length };
}

function isActive(job) {
  return job && (job.status === "queued" || job.status === "running");
}

function severityChips(totals) {
  if (!totals) return "";
  const chips = SEVERITIES
    .filter((sev) => num(totals[sev]) > 0)
    .map((sev) => `<span class="chip ${sev}" title="${sev}">${num(totals[sev])} ${sev}</span>`);
  if (!chips.length) return '<span class="chip clean">clean</span>';
  return chips.join("");
}

function statusBadge(status) {
  return `<span class="badge ${esc(status)}">${esc(status)}</span>`;
}

// Every scan submitted here runs on the kruncher fleet's *manual* queue (it is
// never executed in-process). The surface (api / mcp) says where it came from.
function queueBadge(job) {
  const surface = job.surface ? ` <span class="surface-tag">${esc(job.surface)}</span>` : "";
  return `<span class="queue-badge manual" title="Manual queue - runs on the kruncher fleet, ahead of periodic scans">Manual</span>${surface}`;
}

function formatTime(iso) {
  if (!iso) return "";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

/* ---------- new scan form ---------- */

function buildFamilyChecks() {
  $("family-checks").innerHTML = FAMILIES
    .map((fam) => `<label><input type="checkbox" value="${fam}"> ${fam}</label>`)
    .join("");
}

function selectedFamilies() {
  return Array.from($("family-checks").querySelectorAll("input:checked")).map((cb) => cb.value);
}

function setError(msg) { $("form-error").textContent = msg || ""; }
function setProgress(msg) { $("form-progress").textContent = msg || ""; }

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function pathSkipped(path) {
  return path.split("/").some((seg) => SKIP_DIRS.has(seg));
}

/* -- mode (static / dynamic) -- */

function setMode(mode) {
  state.mode = mode;
  document.querySelectorAll(".mode-tab")
    .forEach((tab) => tab.classList.toggle("active", tab.dataset.mode === mode));
  document.querySelectorAll(".mode-group")
    .forEach((group) => { group.hidden = group.dataset.modeGroup !== mode; });
  setError("");
  setProgress("");
}

/* -- source tabs (within static mode) -- */

function setSource(source) {
  state.source = source;
  document.querySelectorAll(".source-tab")
    .forEach((tab) => tab.classList.toggle("active", tab.dataset.source === source));
  document.querySelectorAll(".source-pane")
    .forEach((pane) => { pane.hidden = pane.dataset.pane !== source; });
  setError("");
  setProgress("");
}

/* -- folder / zip selection (always uploaded as a zip) -- */

function deriveName(files) {
  const first = (files[0] && files[0].path) || "";
  return first.split("/")[0] || "project";
}

function showSelected(text) {
  const el = $("dz-selected");
  el.hidden = false;
  el.innerHTML = `<span>${esc(text)}</span> <button type="button" class="btn small ghost" id="dz-clear">Clear</button>`;
  $("dz-clear").addEventListener("click", clearArchive);
  setError("");
}

function clearArchive() {
  state.archive = { mode: null, file: null, files: [], name: "" };
  $("dz-selected").hidden = true;
  $("folder-input").value = "";
  $("zip-input").value = "";
}

function setFolderSelection(files) {
  const kept = files.filter((f) => !pathSkipped((f.path || "").replace(/\\/g, "/")));
  if (!kept.length) {
    setError("No scannable files in that folder (only skipped dirs?).");
    return;
  }
  state.archive = { mode: "folder", file: null, files: kept, name: deriveName(kept) };
  showSelected(`\u{1F4C1} ${state.archive.name} - ${kept.length} file(s)`);
}

function setZipSelection(file) {
  state.archive = { mode: "zip", file, files: [], name: file.name };
  showSelected(`\u{1F5DC}\u{FE0F} ${file.name} - ${formatBytes(file.size)}`);
}

function onFolderInput() {
  setFolderSelection(Array.from($("folder-input").files || [])
    .map((f) => ({ path: f.webkitRelativePath || f.name, file: f })));
}

function onZipInput() {
  const file = ($("zip-input").files || [])[0];
  if (file) setZipSelection(file);
}

function fileFromEntry(entry) {
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}

function walkEntry(entry, prefix, out) {
  return new Promise((resolve) => {
    if (SKIP_DIRS.has(entry.name)) return resolve();
    if (entry.isFile) {
      entry.file((f) => { out.push({ path: prefix + entry.name, file: f }); resolve(); }, () => resolve());
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const all = [];
      const readBatch = () => reader.readEntries(async (batch) => {
        if (!batch.length) {
          for (const child of all) await walkEntry(child, `${prefix}${entry.name}/`, out);
          resolve();
        } else {
          all.push(...batch);
          readBatch();
        }
      }, () => resolve());
      readBatch();
    } else {
      resolve();
    }
  });
}

async function onDrop(event) {
  event.preventDefault();
  $("dropzone").classList.remove("dragover");
  setError("");
  try {
    const dt = event.dataTransfer;
    const entries = Array.from(dt.items || [])
      .map((it) => (it.webkitGetAsEntry ? it.webkitGetAsEntry() : null))
      .filter(Boolean);
    if (entries.length) {
      if (entries.length === 1 && entries[0].isFile && /\.zip$/i.test(entries[0].name)) {
        setZipSelection(await fileFromEntry(entries[0]));
        return;
      }
      const collected = [];
      for (const entry of entries) await walkEntry(entry, "", collected);
      setFolderSelection(collected);
      return;
    }
    const files = Array.from(dt.files || []);
    if (files.length === 1 && /\.zip$/i.test(files[0].name)) {
      setZipSelection(files[0]);
    } else if (files.length) {
      setFolderSelection(files.map((f) => ({ path: f.webkitRelativePath || f.name, file: f })));
    }
  } catch (err) {
    setError(err.message);
  }
}

async function looksLikeZip(file) {
  if (!/\.zip$/i.test(file.name)) return false;
  const head = new Uint8Array(await file.slice(0, 4).arrayBuffer());
  return head[0] === 0x50 && head[1] === 0x4b
    && (head[2] === 0x03 || head[2] === 0x05 || head[2] === 0x07);
}

async function buildZipFromFiles(files) {
  const entries = [];
  let total = 0;
  for (const { path, file } of files) {
    const name = path.replace(/\\/g, "/").replace(/^\.\//, "");
    if (!name || pathSkipped(name)) continue;
    const bytes = new Uint8Array(await file.arrayBuffer());
    total += bytes.length;
    if (total > MAX_UPLOAD_BYTES) {
      throw new Error("Project exceeds the 200 MiB upload limit - remove build/vendor dirs.");
    }
    entries.push({ name, bytes });
  }
  if (!entries.length) throw new Error("No scannable files found in that folder.");
  return window.DeepScanZip.buildStoreZip(entries);
}

/* -- submit -- */

function submitJson(payload) {
  return api("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ...payload, families: payload.families.length ? payload.families : null }),
  });
}

async function submitArchive(families) {
  const arc = state.archive;
  let blob;
  let name;
  if (arc.mode === "zip") {
    if (!(await looksLikeZip(arc.file))) throw new Error("That file is not a valid .zip archive.");
    blob = arc.file;
    name = arc.file.name;
  } else if (arc.mode === "folder") {
    setProgress(`Zipping ${arc.files.length} file(s) in your browser…`);
    blob = await buildZipFromFiles(arc.files);
    name = `${arc.name || "project"}.zip`;
  } else {
    throw new Error("Drop a folder or a .zip, or choose one.");
  }
  setProgress("Uploading…");
  const form = new FormData();
  form.append("file", blob, name);
  if (families.length) form.append("families", families.join(","));
  return api("/api/scans/zip", { method: "POST", body: form });
}

async function submitScan(event) {
  event.preventDefault();
  setError("");
  setProgress("");
  const button = $("submit-btn");
  const families = selectedFamilies();
  button.disabled = true;
  try {
    let created;
    if (state.mode === "dynamic") {
      const url = $("dast-input").value.trim();
      if (!url) throw new Error("Enter a live URL to scan.");
      created = await submitJson({ target_type: "url", target: url, mode: "dynamic", families: [] });
    } else if (state.source === "archive") {
      created = await submitArchive(families);
    } else {
      const url = $("repo-input").value.trim();
      if (!url) throw new Error("Enter a repository URL.");
      created = await submitJson({ target_type: "git", target: url, mode: "static", families });
    }
    // Track the just-launched scan on the New-scan tab and follow it live.
    state.currentId = created.id;
    setTab("new");  // re-focuses currentId and starts live polling
  } catch (err) {
    setError(err.message);
  } finally {
    button.disabled = false;
    setProgress("");
  }
}

/* ---------- tabs ---------- */

function setTab(tab) {
  state.tab = tab;
  document.querySelectorAll(".main-tab")
    .forEach((b) => b.classList.toggle("active", b.dataset.tab === tab));
  $("view-new").hidden = tab !== "new";
  $("view-history").hidden = tab !== "history";
  $("view-ci").hidden = tab !== "ci";
  // The CI-templates tab is a self-contained wizard (pipelines.js) - it owns no
  // scan detail panel, so park the shared panel and stop any live polling.
  if (tab === "ci") {
    clearTimeout(state.detailTimer);
    clearTimeout(state.listTimer);
    hideDetail();
    if (window.DeepScanPipelines) window.DeepScanPipelines.show();
    return;
  }
  mountDetail();
  if (tab === "history") {
    clearTimeout(state.detailTimer);   // detail polling is the New-tab's concern
    hideDetail();                      // a row click re-opens it within this tab
    loadHistory();
  } else {
    clearTimeout(state.listTimer);
    // Re-focus the scan you just launched (if any), else hide the panel.
    if (state.currentId) showDetail(state.currentId);
    else hideDetail();
  }
}

// The single detail panel lives under whichever tab is active.
function activeMount() {
  return state.tab === "history" ? $("mount-history") : $("mount-new");
}
function mountDetail() {
  const panel = $("detail-panel");
  const mount = activeMount();
  if (panel.parentElement !== mount) mount.appendChild(panel);
}
function hideDetail() {
  state.selectedId = null;
  $("detail-panel").hidden = true;
}

function setBusy(active) {
  $("queue-indicator").hidden = !active;
  if (active) $("queue-indicator-text").textContent = "scan in progress";
}

/* ---------- history (paginated) ---------- */

async function loadHistory() {
  let page;
  try {
    const { offset } = state.history;
    page = await apiPaged(`/api/scans?limit=${HISTORY_PAGE_SIZE}&offset=${offset}`);
  } catch (err) {
    $("jobs-body").innerHTML =
      `<tr><td colspan="7" class="empty">Failed to load scans: ${esc(err.message)}</td></tr>`;
    return;
  }
  // If the page is now empty (e.g. after a delete on the last page), step back.
  if (!page.items.length && state.history.offset > 0) {
    state.history.offset = Math.max(0, state.history.offset - HISTORY_PAGE_SIZE);
    return loadHistory();
  }
  state.history.items = page.items;
  state.history.total = page.total;
  renderHistory();
  renderPager();
  // Auto-refresh the page while it holds active scans (e.g. one just launched).
  const active = page.items.some(isActive);
  setBusy(active);
  clearTimeout(state.listTimer);
  if (state.tab === "history" && active) {
    state.listTimer = setTimeout(loadHistory, POLL_ACTIVE_MS);
  }
}

function jobRow(job) {
  const selected = String(job.id) === String(state.selectedId) ? "selected" : "";
  return `
    <tr data-id="${esc(job.id)}" class="${selected}">
      <td class="mono">${esc(String(job.id).slice(0, 8))}</td>
      <td class="target-cell" title="${esc(job.target)}">${esc(job.target)}</td>
      <td>${esc(job.target_type)}</td>
      <td>${queueBadge(job)}</td>
      <td>${statusBadge(job.status)}</td>
      <td class="dim">${esc(formatTime(job.created_at))}</td>
      <td><div class="chips">${job.status === "done" ? severityChips(job.summary && job.summary.severity_totals) : ""}</div></td>
    </tr>`;
}

function renderHistory() {
  const body = $("jobs-body");
  if (!state.history.items.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No scans yet.</td></tr>';
    return;
  }
  body.innerHTML = state.history.items.map(jobRow).join("");
  body.querySelectorAll("tr[data-id]").forEach((row) => {
    row.addEventListener("click", () => showDetail(row.dataset.id));
  });
}

function renderPager() {
  const { total, offset } = state.history;
  const pager = $("history-pager");
  if (total <= HISTORY_PAGE_SIZE) { pager.hidden = true; return; }
  pager.hidden = false;
  const pages = Math.max(1, Math.ceil(total / HISTORY_PAGE_SIZE));
  const page = Math.floor(offset / HISTORY_PAGE_SIZE) + 1;
  const from = total ? offset + 1 : 0;
  const to = Math.min(offset + HISTORY_PAGE_SIZE, total);
  const atStart = offset <= 0;
  const atEnd = offset + HISTORY_PAGE_SIZE >= total;
  pager.innerHTML = `
    <button class="btn small ghost" data-page="first" ${atStart ? "disabled" : ""}>« First</button>
    <button class="btn small ghost" data-page="prev" ${atStart ? "disabled" : ""}>‹ Prev</button>
    <span class="pager-info">${from}–${to} of ${total} · page ${page}/${pages}</span>
    <button class="btn small ghost" data-page="next" ${atEnd ? "disabled" : ""}>Next ›</button>
    <button class="btn small ghost" data-page="last" ${atEnd ? "disabled" : ""}>Last »</button>`;
  pager.querySelectorAll("button[data-page]").forEach((b) => {
    b.addEventListener("click", () => gotoPage(b.dataset.page));
  });
}

function gotoPage(which) {
  const { total, offset } = state.history;
  const lastOffset = Math.max(0, (Math.ceil(total / HISTORY_PAGE_SIZE) - 1) * HISTORY_PAGE_SIZE);
  const next = {
    first: 0,
    prev: Math.max(0, offset - HISTORY_PAGE_SIZE),
    next: Math.min(lastOffset, offset + HISTORY_PAGE_SIZE),
    last: lastOffset,
  }[which];
  if (next === offset) return;
  state.history.offset = next;
  loadHistory();
}

/* ---------- detail panel ---------- */

function highlightSelectedRow() {
  $("jobs-body").querySelectorAll("tr[data-id]").forEach((row) => {
    row.classList.toggle("selected", row.dataset.id === String(state.selectedId));
  });
}

/* ---------- report sub-tabs (Findings / Code graph) ---------- */

// The graph iframe is heavy, so it is created only when its tab is first opened
// (and once per job); this id remembers which job's graph is currently loaded.
let graphLoadedFor = null;

function setupReportTabs(job) {
  const bar = $("detail-subtabs");
  const findingsPane = $("pane-findings");
  const graphPane = $("pane-graph");
  if (graphLoadedFor !== job.id) {            // a different job: drop its heavy iframe
    $("graph-mount").innerHTML = "";
    graphLoadedFor = null;
  }
  if (!job.has_graph) {                       // no graph → just show the report
    bar.hidden = true;
    graphPane.hidden = true;
    findingsPane.hidden = false;
    return;
  }
  bar.hidden = false;
  bar.innerHTML = `
    <button class="subtab active" data-pane="findings" type="button">Findings &amp; tools</button>
    <button class="subtab" data-pane="graph" type="button">Code graph</button>`;
  bar.querySelectorAll(".subtab").forEach((b) =>
    b.addEventListener("click", () => selectReportTab(job, b.dataset.pane)));
  selectReportTab(job, "findings");
}

function selectReportTab(job, pane) {
  $("detail-subtabs").querySelectorAll(".subtab")
    .forEach((b) => b.classList.toggle("active", b.dataset.pane === pane));
  $("pane-findings").hidden = pane !== "findings";
  $("pane-graph").hidden = pane !== "graph";
  if (pane === "graph") {
    $("graph-open").href = `/api/scans/${esc(job.id)}/graph`;
    // Lazy-load: only build the iframe the first time the graph tab is opened.
    if (graphLoadedFor !== job.id) {
      graphLoadedFor = job.id;
      $("graph-mount").innerHTML =
        `<iframe class="graph-frame" src="/api/scans/${esc(job.id)}/graph"`
        + ` title="Code graph" sandbox="allow-scripts" loading="lazy"></iframe>`;
    }
  }
}

/* ---------- live step progress ---------- */

const STEP_ICON = { pending: "○", running: "◍", done: "✓", skipped: "⊘", error: "✗" };

function stepRow(step) {
  const status = step.status || "pending";
  const meta = [];
  if (step.family) meta.push(esc(step.family));
  if (step.duration != null) meta.push(`${num(step.duration).toFixed(1)}s`);
  if (status === "done" && step.findings != null) {
    meta.push(`${num(step.findings)} finding${num(step.findings) === 1 ? "" : "s"}`);
  }
  if (status === "skipped") meta.push("skipped");
  const detail = step.detail ? `<div class="step-detail">${esc(step.detail)}</div>` : "";
  return `
    <li class="step ${esc(status)}">
      <span class="step-icon">${STEP_ICON[status] || "○"}</span>
      <span class="step-name">${esc(step.label || step.name)}</span>
      <span class="step-meta">${meta.join(" · ")}</span>
      ${detail}
    </li>`;
}

function renderProgress(job) {
  const el = $("detail-progress");
  // The live step view is for in-flight scans; a finished scan shows its report.
  if (job.status === "done") { el.innerHTML = ""; return; }
  if (job.status === "queued") {
    el.innerHTML = `<div class="progress-panel"><span class="dim">Queued - waiting for a worker to pick it up…</span></div>`;
    return;
  }
  const st = job.steps;
  if (!st || !(st.steps || []).length) {
    el.innerHTML = `<div class="progress-panel"><span class="dim">Starting…</span></div>`;
    return;
  }
  const total = st.total || st.steps.length;
  const done = st.done || 0;
  const pct = total ? Math.round((done / total) * 100) : 0;
  const failed = job.status === "failed" || job.status === "dead";
  el.innerHTML = `
    <div class="progress-panel">
      <div class="progress-head">
        <h3 class="section-title">Progress - step ${done} / ${total}</h3>
        <span class="dim mono">${pct}%</span>
      </div>
      <div class="pbar${failed ? " failed" : ""}"><span style="width:${pct}%"></span></div>
      <ol class="steps-log">${st.steps.map(stepRow).join("")}</ol>
    </div>`;
}

async function showDetail(jobId, isRefresh = false) {
  state.selectedId = jobId;
  mountDetail();
  highlightSelectedRow();
  const panel = $("detail-panel");
  panel.hidden = false;
  let job;
  try {
    job = await api(`/api/scans/${jobId}`);
  } catch (err) {
    $("detail-error").textContent = err.message;
    return;
  }
  $("detail-id").textContent = String(job.id).slice(0, 8);
  $("detail-error").textContent = job.error ? `Error: ${job.error}` : "";

  $("detail-meta").innerHTML = [
    ["Status", statusBadge(job.status)],
    ["Type", esc(job.target_type)],
    ["Queue", queueBadge(job)],
    ["Target", `<span class="mono">${esc(job.target)}</span>`],
    ["Files", job.source_path ? `<span class="mono">${esc(job.source_path)}</span>` : "-"],
    ...(job.upload_id ? [["Upload ID", `<span class="mono">${esc(job.upload_id)}</span>`]] : []),
    ...(job.git_commit ? [["Commit", `<span class="mono" title="${esc(job.git_commit)}">${esc(job.git_commit.slice(0, 12))}</span>`]] : []),
    ...(job.fingerprint ? [["Fingerprint", `<span class="mono" title="${esc(job.fingerprint)}">${esc(job.fingerprint.slice(0, 23))}…</span>`]] : []),
    ["Mode", esc(job.mode || "auto")],
    ["Families", esc(job.families.length ? job.families.join(", ") : "all")],
    ["Created", esc(formatTime(job.created_at))],
    ["Updated", esc(formatTime(job.updated_at))],
  ].map(([label, value]) => `
    <div class="meta-item">
      <div class="meta-label">${label}</div>
      <div class="meta-value">${value}</div>
    </div>`).join("");

  renderDetailActions(job);
  renderProgress(job);

  if (job.status === "done" && job.summary) {
    $("detail-summary").innerHTML = `
      <h3 class="section-title">Summary</h3>
      <div class="chips">${severityChips(job.summary.severity_totals)}</div>
      <span class="dim">
        ${num(job.summary.deduplicated_findings)} finding(s)
        (${num(job.summary.raw_findings)} raw, ${num(job.summary.duplicates_removed)} duplicates removed) ·
        tools: ${num(job.summary.tools_run)} ran, ${num(job.summary.tools_skipped)} skipped, ${num(job.summary.tools_error)} errored
      </span>`;
    await renderReport(jobId);
    setupReportTabs(job);
  } else {
    $("detail-summary").innerHTML = "";
    $("detail-findings").innerHTML = "";
    $("detail-tools").innerHTML = "";
    $("detail-subtabs").hidden = true;
    $("pane-graph").hidden = true;
    $("pane-findings").hidden = false;
    $("graph-mount").innerHTML = "";   // drop any heavy iframe from a prior job
    graphLoadedFor = null;
  }

  // Follow the scan live while it is active (poll the same panel in place).
  setBusy(isActive(job));
  clearTimeout(state.detailTimer);
  if (isActive(job)) {
    state.detailTimer = setTimeout(() => showDetail(jobId, true), POLL_ACTIVE_MS);
  }
  if (!isRefresh) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderDetailActions(job) {
  const actions = $("detail-actions");
  let html = "";
  if (job.status === "done") {
    const base = `/api/scans/${esc(job.id)}/report?format=`;
    html += `<a class="btn small" href="${base}html" target="_blank" rel="noopener">Open HTML report</a>`;
    html += `<a class="btn small" href="${base}pdf" download>Download PDF</a>`;
    for (const fmt of ["json", "md", "sarif", "junit"]) {
      html += `<a class="btn small ghost" href="${base}${fmt}" download>${fmt}</a>`;
    }
  }
  if (job.status !== "running") {
    html += `<button class="btn small danger" id="delete-btn" type="button">Delete</button>`;
  }
  actions.innerHTML = html;
  const deleteBtn = $("delete-btn");
  if (deleteBtn) {
    deleteBtn.addEventListener("click", () => deleteJob(job.id));
  }
}

async function deleteJob(jobId) {
  if (!window.confirm("Delete this scan and its reports?")) return;
  try {
    await api(`/api/scans/${jobId}`, { method: "DELETE" });
    if (String(state.currentId) === String(jobId)) state.currentId = null;
    if (String(state.selectedId) === String(jobId)) {
      clearTimeout(state.detailTimer);
      hideDetail();
    }
    if (state.tab === "history") await loadHistory();
  } catch (err) {
    $("detail-error").textContent = err.message;
  }
}

/* -- sortable + filterable report tables -- */

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// `desc: true` => first click on that header sorts descending (severity/numbers
// read best high-to-low); text columns default to ascending.
const FINDING_COLS = [
  { key: "severity", label: "Severity", desc: true },
  { key: "location", label: "Location" },
  { key: "message", label: "Message / CWEs" },
  { key: "tools", label: "Tools" },
  { key: "occurrences", label: "×", desc: true },
];
const TOOL_COLS = [
  { key: "scanner", label: "Scanner" },
  { key: "family", label: "Family" },
  { key: "status", label: "Status" },
  { key: "duration", label: "Duration", desc: true },
  { key: "findings", label: "Findings", desc: true },
  { key: "detail", label: "Detail", sortable: false },
];

function headRow(view, cols) {
  return "<tr>" + cols.map((c) => {
    if (c.sortable === false) return `<th>${esc(c.label)}</th>`;
    const active = view.sort === c.key;
    const arrow = active ? (view.dir === "asc" ? "▲" : "▼") : "↕";
    return `<th class="sortable${active ? " sorted" : ""}" data-sort="${esc(c.key)}">`
      + `${esc(c.label)} <span class="sort-ind">${arrow}</span></th>`;
  }).join("") + "</tr>";
}

function applySort(list, view, valueOf) {
  const dir = view.dir === "asc" ? 1 : -1;
  return list.slice().sort((a, b) => {
    const va = valueOf(a, view.sort), vb = valueOf(b, view.sort);
    if (va < vb) return -dir;
    if (va > vb) return dir;
    return 0;
  });
}

function wireHeaderSort(thead, view, cols, rerender) {
  thead.querySelectorAll("th.sortable").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (view.sort === key) {
        view.dir = view.dir === "asc" ? "desc" : "asc";
      } else {
        view.sort = key;
        const col = cols.find((c) => c.key === key);
        view.dir = col && col.desc ? "desc" : "asc";
      }
      rerender();
    });
  });
}

function countLabel(shown, total) {
  return shown === total ? `(${total})` : `(${shown} / ${total})`;
}

/* findings */

function findingValue(f, key) {
  switch (key) {
    case "severity": return SEV_RANK[f.severity] ?? -1;
    case "location": return (f.location || "").toLowerCase();
    case "message": return (f.message || "").toLowerCase();
    case "tools": return (f.tools || []).join(",").toLowerCase();
    case "occurrences": return num(f.occurrences);
    default: return 0;
  }
}

function findingMatches(f, q, sev, tool) {
  if (sev && f.severity !== sev) return false;
  if (tool && !(f.tools || []).includes(tool)) return false;
  if (!q) return true;
  const hay = `${f.location} ${f.message} ${(f.tools || []).join(" ")} `
    + `${(f.cwes || []).join(" ")} ${(f.rules || []).join(" ")}`;
  return hay.toLowerCase().includes(q.toLowerCase());
}

// Distinct tools across the findings, for the tool filter dropdown.
function findingTools() {
  return Array.from(new Set(state.findings.flatMap((f) => f.tools || []))).sort();
}

function findingRow(f) {
  return `
    <tr>
      <td><span class="chip ${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td class="loc-cell mono">${esc(f.location)}</td>
      <td class="msg-cell">${esc(f.message)}
        ${f.cwes && f.cwes.length ? `<div class="cwe">${esc(f.cwes.join(", "))}</div>` : ""}
      </td>
      <td>${esc((f.tools || []).join(", "))}</td>
      <td class="dim">${esc(f.occurrences)}</td>
    </tr>`;
}

function buildFindingsSection() {
  const view = state.findingsView;
  $("detail-findings").innerHTML = `
    <div class="section-head">
      <h3 class="section-title">Findings <span id="find-count" class="count"></span></h3>
      <div class="filter-bar">
        <input type="search" id="find-q" placeholder="Filter findings…" value="${esc(view.q)}">
        <select id="find-sev">
          <option value="">All severities</option>
          ${SEVERITIES.map((s) => `<option value="${s}"${view.sev === s ? " selected" : ""}>${s}</option>`).join("")}
        </select>
        <select id="find-tool">
          <option value="">All tools</option>
          ${findingTools().map((t) => `<option value="${esc(t)}"${view.tool === t ? " selected" : ""}>${esc(t)}</option>`).join("")}
        </select>
      </div>
    </div>
    <div class="table-wrap">
      <table class="findings-table">
        <thead id="findings-thead"></thead>
        <tbody id="findings-tbody"></tbody>
      </table>
    </div>`;
  $("find-q").addEventListener("input", (e) => { view.q = e.target.value; updateFindings(); });
  $("find-sev").addEventListener("change", (e) => { view.sev = e.target.value; updateFindings(); });
  $("find-tool").addEventListener("change", (e) => { view.tool = e.target.value; updateFindings(); });
  updateFindings();
}

function updateFindings() {
  const view = state.findingsView;
  const all = state.findings;
  const filtered = applySort(all.filter((f) => findingMatches(f, view.q, view.sev, view.tool)), view, findingValue);
  $("findings-thead").innerHTML = headRow(view, FINDING_COLS);
  wireHeaderSort($("findings-thead"), view, FINDING_COLS, updateFindings);
  $("find-count").textContent = countLabel(filtered.length, all.length);
  $("findings-tbody").innerHTML = filtered.length
    ? filtered.map(findingRow).join("")
    : `<tr><td colspan="${FINDING_COLS.length}" class="empty">No findings match the filter.</td></tr>`;
}

/* tools */

function toolValue(t, key) {
  switch (key) {
    case "scanner": return (t.scanner || "").toLowerCase();
    case "family": return (t.family || "").toLowerCase();
    case "status": return (t.status || "").toLowerCase();
    case "duration": return num(t.duration);
    case "findings": return num(t.findings ? t.findings.length : 0);
    default: return 0;
  }
}

function toolMatches(t, q, status) {
  if (status && t.status !== status) return false;
  if (!q) return true;
  const hay = `${t.scanner} ${t.family} ${t.status} ${t.error || ""} ${t.skip_reason || ""}`;
  return hay.toLowerCase().includes(q.toLowerCase());
}

function toolRow(t) {
  return `
    <tr>
      <td class="mono">${esc(t.scanner)}</td>
      <td>${esc(t.family)}</td>
      <td><span class="tool-status ${esc(t.status)}">${esc(t.status)}</span></td>
      <td class="dim">${esc(t.duration)}s</td>
      <td>${esc(t.findings ? t.findings.length : 0)}</td>
      <td class="dim">${esc(t.error || t.skip_reason || "")}</td>
    </tr>`;
}

function buildToolsSection() {
  const view = state.toolsView;
  if (!state.tools.length) {
    $("detail-tools").innerHTML = `
      <h3 class="section-title">Tools</h3>
      <span class="dim">No tools ran.</span>`;
    return;
  }
  const statuses = Array.from(new Set(state.tools.map((t) => t.status))).filter(Boolean).sort();
  $("detail-tools").innerHTML = `
    <div class="section-head">
      <h3 class="section-title">Tools <span id="tool-count" class="count"></span></h3>
      <div class="filter-bar">
        <input type="search" id="tool-q" placeholder="Filter tools…" value="${esc(view.q)}">
        <select id="tool-status">
          <option value="">All statuses</option>
          ${statuses.map((s) => `<option value="${esc(s)}"${view.status === s ? " selected" : ""}>${esc(s)}</option>`).join("")}
        </select>
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead id="tools-thead"></thead>
        <tbody id="tools-tbody"></tbody>
      </table>
    </div>`;
  $("tool-q").addEventListener("input", (e) => { view.q = e.target.value; updateTools(); });
  $("tool-status").addEventListener("change", (e) => { view.status = e.target.value; updateTools(); });
  updateTools();
}

function updateTools() {
  const view = state.toolsView;
  const all = state.tools;
  const filtered = applySort(all.filter((t) => toolMatches(t, view.q, view.status)), view, toolValue);
  $("tools-thead").innerHTML = headRow(view, TOOL_COLS);
  wireHeaderSort($("tools-thead"), view, TOOL_COLS, updateTools);
  $("tool-count").textContent = countLabel(filtered.length, all.length);
  $("tools-tbody").innerHTML = filtered.length
    ? filtered.map(toolRow).join("")
    : `<tr><td colspan="${TOOL_COLS.length}" class="empty">No tools match the filter.</td></tr>`;
}

async function renderReport(jobId) {
  let report;
  try {
    report = await api(`/api/scans/${jobId}/report?format=json`);
  } catch (err) {
    $("detail-findings").innerHTML = `<span class="error-msg">Failed to load report: ${esc(err.message)}</span>`;
    $("detail-tools").innerHTML = "";
    return;
  }

  state.findings = report.findings || [];
  state.tools = report.tools || [];
  state.findingsView = { sort: "severity", dir: "desc", q: "", sev: "" };
  state.toolsView = { sort: "scanner", dir: "asc", q: "", status: "" };

  if (!state.findings.length) {
    $("detail-findings").innerHTML = `
      <h3 class="section-title">Findings</h3>
      <span class="dim">No findings.</span>`;
  } else {
    buildFindingsSection();
  }
  buildToolsSection();
}

/* ---------- scanners & analyses info bubble ---------- */

const FAMILY_INFO = {
  sast: "Static code analysis - source code to vulnerabilities",
  sca: "Dependency vulnerabilities (SCA)",
  secret: "Hardcoded secrets, API keys & tokens",
  iac: "Infrastructure-as-code misconfiguration",
  license: "Dependency license compliance",
  pipeline: "CI/CD pipeline security",
  dast: "Dynamic scanning of a running URL",
  malware: "Malicious intent - malware signatures, threat patterns, prompt injection",
  analysis: "Code-graph taint / reachability analysis (no AI)",
  ai: "LLM triage & prioritization over other scanners' findings",
};

let infoCache = null;

async function loadScannerInfo() {
  if (infoCache) return infoCache;
  const [scanners, tools] = await Promise.all([
    api("/api/scanners"),
    api("/api/tools").catch(() => []),
  ]);
  const installed = {};
  for (const tool of tools || []) installed[tool.name] = tool;
  infoCache = { scanners: scanners || [], installed };
  return infoCache;
}

function scannerToolTag(scanner, installed) {
  if (!scanner.tool) return '<span class="scanner-tag builtin">built-in</span>';
  const tool = installed[scanner.tool];
  if (!tool) return `<span class="scanner-tag">tool: ${esc(scanner.tool)}</span>`;
  const cls = tool.installed ? "ok" : "missing";
  const mark = tool.installed ? "✓ installed" : "· not installed";
  return `<span class="scanner-tag ${cls}">tool: ${esc(scanner.tool)} - ${mark}</span>`;
}

function renderScannerInfo(data) {
  const groups = {};
  for (const scanner of data.scanners) {
    (groups[scanner.family] = groups[scanner.family] || []).push(scanner);
  }
  const order = Object.keys(FAMILY_INFO).filter((fam) => groups[fam]);
  for (const fam of Object.keys(groups)) if (!order.includes(fam)) order.push(fam);

  const total = data.scanners.length;
  let html = `<p class="dim info-count">${total} scanner${total > 1 ? "s" : ""} `
    + `across ${order.length} famil${order.length > 1 ? "ies" : "y"}.</p>`;
  for (const fam of order) {
    const list = groups[fam].slice().sort((a, b) => a.name.localeCompare(b.name));
    const scanners = list.map((scanner) => `
      <div class="scanner">
        <div class="scanner-head">
          <code>${esc(scanner.name)}</code>
          <span class="scanner-mode">${esc(scanner.mode)}</span>
          ${scannerToolTag(scanner, data.installed)}
        </div>
        <div class="scanner-desc dim">${esc(scanner.description || "")}</div>
      </div>`).join("");
    html += `
      <section class="info-group">
        <h3 class="info-group-head">
          <span class="info-fam">${esc(fam)}</span>
          <span class="dim">${esc(FAMILY_INFO[fam] || "")}</span>
        </h3>
        ${scanners}
      </section>`;
  }
  return html;
}

async function openInfo() {
  $("info-modal").hidden = false;
  try {
    $("info-body").innerHTML = renderScannerInfo(await loadScannerInfo());
  } catch (err) {
    $("info-body").innerHTML = `<span class="error-msg">Failed to load scanners: ${esc(err.message)}</span>`;
  }
}

function closeInfo() {
  $("info-modal").hidden = true;
}

/* ---------- boot ---------- */

function wireSourceInputs() {
  document.querySelectorAll(".mode-tab")
    .forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));
  document.querySelectorAll(".source-tab")
    .forEach((tab) => tab.addEventListener("click", () => setSource(tab.dataset.source)));
  $("pick-folder").addEventListener("click", () => $("folder-input").click());
  $("pick-zip").addEventListener("click", () => $("zip-input").click());
  $("folder-input").addEventListener("change", onFolderInput);
  $("zip-input").addEventListener("change", onZipInput);
  const dz = $("dropzone");
  dz.addEventListener("dragenter", (e) => { e.preventDefault(); dz.classList.add("dragover"); });
  dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("dragover"); });
  dz.addEventListener("dragleave", () => dz.classList.remove("dragover"));
  dz.addEventListener("drop", onDrop);
  dz.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("folder-input").click(); }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  buildFamilyChecks();
  wireSourceInputs();
  $("scan-form").addEventListener("submit", submitScan);
  document.querySelectorAll(".main-tab")
    .forEach((b) => b.addEventListener("click", () => setTab(b.dataset.tab)));
  $("refresh-btn").addEventListener("click", () => loadHistory());
  $("info-btn").addEventListener("click", openInfo);
  $("info-close").addEventListener("click", closeInfo);
  $("info-modal").addEventListener("click", (event) => {
    if (event.target.id === "info-modal") closeInfo();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("info-modal").hidden) closeInfo();
  });
  setTab("new");
});
