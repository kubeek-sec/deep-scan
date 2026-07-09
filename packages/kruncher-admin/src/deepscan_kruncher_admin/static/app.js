"use strict";

async function api(p, opts) {
  const r = await fetch("/api" + p, opts);
  if (!r.ok) {
    let detail = r.status + " " + r.statusText;
    try { const j = await r.json(); if (j && j.detail) detail = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); }
    catch (_) { /* non-JSON error body */ }
    throw new Error(detail);
  }
  return r.status === 204 ? null : r.json();
}
function jsonBody(obj) {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(obj) };
}
const el = (sel) => document.querySelector(sel);
const h = (s) => String(s ?? "").replace(/[&<>"]/g, c => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const sevCell = (r) => `
  <span class="pill crit" title="critical">${r.crit ?? 0}</span>
  <span class="pill high" title="high">${r.high ?? 0}</span>
  <span class="pill med"  title="medium">${r.med ?? 0}</span>
  <span class="pill low"  title="low">${r.low ?? 0}</span>`;

function toast(msg, isError) {
  const t = el("#toast");
  t.textContent = msg; t.hidden = false;
  t.classList.toggle("error", !!isError);
  setTimeout(() => { t.hidden = true; }, 3200);
}

// ---- navigation --------------------------------------------------------- //
let view = "dashboard";
let jobPollTimer = null;   // live-refresh of the open job drawer while it runs
document.querySelectorAll(".tab").forEach(btn => btn.onclick = () => {
  view = btn.dataset.view;
  document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b === btn));
  document.querySelectorAll(".view").forEach(v => v.hidden = v.id !== "view-" + view);
  render();
});
el("#refresh").onclick = () => render();

function render() {
  if (view === "dashboard") loadDashboard();
  else if (view === "scopes") loadScopes();
  else if (view === "sources") loadSources();
  else if (view === "jobs") loadJobs();
}

// ---- dashboard ---------------------------------------------------------- //
async function loadDashboard() {
  const p = await api("/posture");
  const t = p.totals || {};
  el("#posture-cards").innerHTML = [
    card("Sources scanned", t.sources_scanned ?? 0, "neutral"),
    card("At risk (crit+high)", t.sources_at_risk ?? 0, "warn"),
    card("Critical findings", t.crit ?? 0, "crit"),
    card("High findings", t.high ?? 0, "high"),
    card("Medium findings", t.med ?? 0, "med"),
  ].join("");

  el("#scope-table").innerHTML = table(
    ["Scope", "Conn.", "Scanned", "Severity"],
    (p.by_scope || []).map(s => [
      h(s.scope_name), h(s.connector), s.sources_scanned, sevCell(s)
    ]));
  el("#top-table").innerHTML = table(
    ["Source", "Scope", "Severity", ""],
    (p.top_sources || []).map(s => [
      h(s.name), h(s.scope_name), sevCell(s),
      `<button class="link" data-src="${s.id}">view</button>`
    ]));
  el("#top-table").querySelectorAll("[data-src]").forEach(b =>
    b.onclick = () => openSource(b.dataset.src));
  loadTrend(currentWindow);
}

function card(label, value, kind) {
  return `<div class="kpi ${kind}"><div class="kpi-val">${value}</div>
          <div class="kpi-label">${label}</div></div>`;
}

let currentWindow = "3m";
document.querySelectorAll(".seg-btn").forEach(b => b.onclick = () => {
  currentWindow = b.dataset.window;
  document.querySelectorAll(".seg-btn").forEach(x => x.classList.toggle("active", x === b));
  loadTrend(currentWindow);
});

async function loadTrend(win) {
  const { series } = await api("/trends?window=" + win);
  el("#trend-chart").innerHTML = stackedBars(series);
}

// Stacked bars (inline SVG, no chart lib): the carried-forward active-findings
// total per bucket, coloured by severity. Each bucket is one <g> with a <title>
// so hovering anywhere on the column shows the full breakdown + total.
const TREND_SEVS = [["crit", "critical"], ["high", "high"], ["med", "medium"], ["low", "low"]];

function stackedBars(series) {
  if (!series.length) return `<p class="empty">No scan history yet.</p>`;
  const W = 760, H = 200, pad = 24;
  const slot = (W - 2 * pad) / series.length;
  const bw = Math.max(6, slot - 6);
  const inner = H - 2 * pad;
  const total = (s) => TREND_SEVS.reduce((a, [k]) => a + (+s[k] || 0), 0);
  const max = Math.max(1, ...series.map(total));

  let svg = "";
  series.forEach((s, i) => {
    const x = pad + i * slot + (slot - bw) / 2;
    const date = String(s.bucket).slice(0, 10);
    const tip = [date, ...TREND_SEVS.map(([k, name]) => `${name}: ${+s[k] || 0}`),
                 `total: ${total(s)}`].join("\n");
    // transparent hit area spans the full column so the whole bar is hoverable
    let g = `<g><title>${h(tip)}</title>`
      + `<rect x="${x.toFixed(1)}" y="${pad}" width="${bw.toFixed(1)}" height="${inner}" fill="transparent"/>`;
    let y = H - pad;
    TREND_SEVS.forEach(([k]) => {
      const v = +s[k] || 0, bh = (v / max) * inner;
      if (bh > 0) {
        y -= bh;
        g += `<rect class="bar ${k}" x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${bh.toFixed(1)}"/>`;
      }
    });
    g += "</g>";
    svg += g;
    svg += `<text class="xlabel" x="${(x + bw / 2).toFixed(1)}" y="${H - 6}" text-anchor="middle">${date.slice(5)}</text>`;
  });
  return `<svg viewBox="0 0 ${W} ${H}" class="svg-chart">${svg}</svg>`;
}

// ---- sources ------------------------------------------------------------ //
let srcOffset = 0, srcLimit = 50, srcTotal = 0;
let scopeCache = [];
async function fillScopeSelect() {
  const sel = el("#src-scope");
  scopeCache = await api("/scopes");
  const current = sel.value;
  sel.innerHTML = `<option value="">All scopes</option>` +
    scopeCache.map(s => `<option value="${s.id}">${h(s.name)}</option>`).join("");
  sel.value = current;
}
["src-search", "src-scope", "src-risk"].forEach(id =>
  el("#" + id).addEventListener("input", () => { srcOffset = 0; loadSources(); }));
el("#src-prev").onclick = () => { srcOffset = Math.max(0, srcOffset - srcLimit); loadSources(); };
el("#src-next").onclick = () => { if (srcOffset + srcLimit < srcTotal) { srcOffset += srcLimit; loadSources(); } };

async function loadSources() {
  await fillScopeSelect();
  const q = el("#src-search").value, scope = el("#src-scope").value, risk = el("#src-risk").value;
  const params = new URLSearchParams({ limit: srcLimit, offset: srcOffset, include_inactive: true });
  if (q) params.set("q", q);
  if (scope) params.set("scope_id", scope);
  if (risk) params.set("risk", risk);
  const data = await api("/sources?" + params);
  srcTotal = data.total;
  el("#sources-table").innerHTML = table(
    ["Source", "Scope", "Kind", "Severity", "Scanned", "Actions"],
    data.items.map(s => [
      h(s.name) + (s.active ? "" : ` <span class="status superseded">inactive</span>`),
      h(s.scope_name), h(s.kind),
      s.scanned ? sevCell(s) : `<span class="muted">unscanned</span>`,
      s.last_scanned_at ? h(String(s.last_scanned_at).slice(0, 16)) : "-",
      sourceActions(s)
    ]));
  wireSourceActions();
  const from = srcTotal ? srcOffset + 1 : 0;
  el("#src-page-info").textContent = `${from}–${Math.min(srcOffset + srcLimit, srcTotal)} of ${srcTotal}`;
}

function sourceActions(s) {
  const toggle = s.active
    ? `<button class="link" data-deact="${s.id}">disable</button>`
    : `<button class="link" data-act="${s.id}">enable</button>`;
  return `<div class="row-actions">
    <button class="link" data-src="${s.id}">view</button>
    <button class="link" data-scan="${s.id}">scan</button>
    <button class="link" data-editsrc="${s.id}">edit</button>
    ${toggle}
    <button class="link" data-delsrc="${s.id}">delete</button></div>`;
}

function wireSourceActions() {
  const root = el("#sources-table");
  root.querySelectorAll("[data-src]").forEach(b => b.onclick = () => openSource(b.dataset.src));
  root.querySelectorAll("[data-scan]").forEach(b => b.onclick = () =>
    act("/sources/" + b.dataset.scan + "/scan", "Scan queued.", loadSources));
  root.querySelectorAll("[data-act]").forEach(b => b.onclick = () =>
    act("/sources/" + b.dataset.act + "/active?active=true", "Source enabled.", loadSources));
  root.querySelectorAll("[data-deact]").forEach(b => b.onclick = () =>
    act("/sources/" + b.dataset.deact + "/active?active=false", "Source disabled.", loadSources));
  root.querySelectorAll("[data-editsrc]").forEach(b => b.onclick = () => editSource(b.dataset.editsrc));
  root.querySelectorAll("[data-delsrc]").forEach(b => b.onclick = () => confirmDelete(
    "source", "/sources/" + b.dataset.delsrc, loadSources));
}

el("#add-source").onclick = () => addSource();

// ---- jobs --------------------------------------------------------------- //
// Two queues share the table: 'adhoc' = manual (API/MCP), 'discovery' = periodic.
const QUEUE = {
  adhoc: { label: "Manual", cls: "manual" },
  discovery: { label: "Periodic", cls: "periodic" },
};
function queueBadge(origin) {
  const q = QUEUE[origin] || { label: origin || "?", cls: "" };
  return `<span class="queue-badge ${q.cls}">${h(q.label)}</span>`;
}
// A periodic job names its source; a manual job names its ad-hoc target.
function jobSubject(j) {
  if (j.source_name) return h(j.source_name);
  if (j.target) return `<span class="mono" title="${h(j.target)}">${h(j.target)}</span>`;
  return "-";
}

el("#job-status").addEventListener("change", loadJobs);
el("#job-origin").addEventListener("change", loadJobs);
async function loadJobs() {
  const status = el("#job-status").value;
  const origin = el("#job-origin").value;
  const [jobs] = await Promise.all([
    api("/jobs?limit=200" + (status ? "&status=" + status : "") + (origin ? "&origin=" + origin : "")),
    renderQueueDepth(),
  ]);
  el("#jobs-table").innerHTML = table(
    ["#", "Queue", "Subject", "Status", "Try", "Progress", "Updated", "Actions"],
    jobs.map(j => [
      j.id, queueBadge(j.origin), jobSubject(j),
      `<span class="status ${j.status}">${j.status}</span>`,
      `${j.attempt}/${j.max_attempts}`,
      `<div class="progress"><span style="width:${j.completion}%"></span></div>`,
      h(String(j.updated_at).slice(0, 16)),
      jobActions(j)
    ]));
  el("#jobs-table").querySelectorAll("[data-relaunch]").forEach(b =>
    b.onclick = () => act("/jobs/" + b.dataset.relaunch + "/relaunch", "Re-queued."));
  el("#jobs-table").querySelectorAll("[data-cancel]").forEach(b =>
    b.onclick = () => act("/jobs/" + b.dataset.cancel + "/cancel", "Cancellation requested."));
  el("#jobs-table").querySelectorAll("[data-job]").forEach(b =>
    b.onclick = () => openJob(b.dataset.job));
}

// Live depth of each queue, so an operator sees manual vs periodic backlog.
async function renderQueueDepth() {
  let queues;
  try { queues = (await api("/overview")).queues || {}; }
  catch (_) { el("#queue-depth").innerHTML = ""; return; }
  const cell = (origin) => {
    const d = queues[origin] || {};
    const q = QUEUE[origin];
    return `<span class="qd ${q.cls}">${q.label}: `
      + `<b>${d.queued || 0}</b> queued · <b>${d.running || 0}</b> running</span>`;
  };
  el("#queue-depth").innerHTML = cell("adhoc") + cell("discovery");
}
function jobActions(j) {
  const relaunch = ["failed", "dead", "done", "superseded", "cancelled"].includes(j.status)
    ? `<button class="link" data-relaunch="${j.id}">relaunch</button>` : "";
  const cancel = ["queued", "failed", "running"].includes(j.status)
    ? `<button class="link" data-cancel="${j.id}">${j.status === "running" ? "stop" : "cancel"}</button>` : "";
  return `<button class="link" data-job="${j.id}">log</button> ${relaunch} ${cancel}`;
}
async function act(path, ok, after) {
  try { await api(path, { method: "POST" }); toast(ok); (after || loadJobs)(); }
  catch (e) { toast("Failed: " + e.message, true); }
}

// ---- drawer ------------------------------------------------------------- //
el("#drawer-close").onclick = () => { clearTimeout(jobPollTimer); el("#drawer").hidden = true; };
async function openSource(id) {
  clearTimeout(jobPollTimer);
  const d = await api("/sources/" + id);
  el("#drawer-title").textContent = d.source.name;
  el("#drawer-body").innerHTML =
    `<h4>Latest findings</h4>` + table(["Sev", "Location", "Message"],
      d.findings.map(f => [`<span class="status ${f.severity}">${f.severity}</span>`,
        h(f.location), h(f.message)])) +
    `<h4>Scan history</h4>` + table(["When", "Severity", "Findings"],
      d.history.map(r => [h(String(r.scanned_at).slice(0, 16)), sevCell(r), r.total_findings]));
  el("#drawer").hidden = false;
}
// ---- job detail: progress (completion + steps) + findings report -------- //
const STEP_ICON = { pending: "○", running: "◍", done: "✓", skipped: "⊘", error: "✗" };

function stepRowHtml(s) {
  const meta = [];
  if (s.family) meta.push(h(s.family));
  if (s.duration != null) meta.push((+s.duration).toFixed(1) + "s");
  if (s.status === "done" && s.findings != null) meta.push(s.findings + (s.findings === 1 ? " finding" : " findings"));
  if (s.status === "skipped") meta.push("skipped");
  const detail = s.detail ? `<div class="step-detail">${h(s.detail)}</div>` : "";
  return `<li class="step ${h(s.status)}"><span class="step-icon">${STEP_ICON[s.status] || "○"}</span>`
    + `<span class="step-name">${h(s.label || s.name)}</span>`
    + `<span class="step-meta">${meta.join(" · ")}</span>${detail}</li>`;
}

function jobProgressHtml(j) {
  const pct = j.completion || 0;
  let html = `<div class="jobprog"><span style="width:${pct}%"></span></div>`
    + `<div class="muted small">${pct}% · ${h(j.stage || j.status)}</div>`;
  const steps = j.steps && j.steps.steps;
  if (steps && steps.length) html += `<ol class="steps-log">${steps.map(stepRowHtml).join("")}</ol>`;
  return html;
}

function jobReportHtml(report) {
  if (!report) return "";
  const sum = report.summary, finds = report.findings || [];
  let html = "";
  if (sum && sum.severity_totals) {
    const t = sum.severity_totals;
    html += `<h4>Summary</h4>`
      + sevCell({ crit: t.critical, high: t.high, med: t.medium, low: t.low })
      + ` <span class="muted small">${sum.deduplicated_findings ?? finds.length} finding(s)</span>`;
  }
  if (finds.length) {
    html += `<h4>Findings (${finds.length})</h4>` + table(
      ["Sev", "Location", "Message", "Tools", "CWE"],
      finds.map(f => [
        `<span class="status ${h(f.severity)}">${h(f.severity)}</span>`,
        `<span class="mono">${h(f.location)}</span>`, h(f.message),
        h((f.tools || []).join(", ")), h((f.cwes || []).join(", ") || "-"),
      ]));
  } else if (sum) {
    html += `<p class="muted small">Full findings not available here - open it in the API dashboard.</p>`;
  }
  return html;
}

async function openJob(id) {
  clearTimeout(jobPollTimer);
  const d = await api("/jobs/" + id);
  const j = d.job;
  el("#drawer-title").innerHTML = "Job #" + id + " " + queueBadge(j.origin);
  el("#drawer-body").innerHTML =
    `<pre class="kv">status: ${h(j.status)}   attempt: ${j.attempt}/${j.max_attempts}
${j.source_name ? "source: " + h(j.source_name) : "target: " + h(j.target || "-")}
${j.source_path ? "files: " + h(j.source_path) + "\n" : ""}${j.upload_id ? "upload: " + h(j.upload_id) + "\n" : ""}${j.git_commit ? "commit: " + h(j.git_commit) + "\n" : ""}${j.fingerprint ? "fingerprint: " + h(j.fingerprint.slice(0, 23)) + "…\n" : ""}${j.target_revision ? "revision: " + h(j.target_revision) + "\n" : ""}${j.error ? "error: " + h(j.error) : ""}</pre>`
    + `<h4>Progress</h4>` + jobProgressHtml(j)
    + jobReportHtml(d.report)
    + `<h4>Attempts</h4>` + table(["#", "Status", "Error"],
        d.attempts.map(a => [a.attempt, h(a.status), h(a.error || a.log || "")]));
  el("#drawer").hidden = false;
  // live-refresh while the job is still running and this drawer stays open
  if (j.status === "queued" || j.status === "running") {
    jobPollTimer = setTimeout(() => { if (!el("#drawer").hidden) openJob(id); }, 2500);
  }
}

// ---- tiny table helper -------------------------------------------------- //
function table(cols, rows) {
  if (!rows.length) return `<p class="empty">Nothing here.</p>`;
  return `<table><thead><tr>${cols.map(c => `<th>${c}</th>`).join("")}</tr></thead>
    <tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

// ---- modal + form helpers ----------------------------------------------- //
function openModal(title, bodyHTML, onSave, saveLabel) {
  const root = el("#modal-root");
  root.innerHTML = `
    <div class="modal-backdrop">
      <div class="modal">
        <div class="modal-head"><h3>${h(title)}</h3><button class="ghost" id="modal-x">✕</button></div>
        <div class="modal-body">${bodyHTML}</div>
        <div class="modal-foot">
          <button class="btn subtle" id="modal-cancel">Cancel</button>
          <button class="btn" id="modal-save">${h(saveLabel || "Save")}</button>
        </div>
      </div>
    </div>`;
  const close = () => { root.innerHTML = ""; };
  el("#modal-x").onclick = close;
  el("#modal-cancel").onclick = close;
  el(".modal-backdrop").onclick = (e) => { if (e.target.classList.contains("modal-backdrop")) close(); };
  el("#modal-save").onclick = async () => {
    try { await onSave(); close(); }
    catch (e) { toast(e.message, true); }
  };
}
const field = (id, label, value, attrs = "") =>
  `<label class="form-field"><span>${h(label)}</span><input id="${id}" value="${h(value ?? "")}" ${attrs}></label>`;

function confirmDelete(label, path, after) {
  openModal("Confirm delete", `<p>Delete this ${h(label)}? This cannot be undone.</p>`, async () => {
    await api(path, { method: "DELETE" });
    toast("Deleted.");
    after();
  }, "Delete");
  const save = el("#modal-save");
  if (save) save.classList.add("danger");
}

// ---- scopes view -------------------------------------------------------- //
async function loadScopes() {
  const [scopes, overview] = await Promise.all([api("/scopes"), api("/overview")]);
  const counts = {};
  (overview.scopes || []).forEach(s => { counts[s.scope_id] = s; });
  el("#scopes-table").innerHTML = table(
    ["Name", "Connector", "Enabled", "Sources", "Config", "Actions"],
    scopes.map(s => {
      const inv = counts[s.id] || {};
      return [
        h(s.name), h(s.connector),
        s.enabled ? `<span class="status done">on</span>` : `<span class="status superseded">off</span>`,
        `${inv.sources ?? 0} (${inv.sources_scanned ?? 0} scanned)`,
        `<code class="hint">${h(JSON.stringify(s.config))}</code>`,
        scopeActions(s),
      ];
    }));
  wireScopeActions();
}
function scopeActions(s) {
  const toggle = s.enabled
    ? `<button class="link" data-disable="${s.id}">disable</button>`
    : `<button class="link" data-enable="${s.id}">enable</button>`;
  return `<div class="row-actions">
    <button class="link" data-discover="${s.id}">discover</button>
    <button class="link" data-editscope="${s.id}">edit</button>
    ${toggle}
    <button class="link" data-delscope="${s.id}">delete</button></div>`;
}
function wireScopeActions() {
  const root = el("#scopes-table");
  root.querySelectorAll("[data-discover]").forEach(b => b.onclick = () =>
    act("/scopes/" + b.dataset.discover + "/discover", "Discovery started.", loadScopes));
  root.querySelectorAll("[data-enable]").forEach(b => b.onclick = () =>
    act("/scopes/" + b.dataset.enable + "/enabled?enabled=true", "Scope enabled.", loadScopes));
  root.querySelectorAll("[data-disable]").forEach(b => b.onclick = () =>
    act("/scopes/" + b.dataset.disable + "/enabled?enabled=false", "Scope disabled.", loadScopes));
  root.querySelectorAll("[data-editscope]").forEach(b => b.onclick = () => editScope(b.dataset.editscope));
  root.querySelectorAll("[data-delscope]").forEach(b => b.onclick = () => confirmDelete(
    "scope (and all its sources & history)", "/scopes/" + b.dataset.delscope, loadScopes));
}

async function scopeForm(existing) {
  const meta = await api("/connectors");
  const conns = meta.available;
  const cfg = existing ? existing.config : (meta.examples[conns[0]] || {});
  const body = `
    ${field("f-name", "Name", existing && existing.name)}
    <label class="form-field"><span>Connector</span>
      <select id="f-connector">${conns.map(c =>
        `<option value="${c}" ${existing && existing.connector === c ? "selected" : ""}>${c}</option>`).join("")}</select></label>
    <label class="form-field"><span>Connector config (JSON)</span>
      <textarea id="f-config">${h(JSON.stringify(cfg, null, 2))}</textarea></label>
    <label class="form-field"><span>Families (comma-separated, blank = all)</span>
      <input id="f-families" value="${h(((existing && existing.families) || []).join(","))}"></label>
    <div class="form-row">
      ${field("f-refresh", "Discovery interval (s)", (existing && existing.refresh_interval_seconds) || 3600, "type=number")}
      ${field("f-rescan", "Change-probe interval (s)", (existing && existing.rescan_interval_seconds) || 86400, "type=number")}
    </div>
    <label class="form-field inline"><input type="checkbox" id="f-enabled" ${!existing || existing.enabled ? "checked" : ""}><span>Enabled</span></label>`;
  const save = async () => {
    let config;
    try { config = JSON.parse(el("#f-config").value || "{}"); }
    catch (e) { throw new Error("Config is not valid JSON: " + e.message); }
    const payload = {
      name: el("#f-name").value.trim(),
      connector: el("#f-connector").value,
      config,
      families: el("#f-families").value.split(",").map(x => x.trim()).filter(Boolean),
      refresh_interval_seconds: +el("#f-refresh").value || 3600,
      rescan_interval_seconds: +el("#f-rescan").value || 86400,
      enabled: el("#f-enabled").checked,
    };
    if (existing) await api("/scopes/" + existing.id, { ...jsonBody(payload), method: "PUT" });
    else await api("/scopes", jsonBody(payload));
    toast(existing ? "Scope updated." : "Scope created.");
    loadScopes();
  };
  openModal(existing ? "Edit scope" : "Add scope", body, save, existing ? "Save" : "Create");
  const connSel = el("#f-connector");
  connSel.onchange = () => {
    if (!existing) el("#f-config").value = JSON.stringify(meta.examples[connSel.value] || {}, null, 2);
  };
}
function addScope() { scopeForm(null); }
async function editScope(id) {
  const scopes = scopeCache.length ? scopeCache : await api("/scopes");
  scopeForm(scopes.find(s => String(s.id) === String(id)));
}
el("#add-scope").onclick = addScope;

// ---- source forms ------------------------------------------------------- //
async function sourceForm(detail) {
  const s = detail ? detail.source : null;
  const scopes = await api("/scopes");
  const body = s ? `
    ${field("s-name", "Name", s.name)}
    ${field("s-location", "Location (clone URL or path)", s.location)}
    ${field("s-branch", "Default branch", s.default_branch)}
  ` : `
    <label class="form-field"><span>Scope</span>
      <select id="s-scope">${scopes.map(x => `<option value="${x.id}">${h(x.name)}</option>`).join("")}</select></label>
    <label class="form-field"><span>Kind</span>
      <select id="s-kind"><option value="git">git</option><option value="directory">directory</option></select></label>
    ${field("s-name", "Name", "")}
    ${field("s-location", "Location (clone URL or path)", "")}
    ${field("s-branch", "Default branch (git)", "main")}`;
  const save = async () => {
    if (s) {
      await api("/sources/" + s.id, { ...jsonBody({
        name: el("#s-name").value.trim(),
        location: el("#s-location").value.trim(),
        default_branch: el("#s-branch").value.trim() || null,
      }), method: "PUT" });
      toast("Source updated.");
    } else {
      await api("/sources", jsonBody({
        scope_id: +el("#s-scope").value,
        kind: el("#s-kind").value,
        name: el("#s-name").value.trim(),
        location: el("#s-location").value.trim(),
        default_branch: el("#s-branch").value.trim() || null,
      }));
      toast("Source added.");
    }
    loadSources();
  };
  openModal(s ? "Edit source" : "Add source", body, save, s ? "Save" : "Add");
}
function addSource() { sourceForm(null); }
async function editSource(id) { sourceForm(await api("/sources/" + id)); }

render();
