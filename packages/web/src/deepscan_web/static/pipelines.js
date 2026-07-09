/* Deep Scan - CI templates wizard (vanilla JS, no build step).
 *
 * A five-step flow that POSTs the user's selection to /api/pipeline/generate and
 * shows a ready-to-commit pipeline file. Self-contained: it owns everything under
 * #view-ci and exposes window.DeepScanPipelines.show(), called by app.js when the
 * "CI templates" tab is opened. */
"use strict";

(function () {
  const $ = (id) => document.getElementById(id);
  const ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ESC_MAP[c]);

  async function apiGet(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error(await errorText(res));
    return res.json();
  }
  async function apiPost(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(await errorText(res));
    return res.json();
  }
  async function errorText(res) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body && body.detail) {
        message = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      }
    } catch (_) { /* non-JSON body */ }
    return message;
  }

  const FORMAT_LABELS = {
    json: "JSON", md: "Markdown", html: "HTML", sarif: "SARIF 2.1.0",
    junit: "JUnit XML", pdf: "PDF",
  };
  const STEP_TITLES = ["Platform", "What to scan", "Report formats", "Severity gate", "Review & generate"];
  const TOTAL = STEP_TITLES.length;
  // Capabilities enabled out of the box - a sensible secure-by-default starter.
  const DEFAULT_ON = new Set(["secret", "sca", "sast"]);

  const wiz = {
    loaded: false,
    options: null,
    step: 1,
    platform: null,
    caps: {},     // key -> { enabled, isSbom, tools: { name: bool } }
    formats: new Set(),
    failOn: "high",
    gate: "fail",
    adv: { image: "", target: "", reportsDir: "", configDir: "", env: [] },
    result: null,
    error: "",
  };

  function initFromOptions() {
    const o = wiz.options;
    wiz.adv.image = o.image || "";
    wiz.adv.target = o.defaults.target || ".";
    wiz.adv.reportsDir = o.defaults.reports_dir || "deepscan-reports";
    wiz.adv.configDir = "";
    wiz.adv.env = [];
    wiz.formats = new Set(o.defaults.formats || ["sarif", "html"]);
    wiz.failOn = o.defaults.fail_on || "high";
    wiz.gate = o.defaults.gate || "fail";
    wiz.caps = {};
    for (const cap of o.capabilities) {
      const tools = {};
      for (const t of cap.tools) tools[t.name] = !!t.default;
      wiz.caps[cap.key] = {
        enabled: DEFAULT_ON.has(cap.key),
        isSbom: cap.family == null,
        tools,
      };
    }
  }

  /* ---------- selection → request ---------- */

  function selectedCapabilities() {
    const out = [];
    for (const cap of wiz.options.capabilities) {
      const st = wiz.caps[cap.key];
      if (!st || !st.enabled) continue;
      if (st.isSbom) { out.push({ key: cap.key, scanners: [] }); continue; }
      const names = cap.tools.filter((t) => st.tools[t.name]).map((t) => t.name);
      if (!names.length) continue;
      // All tools picked → send [] so the backend can use --family (future-proof).
      out.push({ key: cap.key, scanners: names.length === cap.tools.length ? [] : names });
    }
    return out;
  }

  function selectedCapCount() {
    return selectedCapabilities().length;
  }

  function buildRequest() {
    const env = {};
    for (const row of wiz.adv.env) {
      const key = (row.key || "").trim();
      if (key) env[key] = row.value || "";
    }
    return {
      platform: wiz.platform,
      capabilities: selectedCapabilities(),
      formats: Array.from(wiz.formats),
      fail_on: wiz.failOn === "none" ? null : wiz.failOn,
      gate: wiz.gate,
      image: wiz.adv.image.trim() || null,
      target: wiz.adv.target.trim() || null,
      reports_dir: wiz.adv.reportsDir.trim() || null,
      config_dir: wiz.adv.configDir.trim() || null,
      env: Object.keys(env).length ? env : null,
    };
  }

  /* ---------- skeleton + render ---------- */

  async function show() {
    const root = $("view-ci");
    if (!wiz.loaded) {
      root.innerHTML = `<section class="panel"><div class="dim">Loading…</div></section>`;
      try {
        wiz.options = await apiGet("/api/pipeline/options");
      } catch (err) {
        root.innerHTML = `<section class="panel"><span class="error-msg">Failed to load options: ${esc(err.message)}</span></section>`;
        return;
      }
      initFromOptions();
      buildSkeleton(root);
      wiz.loaded = true;
    }
    render();
  }

  function buildSkeleton(root) {
    root.innerHTML = `
      <section class="panel" id="ci-panel">
        <div class="panel-head">
          <h2>Generate a CI pipeline</h2>
          <div id="ci-steps" class="ci-steps"></div>
        </div>
        <p class="dim ci-lead">A ready-to-commit pipeline that runs Deep Scan from this project's Docker image
          (<code>${esc(wiz.options.image)}</code>) via <code>uv run deepscan scan</code>.</p>
        <div id="ci-body" class="ci-body"></div>
        <div class="form-footer ci-footer">
          <button type="button" class="btn ghost" id="ci-back">← Back</button>
          <button type="button" class="btn primary" id="ci-next">Next →</button>
          <span id="ci-error" class="error-msg" role="alert"></span>
        </div>
      </section>
      <section class="panel" id="ci-result-panel" hidden></section>`;
    $("ci-back").addEventListener("click", onBack);
    $("ci-next").addEventListener("click", onNext);
  }

  function render() {
    renderStepper();
    renderBody();
    renderFooter();
    $("ci-error").textContent = wiz.error || "";
  }

  function renderStepper() {
    const el = $("ci-steps");
    el.innerHTML = STEP_TITLES.map((title, i) => {
      const n = i + 1;
      const cls = n === wiz.step ? "active" : n < wiz.step ? "done" : "";
      return `<button type="button" class="ci-step ${cls}" data-step="${n}">
        <span class="ci-step-n">${n}</span><span class="ci-step-t">${esc(title)}</span></button>`;
    }).join("");
    el.querySelectorAll(".ci-step").forEach((b) => {
      b.addEventListener("click", () => goStep(Number(b.dataset.step)));
    });
  }

  function renderFooter() {
    $("ci-back").disabled = wiz.step === 1;
    $("ci-next").textContent = wiz.step === TOTAL ? "Generate template" : "Next →";
  }

  function renderBody() {
    const body = $("ci-body");
    if (wiz.step === 1) renderPlatform(body);
    else if (wiz.step === 2) renderCapabilities(body);
    else if (wiz.step === 3) renderFormats(body);
    else if (wiz.step === 4) renderGate(body);
    else renderReview(body);
  }

  /* ---------- step 1: platform ---------- */

  function renderPlatform(body) {
    body.innerHTML = `
      <p class="ci-help">Pick your CI/CD platform. The generated file goes at the shown path in your repo.</p>
      <div class="ci-cards">
        ${wiz.options.platforms.map((p) => `
          <button type="button" class="ci-card ${wiz.platform === p.key ? "active" : ""}" data-key="${esc(p.key)}">
            <span class="ci-card-title">${esc(p.label)}</span>
            <span class="ci-card-sub mono">${esc(p.filename)}</span>
          </button>`).join("")}
      </div>`;
    body.querySelectorAll(".ci-card").forEach((b) => {
      b.addEventListener("click", () => { wiz.platform = b.dataset.key; wiz.error = ""; render(); });
    });
  }

  /* ---------- step 2: capabilities + tools ---------- */

  function renderCapabilities(body) {
    body.innerHTML = `
      <p class="ci-help">Choose what to scan for, and which tools to run for each. All run in one scan;
        a partial tool selection is passed as explicit <code>--scanner</code> flags.</p>
      <div class="ci-caps">
        ${wiz.options.capabilities.map(renderCapCard).join("")}
      </div>`;
    body.querySelectorAll(".ci-cap-toggle").forEach((cb) => {
      cb.addEventListener("change", () => {
        wiz.caps[cb.dataset.key].enabled = cb.checked;
        wiz.error = "";
        renderBody();
      });
    });
    body.querySelectorAll(".ci-tool-cb").forEach((cb) => {
      cb.addEventListener("change", () => {
        wiz.caps[cb.dataset.key].tools[cb.dataset.tool] = cb.checked;
      });
    });
  }

  function renderCapCard(cap) {
    const st = wiz.caps[cap.key];
    const tools = cap.tools.map((t) => {
      const checked = st.tools[t.name] ? "checked" : "";
      const need = t.needs_tool ? `<span class="ci-tool-need" title="Needs the ${esc(t.tool)} tool installed in the image">${esc(t.tool)}</span>` : "";
      return `<label class="ci-tool ${st.enabled ? "" : "muted"}">
        <input type="checkbox" class="ci-tool-cb" data-key="${esc(cap.key)}" data-tool="${esc(t.name)}" ${checked} ${st.enabled ? "" : "disabled"}>
        <span class="ci-tool-main"><span class="ci-tool-name mono">${esc(t.name)}</span>${need}</span>
        <span class="ci-tool-desc dim">${esc(t.description)}</span>
      </label>`;
    }).join("");
    const single = cap.tools.length === 1;
    return `
      <div class="ci-cap ${st.enabled ? "on" : ""}">
        <label class="ci-cap-head">
          <input type="checkbox" class="ci-cap-toggle" data-key="${esc(cap.key)}" ${st.enabled ? "checked" : ""}>
          <span class="ci-cap-title">${esc(cap.label)}</span>
          <span class="ci-cap-desc dim">${esc(cap.description)}</span>
        </label>
        <div class="ci-tools ${single ? "single" : ""}" ${st.enabled ? "" : "hidden"}>${tools}</div>
      </div>`;
  }

  /* ---------- step 3: formats ---------- */

  function renderFormats(body) {
    body.innerHTML = `
      <p class="ci-help">Which report formats to write. They land in your reports directory and are kept as
        build artifacts; SARIF and JUnit also wire into platform-native report views where available.</p>
      <div class="ci-formats">
        ${wiz.options.formats.map((f) => `
          <label class="ci-chk">
            <input type="checkbox" class="ci-fmt" value="${esc(f)}" ${wiz.formats.has(f) ? "checked" : ""}>
            <span>${esc(FORMAT_LABELS[f] || f)}</span><span class="mono dim">.${esc(f === "junit" ? "junit.xml" : f)}</span>
          </label>`).join("")}
      </div>`;
    body.querySelectorAll(".ci-fmt").forEach((cb) => {
      cb.addEventListener("change", () => {
        if (cb.checked) wiz.formats.add(cb.value); else wiz.formats.delete(cb.value);
        wiz.error = "";
      });
    });
  }

  /* ---------- step 4: severity gate ---------- */

  function renderGate(body) {
    const sevOptions = ["none", ...wiz.options.severities]
      .map((s) => `<option value="${esc(s)}" ${wiz.failOn === s ? "selected" : ""}>${s === "none" ? "- don't gate -" : s}</option>`)
      .join("");
    body.innerHTML = `
      <p class="ci-help">Decide the severity threshold and what crossing it does. The CLI sets its exit code
        from the worst finding (<code>--fail-on</code>); the pipeline step then either fails or just warns.</p>
      <div class="field-row ci-gate">
        <label class="field">
          <span>Fail-on severity (look at)</span>
          <select id="ci-failon">${sevOptions}</select>
        </label>
        <div class="ci-gate-cards">
          <button type="button" class="ci-gate-card ${wiz.gate === "fail" ? "active" : ""}" data-gate="fail">
            <span class="ci-card-title">Fail the build</span>
            <span class="ci-card-sub dim">Step exits non-zero - blocks the pipeline.</span>
          </button>
          <button type="button" class="ci-gate-card ${wiz.gate === "warn" ? "active" : ""}" data-gate="warn">
            <span class="ci-card-title">Warn only</span>
            <span class="ci-card-sub dim">Reports findings but never blocks the pipeline.</span>
          </button>
        </div>
      </div>`;
    $("ci-failon").addEventListener("change", (e) => { wiz.failOn = e.target.value; wiz.error = ""; });
    body.querySelectorAll(".ci-gate-card").forEach((b) => {
      b.addEventListener("click", () => { wiz.gate = b.dataset.gate; wiz.error = ""; renderBody(); });
    });
  }

  /* ---------- step 5: review + advanced + generate ---------- */

  function renderReview(body) {
    const caps = selectedCapabilities();
    const capSummary = caps.length
      ? caps.map((c) => {
          if (c.key === "sbom") return `<li><strong>SBOM</strong> - CycloneDX (Trivy)</li>`;
          const cap = wiz.options.capabilities.find((x) => x.key === c.key);
          const tools = c.scanners.length ? c.scanners.join(", ") : "all tools";
          return `<li><strong>${esc(cap.label)}</strong> - ${esc(tools)}</li>`;
        }).join("")
      : `<li class="dim">nothing selected - go back to step 2</li>`;
    const platform = wiz.options.platforms.find((p) => p.key === wiz.platform);
    body.innerHTML = `
      <div class="ci-review">
        <h3 class="section-title">Summary</h3>
        <ul class="ci-summary">
          <li><strong>Platform</strong> - ${esc(platform ? platform.label : "-")} <span class="mono dim">${esc(platform ? platform.filename : "")}</span></li>
          <li><strong>Scans</strong><ul class="ci-sub">${capSummary}</ul></li>
          <li><strong>Formats</strong> - ${esc(Array.from(wiz.formats).map((f) => FORMAT_LABELS[f] || f).join(", ") || "-")}</li>
          <li><strong>Gate</strong> - ${wiz.gate === "fail" ? "fail" : "warn"} ${wiz.failOn === "none" ? "(no threshold)" : `at <strong>${esc(wiz.failOn)}</strong> or above`}</li>
        </ul>
      </div>
      <details class="ci-advanced">
        <summary>Advanced - image, target path, project rules &amp; environment</summary>
        <div class="ci-adv-grid">
          <label class="field grow"><span>Docker image</span>
            <input type="text" id="adv-image" value="${esc(wiz.adv.image)}" placeholder="${esc(wiz.options.image)}"></label>
          <label class="field"><span>Scan target (path in repo)</span>
            <input type="text" id="adv-target" value="${esc(wiz.adv.target)}" placeholder="."></label>
          <label class="field"><span>Reports directory</span>
            <input type="text" id="adv-reports" value="${esc(wiz.adv.reportsDir)}" placeholder="deepscan-reports"></label>
          <label class="field grow"><span>Project rules dir (DEEPSCAN_CONFIG_DIR)</span>
            <input type="text" id="adv-config" value="${esc(wiz.adv.configDir)}" placeholder=".deepscan/config (optional)"></label>
        </div>
        <div class="ci-env">
          <div class="ci-env-head">
            <span class="field-label">Environment variables</span>
            <span class="dim">leave the value empty to pass a CI secret/variable through (e.g. <code>ANTHROPIC_API_KEY</code>)</span>
          </div>
          <div id="ci-env-rows"></div>
          <button type="button" class="btn small ghost" id="ci-env-add">+ Add variable</button>
        </div>
      </details>`;
    $("adv-image").addEventListener("input", (e) => { wiz.adv.image = e.target.value; });
    $("adv-target").addEventListener("input", (e) => { wiz.adv.target = e.target.value; });
    $("adv-reports").addEventListener("input", (e) => { wiz.adv.reportsDir = e.target.value; });
    $("adv-config").addEventListener("input", (e) => { wiz.adv.configDir = e.target.value; });
    $("ci-env-add").addEventListener("click", () => { wiz.adv.env.push({ key: "", value: "" }); renderEnvRows(); });
    renderEnvRows();
  }

  function renderEnvRows() {
    const host = $("ci-env-rows");
    if (!host) return;
    host.innerHTML = wiz.adv.env.map((row, i) => `
      <div class="ci-env-row">
        <input type="text" class="ci-env-key mono" data-i="${i}" placeholder="KEY" value="${esc(row.key)}">
        <input type="text" class="ci-env-val mono" data-i="${i}" placeholder="value (empty = passthrough)" value="${esc(row.value)}">
        <button type="button" class="btn small ghost ci-env-del" data-i="${i}" title="Remove">✕</button>
      </div>`).join("");
    host.querySelectorAll(".ci-env-key").forEach((el) =>
      el.addEventListener("input", (e) => { wiz.adv.env[Number(e.target.dataset.i)].key = e.target.value; }));
    host.querySelectorAll(".ci-env-val").forEach((el) =>
      el.addEventListener("input", (e) => { wiz.adv.env[Number(e.target.dataset.i)].value = e.target.value; }));
    host.querySelectorAll(".ci-env-del").forEach((el) =>
      el.addEventListener("click", (e) => { wiz.adv.env.splice(Number(e.target.dataset.i), 1); renderEnvRows(); }));
  }

  /* ---------- navigation ---------- */

  function validateStep(step) {
    if (step === 1 && !wiz.platform) return "Pick a CI/CD platform.";
    if (step === 2 && !selectedCapCount()) return "Select at least one thing to scan for (with a tool).";
    if (step === 3 && !wiz.formats.size) return "Select at least one report format.";
    if (step === 4 && wiz.gate === "fail" && wiz.failOn === "none") {
      return "Pick a fail-on severity, or switch the gate to Warn only.";
    }
    return "";
  }

  function goStep(target) {
    if (target > wiz.step) {
      for (let s = wiz.step; s < target; s++) {
        const err = validateStep(s);
        if (err) { wiz.error = err; wiz.step = s; render(); return; }
      }
    }
    wiz.error = "";
    wiz.step = Math.max(1, Math.min(TOTAL, target));
    render();
  }

  function onBack() { if (wiz.step > 1) goStep(wiz.step - 1); }

  function onNext() {
    const err = validateStep(wiz.step);
    if (err) { wiz.error = err; render(); return; }
    if (wiz.step < TOTAL) { goStep(wiz.step + 1); return; }
    generate();
  }

  /* ---------- generate + result ---------- */

  async function generate() {
    const btn = $("ci-next");
    btn.disabled = true;
    btn.textContent = "Generating…";
    wiz.error = "";
    $("ci-error").textContent = "";
    try {
      wiz.result = await apiPost("/api/pipeline/generate", buildRequest());
      renderResult();
    } catch (err) {
      wiz.error = err.message;
      $("ci-error").textContent = err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = "Generate template";
    }
  }

  function renderResult() {
    const panel = $("ci-result-panel");
    const r = wiz.result;
    panel.hidden = false;
    panel.innerHTML = `
      <div class="panel-head">
        <h2>Generated template</h2>
        <div class="detail-actions">
          <button type="button" class="btn small" id="ci-copy">Copy</button>
          <button type="button" class="btn small ghost" id="ci-download">Download</button>
        </div>
      </div>
      <p class="ci-help">Commit this as <code>${esc(r.filename)}</code> in your repository.</p>
      <div class="ci-code-wrap"><pre class="ci-code"><code>${esc(r.content)}</code></pre></div>`;
    $("ci-copy").addEventListener("click", () => copyResult($("ci-copy")));
    $("ci-download").addEventListener("click", downloadResult);
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  async function copyResult(btn) {
    try {
      await navigator.clipboard.writeText(wiz.result.content);
      const old = btn.textContent;
      btn.textContent = "Copied ✓";
      setTimeout(() => { btn.textContent = old; }, 1500);
    } catch (_) {
      btn.textContent = "Copy failed";
    }
  }

  function downloadResult() {
    const r = wiz.result;
    const blob = new Blob([r.content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = r.filename.split("/").pop() || "pipeline.yml";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }

  window.DeepScanPipelines = { show };
})();
