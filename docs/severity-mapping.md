# Severity normalization

Every scanner speaks its own dialect of "how bad is this" - a CVSS score, a
SARIF `level`, a `riskcode`, a template tag, or nothing at all. Deep Scan folds
all of them into **one 5-level scale** so that dedup, the report formats, the
ASPM dashboard and `ai-analysis` triage compare findings on equal footing.

The canonical scale lives in
[`models.py`](../packages/core/src/deepscan_core/models.py) (`Severity`):

```
critical  >  high  >  medium  >  low  >  info        (rank 0 → 4, lower = worse)
```

Two shared converters back most of the mappings below:

- **`Severity.from_cvss(score)`** - CVSS/`security-severity` bands:
  `≥9.0 → critical`, `≥7.0 → high`, `≥4.0 → medium`, `>0 → low`, `0 → info`.
- **`Severity.from_string(raw)`** - text aliases: `error/important → high`,
  `warning/warn/moderate → medium`, `note → low`, `none/informational → info`
  (plus the five canonical words). **Unknown / missing → `medium`** (the
  deliberate default: never silently drop to `info`).

---

## What each level means in Deep Scan (global recap)

This is the *operational* reading an analyst should apply, independent of which
tool raised it:

| Deep Scan level | Concretely means | Typical triggers | Action |
|---|---|---|---|
| **critical** | Exploitable now, severe impact. Proven RCE-class or a live/confirmed exposure. | CVSS ≥ 9.0; proven command/code-injection taint sink; **verified** live secret; malware signature hit. | Fix/rotate/block immediately; page if in prod. |
| **high** | Serious and likely exploitable, but needs a condition or isn't proven-live. | CVSS 7.0–8.9; injection/SSRF/deserialization/path-traversal/XSS/XXE/template sinks; unverified secret; SAST `error`; reachable-from-entrypoint taint. | Prioritize this sprint. |
| **medium** | Real weakness, conditional or unconfirmed exploitability. **Also the fallback** when a tool gives no severity signal. | CVSS 4.0–6.9; SAST `warning`; misconfig; secrets from engines that emit no severity; a reachable-but-unreached vulnerable dep. | Schedule; confirm reachability/context first. |
| **low** | Minor / defense-in-depth / needs an unlikely precondition. | CVSS 0.1–3.9; SAST `note`; ldap-injection / open-redirect sinks; hardening nits. | Batch; fix opportunistically. |
| **info** | No direct risk - coverage, context, or a downgraded/unreached item. | CVSS 0; `none`/`informational`; items downgraded for non-use. | Awareness only. |

> Severity answers **"how bad if true"**. It is distinct from **confidence**
> (the `analysis` taint engine emits `high`/`medium` confidence) and from
> `ai-analysis` **priority** (P0–P3) - both carried separately in `extra`.

---

## The shared path: SARIF ladder

13 of the scanners emit **SARIF** and are normalized by one function,
[`sarif.py::_severity_for`](../packages/core/src/deepscan_core/sarif.py). It
tries each signal in order and stops at the first that resolves:

| # | Signal (SARIF field) | Mapping |
|---|---|---|
| 1 | rule `properties.security-severity` (0–10) | `from_cvss` bands |
| 2 | result `level` | `error→high`, `warning→medium`, `note→low`, `none→info` |
| 3 | rule `properties.severity` / `problem.severity` | `from_string` |
| 4 | rule `defaultConfiguration.level` | same as `level` |
| 5 | *nothing matched* | **`medium`** (default) |

So a SARIF scanner's real-world severity depends on **which of these fields its
output actually populates** - documented per scanner below (verified against
real scan outputs in `reports/`).

---

## Per-scanner mapping

### SARIF scanners

| Scanner | Family | Native severity | SARIF field used | → Deep Scan |
|---|---|---|---|---|
| `trivy` (+ `trivy-misconfig`, `trivy-license`) | SCA / IaC / License | CVE CVSS score | `security-severity` (CVSS) | CVSS bands (e.g. 9.8 → critical) |
| `osv-scanner` | SCA | OSV/CVSS | `security-severity` when present, else `level: warning` | CVSS bands, else medium |
| `codeql` | SAST | query `security-severity` (security queries) / problem severity | `security-severity` for security queries, else `level` | CVSS bands, else high/medium/low |
| `opengrep` | SAST | ERROR / WARNING / INFO | `level` (`error`/`warning`/`note`) | high / medium / low |
| `checkov` | IaC | CRITICAL…LOW | `level` (+ `security-severity` when the policy carries one) | via ladder (CVSS band if present, else level) |
| `cisco-ai-skill-scanner` | SAST/AI | rule severity | via SARIF ladder | ladder result |
| `nuclei` | DAST | template `info…critical` | `security-severity` (numeric) | CVSS bands (e.g. 5 → medium) |
| `titus` | Secret | per-rule CVSS | `security-severity` (e.g. 7.5) + `level` | CVSS bands |
| `nosey_parker` | Secret | (none) | `level: warning` | **medium** |
| `kingfisher` | Secret | (none) | `level: warning` | **medium** |
| `gitleaks` | Secret | (none) | *no `level`, no `security-severity`* | **medium** (ladder default) |
| `betterleaks` | Secret | (none) | *no `level`, no `security-severity`* | **medium** (ladder default) |
| `plumber` | Pipeline | rule severity | `level` (e.g. `error`) | high / medium / low |

> **Secrets are mostly `medium` by design.** Except `titus` (real per-rule CVSS)
> and `trufflehog` (below), the secret engines emit no usable severity, so every
> hit lands at `medium`. The six engines are **deduplicated together**, and
> `ai-analysis` / verification is what pushes a confirmed secret up.

### Custom-mapping scanners (not SARIF)

| Scanner | Family | Native definition | → Deep Scan |
|---|---|---|---|
| `trufflehog` | Secret | secret **Verified** vs unverified | Verified → **critical**, unverified → **high** |
| `zaproxy` | DAST | `riskcode` 3/2/1/0 (High/Med/Low/Info) | 3→high, 2→medium, 1→low, 0→info (default low). *ZAP has no "critical"*. |
| `clamav` | Malware | signature match (binary) | any hit → **critical** |
| `yara` | Malware | rule `threat_type` | per type: most → **high** (prompt-injection, tool-poisoning, injection, credential-harvesting, exfiltration, system-manipulation); `code-execution` → **low**; unknown type → **medium** |
| `mcp-threats` | Malware (text) | pattern `category` | per category from the packaged patterns (e.g. `instruction-override` → high); invisible/bidi Unicode → **medium** |

### Analysis scanners (derived severity)

**`analysis`** (taint engine) - severity is the **sink class's baseline** from
[`analysis/sinks.py`](../packages/core/src/deepscan_core/analysis/sinks.py):

| Sink class | CWE | Baseline |
|---|---|---|
| `command-injection` | CWE-78 | **critical** |
| `code-injection` | CWE-95 | **critical** |
| `deserialization` | CWE-502 | high |
| `sql-injection` | CWE-89 | high |
| `path-traversal` | CWE-22 | high |
| `ssrf` | CWE-918 | high |
| `xss` | CWE-79 | high |
| `xxe` | CWE-611 | high |
| `template-injection` | CWE-94 | high |
| `ldap-injection` | CWE-90 | medium |
| `open-redirect` | CWE-601 | medium |

Then **reachability adjusts it**: a `medium` taint finding reachable from a
web/CLI entry point is raised to `high` (proven exposure); a sink only reachable
from internal code stays conservative.

**`reachable-deps`** (phase-2 consumer) - starts from the **SCA finding's own
severity** and adjusts by whether the vulnerable dependency is actually used
([`analysis/dep_usage.py`](../packages/core/src/deepscan_core/analysis/dep_usage.py)):

| Verdict | Adjustment |
|---|---|
| **used & reachable** from an entry point | keep the SCA severity |
| **used but unreachable** | downgrade **1** level |
| **not-found** (no matching import → likely unused/transitive/dynamic) | downgrade **2** levels |

Downgrades clamp at `info`, and a CVE is **never silently hidden** - each verdict
carries a confidence in `extra`.

**`ai-analysis`** (phase-2, off by default) - does **not** set severity; it reads
everyone else's and maps it to a fallback **priority** (`critical→P0`, `high→P1`,
`medium→P2`, `low`/`info`→P3) when its LLM triage is unavailable. When available,
the model re-prioritizes and flags likely false positives.

---

## Where this bites (gotchas)

- **A `medium` is not always "medium-confidence risk"** - for `gitleaks`,
  `betterleaks`, `nosey_parker`, `kingfisher` it just means *"the engine told us
  nothing"*. Read the family, not only the level.
- **`security-severity` always wins** over `level` in SARIF. A tool that sets a
  CVSS of `1.0` (→ low) *and* `level: error` (→ high) resolves to **low** - the
  CVSS is trusted first (this is why an `osv` finding can read lower than its
  `error` level suggests).
- **Default is `medium`, never `info`.** Missing/garbage severity is treated as a
  real-until-proven issue, not noise.
- Severity is **input to prioritization, not the verdict** - `reachable-deps`
  reachability, `analysis` entry-point exposure, and `ai-analysis` triage are the
  layers that turn a raw level into an actionable priority.
