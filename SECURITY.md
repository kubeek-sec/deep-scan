# Security Policy

Deep Scan is a security tool, so we hold its own code to the same bar it checks
for. Thank you for helping keep it safe.

## Supported versions

The project is pre-1.0 and evolves on `main`. Security fixes land on `main` and
the latest tagged release; please reproduce against the current `main` before
reporting.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately through either channel:

- **GitHub** - open a private advisory via *Security → Report a vulnerability*
  on the [`kubeek-sec/deep-scan`](https://github.com/kubeek-sec/deep-scan)
  repository (preferred).
- **Email** - `security@kubeek.com`.

Please include:

- a description and impact (what an attacker can achieve),
- steps to reproduce or a minimal proof of concept (**harmless only** - a marker
  file or a request to a fictitious `kubeek.com` address; never destructive
  payloads),
- affected component/version (commit hash) and any relevant `deepscan` output.

We aim to acknowledge a report within a few business days, agree on a fix
timeline, and credit you in the advisory once a fix is released (unless you
prefer to stay anonymous). Please give us a reasonable window to ship a fix
before any public disclosure.

## Scope

In scope: the Deep Scan packages (`packages/*`), the deployment manifests
(`deploy/*`), and the install/tooling pipeline.

Out of scope:

- **`guinea-pig/`** is a *deliberately-vulnerable* test target. Findings there
  (and in fixtures) are expected ground truth, not vulnerabilities in Deep Scan.
- Vulnerabilities in third-party scanners/tools Deep Scan installs - report those
  upstream. Issues in *how Deep Scan installs or invokes* them are in scope.

## Our security posture

Deep Scan is built to run untrusted code and untrusted targets safely:

- **Pinned, verified tooling** - every installed tool is pinned by exact version
  and **SHA-256 verified** before extraction; archives are unpacked
  member-by-member (no zip-slip), installs are atomic, downloads are HTTPS-only
  with a size cap.
- **Hardened execution** - subprocesses run with `shell=False` and hard
  timeouts; scan targets are canonicalized (no leading-dash argument injection)
  and can be confined to `DEEPSCAN_SCAN_ROOT`; git clones disable credential
  prompts; zip uploads block traversal, symlinks and bombs.
- **Least privilege at scale** - workers run non-root with a read-only rootfs,
  all capabilities dropped, a default-deny egress `NetworkPolicy`, and optional
  one-pod-per-scan ephemeral runners.
- **Secrets stay out** - connector tokens are never stored in the database (only
  referenced by env-var name); reported secret values are redacted; telemetry is
  off unless a DSN is set and never sends paths, file names or secret values.

Details: [docs/architecture.md](docs/architecture.md#security-model) and
[docs/deployment.md](docs/deployment.md#scan-isolation).
