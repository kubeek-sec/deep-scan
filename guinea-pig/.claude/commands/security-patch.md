---
description: Implement the remediation plan from /security-eval - one review branch per patch group, each demonstrating the fix. Direct-dependency CVEs are bumped iteratively with code migration and tests. Strictly no real exploit code.
argument-hint: "[group id(s) | 'all'] (default: all groups in the plan)"
---

# /security-patch

Turn the grouped remediation plan into **one review branch per patch group**, so
a developer reviews each as a self-contained PR.

## Input
Read `reports/remediation-plan.json` (produced by `/security-eval`). If it is
missing, run `/security-eval` first. `$ARGUMENTS` selects which group ids to
patch (default: **all**).

## ⛔ Safety contract - READ FIRST, non-negotiable
The goal is to **fix** vulnerabilities and **demonstrate** the fix - never to
weaponize them. Every demonstration serves two purposes only: prove a finding is
real so it can be **remediated**, and become a **regression test** that stops it
returning. It is never an end in itself and never a working exploit. In any patch,
test or demonstration the ONLY side effects you may produce are these two inert
canaries:

1. **Create a `.txt` file named after the branch** - e.g. write
   `<branch>.demo.txt` whose contents are the branch name; or
2. **Call a controlled `kubeek.com` canary endpoint** - and ONLY one of the
   endpoints documented in [`../canary-endpoints.md`](../canary-endpoints.md),
   via the canary helper (`canary.sh` / `canary.ps1` / `canary.py` - pick the
   form for this OS, see [`../scripts/README.md`](../scripts/README.md)). These
   are inert, owner-operated endpoints that exist to validate
   drop/exfiltration/info-collection paths; they run nothing harmful. Never
   contact any other external host.

STRICTLY FORBIDDEN - never write, run, or commit any of:
- real exploit payloads, reverse shells, or data/credential exfiltration to any
  host other than the `kubeek.com` canary endpoints above;
- destructive or state-changing commands: `rm` / `rmdir`, `mv` or overwrite of
  real files, `chmod`, `kill`, dropping DB tables, writing outside the repo;
- **installing anything on the host**: no `pip` / `npm` / `apt` / `brew` / `uv`
  install, no global tool, no mutation of the machine's toolchain. If a demo needs
  a runtime or dependencies, isolate them in **Docker** or a scenario dir (step 4) -
  never touch the host;
- real secrets, or any change outside the current patch branch's scope.

A demonstration proves the *behavior* (reachable before, safe after) using only
(1) or (2). If you cannot demonstrate something without a real exploit, describe
it in prose instead - do not implement the exploit.

## Per-group procedure
For each selected group, starting from a clean working tree on the default branch:

1. **Verify before you patch - re-confirm the finding is real.** Open the code at
   `fix_location` and check the plan's `verdict`/`reachability`/`evidence` still
   hold at the current commit: the sink is real, reachable, and unmitigated. If it
   does **not** (already fixed, false positive, or by-design), **do NOT fabricate a
   fix or a demonstration** - record the group as `verified: false` with evidence
   in the output and **skip it**. A "fix" for a non-bug and a demo that exercises a
   synthetic sink are both worse than nothing. For a `latent` group, proceed but
   scope the branch/PR explicitly as **hardening / defense-in-depth**, not a
   live-bug fix.

2. **Branch** - `git switch -c <group.branch>` (one branch per group; never mix
   concerns).

3. **Code fix** (`kind` = `code` / `config`) - apply the remediation at the single
   best `fix_location` from the plan; prefer a shared sanitizer/helper over
   editing every sink. Keep the diff minimal and focused on this one concern.

4. **Prove it with a non-regression test** - the branch has already patched the
   **real product code** (step 3's fix at `fix_location`, or step 5's version bump
   in the real manifest). This test does one job: pin the delta on that real code -
   it **would have tripped on the pre-fix code (at risk _before_)** and **passes on
   the patched code (safe _now_)** - and stays in the suite as a permanent guard.
   Drive the fixed code **where a real consumer would hit it**, never a synthetic
   copy; a test that imports a symbol and pokes a toy reimplementation is the
   weakest proof. Prefer the **highest-fidelity level feasible** for the finding's
   `entry_kind`:

   - **L3 - real app / CLI / server (preferred):** run the actual product
     end-to-end (start the app in this context, invoke the CLI via subprocess, or
     hit the endpoint) and feed the **forged artifact** through the genuine
     interface. *e.g. run `python -m <pkg> ...` / call the documented loader on a
     crafted file and observe the product's behaviour.*
   - **L2 - public API:** drive the documented public entry point a downstream
     user calls - a dataset/model/file **loader**, a parser, an exporter - passing
     a **forged artifact** (crafted archive / dataset / model / file) that trips
     the sink. *e.g. `datasets.load_*` / `load_svmlight_file` / model
     deserialization on attacker-shaped bytes.*
   - **L1 - unit (fallback only):** call the sink directly. Use ONLY when there is
     no reachable product entry point (an internal helper) - and say so.

   Prefer **L3 ≥ L2 ≫ L1**; record which level you used and why a higher one
   wasn't feasible. The forged artifact goes through the **real, reachable path
   confirmed in step 1** - never a rewritten or synthetic sink. If the only way to
   reach the sink is synthetic, the finding was `latent`/FP: label it and argue
   impact in prose instead of staging a fake path. This ladder governs the
   **repro** (how faithfully you show the vuln *before*); the durable
   **non-regression guard** optimises for coverage, not fidelity - the simplest
   check that fully exercises the mitigation (even a direct call / a regex) is fine.

   **Forged-artifact / PoC rules (safety contract, non-negotiable):**
   - **Inert & minimized** - the payload does only enough to prove *reachability*;
     no working weapon, no destructive / persistent / exfiltrating effect.
   - **Sandboxed, and nothing installed on the host** - a lightweight demo builds
     and runs its forged artifact in a fresh **temp dir** (point the loader's
     `data_home` / output dir / cwd there); touch no real user/home/system path and
     no network beyond the canary. **Never install anything** to make a demo run.
   - **Build a scenario dir when the demo needs context.** Create a directory
     **named after the branch** - `tests/<branch-slug>/` (same slug as the
     `<branch>.demo.txt` marker, e.g. `tests/ssrf-allowlist-fetch-scripts/`) - and
     commit it with the branch. It holds **two artifacts + a readme**:
       1. **The repro (with whatever context it takes).** Enough to *get back into
          context* and show the vuln on the **unmodified** code: a minimal driver /
          crafted inputs, plus a **`Dockerfile` / `compose.yaml`** when a runtime or
          absent deps are needed (Docker supplies them - host untouched, container
          ephemeral `--rm`). It drives the **real** code (mount the repo / install
          the branch *in the container*, never a re-implementation) and shows *at
          risk before* by running against the parent commit / fix reverted.
       2. **The non-regression test - as simple as sufficient.** The durable guard
          that stays in the suite; it can be **far lighter than the repro** - often
          a regex or one crafted string passed straight to the fixed function, no
          app or container - as long as it **fully covers the mitigation and the
          whole vulnerability** of the patched code (every sink the fix touches,
          every bypass shape). Passes on the branch; would trip on the pre-fix code.
       3. **`readme.md`** - how it works and the exact commands to test the
          mitigation (*before*: repro on the unmodified code; *after*: guard green).
     The only runtime observable stays the `<branch>.demo.txt` marker or a canary call.
   - **Observable = the two allowed side effects only.** Redirect the "malicious"
     outcome to a sentinel so the test can assert it: for file-write /
     path-traversal / arbitrary-write sinks, the payload targets the
     `<branch>.demo.txt` marker or a sentinel path just outside the sandbox and
     the test asserts it **escaped before the fix / is contained after**; for
     outbound / SSRF / exfil / info-collection sinks, it routes to a `kubeek.com`
     canary (`canary monip` / `info` / `download run.sh`) and the test asserts the
     unfixed path reaches it and the fixed path does not. If proving the sink
     safely would still require *executing attacker-supplied code* (e.g. a
     deserialization RCE), demonstrate that attacker bytes **reach** the sink and
     argue impact in prose - do not run even a benign payload through it.
   - The test **passes on the fixed code** and **would have tripped on the
     unfixed code**; it stays in the suite as a permanent regression guard. See
     [`../canary-endpoints.md`](../canary-endpoints.md) for the endpoint list.
     **Never run a real payload.**

   **Impact assessment:** restate the plan's `impact` block for this group in the
   PR / output (`exploit_difficulty`; `affected_parties` = who supplies the artifact
   vs. who is harmed; `attack_vector`; `impact` = CIA + class + blast radius),
   **refined by what the product-level repro actually showed** (e.g. a precondition
   that proved easier or harder than the plan assumed). It justifies the
   `effective_severity`.

5. **Dependency bump** (`kind` = `dependency`) - do it **iteratively, one commit
   per step**, so the migration is reviewable:
   a. *commit 1* - bump the direct dependency in the manifest
      (`deps/requirements.txt` / `deps/package.json`) from `current` → `target`.
   b. *commit 2* - **migrate the code** that breaks under the new version: grep
      the repo for usages of the package and adapt to renamed/removed APIs,
      changed signatures or defaults.
   c. *commit 3* - **add the missing tests** that pin the prior behavior, so the
      bump is proven non-breaking. **Verify install-free** (nothing on the host):
      run them inside a **Docker** image built with the bumped dependency; if that
      isn't feasible, fall back to a **static check** (assert the manifest/lock now
      pins the safe version and review the migration by reading the diff) and say
      which you did. Add tests for any behavior that had none.
   If a safe target needs intermediate versions, hop version-by-version, each
   with its own migrate + test commits.

6. **Commit** the fix + demo with a clear message
   (`fix(security): <group title>`), then switch back to the default branch for
   the next group.

7. Leave each branch **for review** - do **not** merge. Push or open a PR only if
   the user explicitly asks; otherwise the local branches are ready for the
   developer to review and turn into PRs.

## Secrets groups
Never commit a "fix" that re-embeds the secret. The patch: remove the literal,
read it from the environment / a secret manager, and **note the leaked
credential must be rotated**. Demonstrate by asserting the code reads the value
from the environment (with a dummy value) - no literal secret in the diff.

## Output
A short report - per group: the step-1 verification result (`verified` +
`verdict`, or why it was skipped), branch name, files changed, the **demonstration
level used (L1/L2/L3) and how it was made inert/sandboxed** (and, if a scenario was
built, the `tests/<branch-slug>/` dir - Docker + `readme.md`), the **impact
assessment** (`exploit_difficulty` / `affected_parties` / `attack_vector` /
`impact`), and (for dependency bumps) the version delta + tests added - followed by
the list of branches the developer should review. Groups skipped as
`verified: false` (already fixed / false positive / by-design) are listed with
their evidence, not silently omitted.
