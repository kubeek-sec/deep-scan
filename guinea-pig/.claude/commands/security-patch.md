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
Every demonstration here exists for **exactly two purposes**: (1) to prove a
finding is real so it can be **remediated**, and (2) to become a **regression
test** that keeps the vulnerability from returning. That is the whole point -
identify and mitigate, then lock it down. A demonstration is **never** an end in
itself, never a working exploit, and never used for any other purpose. The goal
is to **fix** vulnerabilities and **demonstrate** the fix - never to weaponize
them. In any patch, test or demonstration the ONLY side effects you may produce
are these two inert canaries:

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

4. **Demonstrate at the product level** - add a regression test (under `tests/`,
   or the project's test dir) that reproduces the issue **where a real consumer
   would hit it**, then shows the fix closes it. A test that merely imports the
   vulnerable symbol and pokes it is the weakest possible proof; prefer the
   **highest-fidelity level feasible** for the finding's `entry_kind`:

   - **L3 - real app / CLI / server (preferred):** run the actual product
     end-to-end (start the app in this context, invoke the CLI via subprocess, or
     hit the endpoint) and feed the **forged artifact** through the genuine
     interface. *e.g. run `python -m <pkg> ...` / call the documented loader on a
     crafted file and observe the product's behaviour.*
   - **L2 - public API:** drive the documented public entry point a downstream
     user calls - a dataset/model/file **loader**, a parser, an exporter - passing
     a **forged artifact** (crafted archive / requests / dataset / model / file) that trips
     the sink. *e.g. `datasets.load_*` / `load_svmlight_file` / model
     deserialization on attacker-shaped bytes.*
   - **L1 - unit (fallback only):** call the sink directly. Use ONLY when there is
     no reachable product entry point (an internal helper) - and say so.

   Prefer **L3 ≥ L2 ≫ L1**; record which level you used and why a higher one
   wasn't feasible. The forged artifact goes through the **real, reachable path
   confirmed in step 1** - never a rewritten or synthetic sink. If the only way to
   reach the sink is synthetic, the finding was `latent`/FP: label it and argue
   impact in prose instead of staging a fake path.

   **Forged-artifact / PoC rules (safety contract, non-negotiable):**
   - **Inert & minimized** - the payload does only enough to prove *reachability*;
     no working weapon, no destructive / persistent / exfiltrating effect.
   - **Sandboxed** - build and run it in a fresh temp dir; touch no real
     user/home/system path and no network beyond the canary. Point the loader's
     `data_home` / output dir / cwd at the sandbox.
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

   **Impact assessment (write it into the PR / output for this group):** a short,
   honest threat model that justifies the `effective_severity` -
   - `exploit_difficulty`: *trivial | moderate | hard* - preconditions, privileges
     needed, whether the attacker must supply the input, network position;
   - `affected_parties`: **who supplies the malicious artifact vs. who is harmed** -
     e.g. a *library user* loading an untrusted dataset/model, a *maintainer*
     running a build/maint script, a *CI job* processing a PR, a *downstream
     service* embedding the library;
   - `attack_vector`: how the forged artifact reaches the sink (user fetches a
     dataset, opens a shared model file, CI checks out a PR, …);
   - `impact`: CIA + class (RCE / arbitrary file write / path traversal / SSRF /
     info-leak / DoS) and blast radius **in this product's context**.

5. **Dependency bump** (`kind` = `dependency`) - do it **iteratively, one commit
   per step**, so the migration is reviewable:
   a. *commit 1* - bump the direct dependency in the manifest
      (`deps/requirements.txt` / `deps/package.json`) from `current` → `target`.
   b. *commit 2* - **migrate the code** that breaks under the new version: grep
      the repo for usages of the package and adapt to renamed/removed APIs,
      changed signatures or defaults.
   c. *commit 3* - **add the missing tests** that pin the prior behavior, so the
      bump is proven non-breaking; run them and confirm green. Add tests for any
      behavior that had none.
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
level used (L1/L2/L3) and how it was made inert/sandboxed**, the **impact
assessment** (`exploit_difficulty` / `affected_parties` / `attack_vector` /
`impact`), and (for dependency bumps) the version delta + tests added - followed by
the list of branches the developer should review. Groups skipped as
`verified: false` (already fixed / false positive / by-design) are listed with
their evidence, not silently omitted.
