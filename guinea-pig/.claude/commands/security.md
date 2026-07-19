---
description: Full security pass - run /security-eval then /security-patch end to end (scan via the MCP jobs infrastructure, group findings, then one review branch per patch group).
argument-hint: "[scope] (default: whole project)"
---

# /security

Do the complete security workflow in one go.

1. **Evaluate** - run the `/security-eval` workflow
   (`.claude/commands/security-eval.md`) over `$ARGUMENTS`: zip the project →
   scan it through the Deep Scan **MCP jobs infrastructure** → **verify each
   finding's reachability in source** → write the grouped remediation plan to
   `reports/remediation-plan.json`.

2. **Patch** - run the `/security-patch` workflow
   (`.claude/commands/security-patch.md`) over **all** groups in that plan:
   **re-verify each group is real**, then one review branch per group, each fixing
   the issue and **demonstrating it at the product level** (drive the real
   API/CLI/app with a forged-but-inert, sandboxed artifact - not just an import),
   with an **impact assessment** (difficulty / who's affected / vector / impact);
   direct-dependency CVEs bumped iteratively with code migration + tests (to a
   verified-real, non-vulnerable target). Before committing each group, **confirm
   the fix**: it is complete and adds no new weakness, the existing tests still
   pass (behavior preserved), and a **re-scan of the patched scope comes back
   clean** (finding gone, nothing new).

## Verdict vocabulary (shared by both phases)
Scanners **detect** patterns; this workflow **confirms** them in source before any
finding becomes a PR. Every finding is graded, with `file:line` evidence, into one
verdict - carried in `reports/remediation-plan.json` from eval through patch:

- **`exploitable`** - real, reachable, unmitigated → becomes a fix branch.
- **`latent`** - real weakness but no current attacker-reachable trigger → optional
  **defense-in-depth** branch, labelled as hardening; severity not inflated.
- **`false_positive`** - the pattern doesn't hold (source not tainted / already
  mitigated / artifact absent) → recorded in `dismissed`, never fixed.
- **`by_design`** - documented intended behaviour → recorded in `dismissed`.

Prioritise on `effective_severity` (post-verification), not the raw scanner label.
`false_positive`/`by_design` findings are **documented with evidence, never
silently discarded**; `/security-patch` re-checks each group and **skips** any that
no longer verifies rather than fabricating a fix or a synthetic demo.

## Safety & purpose (read before any demonstration)
One purpose only: **find vulnerabilities to remediate them and lock them down with
regression tests.** A demonstration proves a finding is real and seeds a permanent
test - never an end in itself, a working exploit, or anything else. "Product-level"
realism means driving the real interface with an **inert, minimized, sandboxed**
artifact whose ONLY observable side effect is a branch-named `.txt` marker or a
`kubeek.com` canary call (helper `canary.sh`/`.ps1`/`.py`, see
[`.claude/canary-endpoints.md`](../canary-endpoints.md)) - never another external
host, a real exploit, or a destructive command. If a finding can't be shown safely,
describe its impact in prose and fix it anyway.

## Output
The evaluation summary + remediation plan, then the list of review branches
created (one per patch group) and what each contains.
