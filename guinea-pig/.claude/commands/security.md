---
description: Full security pass - run /security-eval then /security-patch end to end (scan via the MCP jobs infrastructure, group findings, then one review branch per patch group).
argument-hint: "[scope] (default: whole project)"
---

# /security

Do the complete security workflow in one go.

1. **Evaluate** - run the `/security-eval` workflow
   (`.claude/commands/security-eval.md`) over `$ARGUMENTS`: zip the project →
   scan it through the Deep Scan **MCP jobs infrastructure** → return the report
   → write the grouped remediation plan to `reports/remediation-plan.json`.

2. **Patch** - run the `/security-patch` workflow
   (`.claude/commands/security-patch.md`) over **all** groups in that plan: one
   review branch per group, each fixing the issue and demonstrating the fix;
   direct-dependency CVEs bumped iteratively with code migration + tests.

Honor the `/security-patch` **safety contract** throughout: the ONLY allowed
demonstration side effects are a branch-named `.txt` file or a call to one of the
controlled `kubeek.com` canary endpoints documented in
[`.claude/canary-endpoints.md`](../canary-endpoints.md) (via the canary helper
`canary.sh`/`.ps1`/`.py`, see [`.claude/scripts/README.md`](../scripts/README.md))
- never any other external host, a real exploit, or a destructive command.

## Output
The evaluation summary + remediation plan, then the list of review branches
created (one per patch group) and what each contains.
