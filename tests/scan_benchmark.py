#!/usr/bin/env python3
"""Submit manual-API scans for a benchmark matrix of real-world repositories
(10 languages x 3 complexity tiers) and, optionally, wait for the results.

This is a *utility script*, not a pytest test (it needs a running API and clones
large repos). The name has no ``test_`` prefix so pytest ignores it.

Prerequisites: the Deep Scan API must be up and a worker/dispatcher draining the
queue, e.g.:

    docker compose -f deploy/docker/docker-compose.yml up -d

Examples:

    # submit the whole matrix, don't wait
    python tests/scan_benchmark.py

    # only Python + Go, SCA family only, and wait for results
    python tests/scan_benchmark.py --lang python,go --families sca --wait

    # just the "simple" tier, custom API host, show what would be sent
    python tests/scan_benchmark.py --tier simple --api http://192.168.1.43:8800 --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# (language -> (simple, middle, complex) repo URLs). Keys are lowercase; the
# --lang filter matches on the leading token (e.g. "js" matches "js/ts").
MATRIX: dict[str, tuple[str, str, str]] = {
    "python":  ("https://github.com/pallets/flask",
                "https://github.com/fastapi/fastapi",
                "https://github.com/django/django"),
    "js/ts":   ("https://github.com/expressjs/express",
                "https://github.com/element-plus/element-plus",
                "https://github.com/microsoft/vscode"),
    "go":      ("https://github.com/spf13/cobra",
                "https://github.com/gohugoio/hugo",
                "https://github.com/kubernetes/kubernetes"),
    "rust":    ("https://github.com/sharkdp/fd",
                "https://github.com/BurntSushi/ripgrep",
                "https://github.com/tokio-rs/tokio"),
    "java":    ("https://github.com/google/gson",
                "https://github.com/square/okhttp",
                "https://github.com/spring-projects/spring-framework"),
    "c/c++":   ("https://github.com/DaveGamble/cJSON",
                "https://github.com/redis/redis",
                "https://github.com/llvm/llvm-project"),
    "ruby":    ("https://github.com/sinatra/sinatra",
                "https://github.com/jekyll/jekyll",
                "https://github.com/rails/rails"),
    "csharp":  ("https://github.com/DapperLib/Dapper",
                "https://github.com/dotnet/efcore",
                "https://github.com/dotnet/roslyn"),
    "php":     ("https://github.com/slimphp/Slim",
                "https://github.com/monicahq/monica",
                "https://github.com/laravel/framework"),
    # the table labelled this "nvh/nvm" but the link is the canonical nvm-sh/nvm.
    "bash":    ("https://github.com/nvm-sh/nvm",
                "https://github.com/bats-core/bats-core",
                "https://github.com/ohmyzsh/ohmyzsh"),
}
TIERS = ("simple", "middle", "complex")
_TERMINAL = {"done", "failed", "cancelled", "superseded"}


def _post(api: str, payload: dict) -> dict:
    req = urllib.request.Request(
        f"{api}/api/scans", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - operator-supplied API URL
        return json.loads(resp.read())


def _get(api: str, job_id: int) -> dict:
    req = urllib.request.Request(f"{api}/api/scans/{job_id}", method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - operator-supplied API URL
        return json.loads(resp.read())


def _findings(job: dict) -> int | str:
    summary = job.get("summary")
    if isinstance(summary, str):
        try:
            summary = json.loads(summary)
        except ValueError:
            return "?"
    if isinstance(summary, dict):
        return summary.get("deduplicated_findings", summary.get("findings", "?"))
    return "?"


def _selected(args) -> list[tuple[str, str, str]]:
    """Return the [(language, tier, url)] rows the filters select."""
    langs = [s.strip().lower() for s in args.lang.split(",")] if args.lang else None
    tiers = [s.strip().lower() for s in args.tier.split(",")] if args.tier else list(TIERS)
    rows: list[tuple[str, str, str]] = []
    for language, urls in MATRIX.items():
        head = language.split("/")[0]
        if langs and not any(language == l or head == l for l in langs):
            continue
        for tier, url in zip(TIERS, urls):
            if tier in tiers:
                rows.append((language, tier, url))
    return rows


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Submit the benchmark scan matrix via the manual API.")
    p.add_argument("--api", default=os.environ.get("DEEPSCAN_API_URL", "http://localhost:8800"),
                   help="API base URL (default: $DEEPSCAN_API_URL or http://localhost:8800).")
    p.add_argument("--lang", help="Comma-separated languages to include (e.g. python,go,rust).")
    p.add_argument("--tier", help="Comma-separated tiers: simple,middle,complex (default: all).")
    p.add_argument("--families", help="Comma-separated scanner families (e.g. sca,sast,secret).")
    p.add_argument("--scanners", help="Comma-separated specific scanners (e.g. trivy,opengrep).")
    p.add_argument("--wait", action="store_true", help="Poll until every scan reaches a terminal state.")
    p.add_argument("--poll-interval", type=float, default=15.0, help="Seconds between polls (--wait).")
    p.add_argument("--timeout", type=float, default=7200.0, help="Max seconds to wait (--wait).")
    p.add_argument("--dry-run", action="store_true", help="Print what would be submitted and exit.")
    args = p.parse_args(argv)

    api = args.api.rstrip("/")
    families = [s.strip() for s in args.families.split(",")] if args.families else None
    scanners = [s.strip() for s in args.scanners.split(",")] if args.scanners else None
    rows = _selected(args)
    if not rows:
        print("No repositories match the given filters.", file=sys.stderr)
        return 2

    print(f"Deep Scan benchmark: {len(rows)} repo(s) via {api}"
          + (f" | families={','.join(families)}" if families else "")
          + (f" | scanners={','.join(scanners)}" if scanners else ""))
    if args.dry_run:
        for language, tier, url in rows:
            print(f"  [{language:<7} {tier:<7}] {url}")
        return 0

    submitted: list[tuple[str, str, str, int]] = []  # (lang, tier, url, job_id)
    failed_submit = 0
    for language, tier, url in rows:
        payload = {"target_type": "git", "target": url}
        if families:
            payload["families"] = families
        if scanners:
            payload["scanners"] = scanners
        try:
            res = _post(api, payload)
            job_id = int(res["id"])
            submitted.append((language, tier, url, job_id))
            print(f"  + [{language:<7} {tier:<7}] job {job_id:<6} {url}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:200]
            print(f"  ! [{language:<7} {tier:<7}] SUBMIT FAILED ({exc.code}): {detail}", file=sys.stderr)
            failed_submit += 1
        except (urllib.error.URLError, OSError) as exc:
            print(f"  ! API unreachable at {api}: {exc}", file=sys.stderr)
            return 3

    print(f"\nSubmitted {len(submitted)}/{len(rows)} scan(s)"
          + (f", {failed_submit} rejected" if failed_submit else "") + ".")
    if not args.wait or not submitted:
        if submitted:
            print("Track them: GET", f"{api}/api/scans   (or the dashboard).")
        return 1 if failed_submit else 0

    # --- wait for terminal states ------------------------------------------ #
    print(f"\nWaiting for {len(submitted)} scan(s) (poll={args.poll_interval}s, timeout={args.timeout}s)...")
    pending = {jid: (lang, tier, url) for lang, tier, url, jid in submitted}
    results: dict[int, dict] = {}
    deadline = time.monotonic() + args.timeout
    while pending and time.monotonic() < deadline:
        time.sleep(args.poll_interval)
        for jid in list(pending):
            try:
                job = _get(api, jid)
            except (urllib.error.URLError, OSError) as exc:
                print(f"  (poll job {jid} failed: {exc})", file=sys.stderr)
                continue
            if job.get("status") in _TERMINAL:
                results[jid] = job
                lang, tier, _ = pending.pop(jid)
                print(f"  = job {jid:<6} [{lang:<7} {tier:<7}] {job.get('status'):<10} "
                      f"findings={_findings(job)}")

    # --- results table ----------------------------------------------------- #
    print("\n=== Results ===")
    print(f"{'LANG':<8} {'TIER':<7} {'JOB':<6} {'STATUS':<10} {'FINDINGS':<9} REPO")
    ok = fail = timedout = 0
    for lang, tier, url, jid in submitted:
        job = results.get(jid)
        if job is None:
            status, findings = "TIMEOUT", "-"
            timedout += 1
        else:
            status = job.get("status", "?")
            findings = _findings(job)
            if status == "done":
                ok += 1
            else:
                fail += 1
        print(f"{lang:<8} {tier:<7} {jid:<6} {status:<10} {str(findings):<9} {url}")
    print(f"\n{ok} done, {fail} failed/other, {timedout} still running at timeout.")
    return 0 if (fail == 0 and timedout == 0 and failed_submit == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
