"""Deep Scan command-line interface.

    deepscan scan <dir|url> [--family ...] [--scanner ...] [--format ...]
                            [--fail-on SEVERITY] [--out DIR]
    deepscan scanners
    deepscan tools [status|install <name|all>]

Designed for both local use and CI: ``--fail-on`` sets the process exit code
from the highest severity found, so a pipeline step fails the build.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from deepscan_core import Family, Mode, install, metrics, registry, run_scan
from deepscan_core.log import setup_logging
from deepscan_core.models import Severity
from deepscan_core.reporting import (
    ALL_FORMATS,
    FORMATS,
    render,
    render_triage_console,
    write_report,
    write_triage,
)
from deepscan_core.runner import detect_mode, new_report_dir
from deepscan_core.validation import ScanTargetError

_EXIT_OK = 0
_EXIT_FINDINGS = 1
_EXIT_ERROR = 2


def _add_scan_parser(sub) -> None:
    p = sub.add_parser("scan", help="Run a scan over a directory or URL.")
    p.add_argument("target", help="Local directory (static) or http(s) URL (dynamic).")
    p.add_argument(
        "--mode",
        choices=[m.value for m in Mode],
        help="Force scan mode (default: auto-detect from target).",
    )
    p.add_argument(
        "--family",
        action="append",
        choices=[f.value for f in Family],
        help="Limit to a family (repeatable).",
    )
    p.add_argument(
        "--scanner",
        action="append",
        help="Limit to a named scanner (repeatable). Overrides --family.",
    )
    p.add_argument(
        "--format",
        action="append",
        choices=list(ALL_FORMATS),
        help="Report format(s) to write (repeatable). Default: all.",
    )
    p.add_argument(
        "--out",
        type=Path,
        help="Report output directory (default: ./reports/scan_<ts>_<mode>).",
    )
    p.add_argument(
        "--stdout",
        choices=list(FORMATS),
        help="Also print this format to stdout.",
    )
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit 1 if any finding is at or above this severity (for CI).",
    )
    p.add_argument("--parallel", type=int, help="Max concurrent scanners.")
    p.add_argument("--quiet", action="store_true", help="Suppress the progress summary.")
    p.add_argument(
        "--debug",
        action="store_true",
        help="Verbose DEBUG logging (same as DEEPSCAN_DEBUG=1).",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="deepscan", description="Deep Scan security scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    _add_scan_parser(sub)

    sub.add_parser("scanners", help="List available scanners.")

    tools = sub.add_parser("tools", help="Manage scanner tools.")
    tools_sub = tools.add_subparsers(dest="tools_command", required=False)
    tools_sub.add_parser("status", help="Show install status of every tool.")
    install_p = tools_sub.add_parser("install", help="Install a tool (or 'all').")
    install_p.add_argument("name", help="Tool name, or 'all'.")
    install_p.add_argument("--force", action="store_true", help="Reinstall if present.")
    return parser


def _cmd_scanners() -> int:
    rows = registry.describe()
    width = max(len(r["name"]) for r in rows)
    print(f"{'SCANNER':<{width}}  FAMILY     MODE     DESCRIPTION")
    for r in rows:
        print(f"{r['name']:<{width}}  {r['family']:<9}  {r['mode']:<7}  {r['description']}")
    return _EXIT_OK


def _cmd_tools(args) -> int:
    command = getattr(args, "tools_command", None) or "status"
    if command == "status":
        for s in install.status_all():
            mark = "✓" if s.installed else "·"
            location = s.path or "(not installed)"
            print(f" {mark} {s.name:<14} {s.version:<10} {location}")
        return _EXIT_OK
    if command == "install":
        try:
            if args.name.lower() == "all":
                for s in install.install_all(force=args.force):
                    print(f" ✓ {s.name} {s.version}")
            else:
                s = install.install(args.name, force=args.force)
                print(f" ✓ {s.name} {s.version} -> {s.path}")
            return _EXIT_OK
        except install.InstallError as exc:
            print(f"Install failed: {exc}", file=sys.stderr)
            return _EXIT_ERROR
    return _EXIT_ERROR


def _cmd_scan(args) -> int:
    mode = Mode(args.mode) if args.mode else detect_mode(args.target)
    families = [Family(f) for f in args.family] if args.family else None
    out_dir = args.out or new_report_dir(mode)
    formats = tuple(args.format) if args.format else ALL_FORMATS

    try:
        report = asyncio.run(
            run_scan(
                args.target,
                mode=mode,
                families=families,
                scanners=args.scanner,
                parallel=args.parallel,
                raw_dir=out_dir / "raw",
                surface="cli",
            )
        )
    except ScanTargetError as exc:
        print(f"Invalid scan target: {exc}", file=sys.stderr)
        return _EXIT_ERROR
    except (ValueError, registry.UnknownScannerError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return _EXIT_ERROR

    written = write_report(report, out_dir, formats)
    triage_written = write_triage(report, out_dir)

    if not args.quiet:
        _print_summary(report, written, triage_written)
    if args.stdout:
        print(render(report, args.stdout))

    if args.fail_on:
        threshold = Severity(args.fail_on)
        worst = min((f.severity.rank for f in report.findings), default=99)
        if worst <= threshold.rank:
            return _EXIT_FINDINGS
    return _EXIT_OK


def _print_summary(report, written, triage_written=None) -> None:
    totals = report.severity_totals
    print(f"\nDeep Scan - {report.mode.value} scan of {report.target}", file=sys.stderr)
    print(
        "  "
        + "  ".join(f"{sev.value}={totals[sev.value]}" for sev in Severity)
        + f"  (total {len(report.findings)} deduplicated)",
        file=sys.stderr,
    )
    ran = [t for t in report.tools if t.status.value == "ok"]
    skipped = [t for t in report.tools if t.status.value == "skipped"]
    errored = [t for t in report.tools if t.status.value == "error"]
    print(
        f"  scanners: {len(ran)} ran, {len(skipped)} skipped, {len(errored)} errored",
        file=sys.stderr,
    )
    for t in errored:
        print(f"    ! {t.scanner}: {t.error}", file=sys.stderr)
    print(f"  reports: {', '.join(str(p) for p in written.values())}", file=sys.stderr)
    if report.triage:
        print(render_triage_console(report.triage), file=sys.stderr)
        if triage_written:
            print(
                f"  triage report: {', '.join(str(p) for p in triage_written.values())}",
                file=sys.stderr,
            )


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    setup_logging("DEBUG" if getattr(args, "debug", False) else None)
    if args.command == "scan":
        code = _cmd_scan(args)
    elif args.command == "scanners":
        code = _cmd_scanners()
    elif args.command == "tools":
        code = _cmd_tools(args)
    else:
        code = _EXIT_ERROR
    metrics.flush()  # send any telemetry before this short-lived process exits
    if argv is None:
        sys.exit(code)
    return code


if __name__ == "__main__":
    main()
