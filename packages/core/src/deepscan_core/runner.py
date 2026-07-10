"""Scan orchestration: select scanners, run them concurrently, build a Report."""

from __future__ import annotations

import asyncio
import datetime as dt
import tempfile
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from . import config, metrics, registry
from .dedup import deduplicate
from .log import get_logger
from .models import Family, Mode, Report, ToolStatus
from .scanners import ScanContext
from .validation import resolve_scan_dir, validate_target_url

_log = get_logger("runner")


def detect_mode(target: str) -> Mode:
    parts = urlsplit(target.strip())
    if parts.scheme in ("http", "https"):
        return Mode.DYNAMIC
    return Mode.STATIC


def _relativize_location(location: str, roots: list[str]) -> str:
    """Strip the scan-root prefix from a finding location.

    Tools handed an absolute target echo absolute paths (and the scan root is a
    transient per-run RAM staging dir, e.g. ``/ramscan/deepscan-scan/<hash>/``),
    so their locations read ``/ramscan/.../core/http/src/uri/absolute.rs:15``.
    We rewrite those to ``core/http/src/uri/absolute.rs:15`` - relative to the
    scanned tree (i.e. to the retained source root). Locations that are not
    paths under the scan root (package specs, URLs) or already relative are
    returned unchanged; the rewrite is idempotent.
    """
    if not location:
        return location
    loc = location[7:] if location.startswith("file://") else location
    for root in roots:
        prefix = root if root.endswith("/") else root + "/"
        if loc.startswith(prefix):
            return loc[len(prefix):]
    return location


# A progress callback: ``on_progress(kind, data)`` where ``kind`` is one of
# "plan" (data={"scanners": [{"name","family"}, ...]}), "start" (data={"name"})
# or "finish" (data={"name","status","duration","findings","detail"}). It is
# best-effort (never allowed to break the scan) and lets a caller surface a live
# per-scanner step view. Producers fire before consumers, mirroring run order.
ProgressFn = Callable[[str, "dict[str, Any]"], None]


async def run_scan(
    target: str,
    *,
    mode: Mode | None = None,
    families: list[Family] | None = None,
    scanners: list[str] | None = None,
    parallel: int | None = None,
    raw_dir: Path | None = None,
    allow_private_urls: bool = True,
    surface: str = "library",
    on_progress: ProgressFn | None = None,
    cancel_event: "threading.Event | None" = None,
) -> Report:
    """Run a scan and return the normalized, deduplicated Report.

    ``target`` is a directory (static) or a URL (dynamic); ``mode`` is
    auto-detected when omitted. Disabled scanners (env toggles) are excluded.
    ``on_progress`` (optional) receives live per-scanner step events.
    ``cancel_event`` (optional) is surfaced to scanners via ``ctx.should_stop``
    so a long, CPU-bound scanner can abort cooperatively when the job is
    cancelled.
    """

    def _emit(kind: str, data: dict[str, Any]) -> None:
        if on_progress is None:
            return
        try:
            on_progress(kind, data)
        except Exception:  # noqa: BLE001 - a progress hook must never break a scan
            _log.debug("on_progress hook raised", exc_info=True)
    mode = mode or detect_mode(target)
    if mode == Mode.STATIC:
        target_path: Path | None = resolve_scan_dir(target)
        target_url = None
        target_display = str(target_path)
    else:
        target_path = None
        target_url = validate_target_url(target, allow_private=allow_private_urls)
        target_display = target_url

    # Naming a scanner explicitly opts it in even if it is off-by-default
    # (only a falsey env toggle then disables it); otherwise the scanner's
    # own default decides.
    explicit = bool(scanners)
    selected = [
        s
        for s in registry.select(mode=mode, families=families, names=scanners)
        if config.scanner_enabled(s.name, default=True if explicit else s.enabled_by_default)
    ]
    if scanners:
        # Explicitly requested scanners must match the target mode.
        mismatched = [s.name for s in selected if s.mode != mode]
        if mismatched:
            raise ValueError(
                f"Scanner(s) {', '.join(mismatched)} do not support {mode.value} targets."
            )

    started = time.monotonic()
    semaphore = asyncio.Semaphore(parallel or config.max_parallel_scanners())

    # Two phases: producer scanners run first and their findings are fed to
    # consumer scanners (e.g. ai-analysis) so they can triage across everything.
    producers = [s for s in selected if not s.consumes_findings]
    consumers = [s for s in selected if s.consumes_findings]
    # A consumer needs something to triage: if the user named only consumers,
    # auto-include the default producer set for this mode so there is input.
    if consumers and not producers:
        producers = [
            s
            for s in registry.select(mode=mode)
            if not s.consumes_findings
            and config.scanner_enabled(s.name, default=s.enabled_by_default)
        ]
        _log.info(
            "consumer scanner requested - auto-running %d producer(s) first",
            len(producers),
        )

    _log.info(
        "scan starting: %s mode=%s | producers: %s%s",
        target_display,
        mode.value,
        ", ".join(s.name for s in producers) or "(none)",
        f" | consumers: {', '.join(s.name for s in consumers)}" if consumers else "",
    )

    # Announce the full plan (producers then consumers) so the caller can lay out
    # every step up front and fill them in as they run.
    _emit(
        "plan",
        {"scanners": [{"name": s.name, "family": s.family.value} for s in producers + consumers]},
    )

    with tempfile.TemporaryDirectory(prefix="deepscan-") as tmp:
        ctx = ScanContext(
            work_dir=Path(tmp),
            raw_dir=raw_dir,
            target_path=target_path,
            target_url=target_url,
            cancel_event=cancel_event,
        )

        # Scan-root prefixes to strip from finding locations so the report shows
        # paths relative to the scanned tree, never the transient RAM staging
        # dir. Both the target as given and its resolved (symlink-free) form are
        # stripped, since some scanners pass a resolved path to their tool.
        relativize_roots: list[str] = []
        if target_path is not None:
            relativize_roots.append(str(target_path))
            try:
                resolved = str(target_path.resolve())
                if resolved != str(target_path):
                    relativize_roots.append(resolved)
            except OSError:
                pass

        async def _bounded(scanner):
            async with semaphore:
                _emit("start", {"name": scanner.name})
                result = await scanner.run(ctx)
                if relativize_roots:
                    for finding in result.findings:
                        finding.location = _relativize_location(
                            finding.location, relativize_roots
                        )
                _emit(
                    "finish",
                    {
                        "name": scanner.name,
                        "status": result.status.value,
                        "duration": result.duration,
                        "findings": len(result.findings),
                        "detail": result.error or result.skip_reason or None,
                    },
                )
                return result

        # Pre-scan dependency resolution: generate missing lockfiles (offline, no
        # project code executed) so the SCA scanner sees the full transitive
        # tree. Gated behind DEEPSCAN_RESOLVE_DEPS; only worthwhile when an SCA
        # scanner will run over a directory target. Best-effort - never breaks a
        # scan. Runs in a thread (subprocess-bound) so the event loop stays free.
        if (
            target_path is not None
            and config.resolve_deps_enabled()
            and any(s.family == Family.SCA for s in producers)
        ):
            _emit("start", {"name": "resolve-deps"})
            try:
                from .resolve import ResolveStatus, resolve_dependencies

                res = await asyncio.to_thread(
                    resolve_dependencies,
                    target_path,
                    nexus_url=config.nexus_url(),
                    scratch=Path(tmp) / "resolve",
                )
                gen = sum(1 for r in res if r.status is ResolveStatus.GENERATED)
                _log.info(
                    "resolve: %d lockfile(s) generated | %s",
                    gen,
                    ", ".join(f"{r.ecosystem}:{r.status.value}" for r in res) or "(none)",
                )
                _emit("finish", {"name": "resolve-deps", "status": "ok",
                                 "duration": 0.0, "findings": 0,
                                 "detail": f"{gen} lockfile(s) generated"})
            except Exception as exc:  # noqa: BLE001 - resolution must never break a scan
                _log.warning("resolve: skipped (%s)", exc)
                _emit("finish", {"name": "resolve-deps", "status": "error",
                                 "duration": 0.0, "findings": 0, "detail": str(exc)})

        results = await asyncio.gather(*(_bounded(s) for s in producers))

        consumer_results: list = []
        if consumers:
            ctx.prior_findings = [
                f for r in results if r.status == ToolStatus.OK for f in r.findings
            ]
            _log.info(
                "phase 1 done - %d finding(s) from producers; running %d consumer(s)",
                len(ctx.prior_findings),
                len(consumers),
            )
            consumer_results = await asyncio.gather(*(_bounded(s) for s in consumers))

    results = list(results) + list(consumer_results)
    all_findings = [f for r in results if r.status == ToolStatus.OK for f in r.findings]
    triage = next(
        (r.payload for r in consumer_results if r.status == ToolStatus.OK and r.payload),
        None,
    )
    deduped = deduplicate(all_findings)
    ran = sum(1 for r in results if r.status == ToolStatus.OK)
    errored = sum(1 for r in results if r.status == ToolStatus.ERROR)
    _log.info(
        "scan done in %.1fs - %d scanner(s) ran, %d errored | %d finding(s) (%d after dedup)%s",
        time.monotonic() - started,
        ran,
        errored,
        len(all_findings),
        len(deduped),
        " | triage produced" if triage else "",
    )
    report = Report(
        mode=mode,
        target=target_display,
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        duration=time.monotonic() - started,
        tools=results,
        findings=deduped,
        triage=triage,
    )
    metrics.record_scan(report, surface=surface)  # anonymous, no-op without SENTRY_DSN
    return report


def new_report_dir(mode: Mode, base: Path | None = None) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = (base or config.reports_dir()) / f"scan_{stamp}_{mode.value}"
    directory.mkdir(parents=True, exist_ok=True)
    return directory
