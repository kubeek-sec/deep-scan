"""Anonymous telemetry + operational metrics via the Sentry SDK.

What this sends, per scan, **only when ``SENTRY_DSN`` is set** (and not opted out
with ``DEEPSCAN_TELEMETRY=false``):

* a ``deepscan.scan`` transaction with low-cardinality **tags** (mode, surface
  cli/api/mcp/kruncher, deepscan version, os/arch, an anonymous install id) and
  **measurements** (counts of findings - total, deduped, per family, per
  severity - and scan duration), plus a ``scanners`` context (per-scanner status
  / count / duration). These power both operational dashboards ("how long do
  scans take", "which scanners error") and product analytics ("how often is it
  used", "what kinds of issues are detected", "how much did it help").

**Privacy by construction:** ``send_default_pii=False``; we never send the scan
target path, file names, finding locations/messages, or any secret value - only
aggregate counts and the low-cardinality tags above. The install id is a random
value (no hostname/user), persisted best-effort so repeat scans from one machine
can be counted without identifying it; if it cannot be persisted a per-process
id is used (you still get usage counts, just not unique-install counts).

Everything degrades to a no-op if the SDK is missing, the DSN is unset, or
anything fails - telemetry must never affect a scan.
"""

from __future__ import annotations

import platform
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from . import config
from .log import get_logger

if TYPE_CHECKING:
    from .models import Report

_log = get_logger("metrics")
_initialized = False
_enabled = False
_anon_id: str | None = None

try:
    import sentry_sdk  # type: ignore
except Exception:  # noqa: BLE001 - SDK optional
    sentry_sdk = None  # type: ignore


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("deepscan-core")
    except Exception:  # noqa: BLE001
        return "0.0.0"


def anon_id() -> str:
    """A random, non-identifying install id, persisted best-effort under the
    tools dir so repeat runs share it; per-process otherwise."""
    global _anon_id
    if _anon_id:
        return _anon_id
    path = config.tools_dir() / "telemetry-id"
    try:
        if path.is_file():
            _anon_id = path.read_text(encoding="utf-8").strip() or None
        if not _anon_id:
            _anon_id = uuid.uuid4().hex
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_anon_id, encoding="utf-8")
    except OSError:
        _anon_id = _anon_id or uuid.uuid4().hex
    return _anon_id


def init() -> bool:
    """Idempotently initialise Sentry from config. Returns whether telemetry is
    on. Safe to call from every entry point."""
    global _initialized, _enabled
    if _initialized:
        return _enabled
    _initialized = True
    if sentry_sdk is None or not config.telemetry_enabled():
        _enabled = False
        return False
    try:
        sentry_sdk.init(
            dsn=config.sentry_dsn(),
            environment=config.sentry_environment(),
            release=f"deepscan@{_version()}",
            traces_sample_rate=config.sentry_traces_sample_rate(),
            send_default_pii=False,
            # Server name can leak the hostname - replace with the anon id.
            server_name=False,
        )
        sentry_sdk.set_tag("anon_id", anon_id())
        sentry_sdk.set_tag("deepscan_version", _version())
        sentry_sdk.set_tag("os", platform.system().lower())
        sentry_sdk.set_tag("arch", platform.machine().lower())
        _enabled = True
        _log.debug("telemetry enabled (env=%s)", config.sentry_environment())
    except Exception as exc:  # noqa: BLE001
        _log.debug("telemetry init failed (ignored): %s", exc)
        _enabled = False
    return _enabled


def record_scan(report: "Report", *, surface: str = "library") -> None:
    """Push anonymous, aggregate metrics for one completed scan. Never raises."""
    if not init():
        return
    try:
        _record(report, surface)
    except Exception as exc:  # noqa: BLE001 - telemetry must not break a scan
        _log.debug("telemetry record failed (ignored): %s", exc)


def summarize(report: "Report", surface: str) -> dict:
    """The anonymous payload sent for a scan. Pure function (no Sentry), so the
    privacy contract is testable: only counts + low-cardinality tags, never the
    target path or any finding detail."""
    from .models import Severity, ToolStatus

    ran = [t for t in report.tools if t.status == ToolStatus.OK]
    skipped = [t for t in report.tools if t.status == ToolStatus.SKIPPED]
    errored = [t for t in report.tools if t.status == ToolStatus.ERROR]
    by_family: dict[str, int] = {}
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    for f in report.findings:
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        for fam in f.families:
            by_family[fam] = by_family.get(fam, 0) + 1
    return {
        "tags": {
            "mode": report.mode.value,
            "surface": surface,
            "had_findings": str(bool(report.findings)).lower(),
        },
        "measurements": {
            "findings.total": sum(len(t.findings) for t in report.tools),
            "findings.deduped": len(report.findings),
            "duration.seconds": report.duration,
            "scanners.ran": len(ran),
            "scanners.skipped": len(skipped),
            "scanners.errored": len(errored),
            **{f"family.{k}": v for k, v in by_family.items()},
            **{f"severity.{k}": v for k, v in by_severity.items()},
        },
        "scanners": {
            t.scanner: {"status": t.status.value, "findings": len(t.findings),
                        "duration_s": round(t.duration, 2)}
            for t in report.tools
        },
        "by_family": by_family,
        "by_severity": {k: v for k, v in by_severity.items() if v},
    }


def _record(report: "Report", surface: str) -> None:
    s = summarize(report, surface)
    tx = sentry_sdk.start_transaction(op="scan", name="deepscan.scan")
    try:
        for k, v in s["tags"].items():
            tx.set_tag(k, v)
        tx.set_data("scanners", s["scanners"])
        # Numeric values as span attributes (data) - the supported, queryable
        # form in current Sentry (set_measurement is deprecated).
        for name, value in s["measurements"].items():
            tx.set_data(name, value)
    finally:
        tx.finish()

    # Bonus: the (deprecated/optional) Sentry metrics API, if this SDK has it -
    # gives proper counters/distributions for "how many scans / detections".
    m = getattr(sentry_sdk, "metrics", None)
    if m is not None:
        try:
            base = s["tags"]
            m.incr("deepscan.scan", 1, tags={"mode": base["mode"], "surface": base["surface"]})
            m.distribution("deepscan.scan.findings", len(report.findings),
                           tags={"surface": base["surface"]})
            for fam, c in s["by_family"].items():
                m.incr("deepscan.findings", c, tags={"family": fam, "surface": base["surface"]})
            for sev, c in s["by_severity"].items():
                m.incr("deepscan.findings.severity", c,
                       tags={"severity": sev, "surface": base["surface"]})
        except Exception:  # noqa: BLE001
            pass


def capture_exception(exc: BaseException) -> None:
    """Report an operational error (best-effort)."""
    if init() and sentry_sdk is not None:
        try:
            sentry_sdk.capture_exception(exc)
        except Exception:  # noqa: BLE001
            pass


def flush(timeout: float = 2.0) -> None:
    """Flush pending events - call before a short-lived process exits (CLI)."""
    if _enabled and sentry_sdk is not None:
        try:
            sentry_sdk.flush(timeout=timeout)
        except Exception:  # noqa: BLE001
            pass
