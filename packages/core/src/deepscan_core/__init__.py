"""deepscan-core - shared security scanning engine.

Public API:

    from deepscan_core import run_scan, Mode, Family
    report = await run_scan("/path/to/project")           # static, auto
    report = await run_scan("http://localhost:3000")      # dynamic, auto

    from deepscan_core.reporting import write_report
    write_report(report, Path("reports/scan_x"))
"""

from . import config, install, registry
from .models import (
    DedupedFinding,
    Family,
    Finding,
    Mode,
    Report,
    Severity,
    ToolResult,
    ToolStatus,
)
from .runner import detect_mode, new_report_dir, run_scan
from .validation import ScanTargetError, resolve_scan_dir, validate_target_url

__version__ = "0.1.0"

__all__ = [
    "config",
    "install",
    "registry",
    "DedupedFinding",
    "Family",
    "Finding",
    "Mode",
    "Report",
    "Severity",
    "ToolResult",
    "ToolStatus",
    "detect_mode",
    "new_report_dir",
    "run_scan",
    "ScanTargetError",
    "resolve_scan_dir",
    "validate_target_url",
    "__version__",
]
