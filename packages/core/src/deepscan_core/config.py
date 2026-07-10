"""Environment-driven configuration.

Plain ``KEY=VALUE`` pairs; a ``.env`` file in the current directory is read as
fallback, real environment variables always win. No third-party dependency.
"""

from __future__ import annotations

import os
from pathlib import Path

_FALSEY = {"false", "0", "no", "off", "disable", "disabled"}

_dotenv_cache: dict[str, str] | None = None


def _dotenv() -> dict[str, str]:
    global _dotenv_cache
    if _dotenv_cache is None:
        _dotenv_cache = {}
        path = Path.cwd() / ".env"
        if path.is_file():
            try:
                for line in path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    _dotenv_cache[key.strip()] = value.strip().strip("'\"")
            except OSError:
                pass
    return _dotenv_cache


def get(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, _dotenv().get(key, default))


def env_var_for(scanner_name: str) -> str:
    return scanner_name.upper().replace("-", "_")


def scanner_enabled(scanner_name: str, default: bool = True) -> bool:
    """Whether a scanner runs. An explicit env toggle (e.g. ``OPENGREP=false``,
    ``CLAUDE=true``) always wins; otherwise ``default`` decides - which lets a
    scanner be off-by-default (the LLM scanner) yet opt-in via its env var."""
    value = get(env_var_for(scanner_name))
    if value is None:
        return default
    return value.strip().lower() not in _FALSEY


def tools_dir() -> Path:
    raw = get("DEEPSCAN_TOOLS_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    return Path.home() / ".local" / "share" / "deepscan" / "tools"


def config_dir() -> Path:
    """Root of operator-supplied, per-scanner rule/config overrides.

    ``DEEPSCAN_CONFIG_DIR`` wins; otherwise ``<data>/config`` (the shared data
    volume, e.g. ``/data/config`` in the containers). A scanner uses
    ``<config_dir>/<scanner-name>/`` only when it exists and is non-empty -
    otherwise its built-in / packaged default rules apply.
    """
    raw = get("DEEPSCAN_CONFIG_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    data = get("DEEPSCAN_DATA_DIR") or get("DEEPSCAN_API_DATA_DIR")
    base = Path(data).expanduser().resolve() if data else (
        Path.home() / ".local" / "share" / "deepscan"
    )
    return base / "config"


def scanner_config_dir(name: str) -> Path | None:
    """A scanner's runtime config dir (``config/<name>/``) if it holds files, else None."""
    d = config_dir() / name
    try:
        if d.is_dir() and any(p.is_file() for p in d.iterdir()):
            return d
    except OSError:
        return None
    return None


def reports_dir() -> Path:
    raw = get("DEEPSCAN_REPORTS_DIR")
    if raw:
        return Path(raw).expanduser().resolve()
    return Path.cwd() / "reports"


def scan_root() -> Path | None:
    """Optional confinement: scan targets must live under this directory."""
    raw = get("DEEPSCAN_SCAN_ROOT")
    if raw:
        return Path(raw).expanduser().resolve()
    return None


def timeout_for(scanner_name: str, default: int = 900) -> int:
    specific = get(f"DEEPSCAN_TIMEOUT_{env_var_for(scanner_name)}")
    general = get("DEEPSCAN_TIMEOUT")
    for raw in (specific, general):
        if raw:
            try:
                return max(1, int(raw))
            except ValueError:
                continue
    return default


def max_parallel_scanners(default: int = 4) -> int:
    raw = get("DEEPSCAN_PARALLEL")
    if raw:
        try:
            return max(1, int(raw))
        except ValueError:
            pass
    return default


def analysis_budget_seconds(default: int = 600) -> int | None:
    """Cooperative wall-clock budget (seconds) for the in-process taint pass of
    the ``analysis`` scanner.

    The taint engine builds a whole-program data-flow graph and is CPU-bound; it
    runs in a worker thread that cannot be killed from the outside, so the
    per-scanner ``DEEPSCAN_TIMEOUT`` (a thread-blind ``asyncio.wait_for``) can
    only abandon it, not stop it pegging a core. This budget is checked *inside*
    the engine, which stops cleanly when it is exceeded. Keep it below the hard
    ``DEEPSCAN_TIMEOUT`` so the cooperative stop fires first. ``0`` disables it
    (rely on the hard timeout only). Override with ``DEEPSCAN_ANALYSIS_BUDGET``."""
    raw = get("DEEPSCAN_ANALYSIS_BUDGET")
    if raw:
        try:
            value = int(raw)
            return value if value > 0 else None
        except ValueError:
            pass
    return default


def graph_extract_workers() -> int | None:
    """Subprocess cap for parallel code-graph extraction (the ``analysis`` scanner).

    graphoofy parses files across cores with a ``ProcessPoolExecutor``; on a large
    repo this is the difference between minutes and tens of minutes. Bound it so a
    multi-replica worker host doesn't oversubscribe its CPUs (each kruncher worker
    runs one job at a time, so the risk is several replicas, not several jobs).

    * unset  → graphoofy's own default (one worker per CPU, capped by file count);
    * ``N>0`` → at most ``N`` subprocesses;
    * ``0``  → parallelism disabled (sequential extraction).

    Returns ``None`` when unset (defer to graphoofy), else the parsed integer.
    """
    raw = get("DEEPSCAN_GRAPH_WORKERS")
    if raw:
        try:
            return max(0, int(raw))
        except ValueError:
            pass
    return None


def graph_extract_start_method() -> str | None:
    """multiprocessing start method for the analysis extraction pool.

    The analysis runs inside ``asyncio.to_thread`` (a multi-threaded process), so
    the default ``fork`` start method is unsafe - a forked child can deadlock on a
    lock another thread held at fork time. ``forkserver`` forks pool workers from a
    clean single-threaded server instead, which is safe and still fast.

    ``DEEPSCAN_GRAPH_START_METHOD`` overrides; unset → ``forkserver`` when the
    platform offers it (Linux), else ``spawn``, else ``None`` (platform default).
    """
    raw = get("DEEPSCAN_GRAPH_START_METHOD")
    if raw:
        return raw.strip() or None
    import multiprocessing as mp

    available = mp.get_all_start_methods()
    if "forkserver" in available:
        return "forkserver"
    if "spawn" in available:
        return "spawn"
    return None


def trivy_server() -> str | None:
    """URL of a shared Trivy server, if running in client/server mode.

    When set, the Trivy SCA scanner offloads vulnerability matching to this
    server instead of downloading the vulnerability DB itself - one DB pull for
    the whole fleet, no per-client rate limiting. Honours Trivy's own
    ``TRIVY_SERVER`` as a fallback.
    """
    raw = get("DEEPSCAN_TRIVY_SERVER") or get("TRIVY_SERVER")
    return raw.strip() if raw and raw.strip() else None


def nexus_url() -> str | None:
    """Base URL of the Nexus pull-through mirror, if deployed.

    The dependency resolver points package managers here instead of the public
    registries, so the scan sandbox needs no direct internet and Maven parent-POM
    429s are absorbed by Nexus's cache. ``None`` when unset (resolvers then fall
    back to the public registries, or skip if that is not permitted)."""
    raw = get("DEEPSCAN_NEXUS_URL")
    return raw.strip().rstrip("/") if raw and raw.strip() else None


def resolve_deps_enabled(default: bool = False) -> bool:
    """Whether the pre-scan dependency resolver runs: it generates missing
    lockfiles (without executing project code) so Trivy SCA sees the full
    transitive tree, fully offline. Off by default during rollout; enable with
    ``DEEPSCAN_RESOLVE_DEPS=true``."""
    value = get("DEEPSCAN_RESOLVE_DEPS")
    if value is None:
        return default
    return value.strip().lower() not in _FALSEY


# --- LLM (Claude) scanner -------------------------------------------------- #

def claude_bin() -> str:
    """Path/name of the Claude Code CLI used by the AI scanner."""
    return get("DEEPSCAN_CLAUDE_BIN") or "claude"


def claude_model() -> str | None:
    """Model passed to ``claude --model`` (overrides settings). Optional."""
    raw = get("DEEPSCAN_CLAUDE_MODEL")
    return raw.strip() if raw and raw.strip() else None


def claude_settings() -> str | None:
    """Path to a settings JSON passed via ``--settings`` (e.g. to point at a
    local model through its ``env`` block). Optional."""
    raw = get("DEEPSCAN_CLAUDE_SETTINGS")
    return raw.strip() if raw and raw.strip() else None


def claude_setting_sources() -> str:
    """Which settings sources ``claude`` may load. Defaults to ``user`` only so
    the **untrusted target repo's** ``.claude/settings.json`` (hooks, MCP servers,
    permissions) is NOT loaded when scanning cloned code."""
    return get("DEEPSCAN_CLAUDE_SETTING_SOURCES") or "user"


def claude_permission_mode() -> str:
    """Permission mode for the headless run. ``dontAsk`` denies anything outside
    the allow-list without ever prompting - right for an autonomous read-only
    scan."""
    return get("DEEPSCAN_CLAUDE_PERMISSION_MODE") or "dontAsk"


def claude_allowed_tools() -> str:
    """Comma-separated tool allow-list for the headless run. Read-only by
    default (no Edit/Write) plus the bundled graphoofy analyzer."""
    return get("DEEPSCAN_CLAUDE_ALLOWED_TOOLS") or (
        "Read,Grep,Glob,"
        "Bash(python3 *),Bash(ls *),Bash(find *),Bash(cat *),Bash(head *),Bash(wc *)"
    )


def claude_extra_args() -> list[str]:
    """Extra raw CLI args appended to the ``claude`` invocation (shlex-split)."""
    import shlex

    raw = get("DEEPSCAN_CLAUDE_EXTRA_ARGS")
    return shlex.split(raw) if raw else []


def ai_log_conversation() -> bool:
    """Whether ai-analysis logs the full Claude conversation at INFO (else
    DEBUG). The transcript is always persisted to the report's raw dir.
    Quieten with ``DEEPSCAN_AI_LOG_CONVERSATION=false``."""
    value = get("DEEPSCAN_AI_LOG_CONVERSATION")
    return value is None or value.strip().lower() not in _FALSEY


# --- Logging --------------------------------------------------------------- #

def log_level_name() -> str:
    """Logging level for the ``deepscan`` loggers. ``DEEPSCAN_DEBUG`` (truthy)
    forces DEBUG; otherwise ``DEEPSCAN_LOG_LEVEL`` (e.g. INFO, DEBUG, WARNING)
    decides, defaulting to INFO."""
    debug = get("DEEPSCAN_DEBUG")
    if debug is not None and debug.strip().lower() not in _FALSEY:
        return "DEBUG"
    raw = get("DEEPSCAN_LOG_LEVEL")
    return raw.strip().upper() if raw and raw.strip() else "INFO"


# --- Telemetry (Sentry) ---------------------------------------------------- #

def sentry_dsn() -> str | None:
    """Sentry DSN for anonymous telemetry / error reporting (from env or the
    project ``.env``). Telemetry is fully off when this is unset."""
    raw = get("SENTRY_DSN")
    return raw.strip() if raw and raw.strip() else None


def telemetry_enabled() -> bool:
    """True only if a DSN is set AND not explicitly disabled with
    ``DEEPSCAN_TELEMETRY=false`` (privacy opt-out)."""
    if not sentry_dsn():
        return False
    value = get("DEEPSCAN_TELEMETRY")
    return value is None or value.strip().lower() not in _FALSEY


def sentry_environment() -> str:
    return get("SENTRY_ENVIRONMENT") or "production"


def sentry_traces_sample_rate() -> float:
    raw = get("SENTRY_TRACES_SAMPLE_RATE")
    if raw:
        try:
            return max(0.0, min(1.0, float(raw)))
        except ValueError:
            pass
    return 1.0


# --- CodeQL scanner -------------------------------------------------------- #

def codeql_bin() -> str:
    """Path/name of the CodeQL CLI (the free 'CodeQL CLI bundle', not built from
    source). Override with ``DEEPSCAN_CODEQL_BIN``."""
    return get("DEEPSCAN_CODEQL_BIN") or "codeql"


def codeql_threads() -> str:
    """Threads for db create/analyze (0 = one per core)."""
    return get("DEEPSCAN_CODEQL_THREADS") or "0"


def codeql_query_pack(language: str) -> str:
    """Query pack/suite to run for a language. Defaults to the language's
    standard pack (its default security queries). Override globally with
    ``DEEPSCAN_CODEQL_SUITE`` or per-language with ``DEEPSCAN_CODEQL_SUITE_<LANG>``."""
    return (
        get(f"DEEPSCAN_CODEQL_SUITE_{language.upper()}")
        or get("DEEPSCAN_CODEQL_SUITE")
        or f"codeql/{language}-queries"
    )


def codeql_build_command(language: str) -> str | None:
    """Build command for a compiled language's DB creation
    (``DEEPSCAN_CODEQL_BUILD_<LANG>``, e.g. ``..._GO='go build ./...'``)."""
    raw = get(f"DEEPSCAN_CODEQL_BUILD_{language.upper()}")
    return raw.strip() if raw and raw.strip() else None


def codeql_extra_args() -> list[str]:
    """Extra raw args appended to ``codeql database analyze`` (shlex-split)."""
    import shlex

    raw = get("DEEPSCAN_CODEQL_EXTRA_ARGS")
    return shlex.split(raw) if raw else []
