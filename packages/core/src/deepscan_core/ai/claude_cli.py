"""Headless Claude CLI invocation, shared by AI scanners.

Runs ``claude --print --output-format json`` read-only, inheriting the
environment (so ``ANTHROPIC_BASE_URL`` / ``ANTHROPIC_AUTH_TOKEN`` /
``ANTHROPIC_MODEL`` select a local model) and never loading the untrusted
target repo's ``.claude/`` settings. It never edits files or opens PRs.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .. import config
from ..log import get_logger

_log = get_logger("ai-analysis")


class ClaudeUnavailable(Exception):
    """The Claude CLI binary could not be found."""


@dataclass
class ClaudeRun:
    """One headless Claude invocation: the final assistant text, the full raw
    transcript (stream-json lines), and the parsed events (every turn + tool
    call) so the whole conversation can be logged and persisted."""

    text: str
    raw: str
    events: list[dict] = field(default_factory=list)


def claude_binary() -> str:
    """Resolve the Claude CLI path, raising ClaudeUnavailable if absent."""
    found = shutil.which(config.claude_bin())
    if found is None:
        raise ClaudeUnavailable(
            f"Claude CLI {config.claude_bin()!r} not found. Install Claude Code "
            "or set DEEPSCAN_CLAUDE_BIN (point ANTHROPIC_* at a local model)."
        )
    return found


def build_command(claude: str, *, add_dirs: list[Path] | None = None) -> list[str]:
    cmd = [
        claude,
        "--print",
        # stream-json (+ --verbose, required in --print mode) so the full
        # conversation - every assistant turn and tool call - is captured, not
        # just the final answer.
        "--output-format", "stream-json", "--verbose",
        "--permission-mode", config.claude_permission_mode(),
        "--allowedTools", config.claude_allowed_tools(),
        # Do not load the untrusted target's project/local .claude settings.
        "--setting-sources", config.claude_setting_sources(),
    ]
    for d in add_dirs or []:
        cmd += ["--add-dir", str(d)]
    if model := config.claude_model():
        cmd += ["--model", model]
    if settings := config.claude_settings():
        cmd += ["--settings", settings]
    cmd += config.claude_extra_args()
    return cmd


async def run_claude(prompt: str, *, cwd: Path, timeout: int, add_dirs: list[Path] | None = None) -> ClaudeRun:
    """Invoke claude with *prompt* on stdin; return a :class:`ClaudeRun` with the
    final text, the raw transcript and the parsed events.

    Raises ClaudeUnavailable if the CLI is missing, RuntimeError on a reported
    error, asyncio.TimeoutError on timeout.
    """
    claude = claude_binary()
    cmd = build_command(claude, add_dirs=add_dirs)
    _log.debug("exec %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(cwd),
        env=dict(os.environ),
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(prompt.encode()), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    raw = out.decode(errors="replace")
    events = _parse_events(raw)
    text = _result_text(events, raw, proc.returncode or 0, err.decode(errors="replace"))
    return ClaudeRun(text=text, raw=raw, events=events)


def _parse_events(raw: str) -> list[dict]:
    """Parse the stream-json transcript (one JSON object per line). Tolerant: a
    single ``--output-format json`` envelope parses as one event too."""
    events: list[dict] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def _result_text(events: list[dict], raw: str, code: int, stderr: str) -> str:
    """Extract the assistant's final text from the parsed events."""
    for ev in reversed(events):
        if ev.get("type") == "result":
            if ev.get("is_error"):
                raise RuntimeError(f"claude reported an error: {str(ev.get('result'))[:500]}")
            return str(ev.get("result", ""))
    # No result event: concatenate any assistant text blocks.
    texts: list[str] = []
    for ev in events:
        if ev.get("type") == "assistant":
            for block in (ev.get("message", {}).get("content") or []):
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(block.get("text", ""))
    if texts:
        return "\n".join(texts)
    if code != 0:
        raise RuntimeError(f"claude exited {code}: {stderr.strip()[-500:]}")
    return raw.strip()


def _brief(value, limit: int = 160) -> str:
    s = value if isinstance(value, str) else json.dumps(value, default=str)
    s = " ".join(s.split())
    return s if len(s) <= limit else s[:limit] + "…"


def format_transcript(events: list[dict]) -> str:
    """Human-readable rendering of the whole conversation (turns + tool calls)."""
    lines: list[str] = []
    for ev in events:
        t = ev.get("type")
        if t == "system":
            # Only the one-time init event is interesting; skip the other,
            # field-less system events the CLI streams.
            if ev.get("subtype") == "init" or ev.get("model"):
                lines.append(
                    f"[system] model={ev.get('model')} cwd={ev.get('cwd')} "
                    f"tools={','.join((ev.get('tools') or [])[:10])}"
                )
        elif t == "assistant":
            for block in (ev.get("message", {}).get("content") or []):
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text" and (block.get("text") or "").strip():
                    lines.append(f"[assistant] {_brief(block['text'], 600)}")
                elif block.get("type") == "tool_use":
                    lines.append(f"[tool_use] {block.get('name')}({_brief(block.get('input', {}))})")
        elif t == "user":
            for block in (ev.get("message", {}).get("content") or []):
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    lines.append(f"[tool_result] {_brief(block.get('content'))}")
        elif t == "result":
            lines.append(
                f"[result] is_error={ev.get('is_error')} "
                f"cost=${ev.get('total_cost_usd')} duration={ev.get('duration_ms')}ms"
            )
    return "\n".join(lines)


def tool_call_count(events: list[dict]) -> int:
    return sum(
        1
        for ev in events
        if ev.get("type") == "assistant"
        for b in (ev.get("message", {}).get("content") or [])
        if isinstance(b, dict) and b.get("type") == "tool_use"
    )


def extract_json_object(text: str) -> dict | None:
    """Pull a JSON object out of the model's final message, tolerating prose or
    a ```json fence."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, ValueError):
        pass
    if "```" in text:
        for block in text.split("```")[1:]:
            body = block[4:] if block.lower().startswith("json") else block
            try:
                parsed = json.loads(body.strip())
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                continue
    start = text.find("{")
    end = text.rfind("}")
    if 0 <= start < end:
        try:
            parsed = json.loads(text[start : end + 1])
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass
    return None
