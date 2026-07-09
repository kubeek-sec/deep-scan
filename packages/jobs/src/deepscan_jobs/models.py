"""Shared job constants used across the API, MCP server and kruncher."""

from __future__ import annotations

import enum


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"        # ad-hoc terminal failure (no retry)
    DEAD = "dead"            # discovery terminal failure (retries exhausted)
    SUPERSEDED = "superseded"
    CANCELLED = "cancelled"


class JobOrigin(str, enum.Enum):
    DISCOVERY = "discovery"  # kruncher, tied to a source - the *periodic* queue
    ADHOC = "adhoc"          # API / MCP direct submission - the *manual* queue


# The two logical queues, keyed by ``origin``. Both live in ``scan_jobs`` and are
# drained by the same kruncher worker fleet; the worker prefers MANUAL so an
# operator-submitted scan never waits behind queued periodic work.
QUEUE_MANUAL = JobOrigin.ADHOC.value
QUEUE_PERIODIC = JobOrigin.DISCOVERY.value

# Default queue priorities (lower runs sooner). The worker already drains the
# manual queue ahead of the periodic one (see ``store.claim_job``); these values
# order jobs *within* a queue and act as a second guard if both are claimed at
# once. An admin "scan now" of a known source is the most urgent.
PRIORITY_MANUAL_RESCAN = 10   # admin "scan this source now" (discovery, on demand)
PRIORITY_ADHOC = 20           # API / MCP manual submission
PRIORITY_PERIODIC = 100       # scheduler-enqueued periodic scan

# Statuses that are not terminal and should be superseded by a new scan.
OPEN_STATUSES = ("queued", "failed", "dead")
TERMINAL_STATUSES = ("done", "dead", "superseded", "cancelled")

# Target types accepted for an ad-hoc submission.
ADHOC_TARGET_TYPES = ("url", "git", "path", "zip")
