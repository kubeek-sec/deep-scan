"""Dispatcher: claim one job, run its stages in isolation, keep the lease alive,
finalize on failure.

The dispatcher OWNS the DB lifecycle - it claims the job (so the pod/stages never
race the queue), heartbeats the lease while the stages run, and records a terminal
failure if a stage dies. The stages do the work; the *scan* stage persists the
report (status -> done), so on success the dispatcher does nothing more.

Two executors share the same ``dispatch_one`` control loop:

* **subprocess** (default) - runs the three stages as local subprocesses. The
  ``resolve`` stage gets a secret-free environment, so the untrusted package
  managers it spawns never see git/DB tokens in their env. Used in Compose /
  single-node. NOTE: within one container all stages share a uid, so this is
  defense-in-depth, not a hard secret boundary (a hostile process could read a
  sibling's ``/proc/<pid>/environ``); pair it with gVisor.
* **kubernetes** - one 3-stage pod per job
  (``deploy/kustomize/base/deepscan-scan-3stage-job.template.yaml``), where
  separate containers give a hard secret boundary. Wire it into ``_execute_stages``
  (create the Job with ``DEEPSCAN_JOB_ID``, watch it, propagate failure). Left as
  an extension point - it needs a cluster to validate.

Only **static ad-hoc** jobs use the split; ``url`` (dynamic) jobs run inline via
the monolithic path (there is no source tree to resolve). Discovery/connector
jobs are a follow-up (``materialize_job`` covers ad-hoc targets today).
"""

from __future__ import annotations

import logging
import os
import re
import subprocess  # nosec B404 - fixed argv for our own console scripts, no shell
import threading

from deepscan_jobs import config as jobs_config
from deepscan_jobs import store as jobs_store
from deepscan_jobs.worker import run_job_inline
from deepscan_jobs.models import QUEUE_MANUAL

from . import config, store

log = logging.getLogger("deepscan.kruncher.dispatcher")

# Bump the lease well within config.lease_seconds() (default 1800) while the
# stages run, covering the gaps the scan stage's own progress pump doesn't.
_HEARTBEAT_SECONDS = 30

# Env names carrying secrets - stripped from the resolve stage's environment.
# Denylist (not allowlist) so the trusted `deepscan` CLI keeps PATH/PYTHON*/venv
# vars it needs to start; the untrusted package managers get a stricter allowlist
# inside `deepscan resolve` itself (deepscan_core.resolve).
_SECRET_RE = re.compile(
    r"(TOKEN|PASSWORD|SECRET|_KEY$|_KEYS$|CREDENTIAL|_PAT$|PASSPHRASE|"
    r"ANTHROPIC|OPENAI|AWS_|GITHUB|GITLAB|SENTRY_DSN|DB_PASSWORD)",
    re.IGNORECASE,
)


def _resolve_env() -> dict[str, str]:
    """The resolve stage env: everything the CLI needs minus anything secret."""
    return {k: v for k, v in os.environ.items() if not _SECRET_RE.search(k)}


def _heartbeat_loop(job_id: int, stop: threading.Event) -> None:
    while not stop.wait(_HEARTBEAT_SECONDS):
        try:
            jobs_store.heartbeat(job_id)
        except Exception:  # noqa: BLE001 - heartbeat is best-effort
            log.debug("heartbeat failed for job %s", job_id, exc_info=True)


def _run_stage(cmd: list[str], *, env: dict[str, str], label: str,
               check: bool = True) -> None:
    log.info("stage[%s]: %s", label, " ".join(cmd))
    proc = subprocess.run(  # nosec B603 - argv list, our own console scripts, no shell
        cmd, env=env, capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        msg = f"stage {label} exited {proc.returncode}: {' / '.join(tail) or 'no output'}"
        if check:
            raise RuntimeError(msg)
        log.warning("stage[%s] non-fatal: %s", label, msg)


def _run_subprocess_stages(job: dict) -> None:
    """clone (full env) -> resolve (secret-free env) -> scan (full env, no re-resolve)."""
    jid = str(job["id"])
    src = str(jobs_config.job_source_dir(
        job["id"], origin=job.get("origin"), surface=job.get("surface")
    ))

    _run_stage(["deepscan-kruncher", "materialize", jid, src],
               env=os.environ.copy(), label="materialize")

    # The one untrusted stage: no secrets in its environment. Non-fatal - a
    # resolver hiccup must not fail the scan (Trivy still reads any lockfiles
    # already present).
    _run_stage(["deepscan", "resolve", src],
               env=_resolve_env(), label="resolve", check=False)

    scan_env = os.environ.copy()
    scan_env["DEEPSCAN_RESOLVE_DEPS"] = "false"  # already resolved above
    _run_stage(["deepscan-kruncher", "scan-only", jid, src],
               env=scan_env, label="scan")


def _execute_stages(job: dict) -> None:
    """Run the isolated stages for a claimed static job. The kubernetes executor
    (create the 3-stage pod, watch it) plugs in here."""
    _run_subprocess_stages(job)


def dispatch_one(worker_id: str | None = None) -> bool:
    """Claim one ad-hoc job and run it through the isolated stages. Returns True
    if a job was handled. The dispatcher owns claim/heartbeat/failure; the scan
    stage persists success."""
    wid = worker_id or config.worker_id()
    job = store.claim_job(wid, origins=(QUEUE_MANUAL,))
    if job is None:
        return False
    log.info("Dispatcher %s claimed job %s (attempt %s)", wid, job["id"], job["attempt"])

    # URL/dynamic jobs have no source tree to resolve - run the monolithic path.
    if job.get("target_type") == "url":
        _run_inline(job)
        return True

    stop = threading.Event()
    hb = threading.Thread(target=_heartbeat_loop, args=(job["id"], stop),
                          name=f"hb-{job['id']}", daemon=True)
    hb.start()
    try:
        _execute_stages(job)
    except Exception as exc:  # noqa: BLE001 - turn into a tracked failure
        if jobs_store.is_cancelled(job["id"]):
            log.info("Job %s cancelled mid-flight; leaving terminal state.", job["id"])
        else:
            jobs_store.fail_adhoc(job, error=f"{type(exc).__name__}: {exc}")
            log.warning("Dispatch job %s failed: %s", job["id"], exc)
    finally:
        stop.set()
        hb.join(timeout=5)
    return True


def _run_inline(job: dict) -> None:
    """Dynamic (URL) job: no isolated resolve stage; run the monolithic executor
    (it materializes, scans and persists, recording its own failure)."""
    import asyncio

    asyncio.run(run_job_inline(
        job,
        allow_private=config.allow_private_targets(),
        allow_local_paths=config.allow_local_paths(),
    ))


def run_loop(worker_id: str | None = None, *, stop=None) -> None:
    """Drain the manual queue forever with the isolated-stage dispatcher."""
    wid = worker_id or config.worker_id()
    poll = config.poll_interval_seconds()
    log.info("Dispatcher %s started (poll=%ss, isolated 3-stage execution).", wid, poll)
    import time
    while not (stop and stop()):
        try:
            worked = dispatch_one(wid)
        except Exception:  # noqa: BLE001 - keep the loop alive
            log.exception("Unexpected error in dispatcher loop")
            worked = False
        if not worked:
            time.sleep(poll)
