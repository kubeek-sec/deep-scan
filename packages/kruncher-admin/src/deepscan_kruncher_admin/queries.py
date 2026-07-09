"""Read-side aggregation queries for the ASPM dashboard.

Posture is computed from ``source_latest_result`` (the newest scan per source),
so the dashboard reflects the *current* state regardless of scan cadence.
Trends consolidate history by taking the latest result per source within each
time bucket, which avoids double-counting sources scanned several times.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from deepscan_kruncher import db

_SEV_ORDER = (
    "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
    "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
)


def posture_totals() -> dict[str, Any]:
    row = db.fetchone(
        """
        SELECT count(*) AS sources_scanned,
               COALESCE(sum(crit),0) AS crit, COALESCE(sum(high),0) AS high,
               COALESCE(sum(med),0)  AS med,  COALESCE(sum(low),0)  AS low,
               COALESCE(sum(info),0) AS info,
               COALESCE(sum(CASE WHEN crit > 0 THEN 1 ELSE 0 END),0) AS sources_with_crit,
               COALESCE(sum(CASE WHEN crit+high > 0 THEN 1 ELSE 0 END),0) AS sources_at_risk
        FROM source_latest_result lr
        JOIN sources s ON s.id = lr.source_id
        WHERE s.active
        """
    )
    return row or {}


def posture_by_scope() -> list[dict[str, Any]]:
    return db.fetchall(
        """
        SELECT sc.id AS scope_id, sc.name AS scope_name, sc.connector,
               count(*) AS sources_scanned,
               COALESCE(sum(lr.crit),0) AS crit, COALESCE(sum(lr.high),0) AS high,
               COALESCE(sum(lr.med),0)  AS med,  COALESCE(sum(lr.low),0)  AS low,
               COALESCE(sum(lr.info),0) AS info,
               COALESCE(sum(CASE WHEN lr.crit > 0 THEN 1 ELSE 0 END),0) AS sources_with_crit
        FROM source_latest_result lr
        JOIN sources s  ON s.id = lr.source_id
        JOIN scopes sc  ON sc.id = s.scope_id
        WHERE s.active
        GROUP BY sc.id, sc.name, sc.connector
        ORDER BY crit DESC, high DESC, scope_name
        """
    )


def scope_inventory() -> list[dict[str, Any]]:
    """Every scope with its source/scanned counts (incl. never-scanned)."""
    return db.fetchall(
        """
        SELECT sc.id AS scope_id, sc.name AS scope_name, sc.connector, sc.enabled,
               sc.last_discovered_at,
               count(s.id) FILTER (WHERE s.active) AS sources,
               count(lr.source_id) AS sources_scanned
        FROM scopes sc
        LEFT JOIN sources s ON s.scope_id = sc.id AND s.active
        LEFT JOIN source_latest_result lr ON lr.source_id = s.id
        GROUP BY sc.id, sc.name, sc.connector, sc.enabled, sc.last_discovered_at
        ORDER BY sc.name
        """
    )


def top_risky_sources(limit: int = 25) -> list[dict[str, Any]]:
    return db.fetchall(
        """
        SELECT s.id, s.name, s.kind, sc.name AS scope_name, sc.connector,
               lr.crit, lr.high, lr.med, lr.low, lr.info,
               lr.total_findings, lr.scanned_at
        FROM source_latest_result lr
        JOIN sources s ON s.id = lr.source_id
        JOIN scopes sc ON sc.id = s.scope_id
        WHERE s.active
        ORDER BY lr.crit DESC, lr.high DESC, lr.med DESC
        LIMIT %s
        """,
        (limit,),
    )


def sources_page(
    scope_id: int | None,
    q: str | None,
    risk: str | None,
    limit: int,
    offset: int,
    include_inactive: bool = False,
) -> dict[str, Any]:
    """Paginated, searchable source list joined with its latest posture."""
    clauses = [] if include_inactive else ["s.active"]
    params: list[Any] = []
    if scope_id is not None:
        clauses.append("s.scope_id = %s")
        params.append(scope_id)
    if q:
        clauses.append("s.name ILIKE %s")
        params.append(f"%{q}%")
    if risk == "critical":
        clauses.append("COALESCE(lr.crit,0) > 0")
    elif risk == "high":
        clauses.append("COALESCE(lr.crit,0) + COALESCE(lr.high,0) > 0")
    elif risk == "clean":
        clauses.append("lr.source_id IS NOT NULL AND COALESCE(lr.crit,0)+COALESCE(lr.high,0)+COALESCE(lr.med,0) = 0")
    elif risk == "unscanned":
        clauses.append("lr.source_id IS NULL")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = db.fetchone(
        f"""
        SELECT count(*) AS n FROM sources s
        LEFT JOIN source_latest_result lr ON lr.source_id = s.id
        {where}
        """,
        tuple(params),
    )
    rows = db.fetchall(
        f"""
        SELECT s.id, s.name, s.kind, s.scope_id, sc.name AS scope_name, sc.connector,
               s.location, s.default_branch, s.active,
               s.last_scanned_at, s.last_scanned_revision,
               lr.crit, lr.high, lr.med, lr.low, lr.info, lr.total_findings,
               (lr.source_id IS NOT NULL) AS scanned
        FROM sources s
        JOIN scopes sc ON sc.id = s.scope_id
        LEFT JOIN source_latest_result lr ON lr.source_id = s.id
        {where}
        ORDER BY COALESCE(lr.crit,0) DESC, COALESCE(lr.high,0) DESC, s.name
        LIMIT %s OFFSET %s
        """,
        (*params, limit, offset),
    )
    return {"total": (total or {}).get("n", 0), "items": rows}


def trend(window: str = "1y") -> list[dict[str, Any]]:
    """Active findings over time, by severity - the **carried-forward** posture.

    For every time bucket, each active source contributes the severity counts of
    its **most recent scan as of the end of that bucket**. So a source that was
    not re-scanned in a bucket keeps its previous quantities (they stay until a
    newer scan changes them, or the source disappears); buckets with few scans no
    longer collapse to near-zero. (Inactive/removed sources drop out entirely.)"""
    if window == "3m":
        interval, bucket = "3 months", "week"
    else:
        interval, bucket = "1 year", "month"
    return db.fetchall(
        f"""
        WITH buckets AS (
            SELECT gs AS bucket
            FROM generate_series(
                date_trunc('{bucket}', now()) - interval '{interval}',
                date_trunc('{bucket}', now()),
                interval '1 {bucket}'
            ) AS gs
        )
        SELECT b.bucket,
               COALESCE(sum(lr.crit), 0) AS crit,
               COALESCE(sum(lr.high), 0) AS high,
               COALESCE(sum(lr.med),  0) AS med,
               COALESCE(sum(lr.low),  0) AS low,
               COALESCE(sum(lr.info), 0) AS info,
               count(lr.*)               AS sources
        FROM buckets b
        LEFT JOIN sources s ON s.active
        LEFT JOIN LATERAL (
            -- the source's latest scan result as of the end of this bucket
            SELECT r.crit, r.high, r.med, r.low, r.info
            FROM scan_results r
            WHERE r.source_id = s.id
              AND r.scanned_at < b.bucket + interval '1 {bucket}'
            ORDER BY r.scanned_at DESC
            LIMIT 1
        ) lr ON true
        GROUP BY b.bucket
        ORDER BY b.bucket
        """
    )


def source_history(source_id: int, limit: int = 50) -> list[dict[str, Any]]:
    return db.fetchall(
        """
        SELECT id, revision, crit, high, med, low, info, total_findings,
               duration_seconds, scanned_at
        FROM scan_results WHERE source_id = %s
        ORDER BY scanned_at DESC LIMIT %s
        """,
        (source_id, limit),
    )


def latest_findings(source_id: int, limit: int = 200) -> list[dict[str, Any]]:
    return db.fetchall(
        f"""
        SELECT f.severity, f.message, f.location, f.tools, f.rules, f.cwes
        FROM findings f
        JOIN source_latest_result lr ON lr.id = f.result_id
        WHERE lr.source_id = %s
        ORDER BY {_SEV_ORDER.replace('severity', 'f.severity')}
        LIMIT %s
        """,
        (source_id, limit),
    )


def job_report(job: dict[str, Any], limit: int = 300) -> dict[str, Any]:
    """Summary + findings for one job, for *any* queue:

    * **periodic** (``origin='discovery'``) - read this job's scan result and its
      findings straight from the ASPM tables;
    * **manual** (``origin='adhoc'``) - read the report file the worker wrote
      (``report_dir/report.json``, on the shared data volume), falling back to the
      summary stored on the job row when the file isn't reachable.

    Findings are normalized to ``{severity, location, message, tools, cwes}`` so
    the UI renders both the same way."""
    if job.get("origin") == "adhoc":
        summary = job.get("summary")
        findings: list[dict[str, Any]] = []
        report_dir = job.get("report_dir")
        if report_dir:
            try:
                data = json.loads(
                    (Path(report_dir) / "report.json").read_text(encoding="utf-8")
                )
                summary = summary or data.get("summary")
                for f in (data.get("findings") or [])[:limit]:
                    findings.append({
                        "severity": f.get("severity"),
                        "location": f.get("location"),
                        "message": f.get("message"),
                        "tools": f.get("tools") or [],
                        "cwes": f.get("cwes") or [],
                    })
            except (OSError, ValueError):
                pass  # report file not reachable (e.g. /data not mounted) - summary only
        return {"summary": summary, "findings": findings}

    # discovery: the scan result this job produced + its findings
    result = db.fetchone(
        "SELECT * FROM scan_results WHERE job_id = %s ORDER BY scanned_at DESC LIMIT 1",
        (job["id"],),
    )
    if result is None:
        return {"summary": job.get("summary"), "findings": []}
    summary = result.get("summary") or {
        "severity_totals": {
            "critical": result["crit"], "high": result["high"], "medium": result["med"],
            "low": result["low"], "info": result["info"],
        },
        "deduplicated_findings": result["total_findings"],
        "tools_run": result["tools_ran"], "tools_skipped": result["tools_skipped"],
        "tools_error": result["tools_error"],
    }
    findings = db.fetchall(
        f"""
        SELECT severity, message, location, tools, cwes
        FROM findings WHERE result_id = %s
        ORDER BY {_SEV_ORDER} LIMIT %s
        """,
        (result["id"], limit),
    )
    return {"summary": summary, "findings": findings}
