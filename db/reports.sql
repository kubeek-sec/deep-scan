-- Deep Scan - analysis & scan-tracking queries.
-- Run all of them:        db/report.sh
-- Run one by name:        db/report.sh posture
-- Each query is preceded by a \echo banner so the output is readable.

\echo '== POSTURE: current severity totals (latest scan per active source) =='
-- name: posture
SELECT count(*)                                   AS sources_scanned,
       COALESCE(sum(crit),0)                      AS critical,
       COALESCE(sum(high),0)                      AS high,
       COALESCE(sum(med),0)                       AS medium,
       COALESCE(sum(low),0)                       AS low,
       COALESCE(sum(CASE WHEN crit>0 THEN 1 END),0)        AS sources_with_critical,
       COALESCE(sum(CASE WHEN crit+high>0 THEN 1 END),0)   AS sources_at_risk
FROM source_latest_result lr JOIN sources s ON s.id = lr.source_id
WHERE s.active;

\echo '== POSTURE BY SCOPE =='
-- name: by_scope
SELECT sc.name AS scope, sc.connector,
       count(*) AS scanned,
       COALESCE(sum(lr.crit),0) AS crit, COALESCE(sum(lr.high),0) AS high,
       COALESCE(sum(lr.med),0)  AS med,  COALESCE(sum(lr.low),0)  AS low
FROM source_latest_result lr
JOIN sources s ON s.id = lr.source_id
JOIN scopes sc ON sc.id = s.scope_id
WHERE s.active
GROUP BY sc.name, sc.connector
ORDER BY crit DESC, high DESC;

\echo '== TOP 20 MOST EXPOSED SOURCES =='
-- name: top_sources
SELECT s.name AS source, sc.name AS scope,
       lr.crit, lr.high, lr.med, lr.total_findings, lr.scanned_at
FROM source_latest_result lr
JOIN sources s ON s.id = lr.source_id
JOIN scopes sc ON sc.id = s.scope_id
WHERE s.active
ORDER BY lr.crit DESC, lr.high DESC, lr.med DESC
LIMIT 20;

\echo '== SCAN TRACKING: job queue by status =='
-- name: jobs
SELECT status, count(*) AS jobs,
       round(avg(attempt),2) AS avg_attempts
FROM scan_jobs GROUP BY status ORDER BY jobs DESC;

\echo '== DEAD-LETTER SIDING: jobs that exhausted their retries =='
-- name: dead
SELECT j.id, s.name AS source, j.attempt, j.updated_at,
       left(j.error, 120) AS error
FROM scan_jobs j JOIN sources s ON s.id = j.source_id
WHERE j.status = 'dead'
ORDER BY j.updated_at DESC LIMIT 50;

\echo '== STALE: sources active but never successfully scanned =='
-- name: unscanned
SELECT sc.name AS scope, s.name AS source, s.kind, s.last_checked_at
FROM sources s JOIN scopes sc ON sc.id = s.scope_id
LEFT JOIN source_latest_result lr ON lr.source_id = s.id
WHERE s.active AND lr.source_id IS NULL
ORDER BY sc.name, s.name LIMIT 100;

\echo '== TREND: monthly consolidated posture, last 12 months =='
-- name: trend
WITH per_source_month AS (
    SELECT DISTINCT ON (source_id, date_trunc('month', scanned_at))
           source_id, date_trunc('month', scanned_at) AS month,
           crit, high, med, low
    FROM scan_results
    WHERE scanned_at >= now() - interval '12 months'
    ORDER BY source_id, date_trunc('month', scanned_at), scanned_at DESC
)
SELECT to_char(month,'YYYY-MM') AS month,
       sum(crit) AS crit, sum(high) AS high, sum(med) AS med, sum(low) AS low,
       count(*) AS sources
FROM per_source_month GROUP BY month ORDER BY month;

\echo '== THROUGHPUT: scans completed per day, last 30 days =='
-- name: throughput
SELECT date_trunc('day', scanned_at)::date AS day,
       count(*) AS scans, round(avg(duration_seconds),1) AS avg_seconds,
       sum(total_findings) AS findings
FROM scan_results
WHERE scanned_at >= now() - interval '30 days'
GROUP BY day ORDER BY day;
