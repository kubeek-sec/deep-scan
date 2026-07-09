-- Deep Scan shared job schema (PostgreSQL).
--
-- Canonical source of truth. Loaded at runtime by `deepscan_jobs.db` and
-- mirrored to db/schema.sql for raw `psql` use (a test asserts they match).
-- Every statement is idempotent so it doubles as a migration bootstrap.

-- ------------------------------------------------------------------------- --
-- scopes: a configured discovery unit (an org, a group, a directory). kruncher.
-- ------------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS scopes (
    id                        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                      TEXT NOT NULL UNIQUE,
    connector                 TEXT NOT NULL,
    config                    JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled                   BOOLEAN NOT NULL DEFAULT true,
    refresh_interval_seconds  INTEGER NOT NULL DEFAULT 3600,
    rescan_interval_seconds   INTEGER NOT NULL DEFAULT 86400,
    families                  TEXT[] NOT NULL DEFAULT '{}',
    last_discovered_at        TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------------------- --
-- sources: a concrete scannable, discovered inside a scope. kruncher.
-- ------------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS sources (
    id                     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope_id               BIGINT NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    external_id            TEXT NOT NULL,
    kind                   TEXT NOT NULL,            -- 'git' | 'directory'
    name                   TEXT NOT NULL,
    location               TEXT NOT NULL,            -- clone URL or filesystem path
    default_branch         TEXT,
    metadata               JSONB NOT NULL DEFAULT '{}'::jsonb,
    active                 BOOLEAN NOT NULL DEFAULT true,
    last_revision          TEXT,                     -- last revision we enqueued
    last_scanned_revision  TEXT,                     -- last revision scanned ok
    last_checked_at        TIMESTAMPTZ,              -- last cheap change probe
    last_scanned_at        TIMESTAMPTZ,
    first_seen_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (scope_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_sources_scope ON sources (scope_id);
CREATE INDEX IF NOT EXISTS idx_sources_active ON sources (active);

-- ------------------------------------------------------------------------- --
-- scan_jobs: the shared work queue and per-job tracking.
--   status: queued | running | done | failed | dead | superseded | cancelled
--   origin: 'discovery' (kruncher, has source_id) | 'adhoc' (API/MCP submission)
-- The queue is drained with SELECT ... FOR UPDATE SKIP LOCKED, so multiple
-- workers can claim jobs concurrently without a separate broker. Workers filter
-- by `origin` so each only claims jobs it knows how to materialize.
-- ------------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS scan_jobs (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_id        BIGINT REFERENCES sources(id) ON DELETE CASCADE,  -- NULL for ad-hoc
    origin           TEXT NOT NULL DEFAULT 'discovery',
    status           TEXT NOT NULL DEFAULT 'queued',
    -- ad-hoc submission fields (API / MCP):
    target_type      TEXT,                           -- url | git | path | zip
    target           TEXT,
    mode             TEXT,
    families         TEXT[] NOT NULL DEFAULT '{}',
    scanners         TEXT[] NOT NULL DEFAULT '{}',
    surface          TEXT,                           -- api | mcp | kruncher | cli
    report_dir       TEXT,
    source_path      TEXT,                           -- retained analyzed files (shared volume)
    upload_id        TEXT,                           -- zip upload provenance (uploads.id)
    fingerprint      TEXT,                           -- content SHA-512 of the scanned tree
    git_commit       TEXT,                           -- checked-out commit when a .git is present
    summary          JSONB,
    steps            JSONB,                          -- live per-step progress (scanners + phases)
    -- discovery fields (kruncher):
    target_revision  TEXT,
    branch           TEXT,
    priority         INTEGER NOT NULL DEFAULT 100,   -- lower runs sooner
    attempt          INTEGER NOT NULL DEFAULT 0,
    max_attempts     INTEGER NOT NULL DEFAULT 3,
    completion       INTEGER NOT NULL DEFAULT 0,     -- 0..100
    stage            TEXT,
    error            TEXT,
    locked_by        TEXT,
    locked_at        TIMESTAMPTZ,
    heartbeat_at     TIMESTAMPTZ,
    available_at     TIMESTAMPTZ NOT NULL DEFAULT now(),  -- retry backoff gate
    enqueued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Upgrade an existing (kruncher-only) scan_jobs to the unified shape. Each is a
-- no-op once applied, so the schema stays idempotent across versions.
ALTER TABLE scan_jobs ALTER COLUMN source_id DROP NOT NULL;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS origin      TEXT NOT NULL DEFAULT 'discovery';
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS target_type TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS target      TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS mode        TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS families    TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS scanners    TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS surface     TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS report_dir  TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS summary     JSONB;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS steps       JSONB;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS source_path TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS upload_id   TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS fingerprint TEXT;
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS git_commit  TEXT;

CREATE INDEX IF NOT EXISTS idx_jobs_claim
    ON scan_jobs (origin, priority, available_at)
    WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_jobs_source ON scan_jobs (source_id);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON scan_jobs (status);
CREATE INDEX IF NOT EXISTS idx_jobs_origin_created ON scan_jobs (origin, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_running_heartbeat
    ON scan_jobs (heartbeat_at) WHERE status = 'running';

-- ------------------------------------------------------------------------- --
-- job_attempts: audit trail of every try, including the error log excerpt.
-- ------------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS job_attempts (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id            BIGINT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    attempt           INTEGER NOT NULL,
    status            TEXT NOT NULL,               -- 'done' | 'failed'
    error             TEXT,
    log               TEXT,
    worker            TEXT,
    started_at        TIMESTAMPTZ,
    finished_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_seconds  DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_attempts_job ON job_attempts (job_id);

-- ------------------------------------------------------------------------- --
-- uploads: staging for MCP/API zip uploads (extract once, reference by id).
-- ------------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS uploads (
    id          TEXT PRIMARY KEY,
    path        TEXT NOT NULL,
    filename    TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ------------------------------------------------------------------------- --
-- scan_results: one row per successful scan, severity totals denormalized
-- for fast posture aggregation. kruncher / ASPM.
-- ------------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS scan_results (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id            BIGINT REFERENCES scan_jobs(id) ON DELETE SET NULL,
    source_id         BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    revision          TEXT,
    mode              TEXT,
    duration_seconds  DOUBLE PRECISION,
    tools_ran         INTEGER NOT NULL DEFAULT 0,
    tools_skipped     INTEGER NOT NULL DEFAULT 0,
    tools_error       INTEGER NOT NULL DEFAULT 0,
    total_findings    INTEGER NOT NULL DEFAULT 0,
    crit              INTEGER NOT NULL DEFAULT 0,
    high              INTEGER NOT NULL DEFAULT 0,
    med               INTEGER NOT NULL DEFAULT 0,
    low               INTEGER NOT NULL DEFAULT 0,
    info              INTEGER NOT NULL DEFAULT 0,
    summary           JSONB NOT NULL DEFAULT '{}'::jsonb,
    scanned_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_results_source_time
    ON scan_results (source_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_results_time ON scan_results (scanned_at DESC);

-- ------------------------------------------------------------------------- --
-- findings: deduplicated findings of a result, for drill-down and trends.
-- ------------------------------------------------------------------------- --
CREATE TABLE IF NOT EXISTS findings (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    result_id     BIGINT NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    source_id     BIGINT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    fingerprint   TEXT NOT NULL,
    severity      TEXT NOT NULL,
    families      TEXT[] NOT NULL DEFAULT '{}',
    tools         TEXT[] NOT NULL DEFAULT '{}',
    rules         TEXT[] NOT NULL DEFAULT '{}',
    cwes          TEXT[] NOT NULL DEFAULT '{}',
    message       TEXT,
    location      TEXT,
    occurrences   INTEGER NOT NULL DEFAULT 1,
    scanned_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_result ON findings (result_id);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings (source_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);

-- ------------------------------------------------------------------------- --
-- source_latest_result: newest scan per source (drives the live ASPM posture).
-- ------------------------------------------------------------------------- --
CREATE OR REPLACE VIEW source_latest_result AS
SELECT DISTINCT ON (r.source_id)
       r.*
FROM scan_results r
ORDER BY r.source_id, r.scanned_at DESC;
