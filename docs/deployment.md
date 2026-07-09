# Deployment - continuous scanning, Docker & Kubernetes

Beyond one-off scans, Deep Scan can keep a whole estate scanned and tracked.

```
 input connectors          kruncher                          kruncher-admin
 ────────────────          ────────                          ──────────────
 github  ─┐  discover      scheduler (cheap): probe revs,    ASPM dashboard:
 gitlab  ─┼─ sources ───▶  enqueue only what changed   ───▶  posture, trends,
 directory┘                worker (expensive): clone/copy,    grouping, job
                           scan (core), persist findings      relaunch
                                    └──── PostgreSQL: queue + results ────┘
```

## Connectors, kruncher & ASPM

- **Input connectors** turn a *scope* into concrete **sources** and provide a
  cheap change probe (`git ls-remote` / a `(path,size,mtime)` signature) and a
  materializer (shallow clone / copy). A scope can be a GitHub **org**, a GitLab
  **group**, a server **directory**, or simply a **direct git URL** - e.g.
  `{"url":"https://github.com/michoo/flanby"}`, which needs no org and no token
  for public repos. Only the **default branch** is tracked for now; the job
  schema already carries a `branch`, so widening is additive.
- **Tokens** are never stored in the DB. A scope names an env var via
  `token_env` (e.g. `GITHUB_TOKEN`); provision it through `deploy/docker/.env`
  (compose injects the whole file, so any var name works) or the kustomize
  `secrets.env` → `Secret/deepscan-secrets`. Omit it for public sources.
- **kruncher** is split into a **scheduler** (discover, probe, enqueue changed
  sources, reap dead workers) and a **worker** (claim, materialize, scan,
  persist). The worker fleet is the **single executor for both queues** -
  *periodic* (`origin='discovery'`, scheduler-enqueued) and *manual*
  (`origin='adhoc'`, API/MCP submissions) - and always drains the **manual queue
  first**, so an operator's scan never waits behind queued periodic work. The
  queue is **Postgres** with `FOR UPDATE SKIP LOCKED` - N workers share it with no
  broker, and a scan's result, findings and job state are written in one
  transaction. Up to **3 attempts** with backoff, then a **dead-letter** siding
  (manual jobs fail terminally - no retry); a new scan **supersedes** a source's
  old jobs.
- **kruncher-admin** is a no-build UI + API: ASPM posture from the latest scan
  per source, **3-month / 12-month** trends, by-scope grouping, a searchable
  paginated source list (built for very large estates), and one-click job
  relaunch.

```bash
# 1. database
export DEEPSCAN_DB_DSN=postgresql://deepscan:pw@localhost:5432/deepscan
uv run deepscan-kruncher db init                       # or db/init.sh
# 2. a scope (CLI or db/set-scope.sh)
#    a single public repo by URL - no org, no token:
uv run deepscan-kruncher scope add flanby git \
    --config '{"url":"https://github.com/michoo/flanby"}'
#    or a whole GitHub org with a token read from $GITHUB_TOKEN:
uv run deepscan-kruncher scope add acme github \
    --config '{"org":"acme","token_env":"GITHUB_TOKEN"}' --families sast --families secret
uv run deepscan-kruncher scope discover flanby
# 3. run it
uv run deepscan-kruncher run        # worker + embedded scheduler (all-in-one)
uv run deepscan-kruncher-admin      # dashboard on http://127.0.0.1:8900
```

## Docker Compose & Kubernetes

Workers run with a **read-only rootfs**, so two scratch mounts must stay
writable: a **tmpfs `/tmp`** (always - the scanner uses `tempfile`; without it
you get *"No usable temporary directory"*) and **`/work`** for clones, which can
be an ephemeral tmpfs (`- /work:size=2g,mode=1777`) or a project-local host dir
(`./data/work`, the compose default) for inspecting clones. The container runs
as a non-root user (uid 10001); for the host-dir option a one-shot
`prepare-scratch` service `chown`s `./data/work` to that uid at startup, so it
works without any `sudo`/`chmod` regardless of who Docker created the dir as.

```bash
# Single host, scale workers horizontally:
docker compose -f deploy/docker/docker-compose.yml up --build --scale kruncher=4

# Kubernetes (Postgres + scheduler + workers + admin + NetworkPolicy):
kubectl apply -k deploy/kustomize/overlays/local
```

The compose stack brings up Postgres, the migrate/scratch one-shots, a shared
`trivy-server`, the scheduler, the worker fleet, the REST API + web app (8800),
the MCP server (8000) and the admin dashboard (8900). Configure it through
`deploy/docker/.env` (copy from `deploy/docker/.env.example`). The repo's
`./start.sh` is a thin wrapper around `docker compose … up --scale kruncher=4`.

**Shared Trivy server.** Both stacks run a `trivy-server` (pinned to the bundled
client version) that holds the vulnerability DB; workers scan in **client mode**
via `DEEPSCAN_TRIVY_SERVER`, so the DB is pulled **once** for the whole fleet
instead of once per worker - no registry rate-limiting. Only the SCA (vuln)
scanner offloads; misconfig/license stay local. (Compose: a `trivy-server`
service + healthcheck; Kustomize: a `trivy-server` Deployment/Service plus the
NetworkPolicy allows on port 4954.)

## Scan isolation

**Scan isolation in untrusted infra** (layered, strongest first):

- *ephemeral runner* - one throwaway, locked-down pod per scan
  (`deepscan-kruncher run-one`, template in `deploy/kustomize/base`);
- *network fence* - a default-deny egress `NetworkPolicy` allowing only DNS, the
  DB and outbound 443/80 with RFC1918 ranges excluded (layer a Cilium FQDN
  policy to restrict to your package manager/git host exactly);
- *hardening* - non-root, read-only rootfs, all capabilities dropped,
  RuntimeDefault seccomp, no service-account token, bounded
  CPU/memory/PIDs/ephemeral-storage.

Reporting and analysis SQL live in `db/reports.sql` (`db/report.sh [name]`).
