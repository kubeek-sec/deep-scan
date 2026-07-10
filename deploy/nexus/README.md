# Nexus pull-through mirror

Nexus proxies the public package registries so the dependency **resolver** (which
runs untrusted package-manager code to generate missing lockfiles) never needs
direct internet: it talks only to Nexus. Nexus also caches artifacts, which is
what kills the `repo.maven.apache.org` **429 Too Many Requests** blocks.

Nexus is the *only* component allowed to reach the internet.

## Provisioning

Bring Nexus up, then create the proxy repos once:

```bash
# compose: runs automatically via the `nexus-provision` one-shot service.
# k8s / manual:
NEXUS_URL=http://nexus:8081 NEXUS_PASSWORD='<admin-pw>' \
  python3 deploy/nexus/provision_repos.py
```

The first-boot admin password is inside the data volume at
`<nexus-data>/admin.password`. The script is idempotent (existing repos are left
untouched) and stdlib-only (runs on a bare `python:3-slim`).

## What each package manager points at

Once provisioned, the resolver configures each manager to use Nexus:

| Ecosystem | Nexus repo | Manager config |
|-----------|------------|----------------|
| npm / yarn / pnpm | `npm-proxy` | `npm config set registry http://nexus:8081/repository/npm-proxy/` |
| Python (pip/uv) | `pypi-proxy` | `PIP_INDEX_URL=http://nexus:8081/repository/pypi-proxy/simple` |
| Go | `go-proxy` | `GOPROXY=http://nexus:8081/repository/go-proxy/` |
| Rust (cargo) | `cargo-proxy` | `.cargo/config.toml` source replacement → `cargo-proxy` |
| Ruby (bundler) | `rubygems-proxy` | `bundle config mirror.https://rubygems.org http://nexus:8081/repository/rubygems-proxy` |
| Java (maven) | `maven-central` | `settings.xml` mirror `<url>http://nexus:8081/repository/maven-central/</url>` |
| .NET (nuget) | `nuget-proxy` | `nuget.config` `<add key="nexus" value="http://nexus:8081/repository/nuget-proxy/index.json"/>` |

(The resolver writes these throwaway configs into the per-job sandbox — never the
scanned project — so nothing persists between scans.)

## Known gap: Composer / PHP

Nexus Repository **OSS has no native `composer` (Packagist) format** — unlike
Maven/npm/etc. (`cargo` IS supported from 3.94.0 — see
<https://help.sonatype.com/en/rust-cargo.html>.) Composer options, per rollout:

1. **Offline-only**: scan an existing `composer.lock` (Trivy already does this
   fully offline). Projects shipping only `composer.json` lose transitive
   coverage until a lockfile is added.
2. **Raw proxy**: proxy `https://repo.packagist.org` as a Nexus `raw` repo and
   point Composer's `composer` repository type at it (metadata is static JSON).
   Dist downloads still resolve to GitHub, so it only fully works behind an
   egress allowlist that also permits `*.github.com` — reduces the isolation
   win. Evaluate before enabling.

Tracked for P2/P3; not blocking the other ecosystems.

## Isolation note (P2)

Today the workers share the `deepscan/egress` label and can still reach the
internet directly. The strong-isolation step (P2) flips this so **only Nexus**
carries that label and the resolver pods get an egress policy allowing Nexus +
DNS *only* — see the TODO in `deploy/kustomize/base/networkpolicy.yaml`. The full
isolation model + gVisor enablement are in [`docs/sandboxing.md`](../../docs/sandboxing.md).
