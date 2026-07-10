# Sandboxing untrusted scans

Deep Scan ingests repositories it does not trust. Two operations are dangerous:

- **Dependency resolution** — generating a missing lockfile runs a package
  manager, which can execute arbitrary build/postinstall code.
- **Scanning** — parsing hostile source, archives, etc.

This page describes the isolation layers and how to turn on the strongest one,
**gVisor (runsc)**, in both Docker Compose and Kubernetes.

## Isolation layers (in order of strength)

| Layer | What it stops | Status |
|---|---|---|
| Non-root, all caps dropped, read-only rootfs, seccomp | privilege escalation, host writes | on by default |
| Egress fence (NetworkPolicy) excludes RFC1918 | SSRF / pivot to internal services | on (k8s) |
| Resolver env stripped to an allowlist | dependency code reading secrets from its env | on when the resolver runs |
| **Nexus mirror** — package managers never touch the public internet | exfiltration to arbitrary registries, Maven 429s | opt-in (see below) |
| **gVisor (runsc)** — user-space kernel | kernel-exploit "detonation" | opt-in (this page) |
| Ephemeral pod per scan (`kruncher-ephemeral-job.template.yaml`) | cross-scan contamination | opt-in (k8s) |

The dependency **resolver** and the **Nexus** mirror are covered in
[`deploy/nexus/README.md`](../deploy/nexus/README.md). Enable the resolver with
`DEEPSCAN_RESOLVE_DEPS=true` and point it at the mirror with `DEEPSCAN_NEXUS_URL`
(both already wired in the compose/kustomize configs).

## gVisor (runsc)

gVisor interposes a user-space kernel between the container and the host, so a
container that pops a kernel bug is contained. It is the single biggest upgrade
for running untrusted code. Both platforms are **opt-in** because runsc must be
installed on the host/nodes first.

### Docker Compose

1. Install runsc on the host:

   ```bash
   ARCH=$(uname -m)
   URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
   for f in runsc containerd-shim-runsc-v1; do
     wget "${URL}/${f}" "${URL}/${f}.sha512"
     sha512sum -c "${f}.sha512"
     chmod a+rx "${f}"; sudo mv "${f}" /usr/local/bin/
   done
   ```

2. Register it with the Docker daemon and reload:

   ```bash
   sudo /usr/local/bin/runsc install   # adds "runsc" to /etc/docker/daemon.json
   sudo systemctl reload docker
   ```

3. Opt the worker in — uncomment in
   [`deploy/docker/docker-compose.yml`](../deploy/docker/docker-compose.yml)
   under the `kruncher` service:

   ```yaml
       # runtime: runsc
   ```

4. Verify the sandbox is active (gVisor reports its own kernel):

   ```bash
   docker run --rm --runtime=runsc alpine dmesg | head -1
   # -> ... Starting gVisor...
   docker compose exec kruncher dmesg | grep -qi gvisor && echo "worker sandboxed"
   ```

Nexus stays on the standard runtime (it is trusted infrastructure); only the
worker that runs untrusted resolve/scan code needs runsc.

### Kubernetes

**Managed (GKE Sandbox — simplest).** Create a node pool with gVisor; GKE
pre-registers the `gvisor` RuntimeClass:

```bash
gcloud container node-pools create sandbox \
  --cluster <cluster> --sandbox type=gvisor \
  --node-labels deepscan/sandbox=true \
  --node-taints deepscan/sandbox=true:NoSchedule
```

**Self-managed (containerd + gVisor).** On each sandbox node install runsc +
`containerd-shim-runsc-v1` (step 1 above), then register the handler in
`/etc/containerd/config.toml`:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
```

Restart containerd. Label + taint the pool so only sandboxed workloads land on
it and a sandbox escape can't sit next to Postgres/secrets:

```bash
kubectl label  node <node> deepscan/sandbox=true
kubectl taint  node <node> deepscan/sandbox=true:NoSchedule
```

**Apply the RuntimeClass** (already in the kustomize base):
[`runtimeclass-gvisor.yaml`](../deploy/kustomize/base/runtimeclass-gvisor.yaml)
declares `handler: runsc` and pins gVisor pods to the tainted pool. The ephemeral
scan job ([`kruncher-ephemeral-job.template.yaml`](../deploy/kustomize/base/kruncher-ephemeral-job.template.yaml))
already sets `runtimeClassName: gvisor`.

### Verify gVisor is actually in use

A pod under `runtimeClassName: gvisor` sees **gVisor's own kernel**, not the
host's - so `/proc/version` (and `dmesg`) name it. A runc pod shows the host
kernel instead, so a match is proof the sandbox is real:

```bash
kubectl get runtimeclass gvisor
kubectl run gv --rm -i --restart=Never --image=busybox \
  --overrides='{"spec":{"runtimeClassName":"gvisor"}}' \
  -- sh -c 'cat /proc/version; dmesg 2>/dev/null | grep -i gvisor'
# a line containing "gVisor" => sandboxed. Nothing/host kernel => it ran on runc.
```

### Tooling

- **kind (ephemeral):** `./k8s-test.sh gvisor` installs runsc into the kind
  node(s) and labels them (systrap platform - no KVM needed in nested
  containers); `./k8s-test.sh verify-gvisor` runs the probe above.
- **Real cluster:** `deploy/deploy.sh --gvisor gke|daemonset|skip` deploys and
  verifies. `gke` prints the managed GKE-Sandbox node-pool command (recommended);
  `daemonset` applies the self-managed installer
  [`deploy/gvisor/gvisor-node-installer.yaml`](../deploy/gvisor/gvisor-node-installer.yaml)
  - a **privileged** DaemonSet that drops runsc onto and reconfigures containerd
  on the sandbox nodes (review it, test on one node first).

To also fence egress to the mirror only, apply the (Cilium-only) FQDN policy
[`ciliumnetworkpolicy-egress.yaml`](../deploy/kustomize/base/ciliumnetworkpolicy-egress.yaml)
and drop the broad `0.0.0.0/0:443` rule from `networkpolicy.yaml`.

## Target architecture: the three-stage sandbox

gVisor gives a kernel boundary around the *whole* scan pod, but the resolver and
the scan still share one container that also holds secrets (`run-one` clones +
resolves + scans in one process). The end state splits them **within one pod**,
which is enough because containers in a pod have separate environments and
separate PID namespaces — untrusted resolver code cannot read another container's
secrets or `/proc/<pid>/environ`:

```
Pod (runtimeClassName: gvisor)
├─ initContainer  clone    secrets: git token   egress: git host   → writes /src
├─ initContainer  resolve  secrets: NONE        egress: Nexus only → deepscan resolve /src
└─ container      scan     secrets: DB/trivy    egress: none        → scans /src (no code exec)
```

Why this is safe: the only stage that runs untrusted code (`resolve`) has **no
secrets in its container env**, a separate PID namespace, gVisor isolation, and
Nexus-only egress. `clone` and `scan` hold secrets but run only trusted code.

This pod is wired in
[`deepscan-scan-3stage-job.template.yaml`](../deploy/kustomize/base/deepscan-scan-3stage-job.template.yaml).
The three stage commands exist:

- `deepscan-kruncher materialize <job-id> <dir>` — fetch a claimed job's source;
- `deepscan resolve <dir>` — generate lockfiles (no secrets, via Nexus);
- `deepscan-kruncher scan-only <job-id> <dir>` — scan the resolved tree, persist.

The monolithic `run-one` path is untouched (single-container interim, resolver
in-process with a secret-stripped subprocess env).

**Remaining work:** a small **dispatcher** that claims one queued job (owning its
lease/heartbeat), creates a pod per job with `DEEPSCAN_JOB_ID` set, watches it,
and finalizes the DB row (done/failed) — the pod stages do not claim, so a stage
crash is turned into a job failure by the dispatcher, not lost. Plus a shared
RWX reports volume (`deepscan-data`) and live validation on a gVisor cluster.
