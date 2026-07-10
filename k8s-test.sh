#!/usr/bin/env bash
# Ephemeral Kubernetes test harness - spin up a throwaway kind cluster, deploy
# Deep Scan, run the benchmark, tear it all down. Nothing survives `down`.
#
#   ./k8s-test.sh up               # create cluster, build+load image, deploy, wait
#   ./k8s-test.sh test [args...]   # port-forward the API and run ./benchmark.sh (args pass through)
#   ./k8s-test.sh forward          # expose the API (:8800) + admin UI (:8900) on localhost
#   ./k8s-test.sh debug            # open the k9s terminal dashboard (pods/logs/shell/resources)
#   ./k8s-test.sh gvisor           # install runsc into the kind node(s) + label them
#   ./k8s-test.sh verify-gvisor    # prove a runtimeClassName=gvisor pod is really sandboxed
#   ./k8s-test.sh status           # pods / services / jobs
#   ./k8s-test.sh logs [app]       # tail a component's logs (default: kruncher)
#   ./k8s-test.sh down             # delete the cluster (everything gone)
#   ./k8s-test.sh all              # up, then a small smoke benchmark (--tier simple --wait)
#
# Requires: kind, kubectl, docker. Install kind:
#   go install sigs.k8s.io/kind@latest      # or:  brew install kind
#
# Env:
#   CLUSTER   kind cluster name  (default: deepscan-test)
#   REBUILD=1 force a docker image rebuild even if kubeek-sec/deepscan:dev exists
#   WITH_NEXUS=1  keep the Nexus mirror running (default: scaled to 0 - the
#                 dependency resolver is off by default, so the benchmark doesn't
#                 need it, and Nexus is ~1.5 GB)
#
# Caveats (kind specifics - see docs/sandboxing.md for the real thing):
#   * kind nodes have no gVisor/runsc by default. Run `./k8s-test.sh gvisor` to
#     install it into the node(s), then `verify-gvisor` to confirm. (systrap
#     platform - no KVM needed in nested containers.) Until then the RuntimeClass
#     sits unused and the standard scan path works.
#   * kind's default CNI does NOT enforce NetworkPolicy - the egress fence is a
#     no-op here. Use a Calico/Cilium kind config to test the policies themselves.
#   * Prefer `--tier simple` in kind; the complex repos (llvm, kubernetes, ...) are
#     huge to clone and scan on a single Docker host.
set -euo pipefail
cd "$(dirname "$0")"

CLUSTER="${CLUSTER:-deepscan-test}"
IMAGE="kubeek-sec/deepscan:dev"        # must match overlays/local (newTag: dev)
OVERLAY="deploy/kustomize/overlays/local"
NS="deepscan"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found. $2" >&2; exit 1; }; }
kc() { kubectl --context "kind-${CLUSTER}" -n "$NS" "$@"; }

cmd_up() {
  need kind "Install: go install sigs.k8s.io/kind@latest  (or brew install kind)"
  need kubectl "Install kubectl."
  need docker "Install Docker."

  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "▸ creating kind cluster '$CLUSTER'..."
    kind create cluster --name "$CLUSTER"
  else
    echo "▸ kind cluster '$CLUSTER' already exists."
  fi

  if [ "${REBUILD:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "▸ building $IMAGE (first build is slow)..."
    docker build -f deploy/docker/Dockerfile -t "$IMAGE" .
  else
    echo "▸ reusing existing $IMAGE (set REBUILD=1 to rebuild)."
  fi

  echo "▸ loading image into the cluster..."
  kind load docker-image "$IMAGE" --name "$CLUSTER"

  echo "▸ applying $OVERLAY ..."
  kubectl --context "kind-${CLUSTER}" apply -k "$OVERLAY"

  if [ "${WITH_NEXUS:-0}" != "1" ]; then
    echo "▸ scaling Nexus to 0 (resolver off by default; set WITH_NEXUS=1 to keep it)."
    kc scale deploy/nexus --replicas=0 >/dev/null 2>&1 || true
  fi

  echo "▸ waiting for the schema migration (kind's first-boot DNS can be slow)..."
  kc wait --for=condition=complete job/deepscan-migrate --timeout=480s
  echo "▸ waiting for rollouts..."
  for d in deepscan-api deepscan-kruncher deepscan-scheduler trivy-server; do
    kc rollout status "deploy/$d" --timeout=240s
  done
  echo "✓ up. Run:  ./k8s-test.sh test --tier simple --wait"
}

cmd_test() {
  need kubectl "Install kubectl."
  echo "▸ port-forwarding the API to localhost:8800 ..."
  kc port-forward svc/deepscan-api 8800:8800 >/dev/null 2>&1 &
  PF_PID=$!   # global, so the EXIT trap can see it under `set -u`
  trap 'kill "${PF_PID:-}" 2>/dev/null || true' EXIT
  # wait for the tunnel
  for _ in $(seq 1 20); do
    curl -fsS -o /dev/null --max-time 2 http://localhost:8800/api/healthz 2>/dev/null && break
    sleep 1
  done
  DEEPSCAN_API_URL="http://localhost:8800" ./benchmark.sh "$@"
}

cmd_status() {
  kc get pods,svc,jobs -o wide
}

# metrics-server gives k9s (and `kubectl top`) live CPU/RAM. Idempotent; patched
# with --kubelet-insecure-tls because kind's kubelets use self-signed certs.
_ensure_metrics() {
  kubectl --context "kind-${CLUSTER}" -n kube-system get deploy metrics-server >/dev/null 2>&1 && return 0
  echo "▸ installing metrics-server (CPU/RAM for k9s + kubectl top)..."
  kubectl --context "kind-${CLUSTER}" apply -f \
    https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml >/dev/null
  kubectl --context "kind-${CLUSTER}" -n kube-system patch deployment metrics-server --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]' >/dev/null
  kubectl --context "kind-${CLUSTER}" -n kube-system rollout status deploy/metrics-server --timeout=120s
}

# Install k9s if missing: prefer `go install`, else point at a manual install.
_ensure_k9s() {
  command -v k9s >/dev/null 2>&1 && return 0
  if command -v go >/dev/null 2>&1; then
    echo "▸ installing k9s (go install, compiles ~1 min)..."
    go install github.com/derailed/k9s@latest
    export PATH="$(go env GOPATH)/bin:$PATH"
  fi
  command -v k9s >/dev/null 2>&1 || {
    echo "error: k9s not found. Install it: 'go install github.com/derailed/k9s@latest'" >&2
    echo "       (then add \$(go env GOPATH)/bin to PATH), or 'brew install k9s'." >&2
    exit 1; }
}

# Open the k9s terminal dashboard scoped to this cluster + namespace. Auto-installs
# k9s + metrics-server the first time. Keys once inside: l=logs, s=shell (exec),
# d=describe, y=yaml, Enter=containers; Shift-C/Shift-M=sort by CPU/mem; ?=help.
cmd_debug() {
  need kubectl "Install kubectl."
  _ensure_metrics
  _ensure_k9s
  echo "▸ launching k9s (context kind-${CLUSTER}, namespace ${NS})..."
  exec k9s --context "kind-${CLUSTER}" -n "$NS" "$@"
}

# Expose the API + admin UIs (kind doesn't map NodePorts to the host, so
# port-forward is the portable way). Holds open until Ctrl-C - keep this terminal
# running while you browse. Set FORWARD_ADDRESS=0.0.0.0 to also reach it from
# another device on the LAN (default 127.0.0.1 = this machine only).
cmd_forward() {
  need kubectl "Install kubectl."
  local addr="${FORWARD_ADDRESS:-127.0.0.1}"
  local host="localhost"; [ "$addr" = "0.0.0.0" ] && host="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "▸ forwarding on $addr (Ctrl-C to stop):"
  echo "    API dashboard + REST -> http://$host:8800   (e.g. /api/scans, /api/healthz)"
  echo "    Admin UI             -> http://$host:8900"
  kc port-forward --address "$addr" svc/deepscan-api 8800:8800 >/dev/null 2>&1 &
  FWD_A=$!
  kc port-forward --address "$addr" svc/deepscan-admin 8900:80 >/dev/null 2>&1 &   # admin Service port is 80
  FWD_B=$!
  trap 'kill "${FWD_A:-}" "${FWD_B:-}" 2>/dev/null || true' EXIT INT TERM
  wait
}

cmd_logs() {
  kc logs -l "app.kubernetes.io/name=${1:-kruncher}" --tail=200 -f
}

cmd_down() {
  need kind "Install kind."
  echo "▸ deleting kind cluster '$CLUSTER' (all resources gone)..."
  kind delete cluster --name "$CLUSTER"
}

# Install runsc into the kind node(s) and register it with the node's containerd.
# kind runs containerd INSIDE a Docker container, so we exec into the node, drop
# runsc + the shim on its PATH, add a `runsc` runtime handler, and restart
# containerd. The `systrap` platform is used because nested containers have no
# KVM. Then the node is labelled so the `gvisor` RuntimeClass can schedule onto it.
cmd_gvisor() {
  need kind "Install kind."; need kubectl "Install kubectl."; need docker "Install Docker."
  for node in $(kind get nodes --name "$CLUSTER"); do
    echo "▸ installing runsc into node $node ..."
    docker exec "$node" bash -c '
      set -e
      case "$(uname -m)" in x86_64) a=x86_64;; aarch64|arm64) a=aarch64;; *) a=$(uname -m);; esac
      url="https://storage.googleapis.com/gvisor/releases/release/latest/${a}"
      fetch() { if command -v curl >/dev/null; then curl -fsSL "$1" -o "$2"; else wget -qO "$2" "$1"; fi; }
      for f in runsc containerd-shim-runsc-v1; do fetch "${url}/${f}" "/usr/local/bin/${f}"; chmod a+rx "/usr/local/bin/${f}"; done
      printf "[runsc_config]\n  platform = \"systrap\"\n" > /etc/containerd/runsc.toml
      if ! grep -q "runtimes.runsc" /etc/containerd/config.toml; then
        cat >> /etc/containerd/config.toml <<EOF

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc.options]
    TypeUrl = "io.containerd.runsc.v1.options"
    ConfigPath = "/etc/containerd/runsc.toml"
EOF
      fi
    '
    docker exec "$node" systemctl restart containerd
    kubectl --context "kind-${CLUSTER}" label node "$node" deepscan/sandbox=true --overwrite >/dev/null
  done
  echo "✓ runsc installed + nodes labelled. Verify:  ./k8s-test.sh verify-gvisor"
}

# Prove gVisor is actually in use: a pod under runtimeClassName=gvisor sees
# gVisor's own kernel (its /proc/version and dmesg name it). A runc pod would
# show the host kernel instead - so a match means the sandbox is real.
cmd_verify_gvisor() {
  need kubectl "Install kubectl."
  if ! kubectl --context "kind-${CLUSTER}" get runtimeclass gvisor >/dev/null 2>&1; then
    echo "✗ RuntimeClass 'gvisor' not found - run ./k8s-test.sh up first." >&2; exit 1
  fi
  echo "▸ launching a probe pod under runtimeClassName=gvisor ..."
  # The pod name must NOT contain "gvisor" or the grep below false-positives on
  # it. We grep the pod's LOGS (its /proc/version + dmesg), not any run output.
  local pod="sandbox-probe-$$" out
  kubectl --context "kind-${CLUSTER}" -n "$NS" run "$pod" --image=busybox --restart=Never \
    --overrides='{"spec":{"runtimeClassName":"gvisor"}}' \
    --command -- sh -c 'cat /proc/version; dmesg 2>/dev/null | head -1' >/dev/null 2>&1 || true
  kubectl --context "kind-${CLUSTER}" -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded \
    "pod/$pod" --timeout=60s >/dev/null 2>&1 || true
  out=$(kubectl --context "kind-${CLUSTER}" -n "$NS" logs "$pod" 2>&1)
  kubectl --context "kind-${CLUSTER}" -n "$NS" delete pod "$pod" --now >/dev/null 2>&1 || true
  echo "----"; echo "$out"; echo "----"
  # A gVisor pod reports a "*-gvisor" kernel and "Starting gVisor..."; runc shows
  # the real host kernel. Match the kernel tag / boot banner, never a pod name.
  if echo "$out" | grep -qiE 'gvisor|Starting gVisor'; then
    echo "✓ gVisor IS active - kernel: $(echo "$out" | grep -oiE '[0-9.]+-gvisor' | head -1)"
  else
    echo "✗ gVisor NOT detected: the pod used the standard runtime or failed to schedule."
    echo "  Did you run ./k8s-test.sh gvisor ?  Check: kubectl -n $NS get runtimeclass gvisor"
    exit 1
  fi
}

cmd_all() {
  cmd_up
  cmd_test --tier simple --wait
}

case "${1:-}" in
  up)            shift; cmd_up "$@" ;;
  test)          shift; cmd_test "$@" ;;
  forward)       shift; cmd_forward "$@" ;;
  debug)         shift; cmd_debug "$@" ;;
  status)        shift; cmd_status "$@" ;;
  logs)          shift; cmd_logs "$@" ;;
  gvisor)        shift; cmd_gvisor "$@" ;;
  verify-gvisor) shift; cmd_verify_gvisor "$@" ;;
  down)          shift; cmd_down "$@" ;;
  all)           shift; cmd_all "$@" ;;
  ""|-h|--help)
    awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0" ;;
  *) echo "unknown command: $1 (try: up|test|forward|debug|gvisor|verify-gvisor|status|logs|down|all)" >&2; exit 2 ;;
esac
