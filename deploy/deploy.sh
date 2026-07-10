#!/usr/bin/env bash
# Deploy Deep Scan to the cluster in your CURRENT kubectl context, with gVisor
# for the sandbox node pool.
#
#   deploy/deploy.sh [--overlay DIR] [--gvisor gke|daemonset|skip]
#                    [--sandbox-nodes "n1 n2"] [--image REF] [--yes]
#
# Steps: confirm context -> label+taint the sandbox nodes -> install/enable gVisor
#        -> apply the kustomize -> wait for rollouts -> verify gVisor.
#
# Options:
#   --overlay DIR    kustomize dir to apply     (default: deploy/kustomize/base)
#   --gvisor MODE    gke      : print the GKE Sandbox node-pool command (managed)
#                    daemonset: apply deploy/gvisor/gvisor-node-installer.yaml (self-managed)
#                    skip     : assume runsc + the `gvisor` RuntimeClass exist (default)
#   --sandbox-nodes  space-separated node names to label deepscan/sandbox=true + taint
#   --image REF      image the manifests should use (default: kubeek-sec/deepscan:latest)
#   --yes            don't prompt for confirmation
#
# PREREQUISITES you own: a real Secret for the DB password + connector tokens
# (deploy/kustomize/base/secrets.env feeds the secretGenerator - fill it in), a
# StorageClass for the Postgres/Nexus PVCs, and a CNI that enforces NetworkPolicy
# (Cilium/Calico) if you want the egress fence to actually fence. See
# docs/sandboxing.md.
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

OVERLAY="deploy/kustomize/base"
GVISOR="skip"
SANDBOX_NODES=""
IMAGE=""
ASSUME_YES=0

while [ $# -gt 0 ]; do
  case "$1" in
    --overlay) OVERLAY="$2"; shift 2 ;;
    --gvisor) GVISOR="$2"; shift 2 ;;
    --sandbox-nodes) SANDBOX_NODES="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    -h|--help) awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

command -v kubectl >/dev/null || { echo "error: kubectl not found." >&2; exit 1; }
ctx=$(kubectl config current-context)
echo "▸ context : $ctx"
echo "▸ overlay : $OVERLAY"
echo "▸ gvisor  : $GVISOR"
if [ "$ASSUME_YES" != "1" ]; then
  printf "Deploy Deep Scan to '%s'? [y/N] " "$ctx"; read -r ans
  case "$ans" in y|Y|yes) ;; *) echo "aborted."; exit 0 ;; esac
fi

# 1. Sandbox node pool: label + taint so untrusted (gVisor) pods land only there.
if [ -n "$SANDBOX_NODES" ]; then
  for n in $SANDBOX_NODES; do
    echo "▸ labelling + tainting sandbox node $n ..."
    kubectl label node "$n" deepscan/sandbox=true --overwrite
    kubectl taint node "$n" deepscan/sandbox=true:NoSchedule --overwrite
  done
else
  echo "▸ (no --sandbox-nodes given; label/taint your sandbox nodes with"
  echo "   deepscan/sandbox=true yourself, or gVisor pods won't schedule.)"
fi

# 2. gVisor / runsc.
case "$GVISOR" in
  gke)
    echo "▸ GKE Sandbox is managed - create (or recreate) the node pool with:"
    echo "    gcloud container node-pools create sandbox --cluster <CLUSTER> \\"
    echo "      --sandbox type=gvisor --node-labels deepscan/sandbox=true \\"
    echo "      --node-taints deepscan/sandbox=true:NoSchedule"
    echo "  Then re-run this with --gvisor skip." ;;
  daemonset)
    echo "▸ applying the self-managed gVisor node installer (privileged - review it)..."
    kubectl apply -f deploy/gvisor/gvisor-node-installer.yaml
    kubectl -n deepscan rollout status ds/gvisor-node-installer --timeout=300s || true ;;
  skip)
    echo "▸ assuming runsc + the 'gvisor' RuntimeClass are already in place." ;;
  *) echo "error: --gvisor must be gke|daemonset|skip" >&2; exit 2 ;;
esac

# 3. Image override (optional).
img_args=()
[ -n "$IMAGE" ] && img_args=(--image "$IMAGE")   # informational; edit the overlay's images: for real

# 4. Apply.
echo "▸ applying $OVERLAY ..."
kubectl apply -k "$OVERLAY"

echo "▸ waiting for the schema migration + rollouts..."
kubectl -n deepscan wait --for=condition=complete job/deepscan-migrate --timeout=300s || true
for d in deepscan-api deepscan-kruncher deepscan-scheduler trivy-server; do
  kubectl -n deepscan rollout status "deploy/$d" --timeout=300s || true
done

# 5. Verify gVisor (skips cleanly if the RuntimeClass isn't there).
if kubectl get runtimeclass gvisor >/dev/null 2>&1; then
  echo "▸ verifying gVisor with a probe pod..."
  out=$(kubectl -n deepscan run "gvisor-probe-$$" --rm -i --restart=Never \
    --image=busybox --overrides='{"spec":{"runtimeClassName":"gvisor"}}' \
    --command -- sh -c 'cat /proc/version; dmesg 2>/dev/null | grep -i gvisor || true' 2>&1) || true
  if echo "$out" | grep -qi gvisor; then
    echo "✓ gVisor active on the sandbox pool."
  else
    echo "✗ gVisor probe did not confirm runsc. Output:"; echo "$out" | sed 's/^/    /'
  fi
fi
echo "✓ deploy done. API: kubectl -n deepscan port-forward svc/deepscan-api 8800:8800"
