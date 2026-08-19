#!/usr/bin/env bash
# e2e test: operator in Offline mode on a 5-worker kind cluster without SGX hardware.
#
# Each kind node gets a unique qe_id derived from NODE_NAME (Downward API).
# The test dynamically discovers qe_ids from the created platform-data secrets,
# writes fake -pck secrets, and verifies the certificate file is available in
# the tdx-qgs container of every QGS pod.
#
# Prerequisites: kind, kubectl, docker
#
# Environment variables:
#   KIND_CLUSTER   kind cluster name   (default: intel-tdx-dcap-e2e)
#   NFD_VERSION    NFD release tag     (default: v0.17.1)
#   NUM_WORKERS    number of workers   (default: 5)
#   QGS_NAMESPACE  namespace for CR    (default: intel-dcap-operator-system)
#   TIMEOUT        seconds per wait    (default: 180)
#   KEEP_CLUSTER   set to 1 to skip cluster deletion on exit

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

KIND_CLUSTER="${KIND_CLUSTER:-intel-tdx-dcap-e2e}"
NFD_VERSION="${NFD_VERSION:-v0.17.1}"
QGS_NAMESPACE="${QGS_NAMESPACE:-intel-dcap-operator-system}"
OPERATOR_NAMESPACE="intel-dcap-operator-system"
TIMEOUT="${TIMEOUT:-180}"
NUM_WORKERS="${NUM_WORKERS:-5}"
# Set SKIP_BUILD=1 to skip docker builds (e.g. when images are pre-built in CI).
SKIP_BUILD="${SKIP_BUILD:-0}"
# Set KIND_NODE_IMAGE to override the k8s node image (e.g. kindest/node:v1.35.5@sha256:...).
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-}"

# Certificate content written to each -pck secret and verified in the pods.
TEST_CERT="e2e-test-certificate-placeholder"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log()  { echo "==> $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    [[ "${KEEP_CLUSTER:-0}" == "1" ]] && return
    log "Deleting kind cluster '$KIND_CLUSTER'"
    kind delete cluster --name "$KIND_CLUSTER" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# 1. Create kind cluster (1 control-plane + 5 workers)
# ---------------------------------------------------------------------------

# Generate containerd proxy drop-in and kind cluster config.
# The proxy drop-in is only created when proxy env vars are set; the cluster
# config is generated dynamically so the extraMount only appears when needed.
_HTTP="${http_proxy:-${HTTP_PROXY:-}}"
_HTTPS="${https_proxy:-${HTTPS_PROXY:-}}"
_NO="${no_proxy:-${NO_PROXY:-}}"

if [[ -n "$_HTTP" || -n "$_HTTPS" ]]; then
    log "Generating containerd proxy drop-in"
    # Always exclude the kind Docker network ranges regardless of host no_proxy
    for _cidr in 172.17.0.0/16 172.18.0.0/16; do
        [[ "$_NO" != *"$_cidr"* ]] && _NO="${_NO:+${_NO},}${_cidr}"
    done
    cat > "$SCRIPT_DIR/containerd-http-proxy.conf" <<EOF
[Service]
Environment="HTTP_PROXY=${_HTTP}"
Environment="HTTPS_PROXY=${_HTTPS}"
Environment="NO_PROXY=${_NO}"
EOF
fi

# Generate kind-config.yaml; proxy extraMount is added only when needed.
mkdir -p "$SCRIPT_DIR/efivars"
_node_entry() {
    local role="$1"
    echo "  - role: $role"
    if [[ -n "$_HTTP$_HTTPS" ]] || [[ "$role" == "worker" ]]; then
        echo "    extraMounts:"
        if [[ -n "$_HTTP$_HTTPS" ]]; then
            cat <<EOF
      - hostPath: ./containerd-http-proxy.conf
        containerPath: /etc/systemd/system/containerd.service.d/http-proxy.conf
EOF
        fi
        if [[ "$role" == "worker" ]]; then
            cat <<EOF
      - hostPath: ./efivars
        containerPath: /sys/firmware/efi/efivars
EOF
        fi
    fi
}
{
    echo "kind: Cluster"
    echo "apiVersion: kind.x-k8s.io/v1alpha4"
    echo "nodes:"
    _node_entry control-plane
    for _i in $(seq 1 "$NUM_WORKERS"); do _node_entry worker; done
} > "$SCRIPT_DIR/kind-config.yaml"

log "Creating kind cluster '$KIND_CLUSTER' (1 control-plane + $NUM_WORKERS workers)"
# kind resolves extraMounts hostPath relative to cwd; run in subshell to avoid changing ours
_kind_image_flag=""
[ -n "$KIND_NODE_IMAGE" ] && _kind_image_flag="--image $KIND_NODE_IMAGE"
# shellcheck disable=SC2086
(cd "$SCRIPT_DIR" && kind create cluster --name "$KIND_CLUSTER" --config kind-config.yaml --wait 10m $_kind_image_flag)

# ---------------------------------------------------------------------------
# 2. Build container images
# ---------------------------------------------------------------------------

if [ "$SKIP_BUILD" = "1" ]; then
    log "Skipping docker builds (SKIP_BUILD=1)"
else
    log "Building intel-tdx-qgs:latest"
    docker build -t intel-tdx-qgs:latest \
        -f "$REPO_ROOT/build/tdx-qgs/Dockerfile" "$REPO_ROOT"

    log "Building intel-tdx-dcap-operator:latest"
    docker build -t intel-tdx-dcap-operator:latest \
        -f "$REPO_ROOT/build/operator/Dockerfile" "$REPO_ROOT"

    # Test variant: replaces get_platform_info with the fake binary and adds
    # busybox for exec-based verification.
    log "Building intel-tdx-qgs-test:latest"
    docker build -t intel-tdx-qgs-test:latest \
        -f "$SCRIPT_DIR/Dockerfile.test" "$REPO_ROOT"
fi

# ---------------------------------------------------------------------------
# 3. Load images into the kind cluster
# ---------------------------------------------------------------------------

log "Loading images into kind cluster '$KIND_CLUSTER'"
kind load docker-image intel-tdx-qgs:latest            --name "$KIND_CLUSTER"
kind load docker-image intel-tdx-dcap-operator:latest  --name "$KIND_CLUSTER"
kind load docker-image intel-tdx-qgs-test:latest       --name "$KIND_CLUSTER"

# ---------------------------------------------------------------------------
# 4. Install NFD and apply NodeFeatureRule
# ---------------------------------------------------------------------------

log "Installing NFD $NFD_VERSION"
kubectl apply -k \
    "https://github.com/kubernetes-sigs/node-feature-discovery/deployment/overlays/default?ref=${NFD_VERSION}"

kubectl rollout status deployment/nfd-master \
    -n node-feature-discovery --timeout="${TIMEOUT}s"
kubectl rollout status daemonset/nfd-worker \
    -n node-feature-discovery --timeout="${TIMEOUT}s"

log "Applying NodeFeatureRule (fake SGX label + extended resources)"
kubectl apply -f "$SCRIPT_DIR/node-feature-rule.yaml"

# ---------------------------------------------------------------------------
# 5. Deploy the operator
# ---------------------------------------------------------------------------

log "Deploying intel-tdx-dcap-operator"
kubectl apply -k "$REPO_ROOT/bin/operator/deployment/default"

# INTEL_TDX_QGS_SHA256 overrides the image for all DaemonSet containers
# (platform-registration initContainer, pck-certs-watcher sidecar, tdx-qgs).
kubectl set env deployment/intel-tdx-dcap-controller-manager \
    -n "$OPERATOR_NAMESPACE" \
    INTEL_TDX_QGS_SHA256=intel-tdx-qgs-test:latest

kubectl rollout status deployment/intel-tdx-dcap-controller-manager \
    -n "$OPERATOR_NAMESPACE" --timeout="${TIMEOUT}s"

log "Applying TdxQuoteGenerationService (Offline mode)"
kubectl apply -f "$REPO_ROOT/bin/operator/deployment/samples/offline-mode.yaml"

log "Waiting for QGS DaemonSet to be created"
kubectl wait daemonset/intel-tdx-dcap-qgs \
    -n "$QGS_NAMESPACE" --for=create --timeout="${TIMEOUT}s"

# ---------------------------------------------------------------------------
# 6. Collect platform-data secrets (one per worker node, created by platform-registration)
# ---------------------------------------------------------------------------

# Poll until all NUM_WORKERS platform-data secrets appear; the readinessProbe
# on pck-certs-watcher blocks pods from becoming Ready until PCK secrets exist,
# so we must write those secrets before waiting for rollout.
log "Waiting for $NUM_WORKERS platform-data secrets"
_deadline=$(( $(date +%s) + TIMEOUT ))
while true; do
    PLATFORM_DATA_SECRETS=$(kubectl get secrets -n "$QGS_NAMESPACE" \
        -l type=platform-data -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || true)
    _count=$(echo "$PLATFORM_DATA_SECRETS" | wc -w)
    [[ "$_count" -ge "$NUM_WORKERS" ]] && break
    [[ "$(date +%s)" -gt "$_deadline" ]] && fail "Only ${_count}/${NUM_WORKERS} platform-data secrets appeared within ${TIMEOUT}s"
    sleep 3
done
log "Platform-data secrets (${_count}): $PLATFORM_DATA_SECRETS"

# ---------------------------------------------------------------------------
# 7. Write fake PCK cache secret for each platform-data secret
# ---------------------------------------------------------------------------

log "Creating -pck secrets"
for QE_ID in $PLATFORM_DATA_SECRETS; do
    kubectl create secret generic "${QE_ID}-pck" \
        -n "$QGS_NAMESPACE" \
        --from-literal="certificate=${TEST_CERT}" \
        --dry-run=client -o yaml | kubectl apply -f -
done

# ---------------------------------------------------------------------------
# 8. Verify cert files are available in the tdx-qgs container of each QGS pod
# ---------------------------------------------------------------------------

log "Waiting for QGS rollout to complete"
kubectl rollout status daemonset/intel-tdx-dcap-qgs \
    -n "$QGS_NAMESPACE" --timeout="${TIMEOUT}s"

# Capture pod names after rollout completes so they are current.
QGS_PODS=$(kubectl get pods -n "$QGS_NAMESPACE" -l app=intel-tdx-qgs \
    -o jsonpath='{.items[*].metadata.name}')

for POD in $QGS_PODS; do
    # Verify certs are visible in the QGS container via the shared dcap-qcnl-cache volume.
    # busybox is added to the test image by Dockerfile.test.
    kubectl exec "$POD" -n "$QGS_NAMESPACE" -c tdx-qgs -- \
        /bin/busybox ls /run/dcap/cache/.dcap-qcnl/ | grep -q . \
        || fail "No cert files in $POD"
    log "PASS: $POD — cert file present"
done

echo ""
log "All e2e checks passed"
