#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# ACE Platform — Local developer setup
#
# Prerequisites: Rust, Go 1.22+, Docker, kubectl, helm, kind
# ─────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> ACE dev-setup starting (root: ${ACE_ROOT})"

# ── 1. Check tool versions ────────────────────────────────────
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: $1 not found. Please install it first." >&2
        exit 1
    fi
    echo "  ✓ $1 $(${1} --version 2>&1 | head -1)"
}

echo "--> Checking prerequisites..."
check_tool rustc
check_tool cargo
check_tool go
check_tool docker
check_tool kubectl
check_tool helm
check_tool kind

# ── 2. Create local Kind cluster ─────────────────────────────
KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-ace-dev}"
if kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
    echo "--> Kind cluster '${KIND_CLUSTER_NAME}' already exists"
else
    echo "--> Creating Kind cluster '${KIND_CLUSTER_NAME}'..."
    cat <<EOF | kind create cluster --name "${KIND_CLUSTER_NAME}" --config -
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    kubeadmConfigPatches:
      - |
        kind: InitConfiguration
        nodeRegistration:
          kubeletExtraArgs:
            node-labels: "ingress-ready=true"
  - role: worker
  - role: worker
EOF
fi

# ── 3. Install Helm chart dependencies ───────────────────────
echo "--> Updating Helm chart repositories..."
helm repo add bitnami https://charts.bitnami.com/bitnami 2>/dev/null || true
helm repo update

# ── 4. Build Rust services (debug) ───────────────────────────
echo "--> Building Rust services (debug)..."
cd "${ACE_ROOT}"
cargo build --workspace 2>&1 | tail -5

# ── 5. Build Go operator ─────────────────────────────────────
echo "--> Building Go operator..."
cd "${ACE_ROOT}/services/ace-operator"
go build ./...

echo ""
echo "==> ACE dev-setup complete!"
echo ""
echo "Next steps:"
echo "  1. Deploy infrastructure:  helm install ace-deps ace/deploy/helm/ace-platform/charts/ace-deps"
echo "  2. Deploy operator:        helm install ace-operator ace/deploy/helm/ace-platform/charts/ace-operator"
echo "  3. Apply example pipeline: kubectl apply -f ace/examples/ingestpipeline-sample.yaml"
