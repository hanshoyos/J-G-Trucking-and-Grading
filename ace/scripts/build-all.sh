#!/usr/bin/env bash
# Build all ACE services and push to a registry.
# Usage: REGISTRY=ghcr.io/ace-platform TAG=0.1.0 ./build-all.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

REGISTRY="${REGISTRY:-ghcr.io/ace-platform}"
TAG="${TAG:-dev}"

SERVICES_RUST=(ace-ingest ace-normalize)
SERVICES_GO=(ace-operator)

echo "==> Building ACE Platform images (tag: ${TAG})"

# ── Rust services ─────────────────────────────────────────────
for svc in "${SERVICES_RUST[@]}"; do
    echo "--> Building ${svc}..."
    docker build \
        -t "${REGISTRY}/${svc}:${TAG}" \
        -t "${REGISTRY}/${svc}:latest" \
        "${ACE_ROOT}/services/${svc}"
done

# ── Go services ───────────────────────────────────────────────
for svc in "${SERVICES_GO[@]}"; do
    echo "--> Building ${svc}..."
    docker build \
        -t "${REGISTRY}/${svc}:${TAG}" \
        -t "${REGISTRY}/${svc}:latest" \
        "${ACE_ROOT}/services/${svc}"
done

if [[ "${PUSH:-false}" == "true" ]]; then
    echo "--> Pushing images..."
    for svc in "${SERVICES_RUST[@]}" "${SERVICES_GO[@]}"; do
        docker push "${REGISTRY}/${svc}:${TAG}"
        docker push "${REGISTRY}/${svc}:latest"
    done
fi

echo "==> Build complete."
