# ACE Platform — Developer Reference

ACE (Adaptive Cyber Exposure) is a unified IT/OT/Cloud threat monitoring and
correlation engine.  This document covers the monorepo layout, build commands,
and development workflow.

---

## Monorepo Layout

```
ace/
├── Cargo.toml                  # Rust workspace root
├── go.work                     # Go workspace root
├── proto/                      # Shared Protobuf schemas (ACE-CEF)
│   ├── ace_cef.proto           # Canonical event format
│   └── services/               # Per-service RPC schemas
├── services/
│   ├── ace-ingest/             # Rust — universal log ingestion gateway
│   ├── ace-normalize/          # Rust — ACE-CEF normalization pipeline
│   ├── ace-operator/           # Go   — Kubernetes operator (CRDs)
│   ├── ace-correlate/          # Rust — streaming correlation engine      [Phase 2]
│   ├── ace-mitre-engine/       # Go   — MITRE ATT&CK DB + heatmap API     [Phase 2]
│   ├── ace-threat-intel/       # Go   — IOC feed aggregator + Redis cache  [Phase 2]
│   └── ace-asset-inventory/    # Go   — IT/OT/Cloud CMDB + Purdue model   [Phase 2]
├── deploy/helm/ace-platform/   # Helm umbrella chart
│   ├── Chart.yaml
│   ├── values.yaml             # Single master config file
│   └── charts/
│       ├── ace-ingest/
│       ├── ace-normalize/
│       ├── ace-operator/
│       ├── ace-correlate/      # [Phase 2]
│       ├── ace-mitre-engine/   # [Phase 2]
│       ├── ace-threat-intel/   # [Phase 2]
│       ├── ace-asset-inventory/ # [Phase 2]
│       └── ace-deps/           # Kafka, ClickHouse, Redis, PG, MinIO
├── examples/                   # Sample Kubernetes manifests
├── scripts/                    # Dev-setup and build helper scripts
└── .github/workflows/ci.yml    # GitHub Actions CI
```

---

## Quick Start

```bash
# 1. Create local Kind cluster and check prerequisites
./scripts/dev-setup.sh

# 2. Build all Rust services (debug)
cargo build --workspace

# 3. Run unit tests
cargo test --workspace

# 4. Build Go operator
cd services/ace-operator && go build ./...

# 5. Build all container images
REGISTRY=my-registry.example.com TAG=dev PUSH=false ./scripts/build-all.sh
```

---

## Service Ports

| Service              | Port  | Protocol | Purpose                              |
|----------------------|-------|----------|--------------------------------------|
| ace-ingest           | 8080  | HTTP     | Health (/healthz, /readyz, /metrics) |
| ace-ingest           | 514   | UDP      | Syslog                               |
| ace-ingest           | 6514  | TCP      | Syslog (TLS)                         |
| ace-ingest           | 502   | TCP      | Modbus/TCP passive tap               |
| ace-ingest           | 5985  | TCP      | Windows Event Forwarding             |
| ace-ingest           | 9443  | TCP      | Kubernetes audit webhook             |
| ace-normalize        | 8081  | HTTP     | Health                               |
| ace-operator         | 8080  | HTTP     | Prometheus metrics                   |
| ace-operator         | 8081  | HTTP     | Health probes                        |
| ace-correlate        | 8082  | HTTP     | Health + correlation metrics         |
| ace-mitre-engine     | 8090  | HTTP     | ATT&CK REST API + heatmap            |
| ace-threat-intel     | 8091  | HTTP     | IOC lookup API + feed status         |
| ace-asset-inventory  | 8092  | HTTP     | Asset CMDB REST API                  |

---

## Kafka Topics

| Topic                   | Producer      | Consumer                          | Purpose                    |
|-------------------------|---------------|-----------------------------------|----------------------------|
| `ace.events.raw`        | ace-ingest    | ace-normalize                     | Pre-normalization events   |
| `ace.events.normalized` | ace-normalize | ace-correlate, ace-asset-inventory | ACE-CEF events             |
| `ace.events.enriched`   | ace-correlate | ace-dashboard                     | IOC-enriched events        |
| `ace.alerts`            | ace-correlate | ace-respond                       | Correlated threat alerts   |

---

## Environment Variables

### ace-ingest

| Variable                                         | Default              | Description                  |
|--------------------------------------------------|----------------------|------------------------------|
| `ACE_INGEST__TENANT_ID`                          | `default`            | Tenant scope                 |
| `ACE_INGEST__KAFKA__BROKERS`                     | —                    | **Required**. Kafka brokers  |
| `ACE_INGEST__PROTOCOLS__SYSLOG__ENABLED`         | `true`               | Enable syslog handler        |
| `ACE_INGEST__PROTOCOLS__MODBUS__ENABLED`         | `false`              | Enable Modbus/TCP tap        |
| `ACE_INGEST__PROTOCOLS__CLOUDTRAIL__ENABLED`     | `false`              | Enable CloudTrail polling    |
| `ACE_INGEST__PROTOCOLS__WEF__ENABLED`            | `false`              | Enable WEF receiver          |
| `ACE_INGEST__PROTOCOLS__K8S_AUDIT__ENABLED`      | `false`              | Enable K8s audit webhook     |

### ace-normalize

| Variable                                  | Default                   | Description                  |
|-------------------------------------------|---------------------------|------------------------------|
| `ACE_NORMALIZE__KAFKA__BROKERS`           | —                         | **Required**. Kafka brokers  |
| `ACE_NORMALIZE__KAFKA__RAW_TOPIC`         | `ace.events.raw`          | Input topic                  |
| `ACE_NORMALIZE__KAFKA__NORMALIZED_TOPIC`  | `ace.events.normalized`   | Output topic                 |
| `ACE_NORMALIZE__GEOIP_DB_PATH`            | —                         | Path to MaxMind .mmdb file   |

---

## Code Standards

- **Rust**: `cargo clippy --all-targets -- -D warnings -W clippy::pedantic`
- **Go**: `golangci-lint run` with `.golangci.yml` config
- **Zero unsafe Rust** unless documented with a `// SAFETY:` comment
- **No Python in the hot path** — Python is only for offline ML training scripts
- **All services** expose `/healthz` (liveness) and `/readyz` (readiness) on their health port

---

## Phase Roadmap

| Phase | Focus                                     | Services                              |
|-------|-------------------------------------------|---------------------------------------|
| 1 ✅  | Foundation                                | ace-ingest, ace-normalize, ace-operator, Helm |
| 2 ✅  | Intelligence                              | ace-correlate, ace-mitre-engine, ace-threat-intel, ace-asset-inventory |
| 3     | Analysis                                  | ace-pcap, ace-vuln-assess, ONNX anomaly detection |
| 4     | Interface                                 | ace-dashboard (Next.js 15), ace-api-gateway, ace-respond |
| 5     | Hardening                                 | Istio mTLS, RBAC, load testing, security audit |
