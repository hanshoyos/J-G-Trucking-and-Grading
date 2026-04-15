# ─── Stage 1: Build ───────────────────────────────────────────
FROM rust:1.78-bookworm AS builder

# Install librdkafka build dependencies (cmake-build feature).
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libssl-dev \
    pkg-config \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependencies separately from source.
COPY Cargo.toml Cargo.lock* ./
# Create placeholder src/main.rs so cargo fetch succeeds.
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs
# Fetch workspace deps — this layer is cached when only src changes.
RUN cargo fetch

# Now copy the real source.
COPY . .

# Build release binary.
RUN cargo build --release --bin ace-ingest

# ─── Stage 2: Runtime ─────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Install only runtime shared libraries needed by librdkafka.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libsasl2-2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN useradd -u 65534 -M -s /sbin/nologin ace

WORKDIR /app
COPY --from=builder /build/target/release/ace-ingest /app/ace-ingest
RUN chmod +x /app/ace-ingest

USER 65534:65534

# Health, syslog-tcp, syslog-udp
EXPOSE 8080 6514 514/udp 5985 9443

ENTRYPOINT ["/app/ace-ingest"]
