# ─── Stage 1: Build ───────────────────────────────────────────
FROM rust:1.78-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    libssl-dev \
    pkg-config \
    libsasl2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src && echo 'fn main(){}' > src/main.rs
RUN cargo fetch

COPY . .
RUN cargo build --release --bin ace-normalize

# ─── Stage 2: Runtime ─────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libsasl2-2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -u 65534 -M -s /sbin/nologin ace

WORKDIR /app
COPY --from=builder /build/target/release/ace-normalize /app/ace-normalize
RUN chmod +x /app/ace-normalize

USER 65534:65534

EXPOSE 8081

ENTRYPOINT ["/app/ace-normalize"]
