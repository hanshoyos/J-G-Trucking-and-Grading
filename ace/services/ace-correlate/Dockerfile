# ── Build stage ───────────────────────────────────────────────
FROM rust:1.78-bookworm AS builder

# Build dependencies separately for layer caching
WORKDIR /build
COPY Cargo.toml ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    SKIP_PROTO_BUILD=1 cargo build --release 2>/dev/null || true && \
    rm src/main.rs

# Build the real binary
COPY . .
RUN SKIP_PROTO_BUILD=1 cargo build --release --bin ace-correlate

# ── Runtime stage ─────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/ace-correlate /usr/local/bin/ace-correlate

RUN useradd -r -s /bin/false ace
USER ace

EXPOSE 8082

ENTRYPOINT ["/usr/local/bin/ace-correlate"]
