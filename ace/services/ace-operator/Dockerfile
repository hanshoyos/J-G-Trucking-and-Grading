# ─── Stage 1: Build ───────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

WORKDIR /build

COPY go.mod go.sum* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -a -ldflags="-s -w -X main.buildVersion=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o manager .

# ─── Stage 2: Runtime ─────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot AS runtime

WORKDIR /
COPY --from=builder /build/manager /manager

USER 65534:65534

ENTRYPOINT ["/manager"]
