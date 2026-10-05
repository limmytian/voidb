# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM docker.1ms.run/rust:1.87-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Cache dependencies first
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY . .
# Touch main.rs so cargo rebuilds the final binary
RUN touch src/main.rs && cargo build --release

# ── Stage 2: runtime ─────────────────────────────────────────────────────────
FROM docker.1ms.run/debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/voidb-sync-server /app/voidb-sync-server
COPY config.example.toml /app/config.toml

EXPOSE 7781

CMD ["/app/voidb-sync-server", "--config", "/app/config.toml"]
