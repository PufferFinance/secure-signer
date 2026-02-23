# Stage 1: Chef - dependency caching
FROM rust:1.77-bookworm AS chef
RUN cargo install cargo-chef
WORKDIR /app

# Stage 2: Planner
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 3: Builder
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin secure-signer

# Stage 4: Runtime
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/secure-signer /usr/local/bin/secure-signer

# Create data directories
RUN mkdir -p /data/keys/bls_keys /data/keys/eth_keys /data/slashing

EXPOSE 9001

ENTRYPOINT ["secure-signer"]
