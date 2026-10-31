# syntax=docker/dockerfile:1.7
# DEV ONLY. Images for the local simulated TEE stack
# (docker-compose.simulated-tee.yml): platform-api and the key-release
# stand-in for Cloud KMS, built with the `dev` feature. Never deploy them;
# the production workload image is P49's, in deploy/ (ADR 0004).

FROM rust:1.94.1-bookworm AS builder

WORKDIR /workspace
COPY rust-toolchain.toml ./rust-toolchain.toml
COPY backend ./backend

WORKDIR /workspace/backend
ENV CARGO_TERM_COLOR=always
RUN cargo build --release --locked -p platform-api --features dev \
        --bin platform-api \
        --bin key-release \
        --bin query-demo \
    && strip target/release/platform-api \
             target/release/key-release \
             target/release/query-demo

# ── Target 1: simulated enclave workload (platform-api) ─────────────────────
FROM debian:bookworm-slim AS enclave-api

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --no-create-home nonroot

COPY --from=builder /workspace/backend/target/release/platform-api /usr/local/bin/platform-api
COPY --from=builder /workspace/backend/target/release/query-demo /usr/local/bin/query-demo

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/platform-api"]

# ── Target 2: key-release stand-in for Cloud KMS ────────────────────────────
FROM debian:bookworm-slim AS key-release

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --no-create-home nonroot

COPY --from=builder /workspace/backend/target/release/key-release /usr/local/bin/key-release

USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/key-release"]
