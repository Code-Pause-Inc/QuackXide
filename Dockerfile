# syntax=docker/dockerfile:1.7
# DEV ONLY. Images for the local simulated TEE stack
# (docker-compose.simulated-tee.yml): platform-api, the key-release
# stand-in for Cloud KMS and the simulated attestation service, built with
# the `dev` feature. Never deploy them;
# the production workload image is P49's, in deploy/ (ADR 0004).

# cargo-chef builds the dependencies in their own layer, keyed on the
# manifests and Cargo.lock, so a source-only change reuses them.
FROM rust:1.94.1-bookworm AS chef
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /workspace
COPY rust-toolchain.toml ./rust-toolchain.toml
WORKDIR /workspace/backend
ENV CARGO_TERM_COLOR=always

FROM chef AS planner
COPY backend ./
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /workspace/backend/recipe.json recipe.json
RUN cargo chef cook --release --locked -p platform-api --features dev \
        --recipe-path recipe.json
COPY backend ./
RUN cargo build --release --locked -p platform-api --features dev \
        --bin platform-api \
        --bin key-release \
        --bin query-demo \
        --bin sim-attestation \
    && strip target/release/platform-api \
             target/release/key-release \
             target/release/query-demo \
             target/release/sim-attestation

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

# ── Target 3: simulated attestation service (plays Google's part) ───────────
FROM debian:bookworm-slim AS sim-attestation

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --no-create-home nonroot

COPY --from=builder /workspace/backend/target/release/sim-attestation /usr/local/bin/sim-attestation

USER 65532:65532
EXPOSE 8070
ENTRYPOINT ["/usr/local/bin/sim-attestation"]
