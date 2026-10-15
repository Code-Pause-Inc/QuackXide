# syntax=docker/dockerfile:1.7
# Reproducible multi-stage build for the QuackXide enclave workload and
# standalone attestation-verifying key-release relying party (P49, P50).

FROM rust:1.94.1-bookworm AS builder

WORKDIR /workspace
COPY rust-toolchain.toml ./rust-toolchain.toml
COPY backend ./backend

WORKDIR /workspace/backend
ENV CARGO_TERM_COLOR=always
RUN cargo build --release --locked -p platform-api \
        --bin platform-api \
        --bin key-release \
        --bin query-demo \
    && strip target/release/platform-api \
             target/release/key-release \
             target/release/query-demo

# ── Target 1: Confidential Enclave Workload (platform-api) ───────────────────
FROM debian:bookworm-slim AS enclave-api

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --no-create-home nonroot

# Google Cloud Confidential Space launch policy labels (measured into the
# Confidential Space attestation token and enforced by the hardened COS image).
LABEL "tee.launch_policy.allow_cmd_override"="false"
LABEL "tee.launch_policy.allow_env_override"="BIND_ADDR,METRICS_BIND_ADDR,STORAGE_BUCKET,STORAGE_EMULATOR_HOST,KEY_RELEASE_URL,TEE_ATTESTATION_REQUIRED,FEATURE_ZK_ENABLED,QUERY_MAX_CONCURRENT,RESEARCH_MIN_COHORT_SIZE,RESEARCH_DEFAULT_QUERY_BUDGET,ENCLAVE_CONFIG_DIGEST_HEX"
LABEL "tee.launch_policy.log_redirect"="never"
LABEL "tee.launch_policy.monitoring_memory_allow"="always"

COPY --from=builder /workspace/backend/target/release/platform-api /usr/local/bin/platform-api
COPY --from=builder /workspace/backend/target/release/query-demo /usr/local/bin/query-demo

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/platform-api"]

# ── Target 2: Key-Release Relying Party (key-release) ────────────────────────
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
