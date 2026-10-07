# QuackXide — Project Scope

The work that takes QuackXide to its first production release, and the
definition of done for it. The USF core contribution team owns this scope
(see `CONTRIBUTORS.md`).

QuackXide is a secure database and data-processing system for sensitive and
protected data: encrypted in, at rest, and out, with plaintext confined to
attested enclave memory for one query. See `README.md` for the overview.

## Engineering goals

QuackXide is built to run in real-world production environments, not as a
proof of concept. Every change is judged against five goals:

| Goal | What it means here |
| --- | --- |
| **Security** | The invariants above hold on every path, including failure paths. Fail closed. Established cryptography only. |
| **Efficiency** | Plaintext and key material live for the shortest possible time; columnar storage and query pushdown keep decrypt-and-scan work to what the query needs. |
| **Speed** | Query latency and encryption throughput are measured, benchmarked, and tracked for regressions. |
| **Reliability** | Durable state, restart safety, idempotent operations, clear error semantics, and observability through the audit stream and operational logs. |
| **Real-world operation** | Reproducible deployment on confidential-computing hardware, configuration from the environment, documented operations. |

## Starting point

The architecture is implemented and tested end-to-end against synthetic data
(see `docs/ARCHITECTURE.md`). The tables below mark each step **Built**
(exists and is tested), **Harden** (exists; needs production-grade
completion, review, and failure-path tests), or **Build** (does not exist).

## The two lifecycles

### Dataset lifecycle (steward)

| Step | State | Notes |
| --- | --- | --- |
| Steward signs in | **Build** | Managed sign-in service. RS256/JWKS verification and a TOTP module exist; local development uses HS256 dev tokens. |
| Upload | **Harden** | Browser-side drive encryption exists (Web Crypto, per-file keys, AAD-bound chunks). Research datasets currently enter through connector pipelines; a steward upload path for research datasets is needed. |
| Hybrid post-quantum encryption | **Build** | X25519 + ML-KEM-768 key encapsulation; Ed25519 + ML-DSA-65 signatures. Current suite is X25519 only. No silent downgrade to classical-only. |
| Encrypted storage | **Harden** | `VaultStore` with GCS and in-memory backends; typed tenant paths. |

### Research lifecycle (researcher)

| Step | State | Notes |
| --- | --- | --- |
| Portal and sign-in | **Harden** / **Build** | Portal components exist; sign-in shares the managed sign-in work above. |
| Grant check | **Harden** | `GrantRegistry`, steward-scoped, revocable, no existence oracle. |
| Attestation | **Build** | AMD SEV-SNP report verification. The provider currently refuses (fails closed). |
| Key release | **Build** | Production `EnclaveKeyProvider`. Query endpoints return 503 until wired; the path is proven by `DevKeyProvider` and `query-demo`. |
| Query | **Harden** | DataFusion inside `QueryScope`, plaintext zeroized after use. |
| Disclosure control | **Harden** | Plan gate, genuine-count check, `MinCountThreshold`, budget ledger. |
| Result | **Harden** | Aggregates, suppressed-row count, and remaining budget. |
| Encrypted results | **Build** | Results sealed to the researcher's key inside the enclave and opened only in the researcher's browser. They currently leave as JSON over TLS. |

### Across both lifecycles

| Item | State | Notes |
| --- | --- | --- |
| Durable registries | **Build** | Tenant, grant, budget, and catalog registries are in-memory behind traits; add durable backends without touching call sites. |
| Deployment | **Build** | Reproducible deployment of `platform-api`, with the query engine in-process, into an attested SEV-SNP Confidential VM, with TLS terminating inside the VM and the frontend served from the same origin (ADR 0005). |
| Benchmarks | **Build** | None exist. Measure query latency, encryption throughput, and enclave overhead against synthetic datasets, and track them for regressions. |
| Operations | **Build** | Health checks, structured operational metrics, backup and restore of ciphertext and registries, key-rotation procedure, and a runbook. |
| DataFusion upgrade | **Harden** | Move from DataFusion 49 to the current release to clear the `quick-xml` advisories recorded in `backend/deny.toml` and the `thrift` advisory allowed in `.github/workflows/dependency-review.yml`; the disclosure allowlist and `tests/bypass.rs` must pass unchanged. |
| Dominance rule | **Build** | Suppress `MIN`/`MAX` (and sums) dominated by a single individual, closing the extreme-value residual in `docs/THREAT_MODEL.md`. |
| A test for every failure path | **Harden** | Every refusal (403, 422, 429, 503, attestation, malformed input) has a negative test. |

## Stack

Rust, Apache DataFusion, Arrow, Parquet, Axum; AMD SEV-SNP; AES-256-GCM and
HPKE, with hybrid X25519 + ML-KEM-768 and Ed25519 + ML-DSA-65 as the target
suites; React 19, TypeScript, Web Crypto, Vite, Tailwind. Established
libraries only, and no silent downgrade to classical-only cryptography.

## Constraints

* **Synthetic and public datasets only during development.** QuackXide is
  built to protect sensitive data in production; no protected health
  information or other real sensitive data touches this repository or its
  development environments. See `docs/DATA_POLICY.md`.
* **Fail closed.** Missing key material, unverifiable attestation, and
  malformed input are refused, never defaulted.
* **`scripts/check.sh` passes** before every push.

## Definition of done

The first complete release is done when all of the following hold:

1. A steward can sign in, upload a dataset that is encrypted in the browser
   under the hybrid post-quantum suite, and see it stored as ciphertext.
2. A researcher can sign in, request and receive a grant, and run an
   aggregate query that passes attestation on genuine SEV-SNP hardware,
   receives the key inside the enclave only, and returns a
   disclosure-controlled result sealed to the researcher's key.
3. Every step of both lifecycles is **Built**; no step returns 503 for
   missing wiring in a production build.
4. Registries are durable across restarts.
5. The system deploys reproducibly from this repository's documentation.
6. Benchmarks are committed with their method, results, and performance
   targets, and run in a way that catches regressions.
7. The system survives restarts and failures without data loss or a
   weakened invariant, and can be backed up, restored, and operated from
   the runbook.
8. Every failure path has a negative test, and the audit-coverage test
   covers every new security decision.
9. `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and `README.md`
   describe the system as built, with no "to build" items left in the
   release scope.
10. `scripts/check.sh` passes on `main`.

## Team

A core team of four. Team members
are credited in `CONTRIBUTORS.md`, the git history, `README.md`, and the
release notes in `CHANGELOG.md`.
