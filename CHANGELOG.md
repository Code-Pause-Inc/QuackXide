# Changelog

All notable changes to QuackXide are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

* `platform_enclave::token::TokenVerifier` verifies Confidential Space
  attestation tokens (ADR 0004, P47): RS256 against a key set passed in,
  with issuer, audience, validity (60 s clock-skew leeway), the expected
  nonces, and the release policy (`GCP_INTEL_TDX`, `CONFIDENTIAL_SPACE`,
  `disabled-since-boot`, `STABLE`, an allowed image digest). Tokens over
  16 KiB are refused before parsing, and errors name a class, never token
  contents. A dev-only signer (`simulated_token`, feature `simulated`)
  issues tokens for tests, and the `attestation_token` fuzz target covers
  the verifier.
* Browser envelope sealing: `envelope-wasm` builds `platform-crypto`'s HPKE
  envelope seal for wasm32, and the crypto worker loads it through
  `frontend/src/lib/crypto/envelope.ts` to seal to a tenant's raw public
  key. `scripts/build-wasm.sh` builds it (no debug info, local paths
  remapped) for `check.sh` and the CI jobs that run frontend tests.
  Envelope readers choose the suite from the frame magic, `info` strings
  are defined once in `platform_crypto::info` (with new kinds for steward
  uploads and research results), and `fixtures/envelope/` holds vectors
  that the Rust and vitest tests both check. `platform-crypto`'s AEAD
  helpers, blind indexes and TOTP move behind its default `server`
  feature.
* The drive listing (`GET /api/v1/drive/objects`) is bounded: it returns at
  most 1000 objects (`MAX_LISTED_OBJECTS`) and reads their manifests 16 at a
  time instead of one by one. A drive holding more is refused with 422 "too
  many objects to list" and an audited `data.access` denial, never a
  partial list.
* The GCS vault's timeouts and retries are explicit settings instead of
  `object_store`'s defaults (10 retries within 3 minutes):
  `STORAGE_REQUEST_TIMEOUT_SECS` (30), `STORAGE_CONNECT_TIMEOUT_SECS` (5),
  `STORAGE_MAX_RETRIES` (3) and `STORAGE_RETRY_TIMEOUT_SECS` (20), each
  bounded and refused at startup when out of range. A stalled backend fails
  within retry timeout + backoff + request timeout (55 s by default). The
  client refuses plain HTTP except to a `STORAGE_EMULATOR_HOST`.
  `ObjectStoreVault::new_gcs` takes the settings.
* Storage errors are retryable or fatal. `StorageError::Backend` is
  replaced by `Unavailable` (an `object_store` failure that outlasted the
  client's retries; the API returns 503 with `Retry-After: 5`) and `Fatal`
  (credentials, permissions, invalid paths, unsupported operations and
  configuration; 502). The admin tenant listing now reports a storage
  outage as 503. `platform-api/tests/common/mod.rs` gains `FlakyVault`,
  which can fail `put`, `get`, `delete`, `list` and `usage`, and each drive
  operation has an outage test.
* `docs/DEVELOPMENT.md`: prerequisites (WSL2 on Windows), the first build,
  everyday test commands, running `cargo deny` and `npm audit` before a
  push, what each `scripts/check.sh` step checks and how to fix it, where
  to start reading the code, and a glossary. `CONTRIBUTING.md` "Setup"
  links to it.
* Frontend lint: ESLint (typescript-eslint and the React hooks rules) runs
  as `npm run lint` from `scripts/check.sh` with zero warnings allowed, and
  `CONTRIBUTING.md` "Before every push" says the frontend is linted too.
* CI compiles every fuzz target on each pull request, and runs a gitleaks
  secret scan over the full history (`.gitleaks.toml`); `scripts/check.sh`
  runs the same scan when gitleaks is installed.
* `VaultStore::put_if_absent`, a create-only write (`PutMode::Create`;
  `x-goog-if-generation-match: 0` on GCS). `StorageError` gains
  `AlreadyExists` and `PreconditionFailed`, which the API returns as 409
  instead of 502. `ObjectStoreVault::new` takes any
  `Arc<dyn ObjectStore>`.
* `platform-api/tests/common/mod.rs`: shared token minters (HS256, and a
  cached RS256 keypair), request helpers, and app builders for the API
  integration tests.
* ADR 0006 (Accepted): sign-in through Auth0 with a platform token
  exchange in a separate identity service, running in its own attested
  Confidential VM with its signing key released by Cloud KMS, hybrid Ed25519 + ML-DSA-65 platform tokens, one identity per
  tenant, an `adm` allowlist, the platform's TOTP for every role with
  audited administrator reset for recovery, session lifetimes with the refresh
  token in an `HttpOnly` cookie, and the authorization-code + PKCE browser flow.
  `docs/ARCHITECTURE.md` gains the target authorization model and
  `docs/THREAT_MODEL.md` A3 and A4 list the new controls.
* ADR 0007 (Proposed): the hybrid suite construction (HPKE with X-Wing,
  frame `HPK2`), the libraries and what "established" means, browser
  storage for X-Wing seeds, v1 signature consumers, and no `HPK1`
  migration mode in v1.
* ADR 0004 (Accepted): Confidential Space on Intel TDX with Cloud KMS, in
  place of SEV-SNP, subject to P12 confirming a TDX machine type, region
  and cost. Each dataset has its own data key, which KMS unwraps only for
  the attested workload, per query. The SEV-SNP code and the `key-release`
  relying party serve only the simulated TEE. `docs/THREAT_MODEL.md` A2
  names Google and the key project's administrator as trusted, and the
  architecture, scope, testing guide, README and v1.0 plan (P12, P47,
  P48, P50) follow.
* `docs/TESTING.md`: where each test layer lives, the naming and placement
  convention for negative tests and audit assertions, and the substitutes
  for what CI cannot exercise.
* `GET /readyz` reports whether `platform-api` can serve: storage
  reachable, attestation passing, query service and token verifier
  configured. It answers only `ready` or `not_ready`, and caches the result
  for 5 seconds because it is public.
* `platform-api` exports Prometheus metrics (request counts and latency,
  error responses by kind, plaintext-slot wait) on a separate
  loopback-only listener, `METRICS_BIND_ADDR` (default `127.0.0.1:9464`).
  Startup refuses a non-loopback address.
* `synth-data`, a dev-only crate that writes seeded synthetic Parquet for
  tests, benchmarks and demos: a health-style `cohort` table with groups
  on both sides of the cohort threshold k and one group dominated by a
  single person, and a `wide` table for throughput benchmarks. From
  `backend/`, `cargo run -p synth-data -- --help` lists the options.
* Query and research responses include `tee_platform`, the platform that
  passed the attestation gate: `amd-sev-snp`, `simulated` or `development`.
* `devstack`, a dev-only server that runs the research lifecycle on one
  machine: the API with the research routes on in-process dev keys and
  fabricated attestation, seeded with a synthetic cohort, its catalog
  listing, and a token each for a steward and a researcher. It is built
  only with `platform-api`'s `dev` feature, refuses to start without
  `DEVSTACK_ALLOW_INSECURE=1` and `JWT_HS256_SECRET`, and listens only on
  loopback. The API integration tests share its wiring (`platform_api::dev`),
  and CI checks that a default-feature release build contains no `devstack`
  binary. From `backend/`,
  `DEVSTACK_ALLOW_INSECURE=1 cargo run -p platform-api --features dev --bin devstack`
  starts it.

### Fixed

* GCS emulator writes (`STORAGE_EMULATOR_HOST`) no longer ask the GCE
  metadata server for a credential: `object_store` 0.13 skips signing on
  reads only, so the emulator client now carries a placeholder credential.
* A drive delete that fails partway can be retried: `DELETE
  /api/v1/drive/objects/{id}` now deletes the chunks before the manifest,
  so after a failure the object is still found and the retry removes the
  rest. Before, the manifest went first, the retry got 404 and the chunks
  were stranded.

### Security

* `tokio` 1.54.1 (RUSTSEC-2026-0384; 1.54.0 is yanked) and `zstd-sys`
  2.1.2 (RUSTSEC-2026-0410). `backend/deny.toml` records why
  RUSTSEC-2026-0387 (`crypto-bigint` 0.5) and RUSTSEC-2026-0391, -0398 and
  -0403 (`zstd` 0.13) do not apply until upstream crates move to fixed
  versions.
* `HttpJsonSource` refuses a connector endpoint that is not `https`
  (plain `http` only on loopback), as token endpoints already did, so a
  bearer token is never sent in cleartext. Connector HTTP requests refuse
  redirects, time out, and cap response bodies at 64 KiB for token
  responses and 64 MiB for payloads. Response bodies, `Dataset` cells and
  the query-result JSON buffer are zeroized on drop.
* `GET /api/v1/drive/objects` skips a manifest deleted between listing
  and reading it, instead of failing the whole listing with 404.
* `JWT_HS256_SECRET` and `MOR_WEBHOOK_SECRET` are held as `SecretString`
  (moved to `platform-core`), zeroized on drop and redacted in `Debug`.
  Their environment copies remain; `docs/THREAT_MODEL.md` lists this as a
  residual risk.
* The Drive client checks the vault's plaintext copies of a manifest's
  tenant, chunk count and timestamp against the authenticated manifest,
  shows only authenticated values, and on download refuses a record for
  another object or chunks whose total length differs from the
  authenticated file size.
* The disclosure gate refuses `ROLLUP`, `CUBE` and `GROUPING SETS`. A
  subtotal row beside its group rows let one query recover a suppressed
  cohort's count and values. Sorts and limits below the aggregate are
  refused too. See ADR 0002.
* Query SQL is read-only. DataFusion ran DDL, `SET` and `PREPARE` while
  planning, before the disclosure gate, and with ZK mode off
  `COPY … TO` wrote decrypted rows to the host's disk. DDL, DML, `COPY`
  and session statements are now refused before anything executes, and a
  query scope has no object store.
* The API accepts only access tokens. It verified a token's signature but
  not its type, so a verified pre-MFA (`preauth`) or `refresh` token passed
  every data and admin route, and a token with no `typ` claim counted as an
  access token. Both are now refused with 401 and an audit event.
* Connector data is stored as versioned snapshots, and a query reads only
  the newest committed one. Every sync wrote a new copy of its data and
  queries read all of them, so repeated syncs multiplied each row and
  could lift a small cohort past the disclosure threshold. See ADR 0003.
* `EngineSettings` and `ZkMode` have no default. Both defaulted to ZK mode
  off, so a query service built from `Default` would have returned rows
  unfiltered. Every caller now chooses the mode explicitly.
* Audit records are written whatever `RUST_LOG` says. They shared the
  operational log filter, so `RUST_LOG=warn` silently dropped every
  `SECURITY_AUDIT_EVENT` record. The `log` bridge is no longer compiled
  in: at `debug`, DataFusion and sqlparser wrote SQL text and plan
  literals, including a researcher's `WHERE` values, to the host's logs.
  Query engine errors keep a fixed category instead of library error
  text, which could quote cell values.

### Changed

* The simulated TEE's key-release service is dev-only (ADR 0004): the
  relying party, its clients and `AttestedKeyProvider`
  (`key_release::stand_in`), and the `key-release` and `query-demo`
  binaries, are built only with the `dev` feature. A `platform-api` built
  without it refuses to start when `KEY_RELEASE_URL` is set, with an audited
  `service.start` denial, and keeps no enclave HPKE private key. The
  `Dockerfile` builds the simulated TEE images with `dev` and no longer
  carries Confidential Space launch-policy labels. CI checks that release
  builds contain neither binary and that the release `platform-api` refuses
  `KEY_RELEASE_URL`.
* `platform-api` shuts down gracefully on SIGTERM as well as Ctrl-C, so
  stopping its VM or container lets in-flight requests finish.
* `connector-worker` stops on SIGTERM or Ctrl-C. A sync already running
  finishes and commits its snapshot; jobs not yet started wait for the
  next run.
* Every cargo build, check, clippy, test and coverage command in
  `scripts/check.sh` and CI runs with `--locked`, and the weekly fuzz run
  refuses a stale `backend/fuzz/Cargo.lock`, which is brought up to date.

## [0.1.0] - 2026-09-30

### Added

* Core system, published as the base for the first production release
  (see `docs/PROJECT_SCOPE.md`):
  * Client-side encrypted drive: Web Crypto, non-extractable master keys,
    per-file data keys, AAD-bound chunks.
  * Connector pipelines: OAuth2 sync, bounded NDJSON parsing, Parquet
    output sealed to the tenant's HPKE public key, attestation gate first.
  * Encrypted columnar storage: HPKE envelopes (X25519, HKDF-SHA256,
    AES-256-GCM) with versioned framing and context binding.
  * Query engine: Apache DataFusion inside a scoped, zeroizing
    `QueryScope`; a logical-plan allowlist with a genuine-count check and
    cohort suppression, on by default; a bound on concurrent plaintext
    queries; blind-index equality search.
  * Research access: steward grants, finite query budgets, and a priced
    dataset catalog, behind the same query gate.
  * Security audit stream with tested coverage.
  * Portal components: drive, researcher portal, steward console, admin.
* Documentation: architecture, threat model, project scope, data policy,
  contribution guide, security policy, and ADR 0001 (hybrid post-quantum
  suites).
* Validation gate `scripts/check.sh`: fmt, clippy (warnings as errors),
  tests, build, and the white-label, config, data, and attribution guards.
* Continuous integration: `check.sh`, cross-platform tests (Linux x64/ARM,
  macOS), CodeQL, dependency review, `cargo-deny`, `npm audit`, coverage,
  weekly fuzzing, OpenSSF Scorecard, and release builds with signed
  provenance.
* Property-based tests for untrusted-input parsers, an adversarial SQL
  suite for the disclosure gate, and frontend worker and component tests.
* Project hygiene: code of conduct, code owners, issue and pull request
  templates, Dependabot, pinned toolchains, `.editorconfig`, and
  architecture decision records.

### Contributors

AxolDad — Jeremy L.D. Ryan. The USF core contribution team — Jake
Abendroth, William Shenker, Angelina Tam, and Gabriel Zubovsky — is credited
from its first release onward. See `CONTRIBUTORS.md`.

[Unreleased]: https://github.com/Code-Pause-Inc/QuackXide/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Code-Pause-Inc/QuackXide/releases/tag/v0.1.0
