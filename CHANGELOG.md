# Changelog

All notable changes to QuackXide are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

* Steward dataset upload (ADR 0012, P38): `PUT /api/v1/datasets/{dataset}`
  stores Parquet that the steward's browser sealed, with the snapshot
  manifest the browser also sealed, as the dataset's new snapshot
  (ADR 0003): the object, a plaintext record, then the manifest as the
  commit, then pruning of everything the new snapshot does not list,
  including an object that an earlier attempt at the same version left.
  Uploaded datasets are named in a reserved `upload_` slug namespace that
  no connector may use, and keep using the existing grant, listing and
  research query fields. The route takes the tenant from the token only,
  needs no query service, and refuses with 401, 404 (outside the upload
  namespace), 409 (a version not newer than the current one, or already
  committed), 413 (over `DATASET_MAX_MIB`, default 64, 1 to 512,
  refused at startup when out of range) and 422 (a malformed body or
  envelope frame, a version more than five minutes ahead, or a declared
  schema unlike the recorded one), each audited as `data.access`. The
  body parser (`platform_connectors::upload`) has the `upload_body` fuzz
  target. In the enclave, `QueryScope::register_parquet_declared` refuses
  data unlike its declared schema or row cap
  (`QueryError::DeclarationMismatch`, 502). `platform_crypto` gains
  `check_envelope_frame` and stable suite names (`EnvelopeSuite::id`),
  and `DevResearchStack` gains `register_key` and `with_vault`.
* Production mode (ADR 0009, P18). `APP_ENV` selects the mode: only
  `development` selects development, and unset, blank or unknown values
  are production. `APP_ENV` is read from the process environment before
  `.env`, which is loaded only in development. At startup,
  `PlatformConfig::check_production` refuses `JWT_HS256_SECRET`, an unset
  `STORAGE_BUCKET`, `TEE_ATTESTATION_REQUIRED=false`,
  `SIM_ATTESTATION_URL` and `KEY_RELEASE_URL`, and, in
  `connector-worker`, the demo tenant and fixture sources. It lists every
  reason by key name only and emits a `service.start` "denied" audit
  event. Production mode cannot boot until the production key provider,
  verification keys and durable stores land.
* `npm run build:release` (`vite build --mode release`), run by
  `release.yml`, fails unless `VITE_VAULT_MODE=http` and fails if
  `VITE_DEV_JWT` or `VITE_ADMIN_JWT` is set.
* The simulated TEE stack keeps `enclave-api`'s vault in a directory on a
  Docker volume (`ObjectStoreVault::new_local_dir`, `STORAGE_LOCAL_DIR`),
  and `scripts/test-simulated-tee.sh` checks that it holds only ciphertext.
  Only `dev` builds have this backend: a release `platform-api` refuses to
  start with `STORAGE_LOCAL_DIR` set, which CI checks. No GCS emulator
  accepts `object_store` 0.13's uploads (#153).
* `platform_enclave::token::TokenVerifier` verifies Confidential Space
  attestation tokens (ADR 0004, P47): RS256 against a key set passed in,
  with issuer, audience, validity (60 s clock-skew leeway), a required
  integer `iat` no later than now plus the leeway, an integer `exp` no
  earlier than `iat` and at most one hour after it, the expected nonces,
  and the release policy (`GCP_INTEL_TDX`, `CONFIDENTIAL_SPACE`,
  `disabled-since-boot`, `STABLE`, an allowed image digest). Tokens over 16 KiB are refused before parsing,
  and errors name a class, never token contents. A dev-only signer
  (`simulated_token`, feature `simulated`) issues tokens for tests. The
  `attestation_token` fuzz target covers parsing and the signature check;
  `attestation_claims` signs fuzzed claims to cover claim decoding and the
  release policy.
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
* Drive orphan sweep: `platform-api` deletes, every hour, the chunks of
  drive objects that have no manifest and no chunk written in the last
  24 hours (`platform_api::sweep::ORPHAN_MIN_AGE`), as an aborted upload
  leaves them. Each deletion emits a `data.access` audit event. The sweep
  claims an object with a create-only marker
  (`tenants/{tenant}/drive/sweeping/{object}`) before it deletes, and the
  manifest PUT checks for that marker and for its chunks both before and
  after it writes, so a manifest is never committed over chunks the sweep
  deleted.
  `VaultStore::list_entries` returns each object's size and last-modified
  time, `platform_storage::list_drive_entries_all_tenants` is the only
  cross-tenant listing, and `TenantPaths` can parse drive chunk and manifest
  paths back to their tenant and object.
* `PUT /api/v1/drive/objects/{id}/manifest` returns 409, audited as
  `data.access` "denied", unless every chunk the manifest names is stored
  and the orphan sweep is not deleting the object.
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
  machine: the API with the research routes on the simulated TEE
  (in-process simulated tokens, with tenant keys released by the
  key-release stand-in), seeded with a synthetic cohort, its catalog
  listing, and a token each for a steward and a researcher. It is built
  only with `platform-api`'s `dev` feature, refuses to start without
  `DEVSTACK_ALLOW_INSECURE=1` and `JWT_HS256_SECRET`, and listens only on
  loopback. The API integration tests share its wiring (`platform_api::dev`),
  and CI checks that a default-feature release build contains no `devstack`
  binary. From `backend/`,
  `DEVSTACK_ALLOW_INSECURE=1 cargo run -p platform-api --features dev --bin devstack`
  starts it.
* The steward portal lists approvals that did not finish, under
  "Unfinished approvals": those with no grant, or with an active grant
  but no query budget. A "Retry approval" action approves the request
  again, and a refused retry shows its error. Approvals whose grant is
  revoked are not listed, since the API refuses to retry them.

### Fixed

* GCS emulator writes (`STORAGE_EMULATOR_HOST`) no longer ask the GCE
  metadata server for a credential: `object_store` 0.13 skips signing on
  reads only, so the emulator client now carries a placeholder credential.
* A drive delete that fails partway can be retried: `DELETE
  /api/v1/drive/objects/{id}` now deletes the chunks before the manifest,
  so after a failure the object is still found and the retry removes the
  rest. Before, the manifest went first, the retry got 404 and the chunks
  were stranded.
* An access-request approval that fails partway can be retried: `POST
  /api/v1/research/requests/{id}/approve` on a request that is already
  approved re-runs the idempotent grant and budget steps for its steward
  and returns 200. Before, the request was marked approved first, so when
  the grant or budget step then failed (502) the retry got 404 and the
  request stayed approved with no grant. A deny after a failed approval
  is refused, so no grant is ever minted for a pending or denied request.
  The approval records its query budget (the steward's `query_budget`,
  else the listing's included budget) as the request's `approved_budget`,
  and a retry opens that budget: a retry that names a different
  `query_budget` is refused with 400.
  A retry never re-activates a revoked grant: it is refused with 404, so
  a re-sent approval (a frontend retry, a double-click or a stale tab)
  cannot restore access after a revoke, even one that lands while the
  retry is running; an explicit re-grant or a new request can. The retry
  checks for a revoke and creates the grant in one atomic step, the new
  `GrantRegistry::create_unless_revoked`, which a persistent backend must
  implement as a conditional insert or a transaction. Audit records tell
  a retry from a first approval (`retry=true` in the `research.catalog`
  detail), and a refused retry or a refused deny of an approved request
  is recorded as `denied`.
* A paused tenant comes back when its subscription resumes: the MoR
  webhook maps `subscription.resumed` to reactivation. Before, it was
  ignored and the tenant stayed Suspended. A cancel is final (ADR 0006):
  the tenant becomes Canceled whatever the cancel's `occurred_at`, and no
  later pause or resume changes it. Paddle does not deliver in order, so
  pauses and resumes apply only when their `occurred_at` is newer than the
  last change applied (a tie keeps Suspended), and a late or retried event
  cannot undo a newer one. Provisioning events never change an existing
  tenant's status. Events without a valid RFC 3339 `occurred_at` are
  refused with 400. Each status event is audited as `tenant.provisioned`:
  `ok` when applied, `denied` with `reason=stale` or `reason=canceled`
  when skipped, and `miss` for an unknown subscription.

### Security

* `docs/THREAT_MODEL.md` and `docs/ARCHITECTURE.md` state that ZK mode on
  own-data queries (`POST /api/v1/query`) stops single-query row export
  only. That route has no query budget, so differencing across queries is
  unbounded, including with a stolen access token; only research queries
  are budget-bounded. This is recorded as a residual risk.
* Zero-knowledge and research queries whose expressions can fail at
  runtime are refused at planning (ADR 0011). A conditional division by
  zero or a failing cast used to return 400 for some data and 200 for
  other data, answering a question about rows below the cohort threshold.
  Researchers lose division and modulo by a column or an aggregate,
  string-to-number casts, `LIKE` patterns over 1,000 characters, and
  functions other than `COALESCE`, `NULLIF`, `lower` and `upper`;
  `SUM(x) / COUNT(*)` and `SUBSTR(...)` are now refused. `AVG` and integer
  division by a constant other than 0 and −1 still work. Unary minus works
  on floats only; write `0 - x` for integers.
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

* Every dataset snapshot, a connector sync's included, writes a plaintext
  record (`platform_storage::SnapshotRecord`: its suite, and for an upload
  the declared row cap and schema) before its manifest, writes the
  manifest create-only, so a version commits once, and pruning deletes
  superseded records. A query refuses a snapshot without a valid record
  (one naming a suite this build reads), and a manifest that lists a
  missing object, with 502 (a missing object was a 404). Publishing a
  catalog listing for a dataset the steward does not hold, one without a
  committed snapshot, is refused with 404 and a `research.catalog`
  denial. For this check `ResearchService::new` and `from_config` take
  the vault the app serves.
* ADR 0007's "Browser private-key storage" section is accepted, and ADR
  0004 now says the researcher's result key is held as that section
  describes instead of "non-extractable": a private key that HPKE opens
  with is stored encrypted under a non-extractable AES-256-GCM key.
* `GCP_PROJECT_ID` is removed: nothing read it. The GCS client takes its
  bucket from `STORAGE_BUCKET` and its credentials from `object_store`'s
  `GOOGLE_*` environment variables or the metadata server.
* `docs/PROJECT_SCOPE.md` lists what is not in v1.0: live connector sync,
  the admin connector toggles, charging catalog prices, blind-index search
  and closing differencing. The merchant-of-record webhook and its tenant
  status handling stay. Releases no longer ship `connector-worker`; it is a
  development tool.
* Local runs of `platform-api` and `connector-worker` need
  `APP_ENV=development`, and `devtoken` needs `--features dev`.
  `scripts/check.sh` also lints the release binaries without the `dev`
  feature.
* Research access runs in the `platform-api` binary without key release.
  The catalog, access-request, grant and budget routes use a
  `ResearchService` (`AppState::research`) instead of the confidential
  query service, so they no longer answer 503 when `KEY_RELEASE_URL` is
  unset. The binary always builds it from `RESEARCH_MIN_COHORT_SIZE` and
  `RESEARCH_DEFAULT_QUERY_BUDGET` over in-memory stores, with a startup
  warning that they are lost on restart. The query, research-query and
  attestation routes still answer 503 without key release, and a research
  query checks and charges grants through the same `ResearchService`.
  Without one, the research routes answer 503 "research access not
  configured". `platform_api::wiring::build_state` builds the binary's
  state, so tests can run its exact wiring. `ConnectorQueryService::with_research`
  takes an `Arc<ResearchService>`, and `DevResearchStack::query_service`
  and `query_service_with_attestation` take one in place of the cohort
  size and default budget.
* The SEV-SNP simulation is retired: `SimulatedSnp`, the SEV-SNP report
  parser and P-384 chain verifier (`report`, `verifier`, `TrustRoot`), the
  `snp_report` fuzz target and the `SIMULATED_SNP_*` settings are removed,
  and `AttestationEvidence` drops `report` and `cert_chain`. The simulated
  TEE uses Confidential Space tokens only. `SnpAttestation`, which always
  refuses, and `TeePlatform::SevSnp` stay until P48. `decode_hex_array`
  moves to the crate root.
* The simulated TEE issues Confidential Space-shaped attestation tokens
  instead of SEV-SNP reports (ADR 0004). A dev-only `sim-attestation`
  service plays Google's part (`POST /v1/token`, `GET /jwks`); the enclave's
  `SimulatedTokenProvider` and the key-release stand-in check tokens with the
  production `TokenVerifier` and release policy, refetching the key set (at
  most every 5 s) on an unknown key id. `KeyReleaseRequest` and
  `GET /api/v1/attestation` carry a `token` instead of `report_b64` and
  `cert_chain_b64`, and `PUT /v1/keys` returns the enrolled public key.
  The stand-in answers a refused release with 403 and an unreachable key
  set with 503; the enclave's query endpoints answer 503 in both cases. The
  simulator compiles only with `platform-enclave`'s `simulated` feature
  (enabled by `platform-api`'s `dev`, or `platform-connectors`'
  `simulated`): a build without it refuses every attestation when
  `TEE_ATTESTATION_REQUIRED=false`, so does a dev build whose
  `sim-attestation` is unreachable, and the connector pipeline now refuses
  a rejected attestation in dev mode instead of syncing unattested. A local
  `connector-worker` therefore needs `--features simulated`,
  `SIM_ATTESTATION_URL` and a running `sim-attestation` (README). CI checks
  that release builds do not enable the simulator and that a release
  `connector-worker` refuses unattested syncs. `scripts/test-simulated-tee.sh`
  passes again: its stack drops `fake-gcs` (version 1.49.3 refuses the
  uploads `object_store` 0.13 sends) and keeps snapshots in the in-memory
  vault, and checks a debug image, an unlisted image digest and non-TDX
  hardware. README no longer claims query responses carry an
  `enclave_signature`; none is produced.
* GCS emulator writes (`STORAGE_EMULATOR_HOST`) no longer ask the GCE
  metadata server for a credential: `object_store` 0.13 skips signing on
  reads only, so the emulator client now carries a placeholder credential.
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
