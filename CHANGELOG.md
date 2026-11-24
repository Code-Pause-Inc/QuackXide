# Changelog

All notable changes to QuackXide are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

* Data dictionary on published listings (P59): a catalog listing carries
  `data_dictionary`, the dataset's SQL table name and the columns its
  steward describes (name, type family and an optional description), so a
  researcher can write a query without spending budget to learn the
  schema. The API derives the table name from the slug, double-quoted
  where SQL needs it (`health`, `"2026-cohorts"`), and
  `POST /api/v1/catalog` takes the columns in `data_dictionary.columns`,
  bounded like the listing's other text: at most 512 columns, names of 1
  to 128 bytes with no control characters and none twice, and
  descriptions of at most 500 characters, refused with 400 over a bound
  and 422 when not a dictionary's shape. A re-publish replaces the
  columns. `GET /api/v1/connectors` lists the built-in connectors with the
  columns each one's mapper writes, which the publish form pre-fills a
  connector dataset's dictionary from; an upload's columns are entered by
  hand. The portal shows the dictionary on every catalog listing and each
  authorized dataset, with a `SELECT COUNT(*) AS n` example over the table
  name to copy. The catalog is still in memory, so listings and their
  dictionaries are lost on restart (P62).
* Browser envelope seal benchmark (P34 checkpoint A, #171).
  `scripts/bench-wasm-seal.sh` seals synthetic Parquet from `synth-data`
  at about 1 MiB, 100 MiB and 1 GiB with the wasm module in a Chromium
  worker and reports seal time, the module's peak memory, module load time
  and bundle size. The `bench` workflow's `wasm-seal` job runs it and
  reports only. `docs/BENCHMARKS.md` records the baseline (about 50 MiB/s,
  a module peak of three times the payload, 31.8 KiB brotli-compressed)
  and the largest payload one seal can take (about 1.33 GiB).
* The base for sealed research queries and results (ADR 0010; part of P85
  and P55). `platform-crypto` signs results with Ed25519 and ML-DSA-65
  together (`ResultSigningKey`, `ResultVerifyingKeys`; both signatures must
  verify) and gains the `research_query` `info` string and the query
  binding that `research_result` takes, pinned in `fixtures/envelope/hpk1.json`
  and exposed by the wasm module. `platform-enclave`'s binding v2
  (`EnclaveKeyBinding`) replaces the fixed 32-byte fields of
  `ReportDataBinding` with labelled, length-prefixed values. The enclave's
  key set (`EnclaveIdentity`) is an `HPK2` request key, whose private half
  now exists in every build, and a result-signing key, with a `key_id`.
  `GET /api/v1/attestation` takes the caller's nonce as `?nonce=` (32
  bytes, base64url; 400 when missing or malformed, instead of a nonce the
  server chose) and returns ADR 0010's evidence bundle, and the key-release
  stand-in checks binding v2 and refuses a request key that is not `HPK2`
  (audited as `crypto.suite_refused`). A key-release request carries every
  bound value, the KMS public key included, with its byte fields in
  base64url as ADR 0010 sets out. The sealed-query wire types are
  defined, with result signatures (`SignatureWire`) a type apart from the
  signing keys; nothing routes to them yet. The public evidence token carries
  the audience `urn:platform:browser-attestation`, which key release
  refuses, so a caller who fetches it cannot open key release.
  ADR 0005 and ADR 0010 are accepted.
* Research queries sealed to the enclave (ADR 0010; part of P85).
  `POST /api/v1/research/query` takes `{version, key_id, grant_id,
  envelope}`, the query sealed to the request key from the attestation
  bundle under `research_query`. The enclave refuses a key set it no longer
  holds (409 `reattest`), a frame that does not open or a malformed sealed
  query (400), and a grant other than the one `grant_id` names (403), none
  of them charged and each audited as an `auth.decision` denial. A replay
  store, per key set, records each request nonce just before the charge:
  the same envelope again gets the stored response, uncharged, for an hour;
  another envelope under the nonce, a retry while the query runs and an
  expired response are 409 `nonce_used`, `query_running` and
  `response_expired`. Only `nonce_used` is an `auth.decision` denial; the
  other two are `research.replay` "retry", and a stored response sent
  again is `research.replay` "replayed", never a metered `engine.query`. A refused charge
  records nothing. A sealed query runs
  in a task of its own, so a client that disconnects does not cancel it.
  The plaintext body `{steward_tenant, connector, sql}` is compiled only
  into development builds and refuses unknown fields. `TokenVerifier`
  requires a token's nonces exactly and in order.
* `scripts/test-simulated-tee.sh` uploads the steward's dataset instead of
  seeding it at startup. The dev-only `seal-upload` binary, run on demand
  as its own image with no network, plays the steward's browser: it seals
  a synthetic cohort and its manifest to the steward's public key
  (ADR 0012) and writes the upload body, which the script sends through
  `PUT /api/v1/datasets/{dataset}` before it publishes the dataset and
  runs the research lifecycle on it. The script also checks that an upload
  is refused without a token (401), outside the upload namespace (404) and
  at a stale version (409), that an approval retry after a revoke is
  refused (404), and, after the upload and again after the queries, that
  the vault holds exactly the upload's object and manifest as `HPK2`
  envelopes and its record, whose row cap and schema are the ones the
  steward declared. The compose stack no longer passes `DEMO_TENANT_*` to
  `enclave-api`. The API tests seal uploads with the same code
  (`platform_api::dev::seal_upload`), and CI checks that release builds
  cannot contain `seal-upload`.
* Steward dataset listing (P39): `GET /api/v1/datasets` lists every
  research dataset the caller's tenant holds, connectors' and uploads'
  alike: exactly those it may publish, decided by the same function as
  `platform_connectors::snapshot::holds`. Each entry gives the dataset id,
  the current snapshot's version and write time, the ids, count and total
  ciphertext bytes of the objects stored at that version, and the suite
  its plaintext record names, all read without opening anything;
  superseded snapshots and uploads that have not committed are not
  counted, and a snapshot that an upload or sync replaces during the
  listing is described as the new one. The tenant comes from the token
  only. The route needs no query service, refuses more than
  `MAX_LISTED_OBJECTS` (1000) datasets, or objects across them, with 422,
  and answers a storage failure with 503 or 502, never an empty list; each
  listing is audited as `data.access`. `platform_connectors::snapshot`
  gains `held_datasets`, `held_dataset` and `recorded_suite`, and
  `TenantPaths` gains `connectors_root` and `connector_of`.
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
  namespace), 409 (a version not newer than the current one, already
  committed, or recorded with another row cap, schema or suite), 413
  (over `DATASET_MAX_MIB`, default 64, 1 to 512, refused at startup when
  out of range) and 422 (a malformed body or envelope frame, a version
  more than five minutes ahead, or a declared schema unlike the recorded
  one), each audited as `data.access`. The
  body parser (`platform_connectors::upload`) has the `upload_body` fuzz
  target. In the enclave, `QueryScope::register_parquet_declared` refuses
  data unlike its declared schema or row cap
  (`QueryError::DeclarationMismatch`, 502). `platform_crypto` gains
  `check_envelope_frame` and stable suite names (`EnvelopeSuite::id`),
  and `DevResearchStack` gains `register_key` and `with_vault`.
* Browser timings (P73, #185). `npm run bench:browser`, a Vitest bench,
  times `encryptPayload` at 4 KiB and 4 MiB and the wasm envelope module's
  cold start (load plus first seal) in Chromium, Firefox and WebKit. It
  reports p50 and p99 over batch means (each sample a batch of at least
  50 ms); the cold start is one sample. The `browser` workflow writes them,
  the runner's CPU and the module's size to each run's job summary, report
  only.
* Browser tests (#223 stage A). A vitest `browser` project runs the module
  crypto worker, Web Crypto keys, the sealed HPKE device key, IndexedDB
  persistence across a worker restart and a drive round trip in real
  browsers (`npm run test:browser`, Playwright); `npm test` is unchanged.
  The `browser` workflow runs Chromium on every pull request and Chromium,
  Firefox and WebKit on `main` and nightly.
* Engine query benchmarks and a regression check (P73, #185). Criterion
  times two research-style queries in `quackxide-engine` over `synth-data`
  tables of 10 000 to 1 000 000 rows. On pull requests the `bench` workflow
  benchmarks the base commit and the head in one job, and
  `scripts/bench-compare.sh` flags a benchmark whose whole 95 % interval is
  more than 10 % slower as a warning in the job summary; the job fails only
  when the comparison cannot run. `docs/BENCHMARKS.md` records the targets
  for the hybrid suite and the engine.
* Benchmarks (P73, #185). A criterion harness in `platform-crypto` times
  key generation and envelope seal and open for `HPK1` and `HPK2` at 32 B,
  4 KiB and 4 MiB, and a unit test pins each suite's envelope overhead
  (52 and 1140 bytes). `cargo test` runs each benchmark once, so
  `scripts/check.sh` fails on a broken one. The `bench` workflow runs them
  on pull requests that touch `backend/` or `rust-toolchain.toml` and
  reports only. `docs/BENCHMARKS.md` records the method and both suites'
  numbers from one run.
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
  and `scripts/test-simulated-tee.sh` checks that it holds only ciphertext,
  besides each snapshot's plaintext record, which names only its suite.
  Only `dev` builds have this backend: a release `platform-api` refuses to
  start with `STORAGE_LOCAL_DIR` set, which CI checks. No GCS emulator
  accepts `object_store` 0.13's uploads (#153).
* Browser envelope open (P34 checkpoint B): `envelope-wasm` exports
  `openEnvelope` and `publicKeyFromPrivateKey`, over the new
  `platform_crypto::hpk1_open_with_private_key` and
  `hpk1_public_key_from_private` (`HPK1` only until P36). The crypto
  worker holds the device's HPKE private key as ADR 0007 describes: 32
  random bytes, stored only encrypted under a non-extractable AES-256-GCM
  seed key with AAD
  `x25519-key-v1|{tenant}|{SHA-256 of the public key}`, decrypted just
  before an open and zeroed after (`lib/crypto/devicekey.ts`). The Web
  Crypto X25519 key, which could not open anything, is gone; device
  records that hold one get a new key on the next init. `InitResult`'s
  `x25519Supported` is now `hpkeKeyAvailable`. `fixtures/envelope/hpk1.json`
  carries each recipient's test-only private key, and the browser tests
  open every Rust-sealed vector.
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
  secret scan over every diff in the history being merged (`.gitleaks.toml`,
  `scripts/secret-scan.sh`); `scripts/check.sh` runs a similar scan of the
  branch when gitleaks is installed.
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
* ADR 0007 (Accepted): the hybrid suite construction (HPKE with X-Wing,
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

* `README.md` and `docs/ARCHITECTURE.md` no longer describe live
  connector sync or blind-index search as v1.0 capabilities; both say they
  are not in v1.0 (`docs/PROJECT_SCOPE.md`).
* A query's table is the dataset's exact slug. The engine registered it by
  parsing the slug as SQL, which cut a slug containing `--` short at the
  comment marker, so `a--b` was queried as `a`.
* `POST /api/v1/grants` no longer drops its `query_budget` when the grant
  exists. An active grant that already has a budget is refused with 409
  and audited; the body says to raise the budget with
  `POST /api/v1/grants/{grant_id}/budget`. A revoked grant is re-activated
  first, audited as `reactivated` at once (by a re-grant or an approval),
  and keeps its budget: the re-grant's `query_budget` is added on top, and
  nothing when it is omitted. If that funding fails, the grant stays
  active with its old budget; a retry is refused if the grant had a budget
  and funds it otherwise, so nothing is added twice or dropped. Every
  top-up that raises the limit on a grant path (a re-grant or a follow-up
  approval) emits `research.budget`. A grant with no budget entry (a
  failed approval) is funded by the next direct grant. `BudgetLedger::top_up_once` now
  creates a missing entry in the same step, so a failed approval leaves no
  placeholder. Direct grants, approvals (from recording the decision),
  top-ups and revokes are serialized, so two at once cannot drop a budget
  and a revoke cannot land mid-grant (#235).
* A follow-up access request's approval adds its query budget to the
  existing grant instead of being dropped, and a retry of the same
  approval adds nothing (`BudgetLedger::top_up_once`). A retry of an
  approval whose grant was revoked and re-granted since is refused, so it
  cannot add to the newer grant. A pending request for an unpublished
  listing can no longer be approved (#96).
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
* Enrollment audits every refused key as `crypto.key_enrollment` denied: a
  key of a suite the deployment refuses (also `crypto.suite_refused`) and a
  key that is not valid base64, which emitted nothing.
* `DevResearchStack::query_service` panics on a stack holding an `HPK1`
  key, since key release is `HPK2`-only and every query would fail after
  charging its budget; `query_service_with_attestation` still takes both.

### Security

* The secret scan also reads every commit message in the history it scans
  (`gitleaks stdin`), since a squash merge copies them onto main, and
  `.github/workflows/secret-scan.yml` runs it on every push to every
  branch, never cancelled, under that branch's own `.gitleaks.toml`. A
  branch with no pull request, the intermediate commits of a branch
  squash-merged over a red scan, and a key force-pushed away before its
  run finished are now scanned. The self-test covers a key that is only
  in a commit message.
* `parquet` 59.3.3 (RUSTSEC-2026-0595: bloom filters were written in
  plaintext in encrypted Parquet files), in `backend/Cargo.lock` and
  `backend/fuzz/Cargo.lock`. The backend writes no encrypted Parquet.
* A query decodes only the columns it reads, and nothing before its plan
  passes every gate (P53). `QueryScope` registers a table by reading only
  the Parquet footers, parsed without their column statistics, from its
  own zeroizing copy of each object, and the query service then zeroizes
  its copies. Each table scan decodes, from every object, only the columns
  the query reads, so a query that the plan gate, the count-column check,
  the runtime-failure check or the statement check refuses decodes
  nothing. Registration still refuses footers that report more rows than
  `QUERY_MAX_DECODED_ROWS`. Before a scan decodes, the rows and the
  uncompressed bytes the footers report for its columns, summed over the
  query's scans, must fit `QUERY_MAX_DECODED_ROWS` and
  `QUERY_MAX_DECODED_MIB`, where the whole table's footers had to fit
  before, and the Arrow memory the scans decode to, summed over them, is
  counted against `QUERY_MAX_DECODED_MIB` as each batch decodes. A
  refusal that registration gave for decoded bytes now comes from the
  query that reads the columns. Objects of one snapshot whose columns
  differ answer 502 instead of 400, and a stored object that fails to
  decode, now during a scan, still answers 502. Decryption is still
  whole-object.
* Zero-knowledge and research queries release a `SUM` or `AVG` as null
  when one or two rows dominate it: when the group's absolute values,
  less the two largest, total under *p*% of the largest, so that anyone
  who knows the second-largest would learn the largest to within *p*%
  (the p% rule, ADR 0015, proposed; P58). The mask is applied inside the
  plan, directly above the aggregate, so `HAVING`, `ORDER BY` and derived
  columns read the masked value, and the hidden aggregates it uses never
  reach the result. The row keeps `n` and its other cells, and
  `suppressed_rows` still counts only rows below *k*. *p* is
  `RESEARCH_DOMINANCE_PERCENT`: 10 when unset; a value that is not a whole
  number refuses startup, and 0 refuses every zero-knowledge and research
  query. A sum over fewer than three non-null values is masked unless
  they are all zero. `SUM` and `AVG` with `DISTINCT`, or over an
  interval, are refused.
* `MIN` and `MAX` are refused in zero-knowledge and research queries,
  wherever they appear, `HAVING` and `ORDER BY` included (ADR 0015,
  proposed; P57). Each returns one row's value however large the cohort:
  one query gave the highest salary in a dataset, filtering below it gave
  the next, and an id range said whose it was. Ranges come from counts
  over bands (`salary / 1000 AS band`) and the centre from `AVG`;
  ungated queries keep `MIN` and `MAX`. ADR 0015 also decides the p% rule
  that P58 applies to `SUM` and `AVG`.
* `url` 2.5.9 (RUSTSEC-2026-0592: `Url::origin()` overflowed the stack on
  nested `blob:` URLs), in `backend/Cargo.lock` and
  `backend/fuzz/Cargo.lock`. No backend code calls `Url::origin()`.
* The admin connector toggle route,
  `POST /admin/tenants/{tenant_id}/connectors/{slug}`, answers 503
  (`connector_toggles_disabled`) unless `FEATURE_ADMIN_CONNECTOR_TOGGLES`
  is `true`, which defaults to false: the toggles are not in v1.0 and
  nothing reads them (`docs/PROJECT_SCOPE.md`).
* Code-owner review covers the query engine's source, the API's source,
  grants and budgets (`platform-tenancy`), the audit-coverage and bypass
  tests, `docs/THREAT_MODEL.md` and `docs/adr/`. `scripts/check.sh` fails
  when a `CODEOWNERS` pattern matches no tracked path.
  `CONTRIBUTING.md` describes the review stages, Dependabot handling, and
  how a vulnerability is fixed privately in a security advisory's fork.
* `jsonwebtoken` 12, on `elliptic-curve` 0.14, removes `crypto-bigint`
  0.5, so `backend/deny.toml` no longer ignores RUSTSEC-2026-0387.
  `jsonwebtoken` 12 refuses an empty HMAC secret: minting with one fails,
  and `JwtVerifier::hs256` built from one rejects every token.
* The decoded-size limit (`QUERY_MAX_DECODED_MIB`) also counts the Arrow
  memory of each batch as it decodes, not only the sizes Parquet footers
  report, which understate dictionary- and run-length-encoded columns: a
  small upload whose strings decode a thousandfold is now refused (422)
  instead of decoding past the limit. String and binary columns decode as
  view arrays and are measured before they expand, so a value the file's
  dictionary repeats is refused before it is copied once per row; a
  column the file declares as a dictionary is rebuilt as one, and
  fixed-width columns are checked from their widths before each batch. A
  dataset whose decoded columns take more memory than its footers state
  can now be refused where it was accepted before.
* `backend/deny.toml` records why RUSTSEC-2026-0542, -0543 and -0555
  (`humantime`, `chrono` and `chrono-tz` declared unmaintained, with no
  fixed release) do not fail the dependency audit: they report
  maintenance, not a vulnerability, and arrow, DataFusion 55 and
  object_store 0.13 depend on these crates until they move off `chrono`.
* Per-query resource limits (ADR 0013, proposed; P52;
  `platform_core::QueryLimits`, read by `platform-config`; each bounded,
  and an invalid value refuses startup).
  A query's scope runs in a fixed memory pool (`QUERY_MEMORY_MIB`) with
  DataFusion's disk manager disabled, so a sort or aggregation that runs
  out of memory fails instead of spilling decrypted rows to disk. A query
  waits at most `QUERY_SLOT_WAIT_SECS` for a plaintext slot (503 with
  `Retry-After`, distinct from the unwired 503) and holds plaintext within
  `QUERY_TIMEOUT_SECS` (503). Before any key is released, the snapshot's
  stored objects must fit `QUERY_MAX_INPUT_OBJECTS` and `DATASET_MAX_MIB`,
  checked again while decrypting, and a manifest over 16 KiB fails closed
  (502). Every Parquet footer must fit `QUERY_MAX_DECODED_ROWS` and
  `QUERY_MAX_DECODED_MIB` before anything is decoded, and a result over
  `QUERY_MAX_RESULT_ROWS` or `QUERY_MAX_RESULT_MIB` is refused, never
  truncated; without a disclosure policy the result streams and the query
  stops at the first row over the limit. Every operator yields to the
  runtime as it produces a batch, so the time limit stops a running plan
  and the tasks running its partitions. Startup is refused when
  `QUERY_MAX_CONCURRENT` times one query's worst case (its pool, decoded
  table, three copies of its input and two of its result) exceeds
  `QUERY_TOTAL_MEMORY_MIB` (default 8192). Size limits answer 422 and
  memory exhaustion is no longer reported as the caller's SQL error
  (400). Each refusal is an
  `engine.query` "denied" event naming the limit. A research query is
  charged before all of them, so each costs a unit (P54 decides the
  order). The slot is released and the decrypted blobs zeroized on every
  way out, including the time limit, cancellation and a panic.
  `EngineSettings` gains `limits`, and `wiring::engine_settings` builds
  the settings from configuration.
* A gated query (ZK own-data or research) that runs out of its memory pool
  or its time limit gets exactly the response of a disclosure-control
  refusal: 422, "query rejected by disclosure control (see cohort-size
  rules)", with the same headers, as `ApiError::GatedQueryLimit`. Both
  limits can trip on rows that suppression withholds. Before this change,
  their own 422 and 503 told a researcher which limit a withheld cohort
  tripped (ADR 0013). The `engine.query` "denied" event still names the
  limit, the operator-only metrics keep `query_limit` and
  `query_timed_out`, and the other limits, and ungated queries, keep their
  responses. Whether a query was refused, and how long the refusal took,
  are still visible and recorded as a residual risk in
  `docs/THREAT_MODEL.md`.
* The secret scan reads every file's content whatever git attributes say:
  `--text --no-textconv` stop `-diff`, `binary`, a textconv driver,
  `.git/info/attributes`, a user's attributes file or a NUL byte from
  hiding a credential, so the scan no longer needs git 2.41
  (`GIT_ATTR_SOURCE`). Its selftest no longer reinitialises the repository
  named by an exported `GIT_DIR`, as a git hook or `git rebase -x` sets.
* A revoke, top-up or budget read of a grant that is unknown or not the
  caller's is audited as `denied`: `tenant.provisioned` for a revoke and
  `research.budget` for the others, with the caller's tenant and the grant
  id (`grant=malformed` when the path segment is not an id). The 404 is
  unchanged and the same in both cases. Grant events stay under
  `tenant.provisioned` (`docs/ARCHITECTURE.md`), and `audit_coverage.rs`
  now covers grants and budgets.
* X25519 private keys and Diffie-Hellman results are zeroized on drop.
  `hpke` holds them in `x25519-dalek` types, which wipe themselves only
  with that crate's `zeroize` feature, and nothing turned it on, so every
  `TenantKeypair` (the key-release stand-in's per-query sessions, the dev
  key providers, `EnclaveIdentity`'s HPKE key) and each envelope's
  ephemeral key, in the enclave and in the browser's envelope module, was
  freed without being wiped. `hpke` 0.14 turns the feature on itself, a
  test checks it for both suites' key types, and `TenantKeypair`
  implements `ZeroizeOnDrop`.
* Tenant envelopes use the hybrid post-quantum suite `HPK2` (ADR 0007, P35,
  #187): HPKE with X-Wing (X25519 + ML-KEM-768), HKDF-SHA256 and
  AES-256-GCM, frame `HPK2 || enc (1120) || ciphertext`, on `hpke` 0.14.1.
  Enrollment and snapshot records name the key's suite, and the upload
  route refuses a frame of a suite the deployment does not accept (`HPK1`
  in production), other than the enrolled key's, or, with no enrolled key,
  other than the current snapshot's with 422, each with a
  `crypto.suite_refused` event; a development `HPK1` upload opens only
  under the test key providers, since development key release is
  `HPK2`-only. Production therefore refuses the browser's `HPK1`
  enrollments and uploads until P36 (#186). Every key loader takes a suite
  policy from `APP_ENV`: production refuses `HPK1` frames and X25519 keys
  with a `crypto.suite_refused` audit event; development still accepts
  them until the browser moves to `HPK2` (P36). Private keys are exported
  as `magic || key`; the key-release stand-in holds only `HPK2` tenant
  keys, whether enrolled over HTTP or inserted directly, and the enclave
  accepts only `HPK2` released keys. A query refuses a snapshot whose
  record names another suite than the tenant's key before any key is
  released or budget charged, and opens its envelopes under the record's
  suite.
  X-Wing known-answer tests against `@noble/post-quantum` and frames sealed
  by `hpke-js` pin interoperability. ADR 0007 is accepted.
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

* The benchmark targets and regression threshold in `docs/BENCHMARKS.md`,
  backend and browser, are agreed (no longer proposed).
* `docs/DATA_POLICY.md` says test sign-in users are synthetic `.example`
  identities with email verification off, and `docs/DEVELOPMENT.md` names
  the development-only store for shared values.
* Every dataset snapshot, a connector sync's included, writes a plaintext
  record (`platform_storage::SnapshotRecord`: its suite, and for an upload
  the declared row cap and schema) before its manifest, writes both
  create-only, so a version keeps its first record and commits once, and
  pruning deletes superseded records. A query refuses a snapshot without
  a valid record (one naming a suite this build reads), and a manifest
  that lists a missing object, with 502 (a missing object was a 404).
  Publishing a catalog listing for a dataset the steward does not hold,
  one without a committed snapshot, is refused with 404 and a
  `research.catalog` denial. For this check `ResearchService::new` and
  `from_config` take the vault the app serves.
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
