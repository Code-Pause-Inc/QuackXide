# QuackXide — Architecture

Trust boundaries first, then dataflows, then the enforcement mechanisms that
make the boundaries real. Everything asserted here about the current system
is asserted by a test; release targets are labeled as targets.

## The invariant

**No naked data.** There is no normal application path by which an analytics
user retrieves an unrestricted plaintext dataset. Data enters encrypted or is
encrypted before persistence; it rests encrypted; it is processed inside a
protected execution boundary; and it leaves only as authorized analytical
results that have passed disclosure controls. Export endpoints, table dumps,
and row-level egress for ordinary users are intentionally absent.

## Trust model in one paragraph

The platform is designed so that **the operator is outside the trust boundary
for customer data**. Drive content is encrypted with browser-held keys the
server never sees. Connector data is plaintext only inside hardware-attested
TEE memory, and is re-encrypted to the tenant's public key before it touches
any persistent medium. Analytics run inside the same enclave boundary over
encrypted Parquet, using blind indexes so equality search never reveals
values. Compromise of the object store, of the API host's disk, or of an
operator credential yields ciphertext only.

## Dataflows

### 1. Drive (zero-knowledge storage)

```
Browser UI thread          Crypto worker (isolated)              API (Axum)          Object store
─────────────────          ────────────────────────              ──────────          ────────────
drag & drop (inert UI) ──▶ KEK: non-extractable AES-256-GCM
                           per-file DEK, wrapped under KEK
                           chunk AES-GCM + AAD binding  ──TLS──▶ authn (JWT)
                           manifest (filename/meta) encrypted    tenant boundary check ─▶ tenants/{t}/drive/{obj}
◀── Blob (download) ◀───── decrypt in worker memory ◀────────────────────────────────────┘
```

Client key architecture:

* **KEK (master key)** — AES-256-GCM, generated `extractable: false`, usages
  wrap/unwrap only. Persisted as an opaque handle in IndexedDB; no code path
  can export it (JS *or* WASM — the browser's crypto engine holds the bytes,
  which is why WebCrypto custody beats an in-page WASM implementation).
* **DEK (per-file key)** — random per file; extractable only in the instant
  before being wrapped under the KEK; every unwrapped copy is created
  non-extractable.
* **Worker isolation** — all key handling, encryption, and vault I/O run in a
  dedicated Web Worker (`lib/crypto/worker.ts`). The DOM/UI thread exchanges
  only opaque ids, decrypted summaries it asked for, and download Blobs.
* **AAD discipline** — every AES-GCM operation binds
  `tenant|object|role(|chunk-index)`, so a vault cannot reorder chunks,
  splice records across objects, or re-attach wrapped keys undetected.
* **Crypto-agility seam** — the crypto core sits behind `lib/crypto/core.ts`
  + the worker protocol; a Rust→wasm32 build of the backend's own `hpke`
  crate slots in there without touching UI code.
* **Vault backends** — the worker picks by `VITE_VAULT_MODE`: `LocalVault`
  (IndexedDB, offline) or `HttpVault` (drive API), both behind the same
  ciphertext-only `VaultClient` interface. Server side, one
  `ObjectStoreVault` covers GCS (production) and in-memory (dev/tests).
* **JWT tenant boundary** — tenant identity enters the API only as the
  verified `tid` claim; handlers never read a tenant from paths or bodies.
  No secret configured ⇒ authenticated routes refuse with 503 (fail closed).
  Integration tests verify that cross-tenant reads, lists, and deletes are
  refused.

The server knows tenant id, object id, ciphertext length, and timestamps;
it does not know filenames, content, or keys.

### 2. Connectors (confidential ingress)

```
External APIs      TEE enclave (SEV-SNP, attested)                Object store
─────────────      ─────────────────────────────────              ────────────
OAuth2 ──────────▶ fetch → normalize → Arrow/Parquet (RAM only)
                   HPKE seal to tenant public key ───────────────▶ tenants/{t}/connectors/{slug}/snapshots/{v}/{obj}.parquet
                   zeroize plaintext buffers
                   seal manifest, written last ──────────────────▶ tenants/{t}/connectors/{slug}/manifests/{v}.manifest
```

`platform-connectors`:

* **Attestation gate first.** Every sync starts at
  `EnclavePipeline::attestation_gate`. With `TEE_ATTESTATION_REQUIRED=true`,
  only genuine SEV-SNP evidence passes — development evidence or attestation
  failure refuses the sync (tested). The SNP provider currently probes the
  guest device and still refuses pending report-verification work: fail
  closed until proven attested.
* **Zero-MFA sync**: RFC 6749 refresh-token grant for user-enrolled sources
  (consent + MFA happen once at enrollment); RFC 6749 §4.4
  client-credentials for machine-to-machine sources. Secrets live in
  zeroizing, Debug-redacted containers, and token-endpoint error bodies are
  never echoed (error pages can contain credentials).
* **RAM-only plaintext**: payload → typed `Dataset` (validated at the row
  boundary — arity and column types) → Parquet in a zeroize-on-drop buffer →
  HPKE envelope → vault. The plaintext buffer is zeroized the instant its
  ciphertext exists.
* **Bounded untrusted input**: NDJSON payloads parse under explicit limits
  (lines, line bytes, total bytes) checked before allocation, and a
  malformed line fails the whole batch rather than being skipped — a
  silently dropped row would understate a cohort count, and cohort counts
  are what disclosure control relies on. Parse errors carry line numbers,
  never line content.
* **Envelope binding**: the HPKE `info` string is
  `tenant-envelope-v1|{tenant}|{slug}|{object}` — an envelope replayed under
  a different object id does not open (tested). Framing is versioned
  (`HPK1 || encapped_key || ciphertext`) so cipher suites can migrate
  without redesigning storage.
* **Snapshots** ([ADR 0003](adr/0003-connector-data-as-versioned-snapshots.md)):
  every sync is a full sync, so each one writes a complete snapshot under
  a new time-ordered version and commits it by writing a sealed manifest
  last. Queries read only the newest committed snapshot, so repeated syncs
  never multiply rows (which would inflate cohort counts past *k*) and a
  sync that stops partway changes nothing a query sees. Superseded
  snapshots are deleted after the commit. The manifest's HPKE `info` is
  `tenant-snapshot-manifest-v1|{tenant}|{slug}|{version}`.
* **Scheduler**: fixed-cadence `SyncScheduler`; one job's failure never
  aborts siblings. The `connector-worker` binary runs fixture jobs
  end-to-end without live credentials; `HttpJsonSource` (OAuth refresh →
  GET → mapper) is the production fetch path.

### 3. Query (zero-trust analytics)

```
POST /api/v1/query ──▶ attestation gate ──▶ newest committed snapshot
   (JWT tenant)        (gate_execution)       tenants/{t}/connectors/{slug}/manifests/*
                                              │
                          key released into enclave (EnclaveKeyProvider)
                          open HPKE envelopes → Parquet in RAM
                                              │
                          QueryScope: DataFusion SQL over decrypted frames
                          ZkMode::Enabled → plan allowlist + cohort threshold
                          zeroize blobs; Drop releases Arrow frames
                                              │
                                        JSON result rows
```

`quackxide-engine` + `platform-api::query`:

* **Two query paths.** *Ciphertext scan*: equality filters over a
  blind-index column (HMAC-SHA256/128) — the engine matches HMAC images and
  never sees the plaintext query term or values. *In-enclave analytics*:
  DataFusion SQL over the decrypted frame.
* **`QueryScope` memory hygiene.** Owns the DataFusion `SessionContext` and
  the MemTables built from decrypted Parquet; `Drop` deregisters them and
  releases the Arrow frames. Decrypted Parquet bytes live in zeroizing
  buffers and are wiped on every exit path, including errors.
* **Bounded plaintext.** `max_concurrent_queries` caps how many queries
  hold decrypted data at once; further queries wait for a slot, and a limit
  of zero refuses with 503.
* **ZK gate.** In `ZkMode::Enabled` every query passes the same disclosure
  gate as research access: the plan allowlist, a genuine `COUNT(*) AS n`,
  and suppression of cohorts below `RESEARCH_MIN_COHORT_SIZE` (see
  "Research access" below). Refusals return HTTP 422; results report
  `suppressed_rows`. A ZK scope without a threshold, or with `k = 0`,
  refuses every query.
* **Key-release trust boundary.** The server cannot decrypt tenant data on
  its own (envelopes are sealed to a private key it does not hold). The
  query endpoint models the confidential-computing pattern: the key is
  released only into an attested enclave (`EnclaveKeyProvider`), gated by
  the same attestation seam as the pipeline. That release path is not wired
  in this build → the endpoint fails closed with 503; the full path is
  proven by the `DevKeyProvider` in tests and the `query-demo` binary.

`FEATURE_ZK_ENABLED` sets the platform default and is `true` when unset.
Disabling it permits row-level queries and removes the no-naked-data
guarantee for that deployment.

### 4. Research access (two principals)

The research product is the query path with a second principal. The
**steward** holds the key and seals the data; the **researcher** may run
aggregate queries but never read rows.

```
Researcher ──▶ POST /api/v1/research/query {steward, connector, sql}
                 grant check (GrantRegistry): active steward→researcher grant?  ──no──▶ 403
                 attestation gate
                 budget charge (BudgetLedger): remaining ≥ cost?  ──no──▶ 429 + audit
                 steward's key released into enclave → decrypt steward's Parquet (RAM)
                 QueryScope, ZkMode FORCED Enabled:
                     plan gate: aggregate-only (no row egress)
                     plan gate: COUNT(*) AS n present and genuine (not a literal)
                     DataFusion executes
                     DisclosurePolicy (result gate): drop rows where n < k
                 zeroize plaintext; Drop releases frames
               ─▶ aggregate rows + suppressed_rows + budget_remaining + metering audit event
```

Three enforcement layers at one choke point, all in code:

* **Plan level** (`policy::is_aggregate_only` + `disclosure::verify_count_column`,
  shared with ZK mode): an allowlist, not a denylist. A plan is a single
  table scan, optionally filtered or column-renamed (nothing else may sit
  below the aggregate, so it reads every matching row), feeding exactly
  one `Aggregate` with plain `GROUP BY`, with only projection, filter,
  sort, and limit above it. Aggregates are limited to `COUNT`, `SUM`,
  `AVG`, `MIN`, and `MAX` over plain columns, and `n` must be a genuine
  `COUNT(*)`. Joins, set operations, window functions, grouping sets
  (`ROLLUP`, `CUBE`, `GROUPING SETS`), sorts or limits below the aggregate,
  subquery expressions, table functions, `VALUES`, computed aggregate
  arguments, and value-returning aggregates (`ARRAY_AGG`, `STRING_AGG`,
  `FIRST_VALUE`) are refused — each can inflate a cohort count, single out
  an individual, or put a subtotal beside its parts in one result.
  `tests/bypass.rs` holds the adversarial cases; add to it whenever the
  allowlist changes.
* **Result level** (`disclosure::DisclosurePolicy`): `MinCountThreshold`
  suppresses sub-`k` cohorts; a perturbation/DP policy composes after it via
  `CompositePolicy` without touching the engine.
* **Rate level** (`platform_tenancy::BudgetLedger`): each research query
  spends one unit of the grant's budget, charged after the attestation gate
  (infrastructure failures never cost the researcher) and before execution,
  with no refunds — probing the plan gate costs budget. Exhaustion returns
  429 with a `research.budget` event. Spend is monotonic per grant id;
  re-granting cannot reset it. The `cost` parameter is the seam for a
  sensitivity-scaled or privacy-loss (ε) accountant.

Grants (`platform_tenancy::GrantRegistry`) are steward-scoped and revocable
by the granting steward only. Revoked, unknown, and foreign grants return the
same response, so nothing leaks existence. Budget standing is visible to the
grant's parties only; top-up is steward-only. Metering rides the
`engine.query` event and doubles as the billing meter.

**Catalog** (`platform_tenancy::CatalogRegistry`, frontend Research tab):
publishing a listing — title, description, license fee, compute rate,
included budget, prices in integer cents — is the steward's opt-in to
discoverability. Researchers file access requests (idempotent while
pending); approval mints the grant through the same code path as a direct
grant. `research.catalog` events carry identifiers only.

**Residual risk:** overlapping-query differencing. See
`docs/THREAT_MODEL.md`.

## Crate boundaries (backend/crates/)

| Crate | Owns | Never contains |
| --- | --- | --- |
| platform-core | Typed ids (`TenantId`, `ObjectId`, `ConnectorSlug`), `ZkMode` | I/O, crypto |
| platform-config | Env → `PlatformConfig` (brand/server/storage/research) | Hardcoded brand strings |
| platform-telemetry | JSON tracing init, `SECURITY_AUDIT_EVENT` emitter | Secrets/customer content in events |
| platform-crypto | AEAD seal/open, HPKE suite pin, blind indexes, TOTP, `SecretBytes` | Tenant drive private keys (they don't exist server-side) |
| platform-auth | JWT verification (HS256 dev / RS256+JWKS), `TokenSigner`, keygen | Signing keys on verify-only replicas |
| platform-storage | `TenantPaths` (sole `VaultPath` factory), `VaultStore` trait | Raw-string storage paths |
| platform-enclave | `AttestationProvider` seam, fail-closed dev stub | "Trust me" attestation bypasses |
| platform-connectors | Connector catalog, OAuth2 grants, NDJSON bounds, Parquet-out | Plaintext persistence |
| platform-tenancy | Tenant/grant/budget/catalog registries (traits + in-memory) | Disclosure decisions |
| platform-billing | MoR (Paddle) webhook signature verification, replay guard | Webhook secrets in Debug output |
| quackxide-engine | `QueryScope` RAII, plan gate, disclosure policies | Customer-facing naming |
| platform-api | HTTP edge, routing, JWT tenant middleware | Business logic |
| synth-data (dev-only) | Seeded synthetic Parquet (`cohort`, `wide`) for tests, benchmarks and demos | Real or personal data; dependencies on other workspace crates |

Registries in `platform-tenancy` are in-memory implementations behind
traits; durable backends replace them without touching call sites.

## Cryptography posture

* All primitives come from RustCrypto (`aes-gcm`, `hmac`, `sha2`, `rsa`)
  and the `hpke` crate; TOTP is RFC 6238 over the existing HMAC stack and
  is tested against the RFC's own vectors.
* Suites are pinned at single seams (one `TenantKem` type alias, one
  `JwtVerifier` construction site) and encrypted framing is versioned, so
  algorithm migration is a code change plus a version bump — not a storage
  redesign.
* Verification and signing are separated: `JwtVerifier` holds public
  material only; `TokenSigner` (private key) belongs on a signer process,
  never a verify-only API replica. The RS256 verifier's algorithm allowlist
  is fixed at construction — an HS256 token forged with the public modulus
  bytes is rejected; a test covers this case.
* Transient secrets are zeroize-on-drop with redacted `Debug`; crypto errors
  carry no key material or content.

### Current and target suites

The release target is hybrid post-quantum cryptography, so ciphertext
stored today stays protected against a future quantum adversary ("harvest
now, decrypt later"). The current suites are classical.

| Use | Current | Target |
| --- | --- | --- |
| Key encapsulation (envelopes, enrollment) | X25519 (DHKEM, HKDF-SHA256) | Hybrid X25519 + ML-KEM-768 |
| Bulk encryption | AES-256-GCM | AES-256-GCM |
| Signatures (tokens, attestation-bound material) | RS256 (RSA); HS256 for local development | Hybrid Ed25519 + ML-DSA-65 |

Migration rules:

* Established implementations only (RustCrypto, `hpke`, and vetted
  ML-KEM / ML-DSA crates; Web Crypto where the browser supports the
  algorithm). No invented primitives.
* The suite changes at the existing seams — `TenantKem`, the `JwtVerifier`
  construction site, the browser crypto core — with a new frame version
  alongside `HPK1`.
* No silent downgrade: a reader configured for the hybrid suite refuses
  classical-only envelopes and signatures unless an explicit, logged
  migration mode is enabled.

The work is tracked in `docs/PROJECT_SCOPE.md`; the threat it closes is A4
in `docs/THREAT_MODEL.md`.

## Security telemetry

Emitter: `platform_telemetry::security_audit_event` — one structured JSON
record per security-relevant action, `target: SECURITY_AUDIT_EVENT`, fields
`audit_kind`, `tenant_id`, `outcome`, `detail`.

| `audit_kind` | Emitted on |
| --- | --- |
| `service.start` | API or connector-worker boot |
| `crypto.key_enrollment` | Tenant HPKE public-key enrollment (ok/denied) |
| `tee.attestation` | Every pipeline and query attestation decision |
| `tenant.provisioned` | Provisioning, suspension, connector toggles, grants |
| `data.access` | Every vault read, write, delete, and list — including misses |
| `connector.sync` | Each sealed dataset flush, snapshot commit, and pruned or unprunable superseded snapshot |
| `engine.query` | Every confidential query, with metering fields |
| `auth.decision` | Every rejected token, admin denial, signature rejection |
| `research.budget` | Budget top-ups and exhaustion refusals |
| `research.catalog` | Listing and access-request lifecycle |

Rules, enforced by the capture tests:

1. Identifiers and outcomes only — no key material, plaintext, filenames,
   or SQL text, including on failure paths.
2. Denials and misses are events too: rejected tokens, refused attestations,
   rejected webhook signatures, malformed enrollment keys, budget
   exhaustions, and 404 reads (cross-tenant probe visibility) all appear in
   the stream.
3. Coverage is tested: `platform_telemetry::capture::AuditCapture` records
   emitted events in-process, and `platform-api/tests/audit_coverage.rs`
   asserts the contract for data access (ok + miss), auth denial, key
   enrollment (ok + denied), query attestation + execution (ok + failed),
   and provisioning.

## Structural enforcement

* Cross-tenant storage access is unrepresentable: `VaultPath` has no public
  constructor; ids are UUID-validated at parse time.
* Fail closed is the default everywhere: unset auth secret → 503; unwired
  key release → 503; unverifiable attestation → refusal; fabricated dev
  evidence requires an explicit, logged `allow_insecure_dev()`.
* Workspace-wide `unsafe_code = "deny"`.
* `scripts/check.sh` fails the build if the engine name appears in the
  shipped frontend bundle (white-label guard) or the deployment domain
  appears outside env templates.
