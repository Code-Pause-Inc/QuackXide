# QuackXide — Threat Model

What QuackXide protects, from whom, how, and what it does not claim. Read
with `docs/ARCHITECTURE.md`, which describes the mechanisms named here.
Where a control is not yet built, this document says so; the current state
is also listed under "Status and known limitations" in `README.md`.

## Design goal

Data goes in. Analysis comes out. The dataset doesn't.

Trusted research environments trust the researcher (who sees rows), the
reviewer (who checks exports by hand), and the operator (whose disks hold
plaintext). QuackXide replaces each with a mechanism: researchers never
receive rows, disclosure control runs in the query engine, and the operator
never holds a key that opens the data. Every control below is held to
production requirements, including its failure paths.

## Assets

| Asset | Where it lives | Protection |
| --- | --- | --- |
| Dataset plaintext | Steward's browser before upload; enclave memory during a query | Never persisted in the clear; zeroized after use |
| Dataset ciphertext | Object store (`tenants/{t}/…`) | HPKE envelopes / AES-256-GCM, context-bound AAD |
| Steward private keys | Steward's browser (Web Crypto, non-extractable) | Never sent to the server |
| Dataset data keys | Beside each dataset, wrapped to a Cloud KMS key; unwrapped only in enclave memory for one query | KMS decapsulates only for the attested workload (ADR 0004); its private key cannot be exported |
| Research grants and budgets | `platform-tenancy` registries | Steward-scoped; no existence oracle |
| Aggregate results | Researcher portal | Plan gate, genuine-count check, cohort suppression, budget |
| Audit stream | `SECURITY_AUDIT_EVENT` log target | Identifiers and outcomes only; no content |
| Platform credentials | Environment (`JWT_*`, webhook secrets) | Never committed; the configuration copy is a `SecretString`, zeroized on drop and redacted in `Debug`; the environment copy remains (see residual risks) |

## Principals

* **Steward** — owns a dataset and holds its key. Publishes listings,
  grants, meters, and revokes researcher access.
* **Researcher** — holds a grant. May run aggregate queries within a finite
  budget. Never receives rows.
* **Operator** — runs the infrastructure (API hosts, object store,
  enclaves). Outside the trust boundary for dataset content.
* **Administrator** — provisions tenants and toggles connectors. Has no
  decrypt capability.

## Adversaries and controls

### A1. Malicious or careless researcher

Goal: obtain record-level data, or re-identify individuals from aggregates.

| Attack | Control | Status |
| --- | --- | --- |
| `SELECT *`, bare columns, `DISTINCT` row dumps | Logical-plan allowlist (`policy::is_aggregate_only`), applied in ZK and research mode; ZK mode is on unless explicitly disabled | Built, tested |
| Rebuilding the dataset one group per person (`GROUP BY id`) | Genuine `COUNT(*) AS n` required and cohorts below *k* suppressed, in ZK and research mode | Built, tested (`tests/bypass.rs`) |
| Inflated cohort counts (self-joins, `UNION ALL`, `UNNEST`, table functions) | Plan allowlist: one table scan under one aggregate; joins and set operations refused | Built, tested (`tests/bypass.rs`) |
| Inflated cohort counts through storage (repeated connector syncs leaving every row several times) | A query reads one committed snapshot per connector; a manifest that lists an object twice fails closed ([ADR 0003](adr/0003-connector-data-as-versioned-snapshots.md)) | Built, tested (`query_api.rs`, `pipeline_e2e.rs`) |
| Singling out one person inside a large group (`SUM(CASE WHEN id = …)`, computed columns, subquery expressions) | Aggregate arguments must be plain columns; subquery expressions refused | Built, tested |
| Value-returning aggregates (`ARRAY_AGG`, `STRING_AGG`, `FIRST_VALUE`) | Aggregate allowlist: `COUNT`, `SUM`, `AVG`, `MIN`, `MAX` | Built, tested |
| Overlapping groups in one result (`ROLLUP`, `CUBE`, `GROUPING SETS`: a subtotal minus its published groups reveals a suppressed cohort) | Plan allowlist refuses grouping sets ([ADR 0002](adr/0002-refuse-grouping-sets-and-positional-subsets.md)) | Built, tested (`tests/bypass.rs`) |
| Picking rows by position below the aggregate (`ORDER BY … LIMIT`/`OFFSET` in a subquery or CTE) | Plan allowlist: only filters and column renames below the aggregate | Built, tested (`tests/bypass.rs`) |
| Running statements before the gate (`CREATE TABLE … AS`, `DROP TABLE`, `SET`, `PREPARE`) | Statements are refused before planning finishes, so nothing runs ahead of the plan gate | Built, tested (`tests/bypass.rs`) |
| Spoofed cohort size (`9999 AS n`) | `disclosure::verify_count_column` requires a genuine `COUNT(*) AS n` | Built, tested |
| Small-cohort queries that isolate individuals | `MinCountThreshold` drops rows with `n < RESEARCH_MIN_COHORT_SIZE` | Built, tested |
| Unlimited adaptive probing | `BudgetLedger`: charged before execution, no refunds, monotonic per grant | Built, tested |
| Querying without a grant, or after revocation | `GrantRegistry` check before any decryption (403) | Built, tested |
| Discovering unpublished datasets or other grants | No-oracle responses: revoked, unknown, and foreign look identical | Built, tested |
| Differencing overlapping aggregates | Budget bounds it; perturbation `DisclosurePolicy` seam exists | **Residual risk** — see below |

### A2. Curious or compromised operator

Goal: read dataset content from infrastructure the operator controls.

The controls rely on Google for hardware verification, workload identity
and key custody (ADR 0004): the enclave is a Confidential Space workload
on Intel TDX, and Cloud KMS releases data keys only to it. The
administrator of the KMS key project can authorize another image, which
could then decrypt; policy changes and break-glass access are audited
(P77).

| Attack | Control | Status |
| --- | --- | --- |
| Read the object store | Ciphertext only; envelopes sealed to a key the operator does not hold | Built |
| Read API host disk or logs | Plaintext never persisted; audit events carry no content, SQL, or filenames, and are written whatever `RUST_LOG` says; DataFusion and sqlparser output, which can quote SQL, never reaches the logs; engine errors keep no upstream text | Built, tested (`tests/log_leak.rs`, `audit_records_ignore_the_operational_filter`) |
| Make a query write decrypted rows to disk (`COPY … TO`, `CREATE EXTERNAL TABLE`) | Only read-only queries run: DDL, DML, `COPY` and session statements are refused before anything executes, in every mode; a query scope has no object store, so no plan can reach the host's files | Built, tested (`tests/bypass.rs`, `query_api.rs`, `research_api.rs`) |
| Decrypt drive content server-side | Drive keys exist only in the browser; no server decrypt path | Built |
| Run a query outside a genuine enclave, or a modified binary inside one | Attestation gate with `TEE_ATTESTATION_REQUIRED=true`; Google's attestation token must name TDX hardware, a production Confidential Space image, debug disabled and an allowed image digest | Seam and token verifier built (`platform_enclave::token`, tested on the simulated TEE); **token acquisition on hardware to build** (P48) — fails closed until then |
| Run production on the simulated TEE, a development-only path whose memory the host can read | `TEE_ATTESTATION_REQUIRED=true` refuses simulated evidence; a verifier holding Google's keys rejects tokens signed by the simulator's key; responses report `tee_platform`. The simulator and the key-release stand-in, which accepts tenant private keys over HTTP, compile only with the `dev` feature; a build without it refuses to start when `KEY_RELEASE_URL` is set and refuses every attestation when `TEE_ATTESTATION_REQUIRED=false` | Built, tested (CI `release build has no dev binaries`); **refusal of simulated evidence at startup to build** |
| Obtain a dataset's key for a query | Cloud KMS unwraps the dataset's data key only for the attested workload, per query, with nothing cached (ADR 0004); the steward's private key never leaves their browser | Seam built (`EnclaveKeyProvider`); **production key release to build** — returns 503 until then |
| Authorize a modified image | The KMS key and its release policy live in a separate key project that no deployment identity administers (ADR 0004) | **Residual risk** for the key project's administrator — see below |
| Read results at the API edge | Results sealed to the recipient's key inside the enclave | **To build** — results currently leave as JSON over TLS |
| Swap or replay ciphertext between objects | HPKE `info` / AES-GCM AAD bind tenant, object, role, and chunk | Built, tested |

### A3. External attacker

Goal: gain access through the API.

| Attack | Control | Status |
| --- | --- | --- |
| Forged or algorithm-confused tokens | RS256 verifier with a fixed algorithm allowlist; HS256-with-public-key forgery rejected | Built, tested |
| Skipping the second factor, or using a refresh token as an access token | Only `typ = access` tokens pass the API's authentication; `preauth` and `refresh` tokens and tokens with no `typ` get 401 on every data and admin route | Built, tested (`tests/token_types.rs`) |
| Cross-tenant reads, lists, deletes | Tenant only from the verified `tid` claim; `VaultPath` constructible only from typed ids | Built, tested |
| Missing configuration used as a bypass | Unset auth secret → 503; unwired key release → 503; ZK gate and attestation requirement default to on | Built, tested |
| Oversized or malformed connector input | NDJSON limits checked before allocation; a bad line fails the batch; connector and token-endpoint response bodies capped while streaming | Built, tested |
| Connector credentials sent in cleartext or redirected elsewhere | Token and connector endpoints must be `https` (loopback `http` for test servers); redirects refused | Built, tested |
| Forged billing webhooks | Signature verification with replay tolerance | Built, tested |
| Account takeover of a steward, researcher or administrator | Sign-in through Auth0, then the platform's TOTP before any `access` token is issued, for every role including administrators (ADR 0006); TOTP replay and rate limits; recovery only by audited administrator reset, with an out-of-band identity check, no self-reset and at least two administrators | **To build** (P29, P30) — TOTP module exists |
| Theft of the token signing key, which can mint any `tid` and `adm` token | Key held in Cloud KMS and released only to the attested identity-service Confidential VM (ADR 0006, ADR 0004 option A); never on an API replica | **To build** (P29) |
| Self-assigned administrator access | `adm` set only from a server-side allowlist keyed by the provider's `(iss, sub)`, never from a provider attribute (ADR 0006) | **To build** (P29) |
| Access by a suspended or unknown tenant | The exchange and `require_tenant` / `require_admin` refuse unknown or Suspended tenants with 403 (ADR 0006) | **To build** (P29) — today any validly signed `tid` passes |
| Login CSRF or a replayed sign-in response | Authorization code with PKCE (S256), single-use `state` and OIDC `nonce` checked by the identity service, exact-match redirect URIs; no token in a URL (ADR 0006) | **To build** (P13, P29, P32) |
| Stolen or replayed refresh token | Rotation on every use; reuse revokes the token family; sign-out and administrator disable revoke immediately (ADR 0006) | **To build** (P30) |
| Token theft from browser storage | Access token held in memory only, never `localStorage`, `sessionStorage` or IndexedDB; provider tokens never reach the browser (ADR 0006) | **To build** (P31, P32) |

### A4. Future cryptanalytic adversary ("harvest now, decrypt later")

Goal: store ciphertext today and decrypt it once large quantum computers
exist.

| Attack | Control | Status |
| --- | --- | --- |
| Break X25519 key encapsulation | Hybrid X25519 + ML-KEM-768 (X-Wing in HPKE, ADR 0007) | **To build** — current suite is X25519 only |
| Forge signatures | Hybrid Ed25519 + ML-DSA-65, including platform tokens (ADR 0006, P37) | **To build** — current tokens use RS256 |
| Silent downgrade to classical-only | Versioned framing (`HPK2`); hybrid readers refuse `HPK1` and X25519-only keys, with no migration mode (ADR 0007) | **To build** |

The suite seams (`TenantKem`, the `JwtVerifier` construction site, the
`HPK1` frame version) exist so this migration is a code change plus a
version bump. See "Cryptography posture" in `docs/ARCHITECTURE.md`.

## Out of scope

* **Compromise of the steward's own device or browser.** The steward holds
  the key; malware on that device can read what the steward can read.
* **Side channels against the TEE.** QuackXide relies on Intel TDX
  guarantees and Google's attestation service; microarchitectural attacks
  on the hardware itself are outside this model.
* **Denial of service.** Availability is not a security goal of this
  release.
* **Correctness of the underlying libraries.** RustCrypto, `hpke`,
  DataFusion, and Web Crypto are trusted. QuackXide implements no
  cryptographic primitives. The post-quantum crates (`x-wing`, `ml-kem`,
  `ml-dsa`) and `hpke` have no independent audit; ADR 0007 records this
  as an accepted risk and the cross-implementation vectors that check
  them. Attestation tokens are verified with `jsonwebtoken` (RustCrypto
  backend), and Google's attestation service is trusted for what its
  tokens claim (ADR 0004).
* **Collusion between a steward and a researcher.** A steward can share
  their own data by other means.

## Residual risks

* **Overlapping-query differencing.** Two aggregate queries whose cohorts
  differ by one record can reveal that record. The budget makes this finite
  and priced; it does not prevent it within an allocation. The closure is a
  perturbation `DisclosurePolicy` composed at the existing choke point,
  followed by a formal privacy-loss accountant in place of the constant
  per-query cost.
* **Unzeroized working memory.** Decrypted Parquet bytes, OAuth secrets,
  connector response bodies, `Dataset` cells, the Parquet output buffer
  and the query-result JSON buffer are zeroized. Decoded Arrow arrays, the
  Parquet encoder's and HTTP client's internal buffers, and parsed
  `serde_json` values are freed without zeroization (clearing them would
  require `unsafe` or changes to those libraries). Plaintext is confined to enclave
  memory, so this matters only against an attacker who can read that
  memory.
* **Credentials in the process environment.** Configuration reads
  `JWT_HS256_SECRET` and `MOR_WEBHOOK_SECRET` into zeroizing
  `SecretString`s, but the original values stay in the process
  environment for the life of the process, readable by anything that can
  read that process's memory or `/proc/<pid>/environ`.
* **Extreme values.** `MIN` and `MAX` over a cohort of at least *k* still
  return one individual's actual value. This is standard for aggregate
  release; removing them from the allowlist, or applying a dominance rule,
  is a policy decision.
* **Metadata.** The server sees tenant ids, object ids, ciphertext lengths,
  and timestamps, including when each connector snapshot was written.
* **Forged or rolled-back snapshots.** Connector objects and snapshot
  manifests are sealed to the tenant's public key, which binds them to
  tenant, connector and object or version but does not authenticate the
  writer. An operator can therefore write a fabricated snapshot, or delete
  the newest manifest so queries read an older one. Closing this needs
  an enclave signing key bound to attestation.
* **The key project's administrator.** Whoever administers the KMS key
  project can add an image digest to the release policy, and that image
  can then decrypt. This is the maintainer; changes are audited (P77),
  not prevented. Google is trusted for hardware verification, workload
  identity and key custody, and the platform is tied to GCP.
* **Differencing across snapshots.** Querying before and after a dataset
  update can reveal the rows that changed, bounded by the budget like any
  other overlapping-query differencing.
* **Unfinished controls.** Every item marked "to build" above is a gap, and
  the corresponding path fails closed until it is built.
