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
| Research grants and budgets | `platform-tenancy` registries | Steward-scoped; no existence oracle |
| Aggregate results | Researcher portal | Plan gate, genuine-count check, cohort suppression, budget |
| Audit stream | `SECURITY_AUDIT_EVENT` log target | Identifiers and outcomes only; no content |
| Platform credentials | Environment (`JWT_*`, webhook secrets) | Never committed; zeroize-on-drop; redacted `Debug` |

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

| Attack | Control | Status |
| --- | --- | --- |
| Read the object store | Ciphertext only; envelopes sealed to a key the operator does not hold | Built |
| Read API host disk or logs | Plaintext never persisted; audit events carry no content, SQL, or filenames | Built, tested |
| Make a query write decrypted rows to disk (`COPY … TO`, `CREATE EXTERNAL TABLE`) | Only read-only queries run: DDL, DML, `COPY` and session statements are refused before anything executes, in every mode; a query scope has no object store, so no plan can reach the host's files | Built, tested (`tests/bypass.rs`, `query_api.rs`, `research_api.rs`) |
| Decrypt drive content server-side | Drive keys exist only in the browser; no server decrypt path | Built |
| Run a query outside a genuine enclave | Attestation gate with `TEE_ATTESTATION_REQUIRED=true` | Seam built; **SEV-SNP report verification to build** — fails closed until then |
| Obtain the steward's key for a query | Key released only into an attested enclave (`EnclaveKeyProvider`) | Seam built; **production key release to build** — returns 503 until then |
| Read results at the API edge | Results sealed to the recipient's key inside the enclave | **To build** — results currently leave as JSON over TLS |
| Swap or replay ciphertext between objects | HPKE `info` / AES-GCM AAD bind tenant, object, role, and chunk | Built, tested |

### A3. External attacker

Goal: gain access through the API.

| Attack | Control | Status |
| --- | --- | --- |
| Forged or algorithm-confused tokens | RS256 verifier with a fixed algorithm allowlist; HS256-with-public-key forgery rejected | Built, tested |
| Cross-tenant reads, lists, deletes | Tenant only from the verified `tid` claim; `VaultPath` constructible only from typed ids | Built, tested |
| Missing configuration used as a bypass | Unset auth secret → 503; unwired key release → 503; ZK gate and attestation requirement default to on | Built, tested |
| Oversized or malformed connector input | NDJSON limits checked before allocation; a bad line fails the batch | Built, tested |
| Forged billing webhooks | Signature verification with replay tolerance | Built, tested |
| Account takeover of a steward or researcher | Managed sign-in with MFA (TOTP module exists) | **To build** |

### A4. Future cryptanalytic adversary ("harvest now, decrypt later")

Goal: store ciphertext today and decrypt it once large quantum computers
exist.

| Attack | Control | Status |
| --- | --- | --- |
| Break X25519 key encapsulation | Hybrid X25519 + ML-KEM-768 | **To build** — current suite is X25519 only |
| Forge signatures | Hybrid Ed25519 + ML-DSA-65 | **To build** — current tokens use RS256 |
| Silent downgrade to classical-only | Versioned framing; hybrid suites must refuse classical-only input | **To build** |

The suite seams (`TenantKem`, the `JwtVerifier` construction site, the
`HPK1` frame version) exist so this migration is a code change plus a
version bump. See "Cryptography posture" in `docs/ARCHITECTURE.md`.

## Out of scope

* **Compromise of the steward's own device or browser.** The steward holds
  the key; malware on that device can read what the steward can read.
* **Side channels against the TEE.** QuackXide relies on AMD SEV-SNP
  guarantees and the attestation chain; microarchitectural attacks on the
  hardware itself are outside this model.
* **Denial of service.** Availability is not a security goal of this
  release.
* **Correctness of the underlying libraries.** RustCrypto, `hpke`,
  DataFusion, and Web Crypto are trusted. QuackXide implements no
  cryptographic primitives.
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
  and the Parquet output buffer are zeroized, but decoded Arrow arrays and
  the Parquet encoder's internal buffers are freed without zeroization
  (clearing them would require `unsafe`). Plaintext is confined to enclave
  memory, so this matters only against an attacker who can read that
  memory.
* **Extreme values.** `MIN` and `MAX` over a cohort of at least *k* still
  return one individual's actual value. This is standard for aggregate
  release; removing them from the allowlist, or applying a dominance rule,
  is a policy decision.
* **Metadata.** The server sees tenant ids, object ids, ciphertext lengths,
  and timestamps.
* **Unfinished controls.** Every item marked "to build" above is a gap, and
  the corresponding path fails closed until it is built.
