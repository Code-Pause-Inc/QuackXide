# 0009. Sealed research queries and results

* Status: Proposed
* Date: 2026-11-04

## Context

A research query's SQL text arrives as plaintext JSON
(`ResearchQueryRequest`, `backend/crates/platform-api/src/query.rs:829`)
and its result leaves as plaintext JSON (`query.rs:733`). The browser has
no evidence of what it is talking to. The plan requires queries and
results to be plaintext only in the user's browser and inside the attested
Confidential VM (P85, P55), which closes three threat-model A2 rows: reading
results at the API edge, recipient-key substitution and result forgery.

Already decided, and not reopened here:

* ADR 0004: the browser supplies a nonce; the token carries it and a
  digest of the enclave's keys; the recipient key comes from the
  researcher's sealed request and must match the enrolled key.
* ADR 0005: one process (`platform-api`) in one TDX VM, TLS inside it, and
  the sealing keys stay behind `ConnectorQueryService`.
* ADR 0007: attestation-bound signatures use Ed25519 and ML-DSA-65, both
  required; `info` strings are `kind-vN|field|…`, defined once in
  `platform-crypto/src/info.rs`; the researcher's X-Wing seed is stored
  under a non-extractable AES key.

The current code falls short of those records:

* `ReportDataBinding` (`backend/crates/platform-enclave/src/binding.rs`)
  holds each public key in a 32-byte field. An X-Wing public key is 1216
  bytes and an ML-DSA-65 public key 1952.
* The binding omits the KMS public key that ADR 0004 lists, and its domain
  tag still names SEV-SNP.
* `EnclaveIdentity` (`platform-api/src/key_release.rs`) fills the
  result-signing key with random bytes and builds the request key's
  private half only with the `dev` feature.
* `research_result(researcher_tenant, query)` (`info.rs`) leaves `{query}`
  undefined.

HPKE base mode does not authenticate the sender, and X-Wing has no
authenticated mode, so a result needs a signature to prove it came from
the enclave. Confidential Space issues custom tokens with a caller-chosen
audience and nonces, as OIDC tokens (verified against a key set Google
rotates) or as PKI tokens that carry their certificate chain in `x5c` and
verify against a root certificate Google publishes
([external resources](https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources)).

### Spike

Run on 2026-11-04 with the pinned toolchain (Rust 1.94.1) on x86_64
Linux, outside the repository:

| Check | Result |
| --- | --- |
| `platform-enclave` alone for `wasm32-unknown-unknown` | Fails only because `getrandom` 0.2 (from `jsonwebtoken` and `rand_core`) lacks its `js` backend |
| `TokenVerifier` linked into `envelope-wasm`, which enables that backend, release build | Builds; 1.72 MB against 569 KB without it, before `wasm-bindgen` and `wasm-opt`. Not yet run in a browser |
| How `jsonwebtoken` 11.1 reads the clock on wasm32 | `js_sys::Date` (`validation.rs:179`), not `SystemTime`; `token.rs` reads `SystemTime` only in tests |
| Google's OIDC key set, fetched cross-origin | `Access-Control-Allow-Origin` echoes the requesting origin; `Cache-Control` max-age about 6 hours |
| `rustls-webpki` 0.103.16 with `ring` for wasm32 | Builds, with clang for `ring`'s C code |
| The same, native, on an RSA chain shaped like Google's (4096-bit root, intermediate, leaf) | Accepts a leaf with no extended key usage; refuses a wrong root, an expired chain, and a leaf whose extended key usage it was not told to expect |
| Google's Confidential Space root certificate | RSA-4096, SHA-256, valid until 2034-01-16 |
| Extended key usage of real PKI leaf certificates | Unknown. Google's documentation does not state it, its Go sample accepts any, and Project Oak's Rust verifier (`x509-cert` with `x509-verify`) checks none |

## Decision

### Enclave keys

At start, `ConnectorQueryService` generates a key set and holds it in
memory only, in zeroize-on-drop types, never written, logged or exported:

* a **request key**: a `TenantKem` key pair (X25519 today, X-Wing after
  P35), with its private half in production builds;
* a **result-signing key**: an Ed25519 key pair (`ed25519-dalek`) and an
  ML-DSA-65 key pair (`ml-dsa`).

Any change to a bound value (a restart, a renewed TLS key) produces a new
key set. Its `key_id` is the binding digest below, base64url-encoded.

The opened request (including the SQL text) and the result payload before
sealing are zeroized after use, like the query-result buffer today.

### Binding v2

The token's `eat_nonce` holds two base64url values, as
`nonces_from_bytes` already produces: the browser's 32-byte challenge,
then a 32-byte digest:

```
SHA-256( "attestation-binding-v2"
         ‖ for each entry, in this order:
           u16 len(label) ‖ label ‖ u32 len(value) ‖ value )
```

| Label | Value |
| --- | --- |
| `request-key` | suite magic (`HPK1`, later `HPK2`) ‖ raw public key |
| `signing-ed25519` | 32-byte public key |
| `signing-ml-dsa-65` | encoded public key |
| `kms-public-key` | KMS public key; empty until P50 |
| `tls-spki-sha256` | 32 bytes; empty until P67 |
| `config-digest` | SHA-256 over the token's `submods.container.env` entries, sorted by name, each name and value length-prefixed |

The tag is neutral because the browser module computes it and the
white-label guard forbids the engine name in the shipped bundle. The
browser recomputes the config digest from the verified token rather than
trusting a value in the bundle. It also refuses a configuration that
loosens a control: `TEE_ATTESTATION_REQUIRED` and `FEATURE_ZK_ENABLED`
must be absent or `true`, and `RESEARCH_MIN_COHORT_SIZE` absent or at
least the compiled-in floor (P54). P14's policy may require more, never
less.

### Evidence bundle

`GET /api/v1/attestation?nonce=<base64url, 32 bytes>` is unauthenticated,
rate-limited per client (P65), and refuses a missing or malformed nonce
with 400. Each call requests one custom token with that nonce. The body:

```json
{
  "version": 1,
  "key_id": "…",
  "token": "<OIDC token>",
  "request_key": { "suite": "HPK1", "public_key": "…" },
  "signing_keys": { "ed25519": "…", "ml_dsa_65": "…" },
  "kms_public_key": null,
  "tls_spki_sha256": null
}
```

Byte fields are base64url without padding.

### Challenge and trust in Google's keys

* **Once per session.** The crypto worker draws a 32-byte challenge,
  fetches the bundle and verifies it, then keeps the verified key set in
  worker memory (never persisted) until the token expires or the server
  reports an unknown `key_id`. Each query gets its own freshness from its
  request nonce and the signed result.
* **OIDC tokens, key set fetched from Google.** The token is the OIDC
  type. The worker fetches Google's key set itself, over its own TLS
  connection to Google, from the key-set URL compiled into the release
  bundle with the issuer and P49's image digests. It never takes the key
  set from the API, which the operator controls. It uses the browser's
  HTTP cache, and refetches once when a token names a key the set does
  not hold. A development build compiles in the simulator's issuer and
  key-set URL instead.

### Browser verification

The worker verifies the bundle with P47's `TokenVerifier`, built for
wasm32 in the P34 browser module. In order, it checks:

1. the signature against Google's key set, the issuer, audience and
   validity window;
2. the hardware (TDX), software (Confidential Space), debug and support
   claims;
3. the image digest against the compiled-in allowlist;
4. that the first nonce equals its challenge;
5. that the digest it recomputes from the bundle's keys and the token's
   configuration equals the second nonce.

Any failure stops the query with an error naming the failed check, and
nothing is sent. Browser JavaScript cannot see the TLS key, so
`tls-spki-sha256` is checked by P85's command-line checker, not the
browser.

### Sealed request

`POST /api/v1/research/query` takes, with the bearer token unchanged:

```json
{ "version": 1, "key_id": "…", "grant_id": "…", "envelope": "…" }
```

* `envelope` is a frame sealed to the request key under
  `research-query-v1|{tid}|{grant_id}` (`-v2` with the hybrid suite),
  where `tid` is the session's tenant (P33). `grant_id` is in the clear
  because the enclave needs `info` before it can open the frame.
* The sealed plaintext is JSON, at most 64 KiB, with unknown fields
  refused:

  ```json
  {
    "steward_tenant": "…",
    "connector": "…",
    "sql": "…",
    "request_nonce": "<32 bytes>",
    "recipient_key": { "suite": "HPK1", "public_key": "…" }
  }
  ```

* The grant found for the researcher, steward and connector must have the
  id in `grant_id`.
* A plaintext body is accepted only in builds with the `dev` feature,
  decided at compile time like the key-release stand-in; a release build
  refuses it whatever its configuration.

The enclave refuses in this order, and none of these refusals spends
budget:

| Condition | Status |
| --- | --- |
| Unknown `key_id` | 409, `reattest` |
| Frame does not open, or plaintext malformed | 400 |
| `recipient_key` differs from the researcher's enrolled key | 403 |
| Grant missing, revoked, or not `grant_id` | as today |
| `request_nonce` already recorded with another envelope, or its query still running | 409 |

Replay protection and retries: each key set keeps its recorded nonces in
memory. A nonce is inserted, atomically and only if absent, immediately
before the budget charge (wherever P54 places it), with the SHA-256 of its
envelope, and stays recorded whatever follows. Once the query finishes,
its signed response is stored with it.

* A request whose nonce and envelope digest match a recorded entry gets
  the stored response again, with no new charge, so a client that lost a
  response can retry. A replay gains the operator nothing, because the
  result is sealed to the researcher.
* The same nonce with a different envelope is refused with 409, and so is
  a retry while the first query is still running.
* A query that ended in an error stores that error response. The client
  retries under a new nonce, and whether that is charged again follows
  P54's budget order.

Only granted, authenticated requests reach that step, so the store grows
by one aggregate response per such request, bounded by the rate limit;
it empties when the key set changes, and a client then re-attests and
re-sends under a new nonce.

### Recipient key

`recipient_key` must equal, by suite and bytes, the key enrolled for
`tid`. Audit records carry its fingerprint,
`SHA-256("recipient-key-v1" ‖ suite ‖ public key)`, never the key. The
result is sealed with the recipient key's suite, so P35 changes the
suite without changing this flow.

Anyone can seal a request to the enclave's public key, so what ties a
result to the researcher is the bearer token and the enrolled key. An
operator holding a researcher's token and able to overwrite that
researcher's enrollment could send its own request with its own recipient
key and read the result. Two things close this:

* **Create-once enrollment (P33).** Until it lands, a release build
  refuses sealed research queries with 503; only `dev` builds, which run
  on the simulated TEE, accept them.
* **TLS inside the VM (ADR 0005, P67).** Until then, bearer tokens are
  visible wherever TLS ends, and the threat model records that sealed
  results do not hold against that operator.

### No downgrade

Once P35 ships the hybrid suite, every step refuses the classical one, as
ADR 0007 requires for stored data: the browser refuses an evidence bundle
whose request key is `HPK1`, and the enclave refuses an `HPK1` envelope
and an X25519-only recipient key. There is no fallback mode. The
signatures are hybrid from the first build.

### Sealed and signed result

A successful response is:

```json
{
  "version": 1,
  "key_id": "…",
  "sealed_result": "…",
  "signature": { "ed25519": "…", "ml_dsa_65": "…" }
}
```

* `sealed_result` is the P54 result payload, all of it including counts
  and `budget_remaining`, sealed to `recipient_key` under
  `research_result(tid, query)`, where `query` is the base64url of
  `SHA-256("research-query-binding-v1" ‖ grant_id ‖ request_nonce ‖
  SHA-256(sql) ‖ schema_version)`, each field length-prefixed.
* The signatures are over `"research-result-signature-v1" ‖ u32 len(info)
  ‖ info ‖ u32 len(frame) ‖ frame`, with ML-DSA-65's context string
  empty.
* The browser checks both signatures against the key set it verified for
  `key_id`, recomputes `info` from its own request, and only then opens
  the frame. Any failure discards the response.

Error responses carry a status and an error class, never result data or
an SQL echo. The `engine.query` audit record keeps its counts on the
server, which billing reads.

### Out of scope

The own-data endpoint (`POST /api/v1/query`) stays unsealed. The
end-to-end target covers research queries only, and sealing it is the
same envelope under another `info` kind, for a later record. The
threat model records it as a residual.

## Options considered

| Question | Chosen | Rejected |
| --- | --- | --- |
| Challenge freshness | Browser nonce, one token per session | A cached token on a server nonce, checked by age: ADR 0004 requires the browser's nonce |
| Google's keys | OIDC token, key set fetched by the browser from Google: works in the spike with no new dependency | PKI token with the root pinned: no live fetch, but needs X.509 chain validation in the browser, clang in CI for `ring`, and the leaf's extended key usage, which only a real token shows (open question 1). OIDC key set pinned: breaks on Google's rotation. OIDC key set served by the API: the operator could substitute it |
| Sender authentication | Seal, then sign | HPKE auth mode: X-Wing has none. Sign, then seal: the browser would open before checking |
| Request encoding | JSON inside the frame; the AEAD authenticates the bytes, so no canonical form is needed | CBOR: a new dependency for no gain |
| `grant_id` | In the clear and in `info` | Sealed only: `info` must be known before the frame opens |

## Consequences

* `binding.rs` moves to the v2 layout and `EnclaveIdentity` holds real
  keys, with the request key's private half in production builds.
* `ed25519-dalek` and `ml-dsa`, named in ADR 0007, are added and must pass
  `cargo deny check`.
* `TokenVerifier` is built into the browser module, which grows by about
  1.1 MB before optimisation. The simulated TEE keeps issuing OIDC-shaped
  tokens and serves its key set to development builds, and P85's negative
  tests run there first.
* A release-build check confirms the frontend bundle names only Google's
  issuer and key-set URL, never the simulator's, as CI already checks
  that a release build has no dev binaries.
* P73 benchmarks the attestation round trip, browser verification, seal
  and open, and result signing, and records the shipped module size.
* P65's Content Security Policy adds Google's key-set origin to
  `connect-src`.
* Verification depends on reaching Google's key-set URL: if the browser
  cannot fetch it, no query is sent.
* `info.rs` gains `research_query` and the `query` digest, both pinned by
  vectors under `fixtures/envelope/`.
* The attestation route requires its nonce, and the research route's
  request and response change shape. The worker gains attest, seal, verify
  and open, and P56 renders the opened result.
* `docs/THREAT_MODEL.md` updates the A2 rows, including the dependence of
  sealed results on create-once enrollment (P33) and TLS inside the VM
  (P67), and adds the served-bundle residual (P85) and the unsealed
  own-data endpoint. Its "Metadata" residual adds the `grant_id` sent in
  the clear and the sealed result's length, which shows roughly how many
  groups a result has.
  `docs/ARCHITECTURE.md`'s research flow shows the browser verifying the
  enclave first.
* A restart invalidates every session's key set: one extra round trip per
  session, and no queued query survives it.

## Open questions

1. Should PKI tokens replace OIDC later? P48 records one real PKI token;
   if its leaf certificate has no extended key usage, or one that can be
   named, `rustls-webpki` can validate the chain against the pinned root
   and a later record can switch.
2. The evidence route's rate limit: P65 sets the values.
