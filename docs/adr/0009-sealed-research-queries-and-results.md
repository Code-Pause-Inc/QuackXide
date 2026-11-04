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
trusting a value in the bundle; which settings it requires is P14's
policy.

### Evidence bundle

`GET /api/v1/attestation?nonce=<base64url, 32 bytes>` is unauthenticated,
rate-limited per client (P65), and refuses a missing or malformed nonce
with 400. Each call requests one custom token with that nonce. The body:

```json
{
  "version": 1,
  "key_id": "…",
  "token": "<PKI token>",
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
* **PKI tokens, root pinned.** The token is the PKI type. The browser
  validates its `x5c` chain to Google's Confidential Space root
  certificate, which is compiled into the release bundle alongside P49's
  image digests and changes only with a release. The key set never comes
  from the API, which the operator controls. The library is open question
  1.

### Browser verification

The worker verifies the bundle with P47's `TokenVerifier`, built for
wasm32 in the P34 browser module and extended with the PKI chain. In
order, it checks:

1. the chain, signature, issuer, audience and validity window;
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
* In production mode (P18), a plaintext body is refused.

The enclave refuses in this order, and none of these refusals spends
budget:

| Condition | Status |
| --- | --- |
| Unknown `key_id` | 409, `reattest` |
| Frame does not open, or plaintext malformed | 400 |
| `recipient_key` differs from the researcher's enrolled key | 403 |
| Grant missing, revoked, or not `grant_id` | as today |
| `request_nonce` already recorded under this key set | 409 |

Replay protection: each key set keeps its recorded nonces in memory. A
nonce is inserted, atomically and only if absent, immediately before the
budget charge (wherever P54 places it), and stays recorded whatever
follows. Only granted, authenticated requests reach that step, so the set
grows by 32 bytes per such request, bounded by the rate limit; it empties
when the key set changes.

### Recipient key

`recipient_key` must equal, by suite and bytes, the key enrolled for
`tid`. Audit records carry its fingerprint,
`SHA-256("recipient-key-v1" ‖ suite ‖ public key)`, never the key. The
result is sealed with the recipient key's suite, so P35 changes the
suite without changing this flow. Until P33 makes enrollment create-once,
the enrolled key can be overwritten; that holds on the simulated TEE only.

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
| Google's keys | PKI token, root pinned in the release; fallback in open question 1 | OIDC key set pinned: breaks on Google's rotation. OIDC key set served by the API: the operator could substitute it |
| Sender authentication | Seal, then sign | HPKE auth mode: X-Wing has none. Sign, then seal: the browser would open before checking |
| Request encoding | JSON inside the frame; the AEAD authenticates the bytes, so no canonical form is needed | CBOR: a new dependency for no gain |
| `grant_id` | In the clear and in `info` | Sealed only: `info` must be known before the frame opens |

## Consequences

* `binding.rs` moves to the v2 layout and `EnclaveIdentity` holds real
  keys, with the request key's private half in production builds.
* `ed25519-dalek` and `ml-dsa`, named in ADR 0007, are added and must pass
  `cargo deny check`.
* `TokenVerifier` gains the PKI path and a wasm32 build. The simulated TEE
  issues PKI-shaped tokens chained to a test root, compiled in only with
  the `dev` feature, and P85's negative tests run there first.
* `info.rs` gains `research_query` and the `query` digest, both pinned by
  vectors under `fixtures/envelope/`.
* The attestation route requires its nonce, and the research route's
  request and response change shape. The worker gains attest, seal, verify
  and open, and P56 renders the opened result.
* `docs/THREAT_MODEL.md` updates the A2 rows and adds the served-bundle
  residual (P85) and the unsealed own-data endpoint.
  `docs/ARCHITECTURE.md`'s research flow shows the browser verifying the
  enclave first.
* A restart invalidates every session's key set: one extra round trip per
  session, and no queued query survives it.

## Open questions

1. Which established library validates the `x5c` chain in wasm32
   (`rustls-webpki`, already in `backend/Cargo.lock`, or the RustCrypto
   `x509-cert` crates)? If neither qualifies, the browser fetches the OIDC
   key set directly from Google, which needs Google's endpoint to allow
   cross-origin reads. A spike before review settles this.
2. Does `jsonwebtoken` 11 with `rust_crypto` build for wasm32 without
   pulling in an OS random source?
3. The evidence route's rate limit: P65 sets the values.
