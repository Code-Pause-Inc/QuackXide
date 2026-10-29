# 0007. Hybrid suite construction, libraries, browser key storage and migration

* Status: Proposed
* Date: 2026-10-19

## Context

ADR 0001 fixes the target suites (X25519 + ML-KEM-768 key encapsulation,
Ed25519 + ML-DSA-65 signatures, AES-256-GCM) and the seams they change at,
but not the concrete construction, the libraries, where browser private
keys live, or how existing ciphertext migrates.

* The pinned `hpke` 0.12 (`backend/Cargo.toml`) has only DHKEMs. `hpke`
  0.14.1 adds `hpke::kem::XWing` (X25519 + ML-KEM-768, HPKE KEM id
  0x647a) when its `mlkem` and `x25519` features are on. It uses the
  RustCrypto `x-wing` crate (0.1.1 resolves today), which states that it
  implements draft-connolly-cfrg-xwing-kem-06. 0.14 also moves to
  `rand_core` 0.10, `aes-gcm` 0.11 (behind a new `aes` feature) and
  `x25519-dalek` 3, and `single_shot_seal` no longer takes an RNG.
* The X-Wing draft is at revision 10 (March 2026). Its change log since
  -06 lists an ASN.1 module, SHAKE-256 output length stated in bits
  rather than bytes, a corrected PEM header and editorial changes; none
  changes the wire format, and the spike below confirms it byte for byte.
  The draft requests KEM id 0x647a with Nenc 1120, Npk 1216 and Nsk 32.
* Sizes grow: an X-Wing public key is 1216 bytes and an encapsulated key
  1120 bytes, against 32 and 32 for X25519
  (`backend/crates/platform-crypto/src/lib.rs`, `HPK1` framing).
* Web Crypto has no ML-KEM. An X-Wing private key is a 32-byte seed, so it
  cannot be a non-extractable Web Crypto key, and the drive KEK can only
  wrap and unwrap `CryptoKey`s (`frontend/src/lib/crypto/core.ts`).
* None of the candidate libraries has an independent audit. The `x-wing`,
  `ml-kem` and `ml-dsa` READMEs say so; `hpke` has had no paid audit;
  `@noble/post-quantum`'s README says it has not been independently
  audited (it records a self-audit at 0.6.1). ADR 0001's "established
  libraries only" therefore needs a definition that can be met.
* ADR 0004 (Proposed) keeps a copy of each steward upload wrapped to the
  steward's browser key, generates the researcher's result key in the
  researcher's browser, and wraps data keys to a Cloud KMS X-Wing key.
  Cloud KMS documents `KEM_XWING` (public key 1216, ciphertext 1120,
  shared secret 32 bytes), does no encapsulation, and decapsulation
  returns the shared secret
  ([key encapsulation](https://docs.cloud.google.com/kms/docs/key-encapsulation-mechanisms)).
  It does not run HPKE.
* Nothing is deployed and only synthetic data exists (`README.md`,
  `docs/DATA_POLICY.md`).

### Spike

Run on 2026-10-19 with the pinned toolchain (Rust 1.94.1), outside the
repository:

| Check | Result |
| --- | --- |
| `hpke` 0.14.1 `XWing` + `HkdfSha256` + `AesGcm256`, base mode, native | Seal and open round-trip; seed 32, public key 1216, frame `enc(1120) ‖ ct` |
| Same code for `wasm32-unknown-unknown` (`getrandom` 0.4 `wasm_js`, `opt-level = "z"`, LTO) | Builds; 142 KB, 47 KB gzipped, before `wasm-bindgen` glue. Not yet run in a browser (P34) |
| KEM level: Rust `x-wing` 0.1.1 against `@noble/post-quantum` 0.7.1 (`ml_kem768_x25519`) | Same seed and encapsulation randomness give identical public key, ciphertext and shared secret; each decapsulates the other's ciphertext |
| Suite level: Rust `hpke` 0.14.1 against `hpke-js` (`@hpke/core` 1.9.0, `@hpke/hybridkem-x-wing` 0.7.0) | Each opens the other's sealed frame with the same `info` and AAD; both report KEM id 0x647a |
| `@noble/post-quantum` X-Wing alone, bundled and minified | 46 KB, 18 KB gzipped; no HPKE layer, so a JavaScript path would need a second library for HPKE |

## Decision

### Key encapsulation

* **Suite:** HPKE (RFC 9180) base mode with KEM X-Wing (0x647a), KDF
  HKDF-SHA256 (0x0001), AEAD AES-256-GCM (0x0002).
* **X-Wing revision:** draft-connolly-cfrg-xwing-kem-06, as implemented
  by `x-wing` 0.1.1. A later revision is adopted only by a new record,
  after the known-answer tests below pass against it.
* **Rust:** `hpke` 0.14.1, pinned exactly, with features `alloc`,
  `getrandom`, `x25519`, `mlkem`, `aes` and `hkdfsha2`, and its
  `x-wing` and `ml-kem` dependencies pinned in `Cargo.lock`. The suite
  stays behind the `TenantKem` alias.
* **Browser:** a wasm32 build of the same `hpke` code, in the wrapper
  crate P34 builds, called only from the crypto worker. One
  implementation serves both sides. `@noble/post-quantum` and `hpke-js`
  are not shipped; they are used only to generate the cross-implementation
  vectors below, so `CONTRIBUTING.md` ("RustCrypto, `hpke`, and Web
  Crypto") is unchanged.

### Proof of interoperability

Interoperability is proven by vectors, not assumed. `hpke`'s bundled
X-Wing vectors cover ChaCha20-Poly1305 only.

* **KEM-level known-answer tests** in `platform-crypto`: seed → public
  key, and (public key, encapsulation randomness) → (ciphertext, shared
  secret), with the expected values produced by `@noble/post-quantum` from
  the same inputs, plus decapsulation of its ciphertexts.
* **Suite vectors** committed under `fixtures/` (P34's vector file): frames
  sealed by `hpke-js` that Rust must open, and frames sealed by Rust that a
  vitest test opens with `hpke-js` as a dev dependency. Each records the
  seed, `info`, AAD and plaintext; negative vectors cover a wrong `info`,
  a tampered ciphertext, a wrong recipient and an `HPK1` frame. The
  generator script stays in the repository. Seeds are public and labelled
  test-only (`docs/DATA_POLICY.md`, as P34 amends it).

### Frame and `info` strings

* **Frame:** `HPK2 ‖ enc (1120) ‖ ciphertext`. `HPK2` means exactly the
  suite above. A reader chooses the suite from the magic and refuses any
  other magic, including `HPK1`.
* **`info`:** every hybrid envelope's `info` starts with a kind and `-v2`,
  and the fields are joined with `|`, as today:
  * `tenant-envelope-v2|{tenant}|{connector}|{object}` (connector objects);
  * `tenant-snapshot-manifest-v2|{tenant}|{connector}|{version}`
    (ADR 0003 manifests);
  * `steward-upload-v2|{tenant}|{dataset}|{object}` (P38 uploads);
  * `research-result-v2|{researcher_tenant}|{query}` (P55 results).

  P38 and P55 fix the identifiers in their fields. All strings are defined
  once in `platform-crypto` and pinned by the vectors, so Rust and
  TypeScript cannot drift.

### Browser private-key storage

An X-Wing private key is a 32-byte seed. The browser holds it as follows:

* A dedicated **seed key**: AES-256-GCM, generated `extractable: false`,
  usages `encrypt` and `decrypt` only, separate from the drive KEK (which
  stays wrap/unwrap only). One per device, persisted as an opaque handle in
  IndexedDB like the KEK.
* The seed is stored encrypted under the seed key, with AAD
  `xwing-seed-v1|{tenant}|{fingerprint of the public key}`, so a record
  cannot be moved to another tenant or paired with another public key.
* It is decrypted only in the crypto worker, immediately before an open,
  copied into wasm memory, and the JavaScript copy is overwritten with
  zeros. The wasm side holds it in zeroizing types (`x-wing` and `hpke`
  zeroize on drop) and drops it when the open ends.

This applies to the steward's upload key (ADR 0004) and the researcher's
result key (P55). Under the hybrid suite a result key cannot be
non-extractable as ADR 0004 currently says; ADR 0004 is amended to "held
as ADR 0007 describes" before it is accepted.

Residual risk, as ADR 0001 requires: a copy of the IndexedDB records is
useless off the device, but code running in the worker during an open
can read the seed. That is the same trust ADR 0005 already places in the
served bundle, and a compromised steward device is out of scope.

### Cloud KMS (ADR 0004, option A)

KMS returns an X-Wing shared secret, not an HPKE context, so `hpke`'s open
path cannot be used for KMS-wrapped data keys. This record does not
invent a construction for it. Under ADR 0004 option A, the
construction for KMS-wrapped data keys (for example the HPKE key schedule
computed from the decapsulated shared secret, if a maintained library
exposes it) is decided in ADR 0004's open question 2 or a later record,
with the same vector requirements. The browser and connector paths above
do not depend on it.

### Signatures in v1

ADR 0001's target column names "tokens, attestation-bound material":

* **Tokens** follow ADR 0006 (#40): either the platform issuer mints hybrid
  tokens, built in P37, or a superseding record keeps short-lived tokens
  classical.
* **Attestation-bound material** means signatures made with a key that only
  an attested workload holds: the result-signing key (P55, ADR 0004) and
  the optional snapshot-manifest signing key (ADR 0004). When built, each
  signs with both Ed25519 (`ed25519-dalek`) and ML-DSA-65 (`ml-dsa`), and a
  verifier requires both signatures over the same domain-separated message.
  The encoding is decided by the item that builds it.
* **Third-party classical signatures** (Google's attestation tokens
  under ADR 0004, verified in P47) are out of scope: the project verifies
  them and cannot change them.

### What "established" means

A cryptographic library is established for this project when it:

1. implements a published standard or IETF/CFRG specification, at a
   revision this project pins;
2. is open source under a license `cargo deny` or `npm audit` accepts,
   actively maintained, and published by the RustCrypto organisation, the
   `hpke` maintainer, or (for test tooling only) an author with a public
   record of maintained cryptography libraries;
3. ships the specification's known-answer tests, and passes this
   project's cross-implementation vectors;
4. has no open advisory in RustSec or the npm advisory database.

An independent audit is not required. The audit status of each library
is an accepted risk:

| Library | Use | Audit |
| --- | --- | --- |
| `hpke` 0.14.1 | Backend and browser (wasm) | No paid audit |
| `x-wing` 0.1.1, `ml-kem` 0.3 | Through `hpke` | Not independently audited (README) |
| `ml-dsa`, `ed25519-dalek` | Attestation-bound signatures, when built | `ml-dsa` not independently audited (README) |
| `@noble/post-quantum`, `hpke-js` | Vector generation only, never shipped | Not independently audited |

### Migration

v1 ships no `HPK1`-reading migration mode and no re-seal tool: nothing is
deployed and only synthetic data exists. A hybrid reader refuses `HPK1`
frames and X25519-only enrollment keys, with a negative test and a
`crypto.*` audit event (P35). This supersedes, for v1, ADR 0001's
consequence that existing classical ciphertext needs an audited,
time-limited migration mode. If data is ever deployed under `HPK1` before
the hybrid suite ships, a new record reinstates it.

## Consequences

* Envelopes grow by 1088 bytes each (1124 bytes of header against 36), and
  each enrolled public key is 1216 bytes. P35 benchmarks seal and open
  against the `HPK1` baseline (P73).
* The `hpke` upgrade moves `platform-crypto` to `aes-gcm` 0.11 and
  `rand_core` 0.10; P35 handles the knock-on changes and the `getrandom`
  0.4 `wasm_js` choice for the wasm build.
* The browser holds a private key outside Web Crypto's non-extractable
  store for the first time. `docs/ARCHITECTURE.md`'s KEK note ("JS *or*
  WASM") and `docs/THREAT_MODEL.md`'s steward-key row are updated when P36
  ships it.
* One implementation runs on both sides, so a bug in it is a bug
  everywhere; the second-implementation vectors are the check against
  that.
* `docs/PROJECT_SCOPE.md`'s "Established libraries only" and
  `docs/ARCHITECTURE.md`'s migration rules point to this record's
  definition.
* On acceptance: P35 and P36 may merge; ADR 0004 replaces "non-extractable"
  for the result key; P34's vector file gains the hybrid vectors.

## Open questions

1. Is the maintainer content to pin draft-06, given the RustCrypto crate
   tracks it and the later revisions did not change the bytes?
2. Should the second implementation for committed vectors be `hpke-js`
   (the only other HPKE X-Wing implementation found), or should vectors
   also come from Cloud KMS once ADR 0004 is decided?
3. Accept "established" as defined above, in place of "audited"?
