# Testing

How QuackXide is tested: where each kind of test lives, which file to copy
when adding one, the convention for negative tests and audit assertions,
and what CI cannot exercise. `scripts/check.sh` runs every layer below
except fuzzing; `CONTRIBUTING.md` lists what CI runs on each pull request.

## Test layers

| Layer | Location | Copy from |
| --- | --- | --- |
| Crate unit tests | `#[cfg(test)] mod tests` beside the code, in each crate under `backend/crates/` | `backend/crates/platform-storage/src/lib.rs` |
| API integration tests | `backend/crates/platform-api/tests/*.rs` | `backend/crates/platform-api/tests/research_api.rs` |
| Audit assertions | `backend/crates/platform-api/tests/audit_coverage.rs` | the same file |
| Disclosure attacks | `backend/crates/quackxide-engine/tests/bypass.rs` | add a case to `CASES` or `ZK_CASES` |
| Property tests (Rust) | `proptest!` blocks inside a crate's unit tests | `backend/crates/platform-auth/src/verify.rs` |
| Property tests (TypeScript) | `frontend/src/**/*.property.test.ts` (fast-check) | `frontend/src/lib/vault/wire.property.test.ts` |
| Frontend unit tests | `frontend/src/**/*.test.ts` (vitest `node` project) | `frontend/src/lib/vault/wire.test.ts` |
| Frontend component tests | `frontend/src/**/*.test.tsx` (vitest `dom` project, jsdom) | `frontend/src/components/DrivePanel.test.tsx` |
| Fuzz targets | `backend/fuzz/fuzz_targets/` | `backend/fuzz/fuzz_targets/jwt_verify.rs` |

### Crate unit tests

Test one crate's logic without the HTTP layer. Run them with
`cargo test -p <crate>` from `backend/`.

### API integration tests

Each file builds the full router with `platform_api::build_app` and sends
requests through `tower::ServiceExt::oneshot`, so no port is bound. Tests
that need research access build it with `platform_api::dev::DevResearchStack`,
the same wiring the `devstack` server runs; `research_api.rs` is the
template:

* `DevResearchStack::new()` is an in-memory vault with no tenant keys;
* `commit_snapshot` seals a dataset to a tenant's keypair, commits it as
  that tenant's connector snapshot, and keeps the keypair in a
  `MultiTenantDevKeyProvider` so queries can open it;
* `query_service` adds in-memory grant, budget and catalog registries and
  attestation from `DevAttestation::allow_insecure_dev()`;
  `query_service_with_attestation` takes the attestation provider and
  whether attestation is required, for attestation-refusal tests.

`platform_api::dev` exists only with the `dev` feature. `platform-api`
lists itself as a dev-dependency with that feature on, so test builds
enable it and `cargo test` needs no flag.

`tests/common/mod.rs` holds the shared helpers; a test file uses them with
`mod common;`. It has the HS256 token minters (`token_for`, `admin_token`,
taking the file's secret), the request helpers (`send`, `send_with_headers`,
`send_json`, `call`, `post`, `post_query`), the app builders (`app_state`,
`synced_vault`, `research_app`), and `FlakyVault`, an in-memory vault that
fails the operations chosen in `Faults` with a transient (`outage`) or
permanent (`misconfigured`) storage error. Use them rather than writing new ones, and add a helper
there when a second file needs it. Tests that need RS256 tokens use its
`rs256_token` and `rs256_verifier` (see [Managed sign-in](#managed-sign-in)).

### Audit assertions

`platform_telemetry::capture::AuditCapture` records the
`SECURITY_AUDIT_EVENT` records emitted while it is installed. Install it on
the first line of the test, run the flow, then assert:

```rust
let capture = AuditCapture::install();
// ... drive the flow ...
assert!(capture.contains("auth.decision", "denied"), "{:?}", capture.events());
```

Two rules come from `backend/crates/platform-telemetry/src/capture.rs`:

* **Single-threaded.** The capture is thread-local. Use plain
  `#[tokio::test]` (current-thread runtime), never
  `flavor = "multi_thread"`, and do not emit from spawned threads.
* **Process-exclusive.** Only one capture is active per process; `install`
  blocks until any other capture is dropped. Keep the capture alive until
  the last assertion, and do not install a second one in the same test.

### Disclosure attacks

`bypass.rs` runs adversarial queries against the zero-knowledge and research
gates. Each case must be refused or return only rows with `n >= K` that
carry no identifier or small-cohort value. A new disclosure rule or query
shape adds cases here, not a new file. `disclosure.rs` beside it covers the
gate's expected behaviour.

### Property tests

Use them for parsers, encoders, and verifiers where the claim is "for every
input": round-trips, and "arbitrary input is never accepted". Rust uses
`proptest` inside the crate's unit tests. TypeScript uses fast-check in a
`*.property.test.ts` file next to the module it tests.

### Frontend tests

`frontend/vite.config.ts` defines two vitest projects. The `node` project
runs `*.test.ts` and has no DOM. The `dom` project runs `*.test.tsx` under
jsdom with `src/test/setup.ts`. Run both with `npm test` from `frontend/`.
Neither project runs a real browser; see
[Acceptance tests](#acceptance-tests-for-definition-of-done-items-1-3).

### Envelope vectors

`fixtures/envelope/` holds the vectors that keep the browser and the backend
on one envelope format. `hpk1.json` (test-only recipient keys derived from
published seeds, enrollment keys, `info` strings, and envelopes that open or
must fail) is written by `backend/crates/envelope-wasm/tests/vectors.rs`,
which fails when the file and its generator disagree; regenerate with
`UPDATE_ENVELOPE_VECTORS=1 cargo test -p envelope-wasm --test vectors`.
`hpk1-browser-sealed.json` holds envelopes sealed by the wasm module
(`node scripts/browser-sealed-vectors.mjs` from `frontend/`, after
`scripts/build-wasm.sh`), which the Rust test must open.
`frontend/src/lib/crypto/envelope.test.ts` checks the same files against the
wasm module, and `platform-api/tests/envelope_vectors.rs` runs the
enrollment cases through the enrollment route.

### Fuzz targets

`backend/fuzz` holds the targets for the untrusted-input parsers. It sits
outside the backend workspace and needs a nightly toolchain and
`cargo install cargo-fuzz`:

```bash
cd backend/fuzz
cargo +nightly fuzz run <target>
```

Every pull request checks that each target compiles (`cargo check
--manifest-path backend/fuzz/Cargo.toml --locked --bins`, on stable), and
the targets run weekly in CI.
A new parser of untrusted input gets a target.

## Negative tests and audit assertions

Definition-of-done item 8 (`docs/PROJECT_SCOPE.md`) requires a negative test
for every failure path, and an audit assertion for every security decision.
The PR that adds a refusal adds both, and ticks the matching line in the
refusal checklist in P78.

**Naming.** The name states what is refused and the outcome, as a sentence
in snake_case: `<subject>_is_refused`, `<subject>_is_rejected`,
`<subject>_is_<status>`, or `cannot_<action>`. For example:
`ungranted_research_query_is_forbidden`, `requests_without_a_token_are_401`,
`cannot_grant_to_self`. Do not use the prefixes `test_` or `negative_`.

**Placement.**

| The refusal comes from | The negative test goes in |
| --- | --- |
| An API route | the `platform-api/tests/` file for that route module (`drive_api.rs`, `research_api.rs`, `catalog_api.rs`, `admin_api.rs`, ...), next to its happy-path test |
| The disclosure gate | `quackxide-engine/tests/bypass.rs`, as a new case |
| One crate's own logic | that crate's `#[cfg(test)] mod tests` |
| The frontend | the component's or module's `*.test.ts(x)`, asserting the rendered error state |

Each test asserts the exact status code, not only that the request failed.
A table of inputs inside one test is fine when the refusals share a cause,
as in `malformed_inputs_are_rejected` in `drive_api.rs`.

**Audit assertions.** Assert every new `audit_kind`, or new outcome of an
existing one, in `audit_coverage.rs`. Assert both outcomes: `ok`, and
`denied` or `miss`. Add the assertion to the test for that flow, or add one
test per new flow, named `<flow>_is_audited` (for example
`attestation_refusal_is_audited`). A kind that tests cannot emit
(for example `service.start`, which only the binaries emit) is listed in P78
with the reason.

## What CI cannot exercise

GitHub-hosted runners have no Intel TDX hardware, no account at the managed
sign-in provider, and no GCS bucket. These substitutes are agreed for every
test. The issues named below build them; this guide only records the choice.

### Confidential Space on TDX

* **In CI:** recorded Confidential Space attestation tokens, captured on
  the TDX cloud environment (#36 phase B, and P48) and checked by the
  token verifier (P47). The simulated SEV-SNP mode (P84, #49) runs the
  attestation and key-release protocol for development and lifecycle
  tests.
* **On hardware:** the manual or dispatched hardware test job (P71).

### Managed sign-in

Generate an RS256 key in the test with the public
`platform_auth::generate_rs256_keypair`, sign tokens with
`TokenSigner::rs256_from_pem`, and verify with
`JwtVerifier::rs256_from_jwks`. `rs256_token` and `rs256_verifier` in
`platform-api/tests/common/mod.rs` do this, with the keypair generated once
per test binary in a `OnceLock`. Do not use `keygen::fixtures`: it is
`#[cfg(test)]` and private to `platform-auth`.

### GCS

Use the in-memory `ObjectStoreVault::new_in_memory()`. For a storage
failure seen by the API, use `FlakyVault` from `tests/common/mod.rs`; each
drive operation has an outage test in `drive_api.rs`. To check how an
`object_store` error is classified, wrap a store and pass it to
`ObjectStoreVault::new`, as `FaultyStore` in `platform-storage/src/lib.rs`
does. Timeouts and retries need the real HTTP client: point
`ObjectStoreVault::new_gcs_with_emulator` at a local listener that stalls or
answers 503, as `fake_gcs` in `platform-storage/src/lib.rs` and
`stalled_storage_fails_within_the_documented_bound` in `drive_api.rs` do.

`InMemory` enforces `VaultStore::put_if_absent` natively, but the GCS
emulator does not: fake-gcs-server ignores `ifGenerationMatch`. So check
create-only writes against a real bucket by hand (the P12 development
bucket) whenever the create-only path or the `object_store` version
changes. Write an object with `put_if_absent` and then write it again: the
second write must fail with `StorageError::AlreadyExists` and leave the
first object unchanged.

## Acceptance tests for definition-of-done items 1-3

* **P72:** browser end-to-end tests in CI. Stage A runs the crypto worker
  and keystore in real browsers. Stage B runs the steward and researcher
  lifecycles against the local stack on the simulated TEE.
* **P82:** the v1.0 acceptance run. It runs P72's specs once against staging
  on genuine Intel TDX hardware, and records the evidence in the acceptance
  checklist.

If P72 moves to v1.1, the acceptance test for items 1-3 is the manual
browser run on staging that P82 records under its checklist.
