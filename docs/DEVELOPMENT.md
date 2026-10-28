# QuackXide — Development

How to set up a machine, run the tests, and fix a failing
`scripts/check.sh`. What the system does is in `README.md` and
`docs/ARCHITECTURE.md`; the rules for changes are in `CONTRIBUTING.md`.

## Prerequisites

* **rustup.** `rust-toolchain.toml` pins the toolchain and its components;
  rustup installs them the first time `cargo` runs in `backend/`. Do not
  install a separate Rust.
* **Node**, at the version in `.nvmrc` (for example `nvm install` from the
  repository root).
* **openssl**, to generate the local JWT secret (README "Development").
* **bash**, for `scripts/`. CI runs on Linux and macOS only. On Windows, use
  WSL2 and keep the clone inside the WSL2 file system (`~/…`, not `/mnt/c/…`),
  where builds are much faster.
* **cargo-deny**, to run the dependency audit locally:
  `cargo install --locked cargo-deny`.
* Optional: **gitleaks**, which `scripts/check.sh` runs when it is installed
  (CI always runs it).

Then, once per clone:

```bash
git config core.hooksPath scripts/hooks
```

This enables `scripts/hooks/commit-msg`, which runs the attribution guard
on every commit message (see [Attribution guard](#attribution-guard)).

## First build

The first backend build compiles DataFusion, Arrow and the rest of the
dependency tree. On a 12-core machine, a cold
`cargo test --workspace --no-run` takes about six minutes and leaves about
24 GB in `backend/target/`; expect longer on fewer cores, and keep that much
disk free. Later builds are incremental.

## Everyday commands

From `backend/`:

```bash
cargo test -p <crate>            # one crate, e.g. cargo test -p platform-storage
cargo test -p platform-api --test drive_api   # one integration test file
cargo test --workspace           # everything
cargo deny check                 # advisories, licences, bans, sources
```

From `frontend/`:

```bash
npm test                         # vitest, node and jsdom projects
npm run dev                      # http://localhost:5173
npm run lint
npm audit --omit=dev --audit-level=high
```

`cargo deny` and `npm audit` otherwise run only in CI (the `dependencies`
job), so run them before pushing a dependency change. Fuzz targets have
their own instructions in [`backend/fuzz/README.md`](../backend/fuzz/README.md).
Where each kind of test goes is in [`docs/TESTING.md`](TESTING.md).

To run the API, mint a dev token, or run the sealed-query demo, follow
README [Development](../README.md#development). For the steward and
researcher lifecycle on one machine, use the
[local research stack](../README.md#local-research-stack-dev-only).

## Why check.sh failed

`scripts/check.sh` runs these steps in order and stops at the first failure.
The heading it prints (`== … ==`) names the step.

### backend: rustfmt

Code is not formatted. Run `cargo fmt --all` from `backend/` and commit the
result.

### backend: cargo check, clippy, cargo test

Every cargo command runs with `--locked`, so a `Cargo.toml` change without
the matching `Cargo.lock` fails here: run the build once without `--locked`
and commit `backend/Cargo.lock` (and `backend/fuzz/Cargo.lock`, if it
changed). Clippy runs with `-D warnings`, so every lint is an error; fix it
or, where the lint is wrong, allow it on the narrowest item with a comment
saying why.

### frontend: clean install, typecheck, lint, unit tests, production build

`npm ci` fails if `frontend/package-lock.json` does not match
`package.json`: run `npm install` and commit the lockfile. ESLint runs with
zero warnings allowed. `CONTRIBUTING.md` explains why `npm run typecheck`
can disagree with an editor.

### White-label guard

The engine's name (`quackxide`, any case) must not appear in
`frontend/dist`. It usually comes from a string literal or a comment that
survives the build. Find it with `grep -ri quackxide frontend/dist` after
`npm run build`; customer-facing names come from the `VITE_*` brand settings
instead.

### Config guards

* **Domain:** `yourdomain` appears in `backend/crates` or `frontend/src`.
  The deployment domain is configuration: it belongs in the `.env.example`
  templates, and code reads it from `platform-config` or
  `frontend/src/config/`.
* **Brand fallback:** the neutral default product name ("Confidential
  Drive") appears outside the places that define it
  (`platform-config/src/lib.rs`, `frontend/src/config/brand.ts` and its
  test). Read the name from configuration instead.

### Data guard

A tabular or binary data file (CSV, Parquet, NDJSON and the other
extensions listed in `scripts/check.sh`) is tracked outside a `fixtures/`
directory. Move it under `fixtures/`, keep it small and synthetic, and
follow `docs/DATA_POLICY.md`.

### Secret scan

gitleaks found something that looks like a credential. If it is real, do
not just delete it: follow `docs/DATA_POLICY.md` "Enforcement". If it is a
synthetic test literal, allow that exact value or path in `.gitleaks.toml`
with a comment naming the test, never a whole rule.

### Attribution guard

A tracked file, file name, or commit message credits or names a tool, in
the sense of `CONTRIBUTING.md` "Authorship". The refused terms are the
`PATTERN` in `scripts/attribution-guard.sh`; they are not repeated here,
because the guard scans every tracked file except that script. The guard
prints the matching file and line. The `commit-msg` hook runs the same
check on each commit message, so a refused message never becomes a commit;
reword it and commit again.

## Where to start reading

| `docs/ARCHITECTURE.md` section | Start at |
| --- | --- |
| [Drive](ARCHITECTURE.md#1-drive-zero-knowledge-storage) | `frontend/src/lib/crypto/worker.ts`, then `frontend/src/lib/vault/`; server side, `authenticate` and `require_tenant` in `backend/crates/platform-api/src/lib.rs` |
| [Connectors](ARCHITECTURE.md#2-connectors-confidential-ingress) | `EnclavePipeline` in `backend/crates/platform-connectors/src/pipeline.rs` |
| [Query](ARCHITECTURE.md#3-query-zero-trust-analytics) | `backend/crates/platform-api/src/query.rs`, then `backend/crates/quackxide-engine/` (`QueryScope` in `src/lib.rs`, the gate in `src/policy.rs` and `src/disclosure.rs`) |
| [Research access](ARCHITECTURE.md#4-research-access-two-principals) | `backend/crates/platform-api/src/research.rs`, then `backend/crates/platform-tenancy/` |

## Glossary

Terms the architecture and threat model use without defining:

* **Access, `preauth` and `refresh` tokens** — the `typ` claim of a platform
  token (`TokenType` in `backend/crates/platform-auth/src/lib.rs`): `preauth`
  is issued after sign-in and before the second factor, `refresh` only buys a
  new access token, and only `access` passes the API
  ([threat model, A3](THREAT_MODEL.md#a3-external-attacker)).
* **`tid`** — the token claim that carries the tenant id; the API's only
  source of tenant identity ([Drive](ARCHITECTURE.md#1-drive-zero-knowledge-storage)).
* **Blind index** — a keyed HMAC of a value (`blind_index` in
  `platform-crypto`), so equality lookups work over ciphertext without
  revealing the value ([trust model](ARCHITECTURE.md#trust-model-in-one-paragraph)).
* **`ZkMode`** — whether a query passes the disclosure gate (aggregate-only
  plans and cohort suppression); `Enabled` by default, forced on for
  research queries ([Query](ARCHITECTURE.md#3-query-zero-trust-analytics)).
* **`QueryScope`** — the query engine's per-query context, which drops every
  decrypted table when the query ends
  ([Query](ARCHITECTURE.md#3-query-zero-trust-analytics)).
* **MoR** — merchant of record: the payment provider (Paddle) whose signed
  webhooks provision and suspend tenants (`platform-billing`;
  [crate boundaries](ARCHITECTURE.md#crate-boundaries-backendcrates)).
* **TOTP** — the time-based one-time code (RFC 6238) used as the second
  factor (`platform-crypto/src/totp.rs`;
  [threat model, A3](THREAT_MODEL.md#a3-external-attacker)).
