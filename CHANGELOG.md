# Changelog

All notable changes to QuackXide are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

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
