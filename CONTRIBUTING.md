# Contributing to QuackXide

Read `README.md`, `docs/ARCHITECTURE.md`, and `docs/THREAT_MODEL.md` before
changing anything. The current release scope and its definition of done are
in `docs/PROJECT_SCOPE.md`.

## Setup

* Backend: Rust, pinned in `rust-toolchain.toml` (rustup installs it on
  first use), from `backend/`.
* Frontend: Node, pinned in `.nvmrc`, from `frontend/`.
* Enable the repository's git hooks once per clone:

  ```bash
  git config core.hooksPath scripts/hooks
  ```

See "Development" in `README.md` for running the API and frontend locally.

## Before every push

Run `scripts/check.sh`. It builds, lints (clippy with warnings as errors),
and tests the backend and frontend, and runs the white-label, config, data,
and attribution guards.

## Continuous integration

Every pull request runs:

* `check.sh` on Linux, and the test suites on Linux ARM and macOS;
* CodeQL code scanning (Rust, TypeScript, workflows);
* dependency review, `cargo-deny` (advisories, licenses, sources), and
  `npm audit`;
* the attribution guard over files and commit messages;
* a coverage report in the job summary.

Fuzz targets (`backend/fuzz/`) run weekly, and the OpenSSF Scorecard tracks
the repository's supply-chain posture. Tagged releases are built from
`check.sh`-verified sources with signed build provenance.

## Rules for code

* **Fail closed.** Missing key material, unverifiable attestation, and
  malformed input are refused, never defaulted.
* **No invented cryptography.** Use RustCrypto, `hpke`, and Web Crypto.
  Keep suites behind their single type aliases and version the encrypted
  framing when a suite changes.
* **No `unsafe`.** The workspace denies it.
* **A test for every failure path.** Every new refusal gets a negative
  test, and every new security decision emits a `SECURITY_AUDIT_EVENT`
  covered by `platform-api/tests/audit_coverage.rs`.
* **Audit events carry identifiers and outcomes only** — never key
  material, plaintext, filenames, or SQL text.
* **Synthetic or public data only.** See `docs/DATA_POLICY.md`.

## Branches, commits, and pull requests

* **Branch names** are short, plain-language descriptions of the work:
  `sev-snp-report-verification`, `durable-grant-registry`,
  `hybrid-ml-kem-envelopes`.
* **Commit messages** follow Conventional Commits (`feat:`, `fix:`,
  `docs:`, `test:`, `refactor:`, `chore:`) and are short.
* **Authorship.** The developer who submits a change is its author and is
  accountable for it, including the accuracy, security, and licensing of
  any code a tool helped produce. Tools are never credited: no tool names,
  tool trailers, co-author lines for tools, or "generated" footers in
  files, commit messages, or pull requests.
* **Pull requests** target `main`, describe what changed and why, and are
  squash-merged after review and a passing `scripts/check.sh`.
* **Design decisions** that change a trust boundary, a cryptographic
  suite, a wire or storage format, the disclosure gate, or a public API
  are recorded in `docs/adr/` in the same pull request.
* **Docs** describe the current state of the system, not the history of
  changes to it. Update `docs/` and `README.md` in the same pull request as
  the change they describe, and add a line to `CHANGELOG.md` under
  "Unreleased".

## Credit

Add yourself to `CONTRIBUTORS.md` in your first pull request, under
"Contributors". The founder and the USF core contribution team are listed
above all other contributors.

## Conduct

Participation is governed by `CODE_OF_CONDUCT.md`.

## Security issues

Do not open a public issue for a vulnerability. Follow `SECURITY.md`.

## License

QuackXide is dual-licensed under Apache-2.0 or MIT, at your option (see
`LICENSE-APACHE`, `LICENSE-MIT`, and `NOTICE`). By submitting a
contribution you agree that it is licensed under the same terms.
