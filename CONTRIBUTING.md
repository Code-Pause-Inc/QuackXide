# Contributing to QuackXide

Read `README.md`, `docs/ARCHITECTURE.md`, and `docs/THREAT_MODEL.md` before
changing anything. The current release scope and its definition of done are
in `docs/PROJECT_SCOPE.md`.

## Setup

Follow `docs/DEVELOPMENT.md`: prerequisites (including WSL2 on Windows),
the git hooks, everyday commands, running `cargo deny` and `npm audit`
locally, and what to do when `scripts/check.sh` fails.

The frontend needs the browser envelope module, built by
`scripts/build-wasm.sh` (see "Development" in `README.md` for the
`wasm-bindgen` CLI it needs).

## Before every push

Run `scripts/check.sh`. It builds and tests the backend and frontend, lints
both with warnings as errors (clippy for the backend, ESLint via `npm run lint`
for the frontend), and runs the white-label, config, data, and attribution
guards. "Why check.sh failed" in `docs/DEVELOPMENT.md` covers each step.

`typescript-eslint` does not support TypeScript 7 yet, so in `frontend/` the
`typescript` package is an alias for `@typescript/typescript6` (the TS 6 API
it loads) and TS 7 is installed as `typescript7`. `npm run typecheck` and
`npm run build` call TS 7 explicitly, because both packages provide a `tsc`
command. An editor that uses the workspace TypeScript version gets TS 6, so
it can differ slightly from `npm run typecheck`; use the editor's bundled
TypeScript, or trust `npm run typecheck`.

## Continuous integration

Every pull request runs:

* `check.sh` on Linux, and the test suites on Linux ARM and macOS;
* CodeQL code scanning (Rust, TypeScript, workflows);
* dependency review, `cargo-deny` (advisories, licenses, sources), and
  `npm audit`;
* the attribution guard over files and commit messages;
* a default-feature release build of `platform-api`, which fails if it
  contains the dev-only `devstack` binary;
* a build of every fuzz target (`backend/fuzz/`), which also fails if
  `backend/fuzz/Cargo.lock` is stale;
* a gitleaks secret scan of the full history, diffs and commit messages,
  which also runs on every push to every branch;
* a coverage report in the job summary;
* when `backend/` or `rust-toolchain.toml` changes, the benchmarks in
  `docs/BENCHMARKS.md` at the base commit and the head, in one job, in the
  job summary; a benchmark significantly more than 10 % slower is flagged
  as a warning, and the job fails only when the comparison cannot run (not
  a required check). The browser timings in Chromium are compared the same
  way when their code or the browser envelope module changes;
* when the browser envelope module or `backend/` changes, the wasm envelope
  seal in Chromium (`docs/BENCHMARKS.md`), in the job summary (report only,
  never fails on the numbers);
* the browser tests (`npm run test:browser`) in Chromium. Pushes to `main`
  and a nightly run add Firefox and WebKit.

Every cargo build, check, clippy and test command runs with `--locked`, so
commit `Cargo.lock` (and `backend/fuzz/Cargo.lock`, which a workspace
dependency change can also move) with any `Cargo.toml` change.

Fuzz targets compile on every pull request and run weekly, and the OpenSSF Scorecard tracks
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
  covered by `platform-api/tests/audit_coverage.rs`. `docs/TESTING.md`
  says where each test goes and how to name it.
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
  any code a tool helped produce. AI tools are never credited: no AI tool
  names, Assisted-by trailers, AI co-author lines, or "generated" footers
  in files, commit messages, or pull requests. `Co-authored-by:` lines for
  teammates who paired on a change are welcome.
* **Pull requests** target `main`, describe what changed and why, and are
  squash-merged after review and a passing `scripts/check.sh`.
* **Design decisions** that change a trust boundary, a cryptographic
  suite, a wire or storage format, the disclosure gate, or a public API
  are recorded in `docs/adr/` in the same pull request.
* **Docs** describe the current state of the system, not the history of
  changes to it. Update `docs/` and `README.md` in the same pull request as
  the change they describe, and add a line to `CHANGELOG.md` under
  "Unreleased".

## Reviews

`main` requires one approval, a code owner's review for paths in
`.github/CODEOWNERS`, approval from someone other than the last pusher,
resolved review threads, and passing required checks. A push dismisses
earlier approvals. Pull requests merge through the merge queue, which runs
the required checks on each one against the latest `main`, so nobody needs
to update a branch by hand.

* **Two stages.** A core-team peer reviews first: correctness, tests and
  docs. A code owner then reviews the code-owned paths.
* **The peer is not an author.** The approving peer authored no commits in
  the pull request; a pair partner's approval does not count toward the
  peer stage.
* **Code owners comment, they do not push.** A push to someone else's
  branch makes the pusher the last pusher, and their approval stops
  counting.
* **Security changes stay small,** so the code-owned part can be reviewed
  on its own.
* **ADR numbers are reserved in the issue** before drafting starts, so
  parallel ADR pull requests do not collide.
* **Dependabot.** One person per weekly batch, on the rota in #29:
  * reviews and merges the grouped minor and patch updates once CI passes,
    and asks Dependabot to update a pull request with a
    `@dependabot rebase` comment, never the "Update branch" button, which
    would make them the last pusher;
  * leaves `actions` updates, which touch the code-owned `.github/`, for a
    code owner after a peer approval;
  * does not merge a major-version update, alone or inside a group; it goes
    to the owning stream's primary reviewer, and the maintainer decides.

## Credit

Add yourself to `CONTRIBUTORS.md` in your first pull request, under
"Contributors". The founder and the USF core contribution team are listed
above all other contributors.

## Conduct

Participation is governed by `CODE_OF_CONDUCT.md`.

## Security issues

Do not open a public issue for a vulnerability. Follow `SECURITY.md`.

To fix a vulnerability privately, whoever found it:

1. The maintainer opens a draft repository security advisory, adds the
   person fixing it as a collaborator, and writes the problem and what
   done means in the advisory's description.
2. The fix is made in the advisory's temporary private fork, in one pull
   request to its `main`.
3. Required checks do not run in a temporary private fork, so the pull
   request carries the local output of `scripts/check.sh`, `cargo deny
   check` (from `backend/`) and `npm audit --omit=dev --audit-level=high`
   (from `frontend/`), and a second core-team member reviews it in the
   fork.
4. The maintainer merges it from the advisory. That merge does not apply
   the `main` ruleset, so the maintainer then confirms that the `ci` run
   on the push to `main` passes, and fixes any failure at once.
5. The advisory is published when the fix merges, and the reporter is
   credited in `CHANGELOG.md`.

## License

QuackXide is dual-licensed under Apache-2.0 or MIT, at your option (see
`LICENSE-APACHE`, `LICENSE-MIT`, and `NOTICE`). By submitting a
contribution you agree that it is licensed under the same terms.
