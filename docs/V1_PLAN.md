# QuackXide v1.0 plan

The work that takes QuackXide from v0.1.0 to its first production release (`docs/PROJECT_SCOPE.md`), as plan items P1-P83. Each item is, or will become, one GitHub issue in the `v1.0 - first production release` milestone; [Posted issues](#posted-issues) maps items to issue numbers. Items are posted in waves: wave 1 (team setup, the week 1-3 decisions and small security items) is posted, and the rest follow once the decisions they depend on are recorded. P20-P23 are unused: those four security fixes are merged (see "Security defects found in review"). Every claim cites a repository path and line, or quotes the docs; items that propose new files say so. Record each "Depends on" line as a GitHub "blocked by" relationship when the item is posted.

**Milestone.** `v1.0 - first production release`, for all issues in this file except the final section ("Proposed outside v1.0"). Set its due date once the maintainer confirms the calendar and makes the week-3 capacity decision ("Capacity check first"): the blocker work does not fit the Fall 2026 semester (`docs/PROJECT_SCOPE.md`, "Team and timeline"), so the date falls after it.

**Labels.**
- Work type: `build` (does not exist yet), `harden` (it means "exists, needs production-grade completion", per `docs/PROJECT_SCOPE.md`), area labels `area:auth`, `area:crypto`, `area:enclave`, `area:disclosure`, `area:storage`, `area:frontend`, `area:ops`, plus `area:engine` (query execution and the DataFusion stack, as opposed to the disclosure gate), `needs-adr` (the change must record a decision in `docs/adr/` in the same PR, per `CONTRIBUTING.md:71-73` and `docs/adr/README.md:7-9`), and `tracking` (checklist issues that close at release).
- Existing, reused: `rust`, `javascript`, `good first issue`, `documentation`.

**Conventions in every issue.**
- **Size:** S = one person up to about 2 weeks; M = one or two people for 2-5 weeks; L = larger (none in this revision; anything that size is split). "Pair" marks issues that need two people.
- **Depends on** lists hard dependencies only (the issue cannot close without them); **Sequencing** holds soft ordering and coordination notes.
- **Priority:** *v1 blocker* (delivers a definition-of-done item directly, including a lifecycle step that DoD item 3 requires to be Built, or is a listed hard dependency of a v1 blocker), *v1 needed* (needed for a production-grade v1.0 per the engineering goals), *team enablement* (setup, tooling, process; these keep their label when a blocker depends on them, and are scheduled in weeks 1-3).
- **Target:** semester weeks; P5 converts them to calendar dates.
- **Security impact** names the invariant touched; **ADR** says whether a decision record is required.
- Every pull request completes the checklist in `.github/pull_request_template.md` (negative tests, `audit_coverage.rs`, fail closed, no new cryptographic primitives, docs and `CHANGELOG.md`, ADR, synthetic data only; `CONTRIBUTING.md:76-77` puts the CHANGELOG line under "Unreleased"). Issues list only what is specific to them.
- Code-owned paths (`.github/CODEOWNERS`) need @AxolDad's review; P4 sets the process.


## Posted issues

| Plan item | Issue | Title |
| --- | --- | --- |
| P1 | #25 | Fix the documented backend run commands |
| P2 | #26 | Core-team onboarding (one copy per team member) |
| P3 | #27 | Developer setup guide and "why check.sh failed" |
| P4 | #28 | Review process and code-owner coverage |
| P5 | #29 | v1.0 plan and dependency graph (pinned tracking issue) |
| P6 | #30 | Testing guide: layers, conventions, and what CI cannot exercise |
| P7 | #31 | Same-origin API access from the browser in development |
| P8 | #32 | Local research stack: one dev-only server with research routes wired and seeded data |
| P9 | #33 | Seeded synthetic research-dataset generator |
| P10 | #34 | Shared API test helpers |
| P11 | #35 | Frontend lint in check.sh |
| P12 | #36 | SEV-SNP cloud environment, team access and budget |
| P13 | #37 | Accounts beyond GCP: sign-in provider, staging domain and synthetic test identities |
| P14 | #38 | ADR 0004: key custody and attested key release |
| P15 | #39 | ADR 0005: query and deployment topology |
| P16 | #40 | ADR 0006: sign-in, identity and token signatures |
| P17 | #41 | ADR 0007: hybrid suite construction, libraries, browser key storage and migration |
| P18 | #42 | Production mode: one switch, and refuse dev-only paths at startup |
| P19 | #43 | Record what is not in v1.0: connector ingestion, billing lifecycle, admin toggles and other documented features |
| P24 | #44 | `EngineSettings::default()` and `ZkMode::default()` must fail closed |
| P25 | #45 | Audit stream always on; no SQL or data values in operational logs |
| P26 | #46 | Zeroize platform credentials held in configuration |
| P27 | #47 | Access-request approval converges after a partial failure, and never fails open |

Items not listed are not posted yet.

---

## Suggested order

### Capacity check first

Summing the sizes in this file gives roughly 187-237 person-weeks of work (S about 1.5, S-M about 2-3, M about 3-4, M-L about 5-6), of which the v1-blocker issues alone are about 142-187. Four people over one 15-week semester is about 60 person-weeks before reviews, coursework and onboarding, and the repository went public on 2026-09-30, so fewer than 15 weeks may remain. Blocker work alone is about 2.4 to 3.1 times the semester's capacity, so the definition of done does not fit one semester for four students. That is a planning fact, not a reason to cut security work silently. The maintainer decides by the end of week 3, and records in P5:
- **Required:** extend the v1.0 milestone past the semester, with this semester's target being definition-of-done items 1-2 demonstrated on staging hardware. Do not trim DoD items 5-9 by deferring their issues; descoping any of them needs a maintainer-approved change to `docs/PROJECT_SCOPE.md`.
- **Optional:** move named v1-needed issues to a v1.1 milestone. Candidates that no definition-of-done item depends on: P42, P60, P71 (with its manual fallback), P37 (via the superseding-ADR option in P16) and P53, about 12-17 person-weeks. Three more can move only with matching edits, together about 7-10 person-weeks:
  - P59: P44 shows only the SQL table name (the connector slug, double-quoted where needed) and a `SELECT COUNT(*) AS n` example, and P62 drops the dictionary fields.
  - P72: P82's evidence for items 1-2 becomes a manual browser run on staging, recorded under the acceptance checklist, and P6 names that manual run as the acceptance test.
  - P81: P83 drops it, and P68 takes the item "the release artifact list includes every binary P68 runs".
- **Not candidates:** P65 and P66 are v1 blockers because P68 depends on them. P65's timeouts and panic handling may be split off and deferred, but its CSP, security headers and any CORS allowlist stay in v1. P66 leaves the milestone only if the maintainer chooses per-deployment frontend builds, recorded in `docs/`, with P68's dependency changed to that decision in the same edit.
- **Optional:** have the maintainer own critical-path items directly (for example P12, P14, P49, P68).

### Critical path

The longest chain is hardware and key custody, and it starts with decisions only the maintainer can make:

P12 phase A (week 2) → P14 (accepted by week 3; includes the workload-identity decision) → P47 (from week 2, off-hardware; closes on P12 phase B's fixtures) → P48 (also needs P12's hardware) → P50 → P51 → P68 → P82 → P83. P49 (after P12, P14 and P15) feeds P68 directly; P15 (accepted by week 3) feeds P49, P55, P65, P67 and P68.

Chains that feed it and must finish by about week 12:
- Sealed results: P14 → P33 → P55 → P56. P33 needs P31 (the session token and `tid` in the crypto worker) and P41's conditional-write PR (week 3-4), not the identity service, so this chain runs in parallel with P29.
- Hybrid suite for DoD item 1: P17 → P34 (seal by week 5) and P35 (after P73's `HPK1` baseline) → P36 → P40 closes. P36 also needs P33, so it too waits on P14, P31 and P41's conditional-write PR, not on the identity service. P35 also feeds the main path at P50, which must wrap released keys with the hybrid suite before it closes.
- Steward upload for DoD item 1: P38 → P39 → P40. P38 reuses the versioned-snapshot layout already merged on `main` (ADR 0003); its remaining hard dependencies are P14 and P69.
- Sign-in, which DoD items 1 and 2 both begin with: P16 and P13 (provider development tenant by week 4) → P29 → P30 → P32, which P40 needs to close and P82 runs end to end; P29 and P30 → P63 → P68. A dated week-7 checkpoint in P5 watches P29.
- Durable state: P61 and P27 → P62 → P51; P62's first PR, P29 and P30 → P63 → P68. Sign-in (P29, P30, P63, P32) still gates P68 and P82 directly, so the split frees P51's integration, not the release date.
- HTTP edge: P15 → P65 → P67 (which also needs P18, and P75 if TLS terminates in the VM) → P68, with P66's bundle and the staging domain from P13 by week 8.

### Weeks 1-3: unblocked work for all four people from day one

Everyone, week 1: P2 (one small PR each through the full ruleset).

- **Student A (identity and frontend):** P1, P7, P11, then drafts P16; P31 from week 3.
- **Student B (crypto and sealing):** drafts P17; starts P34 checkpoint A (seal on the current `HPK1` suite needs no decision); P41's conditional-write PR, merged by week 3-4 (needed by P33); P10.
- **Student C (enclave and operations):** P46; drafts P15 and the options memo for P14 with the maintainer; starts P47 against a synthetic certificate chain; the scripts and the attestation-fixture capture in P12 phase B (by week 4).
- **Student D (data and disclosure):** P9, P8; pairs with another student on P69 from week 2.
- **Maintainer:** P4 (the CODEOWNERS fix and the private-fix procedure first), P5 (including the week-3 capacity decision), P19, P12 phase A (including vTPM and attestation-service support for P14), P13's team secret store (weeks 1-2) and the rest of P13 once P16 names the provider, co-owning P14, reserving ADR numbers, the review rota and the weekly Dependabot rotation (P4).
- Also unblocked, for whoever finishes early: P3, P6 (with the maintainer), P80, P24, P25, P26, P70, P45, P79, P43, P18, P61, P27, P75, P57 (the ADR part).

### Phase plan

- **Weeks 1-3, foundations and decisions.** Everything above. All five ADRs (P14 with its workload-identity decision, P15, P16, P17, and the mechanism in P18) accepted by the end of week 3; ADR-only PRs may merge ahead of code. The maintainer records the capacity decision in P5.
- **Weeks 4-8, build the parts.** P12 phase B's fixtures (week 4), the P13 development tenant (week 4), P18, P43, P31, P61 then P62, P28, P29, P34, P35 (after P69 merges, never concurrently), P47, P48, P49, P44 on the local stack, P38, P41, P54, P57, P75, the P73 baseline before P35 merges, P72 stage A, and P65 and P67 from week 6.
- **Week 6 checkpoint (dated in P5).** Does P47 verify P12's recorded reports (and the synthetic chain), and does a Confidential VM from P12 reach the "device present" branch? If not, the maintainer decides the fallback then, not in week 12.
- **Week 7 checkpoint (dated in P5).** Do P29's token exchange and tenant membership work against the provider's development tenant from P13? If not, the maintainer decides the fallback then (for example moving MFA to the provider to shrink P30, or co-owning P29).
- **Weeks 8-12, integrate.** The P13 staging domain (week 8), P50, P33, P30, P63, P32, P36, P39, P40, P55, P56, P58, P52 then P53, P60, P59, P66, P37, P42, P71, P81.
- **Weeks 11-15, deploy, operate, accept.** P51, P68 (with the independent deploy run for DoD item 5 by week 13), P64, P76, P77 (with the restart-and-failure drill), P74, P72 stage B on staging, P82, P83. P78 closes with P82.

### Work streams (one primary student owner each, plus a named secondary reviewer)

1. **Identity and frontend:** P1, P3, P7, P11, P16, P18, P28, P29, P30, P31, P32, P63, P44, P66, P72.
2. **Crypto and sealing:** P10, P6 (with the maintainer), P26, P70, P17, P34, P35, P36, P37, P33, P40, P55, P56, P41, P39, P42.
3. **Enclave and operations:** P46, P15, P47, P48, P49, P50, P51, P68, P67, P71, P75, P76, P77, P64, P74, P65, P81.
4. **Data and disclosure:** P9, P8, P24, P25, P27, P43, P38, P45, P52, P53, P54, P57, P58, P59, P60, P61, P62, P69, P73.

Streams 3 and 4 are the largest; P69, P62, P29, P50 and P77's restart-and-failure drill are paired work and should borrow a second person, and P63 pairs stream 1 with whoever built P62. Shared by all streams: P2 (everyone, week 1), P78 and P79 (each stream adds tests for its own refusals), P80, and the docs each PR changes. Maintainer: P4, P5, P19, P12 phase A, P13, P14 (co-owned with stream 3), ADR acceptance, all code-owner reviews, P82 with a release owner, and P83.

---

## Start here: team setup, process and environments

### P1. Fix the documented backend run commands
**Labels:** harden · area:ops · rust · good first issue
**Size:** S · **Priority:** team enablement · **Target:** week 1

**Summary.** The first backend command a new contributor runs fails on a clean checkout. `cargo run -p platform-api` (`README.md:115` and `:129`) stops with "could not determine which binary to run", because the package has three binaries (`src/main.rs`, `src/bin/devtoken.rs`, `src/bin/query-demo.rs`) and no `default-run`. The end-to-end steps also export `JWT_HS256_SECRET` in terminal 1 and run `devtoken` in terminal 2; the new shell reads `backend/.env`, where the template ships the secret empty (`backend/.env.example:55`), so `devtoken` refuses.

**Done when**
- `default-run = "platform-api"` is set in `backend/crates/platform-api/Cargo.toml` (or the README passes `--bin platform-api`), and every README "Development" command works from a clean clone.
- README "End-to-end locally" tells the reader to put the generated secret in `backend/.env` (gitignored), so `devtoken` in a second terminal mints tokens the API accepts.
- The PR description states that every README command was run from a clean clone on Linux and on macOS.

**Where.** `backend/crates/platform-api/Cargo.toml`, `README.md` (lines 109-136).

**Depends on:** none.

**Security impact.** None; documentation and build metadata only.
**ADR.** Not required.

---

### P2. Core-team onboarding (one copy per team member)
**Labels:** documentation · good first issue
**Size:** S · **Priority:** team enablement · **Target:** week 1

**Summary.** Each of the four core-team members gets a working toolchain and lands one small pull request through the full ruleset (peer approval, CI, squash merge) before feature work starts. `CONTRIBUTORS.md:16-19` lists the four members without the GitHub handle that its own entry format requires (`CONTRIBUTORS.md:23`).

**Maintainer prerequisite (@AxolDad, before assignment).** Add the four members to the repository with write access. They need it to be assigned, to push branches, and for their approvals to count toward the required review.

**Done when**
- Git hooks are enabled (`git config core.hooksPath scripts/hooks`) and `scripts/check.sh` passes on your machine. check.sh is bash, so Windows users run it in WSL2.
- The README "Development" flow works for you, from the API and frontend through `devtoken` to `cargo run -p platform-api --bin query-demo` (needs openssl; `README.md:121-133`, after P1).
- Any editor or tool you use is configured not to add co-author or "generated" lines; `CONTRIBUTING.md:63-68` forbids them, and the commit-msg hook and the CI attribution guard refuse them.
- Your first pull request adds `(@handle)` to your entry in `CONTRIBUTORS.md:16-19`, with a Conventional Commits message (`docs: ...`). It gets a teammate's approving review, passes CI, and is squash-merged. These four PRs touch adjacent lines, so expect to rebase after a teammate's merge.
- You have read README, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md` (required by `CONTRIBUTING.md:3-5`), `docs/PROJECT_SCOPE.md`, `docs/DATA_POLICY.md` and `SECURITY.md`, and told the maintainer which work stream you will review first (P4).

**Where.** `CONTRIBUTORS.md`.

**Depends on:** none.

**Sequencing.** P1 makes the run step smoother.

**Security impact.** None.
**ADR.** Not required.

**Notes.** The nightly toolchain and `cargo-fuzz` are needed only by whoever works on fuzz targets (`backend/fuzz/README.md`).

---

### P3. Developer setup guide and "why check.sh failed"
**Labels:** documentation · area:ops · good first issue
**Size:** S · **Priority:** team enablement · **Target:** weeks 1-2

**Summary.** The setup section of `CONTRIBUTING.md` (lines 7-18) is three bullets that point to the README, and `docs/` has no development guide. CI never runs on Windows and the scripts are bash. `cargo deny` and `npm audit` run only in CI (the `dependencies` job, `.github/workflows/ci.yml:56-70`), so licence and advisory failures appear only after a push. Several `scripts/check.sh` guards are easy to trip by accident.

**Done when**
- `docs/DEVELOPMENT.md` exists and `CONTRIBUTING.md` "Setup" links to it instead of repeating it. It covers:
  - prerequisites: rustup (the toolchain in `rust-toolchain.toml` installs itself), Node from `.nvmrc`, openssl; on Windows, WSL2;
  - how long the first build takes;
  - running one crate's tests (`cargo test -p <crate>` from `backend/`), `npm test` and `npm run dev` from `frontend/`;
  - running `cargo deny check` from `backend/` and `npm audit --omit=dev --audit-level=high` from `frontend/` before pushing;
  - a link to `backend/fuzz/README.md` (not a copy of it).
- It links to the README "Development" section for running the API, `devtoken` and `query-demo`, and to the local stack from P8 once that lands.
- A "Why check.sh failed" section covers each step: rustfmt; clippy with `-D warnings`; the white-label guard (engine name in `frontend/dist`); the domain and brand-fallback config guards; the data guard (`fixtures/` only); and the attribution guard and the `scripts/hooks/commit-msg` hook that runs it. For the attribution guard it points to the pattern in `scripts/attribution-guard.sh` and to `CONTRIBUTING.md` "Authorship" and does not list the refused words, because the guard scans every tracked file except its own script.
- A short "Where to start reading" map links the dataflow sections of `docs/ARCHITECTURE.md` to their entry files: `frontend/src/lib/crypto/worker.ts`, `frontend/src/lib/vault/`, the middleware in `backend/crates/platform-api/src/lib.rs`, `backend/crates/platform-api/src/query.rs`, `backend/crates/quackxide-engine/`, `backend/crates/platform-tenancy/`.
- A short glossary, one line per term with a link to where `ARCHITECTURE.md` or `THREAT_MODEL.md` defines it, for terms used but not defined there (for example the `preauth` token type in `backend/crates/platform-auth/src/lib.rs`). P47 adds the SEV-SNP terms (VCEK, launch measurement) when it lands.
- Each core-team member follows the guide on their own machine (including on WSL2 if anyone uses Windows), reaches a passing `scripts/check.sh` and a local `cargo deny check`, and fixes whatever was wrong.

**Where.** New `docs/DEVELOPMENT.md`; `CONTRIBUTING.md`.

**Depends on:** none.

**Security impact.** None.
**ADR.** Not required.

**Notes.** A `.devcontainer/` that pins the same toolchains is optional. A crate-level code walkthrough is not needed; it would duplicate `docs/ARCHITECTURE.md`.

---

### P4. Review process and code-owner coverage
**Labels:** harden · area:ops
**Size:** S · **Priority:** team enablement · **Owner:** @AxolDad · **Target:** week 1

**Summary.** The `main` ruleset requires code-owner review, approval from someone other than the last pusher, dismissal of stale approvals on push, strict up-to-date status checks and resolved review threads, with squash merges only. @AxolDad is the only code owner, and roughly half of this milestone touches code-owned paths, so without a written process reviews will be the bottleneck. Separately, `.github/CODEOWNERS:12` names `/deny.toml`, which matches no file (the file is `backend/deny.toml`), and several files that make security decisions have no owner: the gating decision in `backend/crates/quackxide-engine/src/lib.rs`, `EnclaveKeyProvider` and the grant/budget path in `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-tenancy/src/grants.rs` and `budget.rs`, `main.rs`, which decides what production runs with, the auth middleware in `platform-api/src/lib.rs`, `docs/THREAT_MODEL.md` and `docs/adr/`. Finally, `SECURITY.md:8-9` bars public issues, discussions and pull requests for a vulnerability, but `CONTRIBUTING.md` ("Security issues", lines 89-91) only points to `SECURITY.md`, so the team has no written path for fixing privately a vulnerability it finds.

**Done when**
- **First, on its own PR:** `/deny.toml` becomes `/backend/deny.toml`. A test PR touching only `backend/deny.toml` requests @AxolDad. This lands before P69, which edits that file.
- The maintainer decides which further paths to own and records the choice in `CODEOWNERS`. Candidates: `/backend/crates/quackxide-engine/src/` (replacing the two single-file lines), `/backend/crates/quackxide-engine/tests/bypass.rs`, `/backend/crates/platform-api/src/` (or at least `query.rs`, `main.rs` and `lib.rs`), `/backend/crates/platform-api/tests/audit_coverage.rs`, `/backend/crates/platform-tenancy/src/`, `/docs/THREAT_MODEL.md`, `/docs/adr/`, `/deploy/`. Prefer directories, so new modules from P50, P62, P63 and P58 are covered. Weigh each against review load.
- Every CODEOWNERS pattern matches at least one tracked path, checked against `git ls-files` (by hand or as a small `scripts/check.sh` step). GitHub's CODEOWNERS error view does not flag patterns that match nothing.
- `/deploy/` will hold the workload image definition (P49), the deployment procedure and secret wiring (P68) and the audit-sink routing (P64); the published attestation values come from `.github/workflows/release.yml`, which `/.github/` already covers. Because every pattern must match a tracked path, the `/deploy/ @AxolDad` line lands in the P12 phase B PR that creates the directory. If review load on the dev-VM scripts is a concern, the maintainer may defer it to the first P49 PR, which adds the image definition.
- `CONTRIBUTING.md` gains a "Reviews" section that the repository settings match:
  - Two-stage review: a core-team peer first (correctness, tests, docs), then @AxolDad for code-owned paths. The maintainer states a turnaround (for example two working days) and a weekly review block.
  - The approving peer review comes from a core-team member who authored no commits in the PR; a co-author's approval does not count toward the peer stage. (The ruleset only excludes the last pusher, so a pair partner could otherwise approve their own pair's work on P29, P50, P62, P69 or P77.) If the maintainer co-authors a PR, for example under P5's week-7 fallback for P29, the maintainer-authored rule below applies: a core-team non-author approves before merge, and the maintainer's code-owner approval alone does not count.
  - Code owners leave review comments instead of pushing to a contributor's branch, because a push by the only code owner then needs a second approver (`require_last_push_approval`).
  - Maintainer-authored PRs to code-owned paths: a core-team member reviews and approves first; the maintainer merges with the admin bypass only after that approval and says so in the PR. Bypass is never used to skip a failing check, an unresolved thread or a missing peer review. The alternative, a second code owner for non-security paths, is recorded if chosen.
  - Strict up-to-date checks: either document the "update branch, wait for CI, re-request review" loop, or enable a merge queue. A merge queue first needs a `merge_group:` trigger in every workflow behind a required check (`ci.yml`, `codeql.yml`, `dependency-review.yml`, `attribution-guard.yml`; none has one today) and confirmation that each required check reports on a merge-group run. Decide after the first week's PRs.
  - Security changes are kept in small PRs so the code-owned part can be reviewed on its own.
  - CHANGELOG: per-PR changelog fragments compiled at release, or the PR title as the changelog line with a periodic non-code-owned PR updating `CHANGELOG.md`. Update `CONTRIBUTING.md:76-77` and the checkbox in `.github/pull_request_template.md` to match. (A maintainer edit at merge time is a push, which triggers last-push approval.)
  - ADR numbers are reserved in the issue before drafting starts, so parallel ADR PRs do not collide.
  - Each work stream in P5 has a named primary and secondary student reviewer.
  - Dependabot opens weekly PRs for `/backend`, `/backend/fuzz`, `/frontend` and GitHub Actions (`.github/dependabot.yml`). One named person per week (a rotation listed in P5 next to the review rota):
    - reviews and merges the grouped minor and patch PRs (the `rust`, `rust-fuzz` and `npm` groups) once CI passes. They ask for an update with `@dependabot rebase`, not the "Update branch" button: whoever clicks "Update branch" becomes the last pusher, and under last-push approval their own approval stops counting;
    - leaves `actions`-group PRs, which touch the code-owned `.github/`, for @AxolDad's code-owner review after a peer approval;
    - does not merge a semver-major update, whether it arrives in its own PR "for deliberate review" (`.github/dependabot.yml:3-5`) or inside the `query-engine` or `vitest` groups, which have no update-type filter; each goes to the owning stream's primary reviewer, and the maintainer decides;
    - closes any PR that bumps `datafusion*`, `arrow*`, `parquet` or `object_store` across a major version while P69 is open, and any `hpke` major while P35 is open, with a link to that issue (optionally commenting `@dependabot ignore <name> major version`, undone after the issue merges). `.github/dependabot.yml` itself is not edited for this.
- The "Security issues" section of `CONTRIBUTING.md` (lines 89-91) gains a general procedure for fixing a vulnerability privately. It applies to anything the team finds during the semester, names no specific vulnerability, and does not go under "Reviews". It covers:
  - the maintainer opens a draft repository security advisory and adds the assignee as an advisory collaborator, who works in the advisory's temporary private fork; the advisory description holds the issue's Summary and Done when;
  - whether the required checks run in that fork, confirmed once and recorded in the procedure. If they do not: the PR attaches local output of `scripts/check.sh`, `cargo deny check` (from `backend/`) and `npm audit --omit=dev --audit-level=high` (from `frontend/`); a second core-team member reviews in the fork; the maintainer merges; and the maintainer confirms that the `ci` run triggered by the push to `main` (`.github/workflows/ci.yml:3-5`) passes, fixing any failure at once;
  - the advisory is published when the fix merges, and the reporter is credited in `CHANGELOG.md` (`SECURITY.md:23-24`).
- Optional: a "Work item" issue template (Summary, Done when, Where, Depends on, Security impact) that applies no `enhancement` label, and bug-template areas aligned with the area labels.

**Where.** `.github/CODEOWNERS`, `CONTRIBUTING.md`, `.github/pull_request_template.md`, optionally `.github/ISSUE_TEMPLATE/` and the workflow `on:` blocks.

**Depends on:** none.

**Security impact.** Restores maintainer review of the dependency-advisory policy, brings the grant, budget, key-release, auth and deployment decisions under code-owner review, and gives privately reported defects a fix path that keeps peer review.
**ADR.** Not required.

---

### P5. v1.0 plan and dependency graph (pinned tracking issue)
**Labels:** tracking
**Size:** S (ongoing) · **Priority:** team enablement · **Owner:** @AxolDad · **Target:** week 1, then weekly

**Summary.** One pinned issue that holds the plan from the "Suggested order" section of this document, with real issue numbers, so slippage on the hardware and key-release path shows early.

**Done when**
- The issue holds a task list of every issue in the milestone, grouped by work stream, each with an assignee and a target week written as a calendar date. The milestone due date comes from the week-3 capacity decision below. The semester's own end (the last week of Fall 2026, confirmed with the maintainer; the repository went public on 2026-09-30, so fewer than 15 weeks may remain) is recorded next to it as this semester's target for definition-of-done items 1-2.
- Every "Depends on" line in this milestone is also recorded as a GitHub "blocked by" relationship or sub-issue link. Where a Depends line names only one item or PR of another issue (for example P41's conditional-write PR, or "P38 (its ADR ...)"), that item gets its own sub-issue and the "blocked by" link points at it, so the graph shows work that can close on time.
- A dated week-6 checkpoint records whether P47 verifies P12's recorded reports (and the synthetic chain) and a Confidential VM boots with `/dev/sev-guest` (P12), and any scope fallback the maintainer decides.
- A dated week-7 checkpoint records whether P29's token exchange and tenant membership work against the provider's development tenant (P13), and the fallback the maintainer decides if they do not (for example moving MFA to the provider to shrink P30, or the maintainer co-owning P29).
- By the end of week 3 the issue records the capacity decision from "Capacity check first": the extended milestone date, and any v1-needed issue moved to v1.1 together with its matching edits.
- The review rota and the weekly Dependabot rotation from P4 are listed with names.
- The plan is updated when an issue is split, merged or moved out of the milestone.

**Where.** GitHub only (issue, milestone description).

**Depends on:** none.

**Security impact.** None.
**ADR.** Not required.

---

### P6. Testing guide: layers, conventions, and what CI cannot exercise
**Labels:** documentation · area:ops
**Size:** S · **Priority:** team enablement · **Target:** weeks 1-2 (drafted with the maintainer)

**Summary.** The test layers exist but are not written down, and four people need one convention for the negative tests and audit assertions that definition-of-done item 8 requires. Some things cannot run in CI (SEV-SNP hardware, the managed sign-in service, GCS), and the substitute for each should be decided once.

**Done when**
- A "Testing" section in `CONTRIBUTING.md`, or a short `docs/TESTING.md` linked from `CONTRIBUTING.md:49-51`, gives each existing layer its location and a file to copy:
  - crate unit tests;
  - API integration tests through `build_app` and `tower::ServiceExt::oneshot` with `MultiTenantDevKeyProvider` and `DevAttestation::allow_insecure_dev()` (copy `backend/crates/platform-api/tests/research_api.rs`);
  - `AuditCapture` assertions in `audit_coverage.rs`, including the single-threaded, process-exclusive rule in `backend/crates/platform-telemetry/src/capture.rs`;
  - `backend/crates/quackxide-engine/tests/bypass.rs` for disclosure attacks;
  - proptest, and fast-check `*.property.test.ts`;
  - the vitest `node` (`*.test.ts`) and `dom` (`*.test.tsx`) projects (`frontend/vite.config.ts`);
  - `backend/fuzz` targets (nightly toolchain; P70 adds a build check on every PR).
- It sets one naming and placement convention for negative tests and audit assertions, and links P78 for the refusal checklist.
- It lists what CI cannot exercise and the agreed substitute: SEV-SNP: recorded reports (captured in P12 phase B and P48, verified by P47) plus the manual or dispatched hardware job (P71); managed sign-in: a locally generated RS256 key through the public `platform_auth::generate_rs256_keypair` and `TokenSigner::rs256_from_pem` (`keygen::fixtures` is `#[cfg(test)]` and crate-private); GCS: the in-memory `ObjectStoreVault` plus the fault-injecting test double from P41. The issues that own the code build these; the guide records the choices.
- It names the acceptance tests for definition-of-done items 1-3 (P72, P82; if P72 moves to v1.1, the manual browser run that P82 records).

**Where.** `CONTRIBUTING.md` or new `docs/TESTING.md`.

**Depends on:** none.

**Security impact.** None directly; makes the negative-test requirement concrete.
**ADR.** Not required.

---

### P7. Same-origin API access from the browser in development
**Labels:** build · area:frontend · javascript · good first issue
**Size:** S · **Priority:** team enablement · **Target:** weeks 1-2

**Summary.** By default the frontend calls `http://127.0.0.1:8080` (`frontend/src/config/brand.ts:39`, `frontend/.env.example`) from the Vite dev server on `localhost:5173`, which is a different origin. `HttpVault`, `ResearchClient` and `AdminClient` all send an `Authorization` header, which forces a CORS preflight, and the API has no CORS layer (`build_app` adds only `TraceLayer`, `backend/crates/platform-api/src/lib.rs:322`). Browsers therefore block the README's "End-to-end locally" flow in `http` vault mode.

**Done when**
- `frontend/vite.config.ts` proxies `/api`, `/admin` and `/healthz` to a target taken from env, defaulting to `http://127.0.0.1:8080`.
- The default API base becomes same-origin. `nonEmpty()` in `brand.ts` turns an empty value into the fallback, so the fallback itself changes; `frontend/src/config/brand.test.ts` is updated, and `VITE_API_BASE_URL` in `frontend/.env.example` is blanked with a comment.
- Unit tests show that `HttpVault`, `ResearchClient` and `AdminClient` build `/api/v1/...` and `/admin/...` paths correctly from a same-origin base. `HttpVault` runs inside the crypto worker (`frontend/src/lib/crypto/worker.ts:30-38`), so the test confirms relative URLs resolve against the page origin.
- The PR records a manual browser run of the README end-to-end flow in `http` mode (upload, list, download a synthetic file) with no CORS errors, and the README "Development" section is updated.

**Where.** `frontend/vite.config.ts`, `frontend/src/config/brand.ts`, `frontend/src/config/brand.test.ts`, `frontend/.env.example`, `frontend/src/lib/vault/`, `README.md`.

**Depends on:** none.

**Security impact.** None in production; the production origin and CORS decision belong to P65 and P68.
**ADR.** Not required.

---

### P8. Local research stack: one dev-only server with research routes wired and seeded data
**Labels:** build · area:ops · rust
**Size:** S-M · **Priority:** team enablement · **Target:** weeks 1-3

**Summary.** Nobody can run the research lifecycle locally today. `platform-api` passes `query: None` (`backend/crates/platform-api/src/main.rs:68`), so catalog, grant, request and research-query routes all return 503 (`lib.rs:423-425`), and the portal shows "research access is not enabled on this deployment" (`frontend/src/lib/research/client.ts:148`). The full research wiring exists only in `backend/crates/platform-api/tests/research_api.rs:58-99`. Production key release needs SEV-SNP hardware, so this dev mode is how most contributors will run research routes all semester. It is not a stopgap.

**Done when**
- A dev-only binary (for example `src/bin/devstack.rs`) is declared with `required-features = ["dev"]` behind a new non-default feature in `backend/crates/platform-api/Cargo.toml`, so `cargo build --release -p platform-api` (`.github/workflows/release.yml`) never builds it. It refuses to start unless `JWT_HS256_SECRET` and an explicit dev flag are both set, and logs a loud "insecure, development only" warning.
- The research wiring moves out of `tests/research_api.rs` into one shared dev-only function: `ConnectorQueryService::new(..).with_research(..)` over `MultiTenantDevKeyProvider`, `DevAttestation::allow_insecure_dev()`, an in-memory vault and the in-memory grant, budget and catalog registries. `research_api.rs` and the dev server both call it, so they cannot drift apart.
- At startup, inside the same process (the vault, registries and dev keys are per-process), the server creates a steward tenant and a researcher tenant, commits a synthetic cohort dataset sealed to the steward's key as a snapshot (`SnapshotWriter`, as `research_api.rs` now does; queries read only the newest committed snapshot, ADR 0003), publishes a catalog listing, and prints an HS256 dev token for each role (minted as `devtoken` does). Until P9 lands, the dataset is built in code the way `cohorts_parquet()` in `research_api.rs` does, with cohorts on both sides of k.
- README "Development" documents the two-terminal flow from a clean checkout to the portal showing one suppressed and one released query result (start the dev server, start Vite with the proxy from P7, steward publishes, researcher requests, steward approves, researcher queries).
- CI shows that a default-feature release build of `platform-api` contains no dev-server binary.

**Where.** New `backend/crates/platform-api/src/bin/devstack.rs` (name is the implementer's choice), `backend/crates/platform-api/Cargo.toml`, `backend/crates/platform-api/tests/research_api.rs` (reference wiring), `README.md`.

**Depends on:** none.

**Sequencing.** The browser half uses the proxy from P7.

**Security impact.** Adds a binary that runs without attestation; it must be impossible to build or start in production (feature-gated, refuses without explicit opt-in). P18 later moves `devtoken` and `query-demo` behind the same mechanism.
**ADR.** Not required.

**Notes.** A one-command wrapper script under `scripts/` (code-owned) and a filesystem vault shared with `connector-worker` are out of scope.

---

### P9. Seeded synthetic research-dataset generator
**Labels:** build · area:ops · rust · good first issue
**Size:** S · **Priority:** team enablement · **Target:** weeks 1-3

**Summary.** `docs/DATA_POLICY.md` (lines 38-43) says to generate synthetic data with a fixed seed, keep the generator in the repository, and use fixture cohort sizes on both sides of `RESEARCH_MIN_COHORT_SIZE`. No generator exists; the only research-shaped data is a hand-built 7-row cohort Parquet copied into `backend/crates/platform-api/tests/research_api.rs`, `catalog_api.rs` and `backend/crates/quackxide-engine/tests/disclosure.rs`. The local stack (P8), upload (P38), disclosure work (P54, P58), benchmarks (P73) and the acceptance run (P82) all need shared synthetic data, some of it larger than rule 5 allows in commits (enforced by the data guard in `scripts/check.sh`).

**Done when**
- A small `publish = false` crate (or binary) depends only on workspace `arrow`, `parquet` and a portable seeded RNG (for example `rand_chacha`'s ChaCha8, not `StdRng`), and not on `platform-api`, so engine tests and benches can use it as a dev-dependency without a cycle.
- It takes a seed, a row count and a schema name and writes Parquet (the engine ingests only Parquet, `register_parquet` in `backend/crates/quackxide-engine/src/lib.rs`). Values are obviously fake and use reserved `.example` domains (DATA_POLICY rule 2).
- At least two schemas: a health-style cohort table with groups on both sides of a configurable k, including one group dominated by a single individual (for P58); and a wide table for throughput benchmarks.
- A determinism test: two runs with the same seed give identical decoded record batches. (Do not compare against a committed file hash; parquet-rs writes its version into file metadata and P69 changes it.)
- Large outputs go to a gitignored directory such as `target/`. Small committed outputs live only under `fixtures/`, with their schema and generation command recorded next to them.
- The hand-built 7-row cohort and the `bypass.rs` fixtures stay as small named fixtures: security tests need cohorts whose exact contents are readable.
- If the generator is a separate workspace member, the crate table in `docs/ARCHITECTURE.md` ("Crate boundaries", lines 236-251) gains a one-line row for it, marked dev-only.

**Where.** New dev-only crate under `backend/crates/` (name is the implementer's choice); `backend/Cargo.toml` workspace members; a `fixtures/` directory beside it for small committed outputs; `docs/ARCHITECTURE.md`.

**Depends on:** none.

**Security impact.** Keeps all test, demo and benchmark data synthetic, as `docs/DATA_POLICY.md` requires.
**ADR.** Not required.

---

### P10. Shared API test helpers
**Labels:** harden · rust · good first issue
**Size:** S · **Priority:** team enablement · **Target:** weeks 1-3

**Summary.** Each `platform-api` integration test file writes its own token minter, request helpers (`send`, `call`, `post`, `post_query`, `admin_auth`) and app builder. Every security issue in this milestone adds tests to these files, so shared helpers save time and keep the negative tests consistent.

**Done when**
- `backend/crates/platform-api/tests/common/mod.rs` holds a token minter that takes the secret (and token type) as parameters, the request helpers, and the app builders now duplicated in `drive_api.rs`, `query_api.rs`, `research_api.rs`, `catalog_api.rs`, `admin_api.rs`, `audit_coverage.rs` and `token_types.rs`.
- The seven test files use it, with no change in test behavior (same test names, same assertions, all passing).
- It includes an RS256 helper built from the public `platform_auth::generate_rs256_keypair`, `JwtVerifier::rs256_from_jwks` and `TokenSigner::rs256_from_pem(..).mint(..)`, generated once per test binary (RSA generation is slow), for P28. `token_types.rs` (added by Code-Pause-Inc/QuackXide#23) already builds one inline and moves to the shared helper.

**Where.** New `backend/crates/platform-api/tests/common/mod.rs`; the seven files under `backend/crates/platform-api/tests/`.

**Depends on:** none.

**Sequencing.** Coordinate with P8, which moves the research wiring into a shared function.

**Security impact.** None; test code only.
**ADR.** Not required.

---

### P11. Frontend lint in check.sh
**Labels:** build · area:frontend · javascript · good first issue
**Size:** S · **Priority:** team enablement · **Target:** weeks 1-3

**Summary.** The frontend has no linter. `scripts/check.sh` (lines 22-32) runs only `npm ci`, typecheck, unit tests and build, and `frontend/package.json` has no lint script. The sign-in, upload and portal work (P32, P40, P44) should land lint-clean from the start.

**Done when**
- ESLint (flat config with typescript-eslint and eslint-plugin-react-hooks) runs as `npm run lint` from `scripts/check.sh` with zero warnings.
- `CONTRIBUTING.md` "Before every push" says the frontend is linted too.
- New dev dependencies pass dependency review (the licence deny list and `fail-on-severity: moderate` in `.github/workflows/dependency-review.yml`).
- Optional: `eslint-plugin-jsx-a11y` in the recommended config; if included, the zero-warnings bar means the existing label, alert and tab findings are fixed in the same PR (a few lines each).

**Where.** `frontend/package.json`, new `frontend/eslint.config.js`, `scripts/check.sh` (code-owned), `CONTRIBUTING.md`.

**Depends on:** none.

**Sequencing.** Land before the frontend feature work.

**Security impact.** None directly; catches hook and type mistakes in key-handling UI code.
**ADR.** Not required.

**Notes.** Automated axe checks and a standalone accessibility retrofit are proposed outside v1; new UI issues carry their own label and `role="alert"` requirements.

---

### P12. SEV-SNP cloud environment, team access and budget
**Labels:** build · area:enclave · area:ops
**Size:** M · **Priority:** v1 blocker · **Owner:** @AxolDad (account, billing, IAM), one student for the scripts · **Target:** phase A by week 2; phase B, including the attestation fixtures, by week 4

**Summary.** Attestation on hardware (P48), key release (P50), deployment (P68), the hardware test job (P71), enclave-overhead benchmarks (P74) and definition-of-done item 2 all need genuine AMD SEV-SNP hardware and a cloud project. The code targets GCP Confidential VMs (`backend/crates/platform-enclave/src/lib.rs:1-2, 84-85`, which probes `/dev/sev-guest`) and a GCS vault (`ObjectStoreVault::new_gcs`). GitHub-hosted runners have no SEV-SNP, and nothing in the repository says how a contributor gets access. This is the first item on the critical path.

**Done when**
- **Phase A (maintainer, by week 2):**
  - A development project and billing account owned by the maintainer, with a budget alert at an agreed monthly cap wired to the maintainer. Education or research credits are applied for and the outcome recorded.
  - A machine type and zone that support SEV-SNP are checked against current provider documentation, and a booted VM shows `/dev/sev-guest`. If the image exposes only configfs-tsm, that is recorded as a requirement for P48.
  - Whether the chosen machine type and image expose a vTPM and support the provider's attestation service is recorded, as input to P14's workload-identity decision.
  - Budget alerts alone do not stop spending, so at least one hard control is in place: a per-project VM or CPU quota, automatic shutdown of idle VMs (instance schedule or TTL label), or a budget-triggered billing disable.
  - Each team member has their own least-privilege identity, revoked at the end of the semester: create, stop and delete VMs in this one project; no access to production secrets, key material, other projects, project-owner or billing roles. If P13 puts the team secret store in Secret Manager in this project, the role also reads those team secrets, and only those. No shared accounts. No service-account key files are issued (enable the organization policy that blocks key creation if available); locally, use application-default user credentials; on the VM, the attached service account.
- **Phase B (student, by week 4, before P48 starts on hardware):**
  - A script in a new `deploy/` directory (for example `deploy/dev-cvm.sh up|down`) creates and destroys a dev Confidential VM, and VMs stop or delete themselves after a set run time. It is the seed that P68 extends, not a parallel deployment path.
  - The PR that creates `deploy/` adds `/deploy/ @AxolDad` to `.github/CODEOWNERS` (P4).
  - A development GCS bucket wired through the existing `GCP_PROJECT_ID` and `STORAGE_BUCKET` settings (`backend/.env.example`).
  - On the VM, `scripts/check.sh` builds, `platform-api` starts, and `SnpAttestation::produce_evidence` returns the "device present" refusal (`backend/crates/platform-enclave/src/lib.rs:116-120`), not "guest device not present". (`query-demo` uses `DevAttestation`, so it proves only the toolchain.)
  - Two or more attestation reports are captured on the VM, each with a fixed synthetic REPORT_DATA (nonce), plus the AMD certificate chain (VCEK or VLEK, whichever the platform uses, its ASK or ASVK intermediate, and the ARK, matching P47). Today `SnpAttestation::produce_evidence` refuses even on hardware (`backend/crates/platform-enclave/src/lib.rs:116-120`), so project code cannot do this capture: use an established off-the-shelf SEV-SNP guest tool run on the VM, named with its version, source and licence in the PR. The tool is not vendored or added as a project dependency, so CI does not check it. The captures go into `backend/crates/platform-enclave/tests/fixtures/` (the path P48's recorder later writes) with a README recording machine type, zone, firmware/TCB, date, the tool's name, version and source, and the source and terms of the AMD certificates. Fixtures contain no keys, credentials, project IDs or VM addresses.
  - `CONTRIBUTING.md` ("Setup") or `docs/DEVELOPMENT.md` explains how a contributor requests access and tears resources down. The machine type, zone, image and estimated cost per hour are recorded in one doc that P68 reuses.
- Project IDs, billing details, member emails and VM addresses stay out of public issues, docs and fixtures. `.gitignore` covers key-file patterns.
- End of semester: no VMs are left running.

**Where.** New `deploy/`; `.github/CODEOWNERS`; `docs/`; `CONTRIBUTING.md`; `.gitignore`; `backend/crates/platform-enclave/tests/fixtures/` (new).

**Depends on:** none.

**Security impact.** Sets the credential rules for the only environment that runs the enclave code; no long-lived keys exist to leak.
**ADR.** Not required (the provider choice is already implied by the code; record it in `docs/`).

**Notes.** Open decision for the maintainer: which provider and region, the monthly cap, and whether credits are available. Offline attestation work (P47) starts without this issue; it closes on phase B's recorded fixtures. Sign-in provider tenants, the staging domain and test identities are in P13.

---

### P13. Accounts beyond GCP: sign-in provider, staging domain and synthetic test identities
**Labels:** build · area:auth · area:ops
**Size:** S · **Priority:** v1 blocker · **Owner:** @AxolDad · **Target:** team secret store by week 2; provider development tenant by week 4 (before P29 integrates); staging domain by week 8 (before P68)

**Summary.** P12 provisions GCP only. P29, P32, P65, P68 and P82 need a tenant at the managed sign-in provider that P16 chooses, and P68 needs a domain for HTTPS (P67) and for the provider's redirect URIs. `APP_DOMAIN_NAME` defaults to `localhost` (`backend/crates/platform-config/src/lib.rs:157`). `docs/DATA_POLICY.md` applies to "every development and test environment" (lines 3-4), and rule 2 (lines 13-16) forbids real email addresses and uses fake addresses on reserved `.example` domains, which cannot receive the verification, reset or enrolment email a real provider sends. Without a decision, team members will register their personal addresses as test users.

**Done when**
- **Team secret store (maintainer, by week 2; does not wait for P16).** It exists before the first shared value is created (the development tenant, week 4). Either a shared vault in an organization-owned password manager with per-member accounts and MFA, which suits values people read and type (test-user passwords, TOTP seeds, tenant URLs, client IDs); or Secret Manager in the P12 development project, in which case P12 phase A's per-member role adds read access to those team secrets only. Each core-team member has individual access with MFA. Members can read development values only: the P12 development project settings, the development tenant's client values, and test users' passwords and TOTP seeds. Staging-tenant secrets are readable only by the maintainer, and production secrets live only in P68's secret store, which no team identity accesses as a matter of course. `docs/DEVELOPMENT.md` (P3) names the store and how to request access. Values from it are never pasted into issues, PRs, commits or chat. Access is revoked at the end of the semester on the same checklist as the P12 and provider-tenant revocations.
- **Provider tenants.** The organization owns a development tenant and a staging tenant at the provider P16 chose; a production tenant, if one is needed, is created by P68's documented procedure. Team members get least-privilege admin on the development tenant only, with MFA on their admin accounts, and lose it at the end of the semester. No provider client secret is in the repository; provider secrets live in the team secret store (development and staging, with the access rules above) or in P68's secret store (production). Cost and free-tier limits are recorded.
- **App registrations.** Redirect URIs cover `http://localhost:5173` (`frontend/vite.config.ts:10`) and the staging origin, and are exact-match with no wildcards. The implicit and hybrid grants are disabled and PKCE is required for the public client (P16). These settings are listed in the PR and in the P68 deployment doc. The configuration keys for the issuer, JWKS URL and client ID are added to `backend/.env.example` and `frontend/.env.example` with empty values. `docs/DEVELOPMENT.md` (P3) says how a team member gets access and where the values live. The tenant-specific values (tenant URLs, client IDs, the staging domain) stay in the team secret store and the gitignored `.env`, never in public docs or issues: the same rule P12 applies to project IDs.
- **Synthetic test identities.** The decision is recorded as an amendment to `docs/DATA_POLICY.md`: either provider test users with email verification off, or addresses on a maintainer-controlled test subdomain with a catch-all mailbox. No team member's personal email address or phone number is a test identity. Test users' passwords and TOTP seeds live in the team secret store and are never committed.
- **Staging domain.** The maintainer delegates a staging domain or subdomain, or P15 records a provider-managed hostname instead. DNS records come from `deploy/` templates and the name is never committed, as P68 requires. The `scripts/check.sh` domain guard (lines 40-46) only looks for the `yourdomain` placeholder in `backend/crates` and `frontend/src`, so it does not enforce this: review does, or this issue extends the guard to `deploy/`.
- If the provider sends white-label email (P29) from a custom sender domain, sender authentication (SPF and DKIM) is configured for it. TLS certificates for the staging origin belong to P67 and P68.

**Where.** The team secret store; maintainer and provider accounts; `docs/DEVELOPMENT.md`; `docs/DATA_POLICY.md`; `backend/.env.example`; `frontend/.env.example`; `deploy/` templates; optionally `scripts/check.sh`.

**Depends on:** P16 (provider choice; the team secret store and the staging domain do not wait for it).

**Sequencing.** The development tenant exists before P29 integrates against the provider; the week-7 checkpoint in P5 uses it.

**Security impact.** Keeps real personal data out of test environments, and keeps provider secrets and tenant identifiers out of the public repository.
**ADR.** Not required.

**Notes.** Open decisions for the maintainer: the team secret store's tool, the test-identity approach and who owns the staging domain. "Team secret store" is used instead of "team vault" because "vault" already means the product's encrypted storage (`VaultStore`, `ObjectStoreVault`, `HttpVault`, `VITE_VAULT_MODE`). The maintainer may fold this into P12 as a "phase C" instead of a separate issue; if so, keep the three targets.

---

## Decisions that block build work (weeks 1-3)

Each of these is drafted by one student and accepted by @AxolDad. An ADR-only PR may merge ahead of the implementation; the implementing PR links it (`CONTRIBUTING.md:71-73`, `docs/adr/README.md:7-9`). Reserve each ADR number in its issue before drafting (P4). ADRs 0001-0003 are already taken on `main`, so the four numbered here are 0004-0007.

### P14. ADR 0004: key custody and attested key release
**Labels:** build · area:crypto · area:enclave · needs-adr
**Size:** M · **Priority:** v1 blocker · **Owner:** @AxolDad with one student · **Target:** accepted by end of week 3

**Summary.** The documents contradict each other on the key that opens a research dataset, and the code sides with one of them. `docs/THREAT_MODEL.md:25` says steward private keys are non-extractable in the browser and never sent to the server; the browser generates the X25519 HPKE private key with `extractable: false` and exports only the public half (`frontend/src/lib/crypto/core.ts:171-180`), and every server-side `TenantKeypair` is test or dev only (`backend/crates/platform-crypto/src/lib.rs:203-204`). Yet `docs/THREAT_MODEL.md:77`, `docs/ARCHITECTURE.md:159-165` and `docs/PROJECT_SCOPE.md` say the steward's key is released into the enclave for each research query, which runs on the researcher's request with the steward offline. A non-extractable browser key cannot be released anywhere, and no key broker or KMS exists, so a production `EnclaveKeyProvider` (`backend/crates/platform-api/src/query.rs:37-47`) has nothing to release. Drive uploads are wrapped under a browser-only key-encryption key (`frontend/src/lib/crypto/drive.ts`, `docs/ARCHITECTURE.md:34-49`), so no enclave can open them either. Decide how an attested enclave gains the ability to open a steward's dataset while the operator cannot.

**Done when**
- `docs/adr/0004-key-custody.md` is Accepted (format per `docs/adr/README.md`) and listed in its Records section. It compares at least: (a) a per-dataset data key wrapped both to the steward and to an attestation-gated release service (a managed KMS with an attestation policy, or a broker in its own confidential VM) that unwraps only for verified SEV-SNP evidence; (b) steward-online release, where the steward's browser unwraps each dataset key and re-seals it to an attested enclave key at grant time (this changes the custody rules in `core.ts:5-9`); (c) any other off-the-shelf option. No custom key-release protocol. For each, it says who can decrypt in each failure case and whether the steward must be online.
- It specifies, in full (these block P50 and P55):
  - the decryption root for connector-sealed and steward-uploaded datasets, and therefore what P38 seals to;
  - the relying party that verifies SEV-SNP reports before release, and why it is outside the operator's control (if nothing is, `THREAT_MODEL.md` A2 says so);
  - who issues the nonce and the 64-byte REPORT_DATA layout (at least the nonce and an enclave ephemeral public key that released keys are wrapped to; optionally a digest of the effective disclosure configuration). Today `produce_evidence` takes only a nonce (`platform-enclave/src/lib.rs:41`), and `gate_execution` (`lib.rs:130-144`) and `EnclavePipeline::attestation_gate` (`platform-connectors/src/pipeline.rs:92`) check only the platform tag of evidence the same process produced;
  - where the researcher's result key (P55) is generated and stored, and how the enclave gets an authentic copy of its public key when the operator controls the vault that holds enrollments.
- **Workload identity.** It decides how attestation evidence proves *which binary* runs, not only that it runs in a GCP SEV-SNP VM. On GCP Confidential VMs the SNP MEASUREMENT covers only Google-supplied firmware (P49), and the guest chooses REPORT_DATA itself, so a report with a valid AMD chain, a fresh nonce and a REPORT_DATA-bound key can come from any guest on that firmware, including an operator-modified `platform-api` that would then obtain dataset keys. It compares at least:
  1. a vTPM measured-boot quote checked alongside the SNP report: whose root of trust the vTPM's attestation key chains to (AMD, or the cloud provider), and whether and how the quote is bound to the SNP report. If the vTPM is hosted by the hypervisor rather than rooted in the SNP report, the cloud provider is in the trusted computing base for this property;
  2. an attestation token that the provider issues for a hardened workload runtime, and whom the relying party then trusts;
  3. a launch-measurement policy over firmware and a guest image the project builds and controls. On GCP the image is not in MEASUREMENT, so this option means changing the host platform named in `backend/crates/platform-enclave/src/lib.rs:1-2`; the ADR states whether that is feasible.

  For each option it states what the relying party verifies, who must be trusted for workload identity, which values P49 publishes, and whether P47's raw-report verifier is the primary check or one input. P12 phase A supplies whether the chosen machine type and image expose a vTPM and support the provider's attestation service. Whatever trust remains is written into `THREAT_MODEL.md` A2; if no option binds the workload on the chosen platform, A2 says so explicitly and P5 records the re-plan.
- It settles briefly, or records as a residual risk in `THREAT_MODEL.md` rather than designing a mechanism: the v1 enrollment policy (for example one enrolled key per tenant, create-once, explicit rotation; implemented in P33); which datasets stay queryable after a steward loses a device (recovery may be out of scope for v1 and documented as a limit; reconcile with the `KeySetupGate` warning and definition-of-done item 7); what revoking a grant or changing the measurement does to keys already released; what rotation (P77) and backup (P76) cover; operator-forged grants, budgets or identities (sign them, bind configuration into REPORT_DATA, or record as A2 residual); forged or rolled-back connector snapshots, which ADR 0003 records as a residual that only an attested enclave signing key closes; the operator-served JavaScript bundle.
- `docs/THREAT_MODEL.md` (Assets row line 25, A2 rows 76-78, "Out of scope") and `docs/ARCHITECTURE.md` (key-release trust boundary, research access flow, line 243) agree with the decision. ADR 0001 is not edited; the classical-to-hybrid re-seal question in P35 links this ADR.

**Where.** New `docs/adr/0004-key-custody.md`; `docs/adr/README.md`; `docs/THREAT_MODEL.md`; `docs/ARCHITECTURE.md`; `docs/PROJECT_SCOPE.md`.

**Depends on:** P12 (phase A facts only: vTPM and attestation-service support, by week 2).

**Sequencing.** Drafted together with P15. P12 phase A supplies the vTPM and attestation-service facts for the workload-identity decision by week 2.

**Security impact.** Defines the central trust boundary of the system (A2: who can ever hold a dataset key).
**ADR.** This is the ADR.

**Notes.** Blocks P50, P55, P38, P33, P48, P49, P77 and P34's checkpoint B; partly blocks P47 (only the relying-party placement, nonce source, REPORT_DATA layout and workload-identity mechanism wait for it; report parsing and AMD chain verification do not); informs P35 (whether the browser holds a tenant private key at all) and P68. If acceptance slips past week 4, the maintainer re-plans the critical path in P5.

---

### P15. ADR 0005: query and deployment topology
**Labels:** build · area:enclave · area:ops · needs-adr
**Size:** S · **Priority:** v1 blocker · **Owner:** one student, @AxolDad accepts · **Target:** accepted by end of week 3

**Summary.** Queries run inside the `platform-api` process: `ConnectorQueryService` sits on the same Axum router (`backend/crates/platform-api/src/lib.rs:266-268, 312-323`) and gates on that process's own SEV-SNP probe (`query.rs:201-234`). The release workflow builds and ships only `platform-api` and `connector-worker` (`.github/workflows/release.yml`). `docs/PROJECT_SCOPE.md` speaks of "the API and enclave workers", and the first draft of sealed results said "the API never sees result plaintext"; neither has a defined meaning until the process boundary is decided.

**Done when**
- `docs/adr/0005-query-topology.md` is Accepted and records:
  - whether `platform-api` as a whole runs inside the SEV-SNP Confidential VM, or a separate enclave query worker sits behind an API that never handles plaintext; if a worker, the RPC between them, its authentication, how the API verifies the worker's attestation, and that `release.yml` builds the new binary;
  - where TLS terminates, and therefore what "results sealed to the researcher" (P55) protects against (for example a TLS-terminating load balancer, or an API outside the enclave). If TLS terminates inside the VM, it also names the component that holds the TLS private key, with its version and licence: a named server TLS crate on rustls in `platform-api` (rustls 0.23 and tokio-rustls 0.26 are already in `backend/Cargo.lock`, today only on the client side through `reqwest`), or a named proxy in the image (P49). That satisfies `docs/adr/README.md:7-9` for a dependency that handles keys;
  - whether `connector-worker` runs in its own Confidential VM, and how it reaches the vault (depends on P19);
  - same-origin serving of the frontend and API (built in P67), or an allowlisted CORS configuration (P65);
  - how the operator's environment (variables, `.env`) is or is not trusted inside the VM (P18).
- `docs/ARCHITECTURE.md` and `docs/PROJECT_SCOPE.md` ("Deployment") use the decided wording.

**Where.** New `docs/adr/0005-query-topology.md`; `docs/ARCHITECTURE.md`; `docs/PROJECT_SCOPE.md`.

**Depends on:** P19 (the `connector-worker` scope decision only).

**Sequencing.** Drafted together with P14.

**Security impact.** Decides which processes ever hold plaintext, and therefore what sealed results and the attestation gate protect.
**ADR.** This is the ADR.

**Notes.** Blocks P68, P49 (what the measured image contains), P55, P65 and P67. The measured-workload mechanism is decided in P14; this ADR fixes only what the image contains.

---

### P16. ADR 0006: sign-in, identity and token signatures
**Labels:** build · area:auth · needs-adr
**Size:** S-M · **Priority:** v1 blocker · **Owner:** one student, @AxolDad accepts · **Target:** accepted by end of week 3

**Summary.** Accepted ADR 0001 moves token signatures to Ed25519 + ML-DSA-65 and keeps the RS256 verifier "only as long as migration requires" (`docs/adr/0001-hybrid-post-quantum-suites.md:24, 28, 43-44`); `backend/deny.toml:11-15` justifies ignoring RUSTSEC-2023-0071 with "RS256 retired by ADR 0001". A managed identity provider issues classical tokens, and `jsonwebtoken` 10.x has no ML-DSA. The code already implies a platform token service between the provider and the API: `TokenType::Preauth` "issued after IdP sign-in, before the TOTP challenge", then `Access` plus a rotating `Refresh` (`backend/crates/platform-auth/src/lib.rs:24-36`), minted by `TokenSigner`, which "runs on the identity-service signer" (`sign.rs:1-4`). That service does not exist, and nothing models users: tenants are created only by the Paddle webhook (`backend/crates/platform-api/src/admin.rs:64-108`) and `TenantRecord` (`backend/crates/platform-tenancy/src/lib.rs:40-52`) has no members. Trusting provider tokens directly needs care: since Code-Pause-Inc/QuackXide#23 the verifier requires a `typ` claim (`platform-auth/src/lib.rs:71-73`) and `authenticate` (`backend/crates/platform-api/src/lib.rs:172-214`) accepts only `access` tokens, so any direct trust must map the provider token to a platform token type without letting a pre-MFA provider token count as fully authenticated.

**Done when** `docs/adr/0006-sign-in-and-tokens.md` is Accepted and decides:
- **Provider and topology.** The managed identity provider (an open decision for the maintainer), and whether the API verifies provider tokens directly or a platform token service exchanges them. The ADR evaluates the exchange design first, since the code describes it: the provider's token is verified only at the exchange (public-key operations only, with JWKS fetch and refresh there), and the API verifies only platform tokens (`tid`, `adm`, `typ`).
- **Token signatures.** Either (a) the platform issuer mints hybrid Ed25519 + ML-DSA-65 tokens (a non-JWT or custom format, since `jsonwebtoken` has no ML-DSA), built in P37, with a classical signer allowed only as ADR 0001's explicit, logged, time-limited migration mode; or (b) a superseding ADR limits hybrid signatures to long-lived material and records why short-lived tokens stay classical. Either way it names exactly one issue that builds the signer and verifier, and updates `THREAT_MODEL.md` A4, the suite table in `ARCHITECTURE.md` and the RUSTSEC-2023-0071 reason in `backend/deny.toml` if RSA private-key operations become network-facing.
- **Identity and tenancy.** How a signed-in person maps to a `tid` (recommended v1 model: one identity, one tenant, via a membership lookup); that steward and researcher stay grant relationships (`backend/crates/platform-tenancy/src/grants.rs:3-6`) with no new role claims unless a concrete need is named; how a researcher or non-paying tenant is created without a Paddle subscription; how `adm` is granted (server-side allowlist, never a user-editable provider attribute); whether a suspended or unknown tenant is refused (recommended: yes, implemented in P29). Multi-member tenants and invitations are out of v1 unless the ADR shows they are needed.
- **Second factor.** Whether MFA is enforced by the provider (verified through a required claim at the exchange) or by the platform's TOTP (`backend/crates/platform-crypto/src/totp.rs:1-2`, "the platform's mandatory second factor"); that administrators need it too (`THREAT_MODEL.md` A3 names only stewards and researchers); and where TOTP secrets, the last accepted step and refresh-token families are stored (an `IdentityRegistry` trait with an in-memory implementation in P29, durable in P63).
- **Session.** Access-token TTL, refresh rotation with reuse detection, sign-out and revocation, and where the browser keeps the token (in memory, passed to the crypto worker; never `localStorage`).
- **Browser sign-in flow.** OAuth 2.0 / OIDC authorization code with PKCE (S256); the implicit and hybrid flows are not used. The ADR names which component runs the code exchange (the browser as a public client using the provider's maintained SDK, with no hand-written OAuth; or the identity service as a confidential client) and where `state`, `nonce` and the PKCE verifier are kept across the redirect. Whichever component starts the request generates and checks a single-use `state` (the login-CSRF defence, needed even with bearer-only API auth) and an OIDC `nonce`. Redirect URIs are exact-match (P13). No access, ID or refresh token is ever placed in a URL, fragment or browser history. If the provider's SDK hides these parameters, the ADR shows how it gives equivalent login-CSRF, replay and audience binding. If cookies carry the API session, CSRF defences for API calls are also required.
- `docs/ARCHITECTURE.md` documents the resulting authorization model.

**Where.** New `docs/adr/0006-sign-in-and-tokens.md`; `docs/ARCHITECTURE.md`; `docs/THREAT_MODEL.md`; `backend/deny.toml` (reason text only, if needed).

**Depends on:** none.

**Security impact.** Decides the A3 controls (who can obtain a token, with which factor) and whether ADR 0001's signature target applies to tokens.
**ADR.** This is the ADR (it may supersede the token clause of ADR 0001).

**Notes.** Blocks P28, P29, P30, P32, P37 and P13 (which provider's tenants to create). The token-type check it builds on is already merged (Code-Pause-Inc/QuackXide#23).

---

### P17. ADR 0007: hybrid suite construction, libraries, browser key storage and migration
**Labels:** build · area:crypto · needs-adr
**Size:** S · **Priority:** v1 blocker · **Owner:** one student, @AxolDad accepts · **Target:** accepted by end of week 3

**Summary.** ADR 0001 fixes the target suites (X25519 + ML-KEM-768; Ed25519 + ML-DSA-65; AES-256-GCM) and the seams, but leaves the concrete construction open. The pinned `hpke` 0.12 (`backend/Cargo.toml:73`) has only DHKEMs. `hpke` 0.14.x provides `hpke::kem::XWing` (X25519 + ML-KEM-768, HPKE KEM id 0x647a) behind an `mlkem` feature, and moves to `rand_core` 0.10, `aes-gcm` 0.11 (the `aes` feature must be enabled explicitly) and `x25519-dalek` 3; `single_shot_seal` no longer takes an RNG. Its X-Wing public key is 1216 bytes and its encapsulated key 1120 bytes, against 32 bytes today (`backend/crates/platform-crypto/src/lib.rs:136-142`). Web Crypto has no ML-KEM. An X-Wing private key is a 32-byte seed, so it cannot be held as a non-extractable Web Crypto key, and the current KEK can only wrap and unwrap `CryptoKey`s (`frontend/src/lib/crypto/core.ts:56-62`). The candidate libraries are not independently audited: the `ml-kem` 0.3.2, `x-wing` 0.1.0 and `ml-dsa` 0.1.1 READMEs say so, `@noble/post-quantum`'s README says it has not been independently audited yet, and `hpke` has had no paid audit. So the first draft's "audited libraries only" bar cannot be met and must be replaced with a stated definition of "established" (`docs/PROJECT_SCOPE.md`, "Established libraries only").

**Done when** a new ADR is Accepted, before any code PR for P35 or P36 merges, and records:
- The KEM: X-Wing as HPKE KEM 0x647a with the exact draft revision pinned (the sources cite different revisions), HKDF-SHA256, AES-256-GCM, base mode. Interoperability is proven by vectors, not assumed: the HPKE-level X-Wing vectors shipped with `hpke` cover ChaCha20-Poly1305 only, so the issue requires KEM-level known-answer tests plus committed vectors for the exact suite, generated with a second implementation.
- The frame: a magic or version that maps to exactly one suite (for example `HPK2 || enc || ct`) and the new HPKE `info` strings (for example `tenant-envelope-v2|...`, upload objects for P38, and result envelopes for P55).
- The Rust library (`hpke` 0.14 `XWing`) and the browser implementation, chosen after a short spike comparing a wasm32 build of the backend crate (preferred by `docs/ARCHITECTURE.md:56-58` and `CONTRIBUTING.md:45`) with a named JavaScript library. Each library's audit status is recorded as an accepted risk, with the definition of "established" used.
- Browser private-key storage: for example, the seed encrypted under a dedicated non-extractable AES-GCM key with an AAD binding, decrypted only in the crypto worker, with the residual risk documented as ADR 0001:37-40 requires. Coordinate with the custody decision in P14.
- Signature consumers for v1, taken from `docs/ARCHITECTURE.md` ("tokens, attestation-bound material"): token signatures follow P16; "attestation-bound material" is defined or excluded; third-party classical signatures (AMD's certificate chain in P47) are out of scope.
- Migration. Expected path: nothing is deployed and only synthetic data exists (`README.md:144-145`, `docs/DATA_POLICY.md`), so v1 ships no `HPK1`-reading migration mode, and a superseding note records that ADR 0001's migration consequence does not apply to v1. If the maintainer decides otherwise, P35 builds an explicit, audited, time-limited mode and a re-seal tool.
- `docs/ARCHITECTURE.md` ("Current and target suites") and `docs/THREAT_MODEL.md` are updated in the same PR. If the browser implementation is not the wasm32 build of the RustCrypto/`hpke` code (for example a JavaScript post-quantum library), the same PR names that library in `CONTRIBUTING.md:45` ("No invented cryptography. Use RustCrypto, `hpke`, and Web Crypto.") and in `docs/THREAT_MODEL.md` "Out of scope: Correctness of the underlying libraries" (lines 119-121). `ml-kem`, `x-wing`, `ml-dsa` and `hpke` 0.14 need no such edit: they are RustCrypto or `hpke` crates.

**Where.** New `docs/adr/` record; `docs/ARCHITECTURE.md`; `docs/THREAT_MODEL.md`; `CONTRIBUTING.md` (only if a non-RustCrypto browser library is chosen).

**Depends on:** none.

**Sequencing.** Informed by P14 (whether the browser holds a tenant private key at all); both are accepted by week 3.

**Security impact.** Fixes the exact post-quantum construction and the library risk the project accepts.
**ADR.** This is the ADR.

---

### P18. Production mode: one switch, and refuse dev-only paths at startup
**Labels:** build · area:ops · rust · javascript · needs-adr
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 1-4

**Summary.** Definition-of-done item 3 (`docs/PROJECT_SCOPE.md`), `README.md:153` and several issues say "production build", but nothing defines one: no crate declares Cargo features, the only `cfg` gates are `#[cfg(test)]`, and `release.yml` runs the same `cargo build --release` developers run. Dev-only paths reach the shipped binaries, selected by environment variables with at most a warning:
- `platform-api` and `connector-worker` fall back to an in-memory vault when `STORAGE_BUCKET` is unset (`backend/crates/platform-api/src/main.rs:16-28`, `backend/crates/platform-connectors/src/bin/connector-worker.rs:34-46`);
- `platform-api` builds only an HS256 verifier (`main.rs:30-36`) and always an in-memory tenant registry (`main.rs:47-52`);
- `TEE_ATTESTATION_REQUIRED=false`, which `backend/.env.example:29` sets, makes `provider_for` return `DevAttestation::allow_insecure_dev()` (`backend/crates/platform-enclave/src/lib.rs:146-154`, called at `connector-worker.rs:49`), and `gate_execution` then proceeds even when attestation fails (`lib.rs:137, 141`);
- `connector-worker` runs embedded fixture sources and falls back to an ephemeral demo keypair (`TenantKeypair::generate`, documented test/dev-only) when `DEMO_TENANT_*` is unset (`connector-worker.rs:54-70, 89-118`);
- `.env` is always loaded (`backend/crates/platform-config/src/lib.rs:148`);
- `cargo build --release -p platform-api` also builds `devtoken` and `query-demo`;
- the released frontend is the `frontend/dist` that `scripts/check.sh` builds with no `VITE_*` variables (`release.yml`), so it defaults to `http://127.0.0.1:8080` (`frontend/src/config/brand.ts:39`) and to the IndexedDB-only `local` vault (`frontend/src/config/vault.ts:20-21`).

**Done when**
- An ADR records one mechanism. Recommended: a runtime switch such as `APP_ENV=production|development`, where unset or unknown means production, read from the process environment before `.env` is loaded, with `.env` not loaded at all in production; optionally plus a non-default Cargo feature that gates `DevKeyProvider`, `MultiTenantDevKeyProvider` (`platform-api/src/query.rs:49-113`), `DevAttestation::allow_insecure_dev` and the `devtoken`/`query-demo` binaries (`[[bin]] required-features`). If a feature is chosen, the integration tests that use these paths (`platform-api/tests/{audit_coverage,drive_api,admin_api,research_api,query_api,catalog_api}.rs`, `platform-connectors/tests/pipeline_e2e.rs`, and `backend/fuzz`) enable it, and `scripts/check.sh` also builds and lints the default (production) feature set. `backend/.env.example` opts into development explicitly.
- Startup in `platform-api` and `connector-worker` is factored out of `main()` into a testable function that calls one validation function (for example `PlatformConfig::check_production`), which later issues extend. Not inside `from_source`, so tests can still build any config.
- In production mode each binary refuses to start, with a clear error and a `service.start` audit event recording the refusal, when: `JWT_HS256_SECRET` is set; `STORAGE_BUCKET` is unset; `TEE_ATTESTATION_REQUIRED=false`; `provider_for` would return the dev provider; or (for `connector-worker`) the demo tenant or fixture sources would be used. Each refusal has a test that drives `PlatformConfig::from_source`.
- Later issues add their own refusals through this function: no verification keys (P28); no production key provider or research stores (P51); in-memory registries (P62) and in-memory identity and session stores (P63); no TLS certificate when TLS terminates in-process (P67). Until those land, production mode cannot boot; development mode is used, and the PR says so.
- Frontend: a release build mode (for example `vite build --mode release` or `VITE_PLATFORM_ENV=production`) fails unless `VITE_VAULT_MODE` is explicitly `http`, and fails if `VITE_DEV_JWT` or `VITE_ADMIN_JWT` is non-empty. It runs as a dedicated step in `release.yml`, not in `check.sh`'s dev build. (Runtime configuration of the bundle is P66.)
- `docs/ARCHITECTURE.md` defines production mode; `README.md:153` and definition-of-done item 3 use the defined term (with P80).

**Where.** `backend/crates/platform-config/src/lib.rs`; `backend/crates/platform-api/src/main.rs`; `backend/crates/platform-connectors/src/bin/connector-worker.rs`; `backend/crates/platform-enclave/src/lib.rs`; `backend/crates/platform-api/Cargo.toml` (if a feature); `backend/.env.example`; `frontend/vite.config.ts`; `.github/workflows/release.yml`; `docs/ARCHITECTURE.md`; new ADR.

**Depends on:** none.

**Sequencing.** Do it first; P28, P50, P51, P62, P63 and P68 build on it.

**Security impact.** Closes the paths by which an operator setting, a stray `.env` or a plain release build silently disables attestation, durability or real authentication. Corrects the A2 control row that relies on an operator-set flag.
**ADR.** Required (the mechanism sets a trust boundary).

**Notes.** Open decisions for the maintainer: runtime switch versus Cargo feature; whether `FEATURE_ZK_ENABLED=false` is also refused in production (research mode already forces ZK on in code, `query.rs:571-573`). The k floor for `RESEARCH_MIN_COHORT_SIZE` is in P54.

---

### P19. Record what is not in v1.0: connector ingestion, billing lifecycle, admin toggles and other documented features
**Labels:** area:ops · documentation
**Size:** S · **Priority:** team enablement · **Owner:** @AxolDad (decision), one student for the doc edits · **Target:** week 1-2

**Summary.** Several things ship or are documented but have no row in `docs/PROJECT_SCOPE.md`: `connector-worker` is a release artifact (`.github/workflows/release.yml:29-34`) but runs only three fixture jobs for one demo tenant, or an ephemeral key (`backend/crates/platform-connectors/src/bin/connector-worker.rs:54-70, 89-118`), and `HttpJsonSource` keeps OAuth refresh tokens in memory only (`source.rs:82-85`); the Paddle (MoR) webhook is live and is the only path that provisions tenants (`backend/crates/platform-api/src/admin.rs`); the webhook sets `TenantStatus::Suspended`, and admin connector toggles write `TenantRecord.connectors`, but nothing reads either; blind-index equality search has no producer of the column and no key management; the differencing closure is already a documented residual (`docs/THREAT_MODEL.md:127-132`); catalog prices are recorded but not charged. Connectors are not a separable add-on: research datasets are stored under `tenants/{t}/connectors/{slug}/`, and grants, listings and the query path are keyed by connector slug (`backend/crates/platform-api/src/query.rs:248-298`, `backend/crates/platform-tenancy/src/catalog.rs`), so "connectors out of v1" can only mean the worker binary, live ingestion and the toggles, never that storage and grant model.

**Done when**
- `docs/PROJECT_SCOPE.md` gains a "Not in v1.0" list with a decision on each: live connector sync for real tenants (`HttpJsonSource`, OAuth credential persistence, a sync-job registry driven by the admin toggles); the billing/MoR tenant lifecycle and connector toggles; blind-index search beyond the engine library; the differencing closure; charging researchers catalog prices. Recommended default: defer all five, keep tenant suspension in v1 only as P29 implements it.
- For each deferred feature that is still mounted or shipped, there is an explicit setting that defaults to off and fails closed (503 or not mounted), with a test; or the artifact is removed. In particular `release.yml` stops shipping `connector-worker` as a production artifact (or labels it development only), and P68 names exactly which binaries it deploys.
- The decision says how the steward upload (P38) fits the connector-keyed layout (reserved slug namespace or a generalized dataset id).
- `docs/ARCHITECTURE.md` and `README.md` stop describing deferred features as production capabilities (with P80).

**Where.** `docs/PROJECT_SCOPE.md`, `docs/ARCHITECTURE.md`, `README.md`, `.github/workflows/release.yml`, `backend/crates/platform-api/src/lib.rs` (route mounting), `backend/crates/platform-config/src/lib.rs` (flags).

**Depends on:** none.

**Sequencing.** Decide in weeks 1-2; informs P38, P61, P68, P18 and P82.

**Security impact.** Removes or fails closed every shipped path the threat model does not cover.
**ADR.** Not required (a scope decision), unless a mounted public API is removed.

---

## Security defects found in review (small, land early)

Four defects found in review are fixed and merged on `main`: Code-Pause-Inc/QuackXide#21 refuses `ROLLUP`, `CUBE` and `GROUPING SETS`, and sort or limit below the aggregate (ADR 0002, `docs/adr/0002-refuse-grouping-sets-and-positional-subsets.md`); Code-Pause-Inc/QuackXide#22 allows only read-only queries (no DDL, DML, `COPY` or session statements) and gives a query scope no object store; Code-Pause-Inc/QuackXide#23 refuses `preauth`, `refresh` and untyped tokens on data and admin routes; Code-Pause-Inc/QuackXide#24 stores connector data as versioned snapshots, so a query reads exactly one committed snapshot of each dataset (ADR 0003, `docs/adr/0003-connector-data-as-versioned-snapshots.md`). Their `docs/THREAT_MODEL.md` rows are in place. The items below remain.

### P24. `EngineSettings::default()` and `ZkMode::default()` must fail closed
**Labels:** harden · area:disclosure · rust · good first issue
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 1-4

**Summary.** `EngineSettings::default()` turns ZK mode off (`backend/crates/quackxide-engine/src/lib.rs:65-72`), `ZkMode` derives `Default` as `Disabled` (`backend/crates/platform-core/src/lib.rs:215-220`), and `default_settings_are_conservative` (`quackxide-engine/src/lib.rs:296-301`) asserts that ZK is off. That contradicts `FEATURE_ZK_ENABLED` defaulting to true ("disabling the gate must be an explicit choice", `platform-config/src/lib.rs:130-131, 207`). With ZK off and no policy, `QueryScope::sql` returns rows unfiltered, so a production wiring that uses `Default` (P51) would silently allow row-level egress on the own-data path. Research mode already forces ZK on (`platform-api/src/query.rs:572-573`).

**Done when**
- `EngineSettings::default()` is removed (preferred: every caller must choose) or enables ZK.
- `ZkMode`'s `Default` derive is removed or is `Enabled`; the `zk_mode_flag_round_trip` test (`platform-core/src/lib.rs`) is updated.
- `default_settings_are_conservative` asserts the fail-closed default, or is removed with `Default`.
- If `Default` is removed, every caller compiles with an explicit choice (for example `querying_unregistered_table_errors` in `quackxide-engine/tests/engine_query.rs`).

**Where.** `backend/crates/quackxide-engine/src/lib.rs`, `backend/crates/platform-core/src/lib.rs`, `backend/crates/quackxide-engine/tests/`.

**Depends on:** none.

**Sequencing.** Land before P51, which builds `EngineSettings.zk` from `config.features.zk`.

**Security impact.** Removes a fail-open default on the disclosure gate.
**ADR.** Not required.

---

### P25. Audit stream always on; no SQL or data values in operational logs
**Labels:** harden · area:ops · rust
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 1-4

**Summary.** `SECURITY_AUDIT_EVENT` records go through the same global `RUST_LOG` `EnvFilter` as operational logs (`backend/crates/platform-telemetry/src/lib.rs:17-28`), so `RUST_LOG=warn` silently drops all of them. `tracing-subscriber` keeps its default features (`backend/Cargo.toml:65`), so `try_init()` installs a `log` bridge, and at `debug` DataFusion logs whole logical plans and `sqlparser` logs SQL text and parsed expressions, both including the literals of a researcher's `WHERE` clause. The engine runs inside `platform-api`, so these reach the host's logs. `QueryError::Execution` and `QueryError::Parquet` keep upstream message text, and Arrow cast errors quote cell values; `map_query_error` drops that text today, but nothing stops a future log line from leaking it. `docs/THREAT_MODEL.md:73` marks "Read API host disk or logs" as "Built, tested".

**Done when**
- The subscriber is built by a function that takes the filter string and a writer and that tests can call; `init_from_env` only installs it.
- Audit records are emitted whatever `RUST_LOG` says, through a per-layer filter on the operational layer and a separate layer for the `SECURITY_AUDIT_EVENT` target fixed in code. A test builds the subscriber with the filter `error` and still captures audit records. (`AuditCapture` builds its own registry and cannot prove this.)
- Third-party diagnostics cannot carry SQL or plaintext: either the `log` bridge is turned off (`default-features = false` on `tracing-subscriber`, keeping `fmt`, `json`, `env-filter`, `registry`, `std`), or `datafusion*`, `sqlparser`, `arrow*` and `parquet` are capped at `warn` by a separate filter layer that `RUST_LOG` cannot raise (an added `EnvFilter` directive loses to a longer `RUST_LOG` target). This covers every binary (`platform-api`, `connector-worker`, `query-demo`).
- `QueryError::Execution` and `QueryError::Parquet` store a content-free category, set where the errors are created, never upstream message text.
- A test in its own test binary (the `log` logger is process-global) runs a query with a unique string literal that also fails a cast on a sentinel cell value, with the filter at `trace`, and asserts neither sentinel appears in any log line, audit event, or the research route's HTTP response body.
- `docs/THREAT_MODEL.md:73` and the `docs/ARCHITECTURE.md` "Security telemetry" section say audit records ignore `RUST_LOG` and name the test.

**Where.** `backend/crates/platform-telemetry/src/lib.rs`, `backend/Cargo.toml`, `backend/crates/quackxide-engine/src/lib.rs`, `backend/crates/platform-api/tests/`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`.

**Depends on:** none.

**Sequencing.** Land before P69 if possible, so the upgrade is checked against the leak test.

**Security impact.** Makes the audit stream impossible to disable by configuration and keeps query content out of operator-readable logs (A2).
**ADR.** Not required.

**Notes.** Shipping audit records to durable storage is P64.

---

### P26. Zeroize platform credentials held in configuration
**Labels:** harden · rust · good first issue
**Size:** S · **Priority:** v1 needed · **Target:** weeks 2-5

**Summary.** `docs/THREAT_MODEL.md:29` says platform credentials are "zeroize-on-drop; redacted `Debug`". `JWT_HS256_SECRET` (`AuthConfig::hs256_secret`, `backend/crates/platform-config/src/lib.rs:108`) and `MOR_WEBHOOK_SECRET` (`BillingConfig::paddle_webhook_secret`, `lib.rs:37`) are plain `Option<String>`; only their hand-written `Debug` impls redact them. A zeroizing, redacted `SecretString` already exists in `backend/crates/platform-connectors/src/oauth.rs`.

**Done when**
- `SecretString` moves to a shared crate and `platform-connectors` re-uses it. Suggested home: `platform-core` (already the only internal crate `platform-config` depends on; add `zeroize`). If it goes to `platform-crypto` instead, its `Deserialize` impl moves with it.
- It implements `zeroize::ZeroizeOnDrop` and `Clone` (or the config structs stop deriving `Clone`), with a compile-time `ZeroizeOnDrop` assertion following the pattern in `platform-api/src/query.rs`.
- Both config secrets are `Option<SecretString>`; call sites use an explicit accessor (`platform-api/src/main.rs:30`, `platform-api/src/lib.rs`, `platform-api/src/bin/devtoken.rs`). Secrets added later (for example a database password from P62) use the same type.
- The existing redaction tests in `platform-config/src/lib.rs` still pass.
- `docs/THREAT_MODEL.md:29` says what is true: the config copy is zeroized on drop, but the original value stays in the process environment for the life of the process; that is added to "Residual risks".

**Where.** `backend/crates/platform-config/src/lib.rs`, `backend/crates/platform-core/src/lib.rs` (or `platform-crypto`), `backend/crates/platform-connectors/src/oauth.rs`, call sites above, `docs/THREAT_MODEL.md`.

**Depends on:** none.

**Sequencing.** Land before P62, P63 and P68 add new secrets.

**Security impact.** Makes the threat model's credential claim true and shortens the life of secrets in memory.
**ADR.** Not required.

---

### P27. Access-request approval converges after a partial failure, and never fails open
**Labels:** harden · area:disclosure · rust
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 3-6

**Summary.** `resolve_access_request` marks the request Approved (`catalog.resolve`) before it fetches the listing and mints the grant and budget (`backend/crates/platform-api/src/research.rs:172-218`). If a later step fails (a registry error becomes a 502), the request is stuck Approved with no grant, and a retry gets 404 because `resolve` acts only on Pending requests. The comment at `research.rs:172-174` says retries converge; they do not. In-memory stores hide this; durable or networked stores (P62) make it realistic. Reordering naively creates the opposite fault: a grant minted, `resolve` failing, then a steward's Deny leaving the grant live.

**Done when**
- A retried approval by the same steward converges: approving an already-Approved request re-runs the idempotent grant and budget calls and returns 200; Denied stays terminal. (Alternatively, resolve, grant and budget commit in one transaction in the durable backend.)
- The `get_listing` and `ConnectorSlug::new` steps between resolve and grant are covered by the same rule.
- No grant is ever active for a request that is Pending or Denied: a deny after a failed approval revokes the grant minted for that (steward, researcher, connector), or the deny is refused while a grant exists.
- Other stewards and unknown ids still get the same 404 (no existence oracle).
- An integration test with a `BudgetLedger` (or `GrantRegistry`) that fails once: the first approve returns 502, the second returns 200 with an active, funded grant, and a deny issued after the failed approve never leaves an active grant.
- The comment at `research.rs:172-174` matches the behaviour.

**Where.** `backend/crates/platform-api/src/research.rs`, `backend/crates/platform-tenancy/src/catalog.rs` (`CatalogRegistry::resolve`; prefer the existing `list_requests_for` over widening the trait), `backend/crates/platform-api/tests/research_api.rs`.

**Depends on:** none.

**Sequencing.** Land before P61 fixes the trait contracts.

**Security impact.** Keeps grant state consistent under failure, in the fail-closed direction (A1 grant check).
**ADR.** Not required.

---

## Sign-in, identity and keys

The first draft's single sign-in issue is split into backend verification, identity and tenancy, second factor and session, frontend session, and key enrollment. All follow ADR 0006 (P16). The token-type check is already merged (Code-Pause-Inc/QuackXide#23): only `access` tokens reach data and admin routes.

### P28. API: production token verification from configuration
**Labels:** build · area:auth · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 4-7

**Summary.** RS256/JWKS verification and TOTP exist only as library code. `AuthConfig` (`backend/crates/platform-config/src/lib.rs:103-113`) has only `hs256_secret`, `issuer` and `audience`; `platform-api` builds only an HS256 verifier (`backend/crates/platform-api/src/main.rs:30-36`); the `JWT_JWKS_JSON` value that `keygen` prints is read nowhere. So the API cannot verify a production token today. The RS256 verifier takes a static JWKS document (rotation only by overlap and restart, `backend/crates/platform-auth/src/verify.rs:332-369`), accepts RSA keys only (`jwks.rs:35-37`) and pins RS256 (`verify.rs:44`). Library-level refusal tests exist (`verify.rs:133-438`); every `platform-api` integration test builds an HS256 verifier.

**Done when**
- `AuthConfig` gains the verification-key source in the form ADR 0006 chooses (a JWKS URL, HTTPS only, plus a refresh interval; or a static document such as `JWT_JWKS_JSON`), and `main.rs` builds the production verifier from it at the `JwtVerifier` construction site. If ADR 0006 keeps RS256 as a migration bridge until P37 lands, it is accepted only in that explicit, logged mode.
- If keys are fetched: they are fetched over TLS with the workspace `reqwest` and cached; `JwtVerifier::verify` and `authenticate` stay synchronous, so the key set becomes swappable and is filled by a background refresher (no fetch inside `verify`); an unknown `kid` triggers a rate-limited refresh and is otherwise 401 with an `auth.decision` "denied" event; a failed refresh keeps the last good set; the fetched document size and the fetch timeout are bounded. Initial fetch, rotation (new `kid`), rate limiting and fetch failure each have a test against a local stub server.
- If no key set has ever loaded, authenticated routes return 503 (`ApiError::AuthNotConfigured`) with an `auth.decision` "refused" event and never fall back to HS256. In production mode (P18) the binary refuses to start without a key source.
- API-level negative tests run through the router with the production verifier injected into `AppState.jwt`: expired, wrong issuer, wrong audience, bad signature, unknown `kid`, algorithm confusion, wrong or missing `typ`, and a key-set outage at boot and after boot. RS256 gains wrong-issuer and not-yet-valid (`nbf`) tests next to the existing ones in `verify.rs`.
- The `RUSTSEC-2023-0071` reason in `backend/deny.toml:11-15` is rewritten to match what is true after ADR 0006 (for example: RS256 verification only, public-key operations only, `TokenSigner` never deployed on an API replica).
- Optional: a fuzz target for the JWKS document input to `rs256_from_jwks` (the existing `jwt_verify` target already fuzzes both verifiers), added to the matrix in `.github/workflows/fuzz.yml`.

**Where.** `backend/crates/platform-config/src/lib.rs`, `backend/crates/platform-api/src/main.rs`, `backend/crates/platform-api/src/lib.rs:172-244`, `backend/crates/platform-auth/src/{verify,jwks}.rs`, `backend/crates/platform-api/tests/`, `backend/.env.example` (Auth section, lines 51-58), `backend/deny.toml`.

**Depends on:** P16, P18.

**Security impact.** Makes real authentication possible in production and keeps it fail-closed when keys are missing (A3).
**ADR.** Covered by P16.

---

### P29. Identity service: sign-in exchange, tenant membership and roles
**Labels:** build · area:auth · rust
**Size:** M-L (pair) · **Priority:** v1 blocker · **Target:** weeks 4-10

**Summary.** Implements the identity and tenancy half of ADR 0006. Nothing models users: tenants are created only by a Paddle `subscription.created`/`subscription.activated` webhook (`backend/crates/platform-api/src/admin.rs:64-108`), `TenantRecord` has no members, and `require_tenant` accepts any validly signed `tid` without checking the registry (`backend/crates/platform-api/src/lib.rs:216-224`). A tenant suspended by a cancel webhook keeps full access, because nothing reads `TenantStatus`. Under the token-exchange design the platform service verifies the provider's token and mints platform tokens with `TokenSigner` (`backend/crates/platform-auth/src/sign.rs`, used only in tests today).

**Done when**
- The service verifies the managed provider's sign-in token (fetching and refreshing the provider's keys there; the checks are in the next item), resolves tenant membership and the admin allowlist, and stops before the second factor: it mints only a `preauth` token carrying `tid` (and the allowlisted `adm` flag, if ADR 0006 puts it on `preauth`). Minting `access` plus `refresh` happens only after the second factor and is P30's work, whichever second factor ADR 0006 chooses (platform TOTP, or checking the provider's MFA claim). No exchange path mints `access` without the second factor in any mode, and no development-mode switch is added for that. The service is deployed as ADR 0006 and P15 decide, and its signing-key custody is documented for P68 and P77.
- **Provider-token verification.** Wherever ADR 0006 places it (here, or in P28 if the API verifies provider tokens directly), it uses a dedicated verifier with its own claims type. `JwtVerifier` and `RawClaims` cannot be reused unchanged: `RawClaims` requires `tid` and a string `aud` (`backend/crates/platform-auth/src/lib.rs:62-66`), the RS256 constructor pins RS256 (`verify.rs:44`), and the JWKS loader keeps RSA keys only (`jwks.rs:35-37`). It checks: an explicit algorithm allowlist matching the provider's published keys; `iss` exactly equals the configured issuer; `aud` (string or array) contains the registered client id or API audience and no audience outside a configured allowlist, and `azp`, if present, equals the client id; `exp` and `nbf` are required, with a bounded clock skew; `nonce` matches the value bound to this sign-in and is single-use, where this service started the request (P16); and the MFA claim, if P16 chose provider MFA. Every check has a negative test against a synthetic key set served by a local test issuer (as in P28's stub server), including a validly signed token issued to a different client id of the same issuer and, where `nonce` applies, a replayed nonce. Each refusal emits `auth.decision` and is ticked in P78.
- An `IdentityRegistry` trait (or a sibling of `TenantRegistry`) in `platform-tenancy` with an in-memory implementation holds the provider subject to tenant mapping and the admin flag (and, per P30, second-factor and refresh state). The durable backend is in P63.
- A researcher or non-paying tenant can be created without a Paddle subscription, through the path ADR 0006 chose (for example admin provisioning), with an audit event.
- `adm` is set only from a server-side allowlist, never from a provider attribute the user can edit. Negative tests at the exchange cover a forged or self-assigned `adm`. (Requiring the second factor for `adm` access tokens is P30's.) The doc comment at `backend/crates/platform-auth/src/lib.rs:24-26` says that `adm` grants cross-tenant powers, not "a tenant privilege".
- `require_tenant` and `require_admin` refuse a token whose tenant is unknown or Suspended (as ADR 0006 decided) with 403 and an `auth.decision` event, fail closed when no registry is configured, and have tests next to `cancellation_webhook_suspends_the_tenant` in `tests/admin_api.rs`, asserted in `audit_coverage.rs`. Reactivation (Suspended to Active) is decided and tested. These tests use access tokens from the existing `platform_auth::mint_token`/`mint_admin_token` or `TokenSigner::mint` helpers, as `backend/crates/platform-api/tests/admin_api.rs:236, 258` do today, so they do not wait for P30.
- White-label: every customer-facing sign-in surface shows the brand from `APP_PUBLIC_NAME` / `VITE_APP_PUBLIC_NAME`, never the engine name: the provider's hosted sign-in and MFA pages, its verification and reset emails, and its application and tenant names. These provider settings are listed in the PR and in the deployment doc (P68). The `scripts/check.sh` white-label guard still passes.
- `docs/ARCHITECTURE.md` lists the identity service in the crate table or a component list (if ADR 0006 makes it a separate binary or module) and describes the sign-in and token-exchange step in the dataflows, consistent with the authorization-model text from P16.

**Where.** `backend/crates/platform-auth/src/` (exchange and minting), a new service module or binary as ADR 0006 decides, `backend/crates/platform-tenancy/src/lib.rs`, `backend/crates/platform-api/src/lib.rs:172-244`, `backend/crates/platform-api/src/admin.rs`, `backend/crates/platform-api/tests/admin_api.rs`, `audit_coverage.rs`, `docs/ARCHITECTURE.md`.

**Depends on:** P16, P13 (provider development tenant).

**Sequencing.** Integrates with P28. A dated week-7 checkpoint in P5 checks the token exchange and tenant membership against the provider's development tenant.

**Security impact.** Defines who can obtain a token for which tenant (A3) and makes suspension effective.
**ADR.** Covered by P16.

**Notes.** About a semester of work for one person if the token exchange is in-house; co-own it or split it again (exchange, membership) when it is picked up.

---

### P30. Second factor and session lifecycle
**Labels:** build · area:auth · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 6-10

**Summary.** The code makes the second factor mandatory ("the platform's mandatory second factor", `backend/crates/platform-crypto/src/totp.rs:1-2`; `docs/THREAT_MODEL.md:93`), and `TokenType::Refresh` "rotates on use" (`backend/crates/platform-auth/src/lib.rs:34`). The TOTP module leaves replay protection to the caller (`totp.rs:8-10, 66-69`) and storage of secrets to the caller (`totp.rs:36-41`), and no refresh rotation exists. If ADR 0006 moves MFA to the provider, this issue shrinks to requiring and auditing the provider's MFA assertion for stewards, researchers and admins, minting `access` and `refresh` after it, plus revocation and the negative tests.

**Done when** (platform TOTP case)
- `access` and `refresh` tokens are minted here, after the second factor; sign-in through P29 yields only a `preauth` token. An `access` token is issued only after a successful second-factor check for every steward, researcher and admin.
- An `adm` access token is issued only after the second factor. A negative test shows that a `preauth` holder on the admin allowlist cannot obtain an `adm` access token without it.
- Enrollment presents `TotpSecret::otpauth_uri` with `config.brand.public_name` as the issuer (`totp.rs:51-53`), never the engine name, with a test, and confirms one valid code before activating.
- Replay: the last accepted step is stored per user, and any code at or below it is refused, with a test.
- TOTP secrets are AEAD-encrypted at rest with `platform-crypto` under a key from configuration; a missing key fails closed; secrets are never logged.
- Failed attempts are rate-limited per account (429, counter kept in the identity registry so it holds across replicas), each attempt emitting `auth.decision`, with a test. Lockout and recovery are decided (one-time recovery codes stored hashed, or an audited administrator reset documented in the runbook).
- Refresh tokens rotate on use; reuse of a rotated token is refused and revokes the whole family; sign-out and administrator disable revoke refresh tokens immediately. Each refusal emits `auth.decision` and has a negative test.
- The stores sit behind traits with in-memory implementations; durable backends and restart tests (a replayed step and a reused refresh token are still refused after restart) are in P63.

**Where.** `backend/crates/platform-crypto/src/totp.rs`, `backend/crates/platform-auth/src/`, the identity service from P29, `backend/crates/platform-tenancy/src/`, `backend/crates/platform-api/tests/audit_coverage.rs`.

**Depends on:** P16, P29.

**Sequencing.** Once this lands, P33's key-rotation call requires a fresh second factor; until then that call refuses.

**Security impact.** Implements the A3 second factor and session revocation.
**ADR.** Covered by P16.

---

### P31. Session token and verified identity in the crypto worker
**Labels:** build · area:frontend · area:auth · javascript
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 3-5

**Summary.** The crypto worker reads a build-time `VITE_DEV_JWT` (`frontend/src/lib/crypto/worker.ts:31-39`, `frontend/src/config/vault.ts:21`), caches a never-refreshed vault instance (`worker.ts:29-43`), and invents a random tenant id (`worker.ts:62`) that is used in every drive AAD. Binding browser keys to the signed-in identity (P33), and through it the hybrid suite (P36), steward upload (P40) and sealed results (P56), needs the session's identity inside the worker, not the sign-in UI. Development HS256 tokens from the `devtoken` binary already carry `iss`, `sub` and `tid` (`RawClaims`, `backend/crates/platform-auth/src/lib.rs:62-66`), so this work does not wait for the identity service (P29).

**Done when**
- A new worker protocol message (`frontend/src/lib/crypto/protocol.ts`) carries the bearer token into the worker. The worker no longer reads `vaultConfig.devJwt` (`worker.ts:31-39`); in development the UI thread supplies the dev token. A refreshed token reaches the worker without a restart.
- The worker exposes the token's `iss`, `sub` and `tid` claims to the crypto core. The browser decodes these claims but cannot check an HS256 signature; the API verifies the token on every request, and the API accepting the same token is what makes the `tid` authoritative.
- The token is held in memory only, never in `localStorage` or IndexedDB.
- Worker-protocol tests cover delivering a token, replacing it with a refreshed one, a malformed token (refused, no claims exposed) and, in `http` vault mode, a missing token (vault calls refused).
- Switching the key store and AAD from the random UUID (`worker.ts:62`) to the session `tid` is left to P33, which owns migrating objects sealed under the old UUID or declaring them unsupported.

**Where.** `frontend/src/lib/crypto/worker.ts`, `protocol.ts`, `workerClient.ts`; `frontend/src/config/vault.ts`.

**Depends on:** none (uses development HS256 tokens until P28 and P29 land).

**Sequencing.** P32 later supplies real session tokens through the same message. Follows P16's session decision (token in memory, passed to the crypto worker).

**Security impact.** Removes the build-time token from the worker's vault path and gives the key store a verified identity to bind to (A3).
**ADR.** Covered by P16.

**Notes.** `frontend/src/lib/crypto/` is code-owned.

---

### P32. Frontend session: sign-in, sign-out, refresh, and no pasted tokens
**Labels:** build · area:frontend · area:auth · javascript
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 6-11

**Summary.** The frontend has no sign-in. The research portal and admin console use pasted bearer tokens prefilled from `VITE_DEV_JWT` and `VITE_ADMIN_JWT` (`frontend/src/components/research/ResearchPortal.tsx:44`, `frontend/src/components/admin/AdminConsole.tsx:9`), and a rejected token produces "mint a fresh dev token" (`frontend/src/lib/vault/httpVault.ts:48`). P31 delivers the token to the crypto worker; this issue obtains, refreshes and ends the session that DoD items 1 and 2 begin with ("can sign in").

**Done when**
- Sign-in and sign-out UI against the provider and identity service from P29, including the second-factor step from P30.
- The token is held in memory (never `localStorage`) and passed to the crypto worker through the message from P31. Outside development builds nothing reads `VITE_DEV_JWT`.
- A 401 triggers a refresh, then re-sign-in; `HttpVault` no longer tells the user to "mint a fresh dev token".
- Sign-out terminates the worker and drops in-memory key handles without deleting persisted keys.
- The token paste fields and their env prefills are removed from the portal and admin console in release builds (they may remain behind the development mode from P18).
- Page titles of new sign-in screens come from `brand.publicName` (as `frontend/src/main.tsx` does today).
- New form controls have associated labels and error messages use `role="alert"` (testable with `getByLabelText`/`getByRole`).
- A test shows that a callback whose `state` is missing, mismatched or already used is refused before any code exchange (a mocked callback; or, if the provider's SDK enforces it, the PR cites where and the test covers the SDK's refusal). After sign-in, no token remains in `location`, history, `localStorage`, `sessionStorage` or IndexedDB, with a test. (PKCE enforcement itself is the provider's, configured in P13.)
- Component and worker-protocol tests cover sign-in, refresh, 401 handling and sign-out.

**Where.** `frontend/src/lib/crypto/workerClient.ts`, `frontend/src/config/vault.ts`, `frontend/src/lib/vault/`, `frontend/src/components/research/ResearchPortal.tsx`, `frontend/src/components/admin/AdminConsole.tsx`, new sign-in components under `frontend/src/components/`.

**Depends on:** P16, P29, P30, P31.

**Sequencing.** UI work can start against dev tokens and the local stack (P8). The week-7 checkpoint in P5 decides the fallback if P29 slips.

**Security impact.** Removes long-lived build-time tokens from the browser and keeps tokens out of persistent storage.
**ADR.** Covered by P16.

**Notes.** `frontend/src/lib/crypto/` is code-owned.

---

### P33. Bind browser keys and enrollment to the signed-in identity (no silent re-keying)
**Labels:** build · area:crypto · area:frontend · rust · javascript
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 5-10

**Summary.** The browser keeps one `device` key row (`frontend/src/lib/crypto/keystore.ts:9-19`) whose tenant id is a random local UUID (`worker.ts:62`). Every drive load re-runs enrollment (`worker.ts:78-86`), and the server overwrites `control/enrollments/{tenant}.json` unconditionally (`backend/crates/platform-api/src/lib.rs:715-777`; `backend/crates/platform-storage/src/lib.rs:125-129`). The record has no key id, suite, creation time or history, and the audit event does not distinguish a replacement from a first enrollment. A second device or a cleared browser therefore silently re-keys the tenant, and data sealed earlier stays under the old key. `VaultStore` has only an unconditional `put`.

**Done when**
- The IndexedDB key store is keyed by verified identity (issuer, subject, `tid`) instead of the single `device` row; the `KeySetupGate` acknowledgement is per identity; the tenant id used in AAD is the session's `tid` (from P31), never a random UUID. A mismatch between the stored row and the session refuses the operation, with a test using `fake-indexeddb` (already a dev dependency) that includes an IndexedDB version upgrade. Objects sealed under the old local UUID are either migrated or documented as unsupported pre-v1 data.
- Enrollment records carry key id, suite and creation time. Enrollment is create-once, using the create-only write from P41's first PR. `PUT /api/v1/drive/enrollment` with a different key returns 409 and is audited as `crypto.key_enrollment` "denied"; re-sending the same key is an idempotent success.
- Replacing a key is a separate, explicit rotation call that requires a fresh second factor (P30), is audited as a distinct outcome, and is never triggered by worker initialization. Until P30 lands, the rotation call refuses (fail closed). Negative tests in `platform-api/tests` and `audit_coverage.rs`.
- The v1 multi-device and recovery policy from P14 is implemented (for example: a second device gets a clear refusal), and `KeySetupGate` explains the second-device and unsupported-browser cases.
- A device without an HPKE key can generate and enroll one later without losing its master key.
- Enrollment records are verifiable as P14 specifies: a Rust check (used by `connector-worker` before sealing, if P19 keeps connector ingestion) refuses a record that fails verification (fail closed), with negative tests. If P14 makes a browser sealer depend on a server-stored enrollment, this issue also exposes the same check in the crypto worker; P40 calls it before sealing. Today nothing reads the enrollment: `connector-worker` takes the sealing key from `DEMO_TENANT_PUBLIC_KEY_B64` (`backend/crates/platform-connectors/src/bin/connector-worker.rs:89-118`).

**Where.** `frontend/src/lib/crypto/keystore.ts`, `worker.ts`, `core.ts`; `frontend/src/components/KeySetupGate.tsx`; `backend/crates/platform-api/src/lib.rs` (`put_enrollment`); `backend/crates/platform-storage/src/lib.rs`; `backend/crates/platform-api/tests/`.

**Depends on:** P14, P31, P41 (conditional-write PR only).

**Sequencing.** P41's conditional-write PR lands by week 3-4. P30 wires the fresh-second-factor check into the rotation call; the rest of this issue does not wait for sign-in (P32).

**Security impact.** Prevents silent key substitution by a second device, a stolen token or worker restarts (A2/A3); makes enrolled keys auditable.
**ADR.** Covered by P14; record any change to the enrollment format there.

**Notes.** Multi-device key sync and key escrow are proposed outside v1.

---

## Hybrid post-quantum cryptography

The first draft's single hybrid-suite issue is split into a suite ADR (P17, with the other decisions above), a browser HPKE core, the backend KEM, the browser switch to the hybrid suite, and token signatures. ADR 0001 is Accepted and is never rewritten (`docs/adr/README.md`).

### P34. Browser HPKE seal and open: wasm32 build of the backend envelope code
**Labels:** build · area:crypto · area:frontend · rust · javascript
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 2-8 (seal by week 5)

**Summary.** The browser cannot do HPKE. It only generates a non-extractable X25519 keypair whose private key is never used (`frontend/src/lib/crypto/core.ts:171-180`), yet the backend expects a browser-side reader ("The browser-side reader must derive the identical string", `backend/crates/platform-connectors/src/pipeline.rs:59-63`), and steward upload (P40) and sealed results (P55) need seal and open in the browser. `docs/ARCHITECTURE.md:56-58` plans a Rust-to-wasm32 build of the backend `hpke` code behind `core.ts`. Nothing in the repository can build or test wasm today (`rust-toolchain.toml` lists only rustfmt and clippy; `frontend/package.json` depends only on react and react-dom).

**Done when**
- **Checkpoint A, seal (by week 5; unblocks P40).** A thin wrapper crate (neutral name, no I/O or logging dependencies, not all of `platform-crypto`: no TOTP or blind index) exports envelope seal for the current suite (`HPK1 || encapped_key || ciphertext`, `platform-crypto/src/lib.rs:132-201`). It runs only inside the crypto worker, behind `core.ts` and the worker protocol, never on the UI thread. Seal uses only the recipient's public key, so no private key enters wasm memory, and the module never handles the drive KEK or per-file keys.
- **Checkpoint B, open (for P55).** Open is added once P17 and P14 have decided private-key custody; where a private key cannot stay in Web Crypto's non-extractable store, the ADR says so and `docs/THREAT_MODEL.md` gains a row for researcher private keys. `TenantKeypair` (`lib.rs:203-217`) stays dev/test-only; the browser-facing open API is new.
- Seal and open choose the suite from the frame magic (with `HPK1` as the first suite), so P35's new frame drops in without an API change, and seal takes a caller-supplied `info` string.
- `info` bindings are defined once and shared by Rust and TypeScript: move `envelope_info` from `platform-connectors` into `platform-crypto`, or pin it with shared vectors, and add the new kinds for uploaded datasets and sealed results.
- Cross-implementation vectors: a committed vector file under a `fixtures/` directory, written by a seeded generator kept in the repository, is checked by both a Rust test and a vitest test. It covers raw public-key enrollment (valid, wrong length, bad base64), `envelope_info` strings, the frame layout, a browser-sealed envelope opening in Rust and (after B) the reverse, and negative vectors (tampered ciphertext, wrong `info`, wrong recipient, wrong frame magic). Keys are derived from documented public seeds and labelled test-only; before the first such PR the maintainer amends `docs/DATA_POLICY.md` rule 3 ("No credentials ... private keys") to allow this.
- Toolchain: `rust-toolchain.toml` adds `wasm32-unknown-unknown`; every `getrandom` major version in the wrapper's wasm dependency tree gets its JavaScript backend for the wasm target only (`js` for 0.2, which `rand` 0.8's `OsRng` in `platform-crypto` uses today; `wasm_js` for 0.3 and 0.4, which the `hpke` upgrade in P35 brings in); `wasm-bindgen-cli` is pinned to the `wasm-bindgen` crate version. The module is built by `scripts/check.sh` and by the CI jobs that run the frontend tests outside it (the portability job's `npm test` and the coverage job's `npx vitest run` in `.github/workflows/ci.yml`). New dependencies pass `cargo deny check`, dependency review and `npm audit`.
- White-label: the build uses release mode without debuginfo and `--remap-path-prefix`, so no path containing the repository name reaches `frontend/dist`; the guard in `scripts/check.sh:34-38` passes on the built bundle. Bundle-size and load-time figures are recorded in `docs/BENCHMARKS.md` (P73).
- **Checkpoint A benchmark (by week 5).** Wasm seal throughput and peak memory in the crypto worker are measured in a real browser (Chromium, through P72 stage A's browser runner or a documented manual run; not a Node Vitest bench) on synthetic data from P9 at 1 MB, 100 MB and one larger size. Today's seal is single-shot (`hpke_seal_to_tenant` calls `hpke::single_shot_seal`, `backend/crates/platform-crypto/src/lib.rs:172-191`), so plaintext, ciphertext and the framed envelope are all in memory at once. The results go into `docs/BENCHMARKS.md` with a target agreed with @AxolDad, and the benchmark joins P73's harness and regression run (or the PR states why it can run only as a recorded manual run per release candidate). They give P38's ADR a measured bound for the maximum dataset size and for the choice between one object per dataset and a per-object size cap.
- `docs/ARCHITECTURE.md` gains a crate-table row for the wrapper crate, and its "Crypto-agility seam" bullet (lines 56-58) describes what is built instead of a plan. If checkpoint B puts a private key in wasm memory, the KEK note (lines 43-46, "JS *or* WASM") is reconciled with that.
- Developer setup docs (P3) list the new toolchain steps.

**Where.** New wrapper crate under `backend/crates/`; `backend/crates/platform-crypto/src/lib.rs`; `backend/crates/platform-connectors/src/pipeline.rs` (`envelope_info`); `frontend/src/lib/crypto/core.ts`, `worker.ts`, `protocol.ts`; `rust-toolchain.toml`; `scripts/check.sh`; `.github/workflows/ci.yml`; `fixtures/`; `docs/DATA_POLICY.md`; `docs/ARCHITECTURE.md`; `docs/BENCHMARKS.md`.

**Depends on:** P17 and P14 (checkpoint B only).

**Sequencing.** Checkpoint A starts immediately.

**Security impact.** Puts dataset sealing in the steward's browser (DoD item 1) with one implementation shared with the enclave; open moves a private key into wasm memory, which must be documented.
**ADR.** Custody of the open path is recorded in P17.

**Notes.** `frontend/src/lib/crypto/`, `scripts/` and `.github/` are code-owned.

---

### P35. Hybrid KEM on the backend (X-Wing, new frame version)
**Labels:** build · area:crypto · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 4-9

**Summary.** Replace `TenantKem = hpke::kem::X25519HkdfSha256` (`backend/crates/platform-crypto/src/lib.rs:30`) with the hybrid KEM chosen in P17, with a new frame version alongside `HPK1` and no silent downgrade (ADR 0001:29-31). The enrollment endpoint validates an X25519 point and records `HPKE_SUITE = "DHKEM(X25519,HKDF-SHA256)+AES-256-GCM"` (`backend/crates/platform-api/src/lib.rs:43, 715-777`).

**Done when**
- `hpke` is upgraded to the version P17 names with the `mlkem` and `aes` features. The upgrade's knock-on changes (`aes-gcm` 0.11, `rand_core` 0.10, `sha2`, `hkdf`) to `platform-crypto`'s own AES-GCM and `OsRng` use (`lib.rs:9-10`) are made, and new crates pass `cargo deny check` and dependency review.
- `TenantKem`, `hpke_seal_to_tenant` and the open path produce and consume the new frame; `X25519_PUBLIC_KEY_BYTES` and `ENCAPPED_KEY_BYTES` become suite-specific; `TenantPublicKey` handles hybrid keys.
- `HPKE_SUITE` names the hybrid suite; `EnrollmentBody`/`put_enrollment` accept, validate and record hybrid public keys against the declared suite. The connector producer and key loading (`platform-connectors/src/pipeline.rs`, `connector-worker.rs`) use the hybrid key.
- Readers configured for the hybrid suite refuse `HPK1` envelopes and X25519-only enrollment keys with negative tests and a `crypto.*` audit event (via `platform_telemetry::security_audit_event`). Per P17, either there is no migration mode at all in production, or there is an explicit, audited, time-limited one with a re-seal tool and a test that it expires.
- KEM-level known-answer tests pass, and the committed suite vectors from P34 are extended to the hybrid frame (both directions once P36 lands).
- The `hpke_envelope` fuzz target (`backend/fuzz/fuzz_targets/hpke_envelope.rs`, which imports `X25519_PUBLIC_KEY_BYTES` and `TenantPublicKey`) covers the new frame.
- If the P34 wasm wrapper has merged, it still builds in `scripts/check.sh` after the upgrade. The upgraded `hpke` brings in `getrandom` 0.4 through its default `getrandom` feature, and on `wasm32-unknown-unknown` that crate does not compile without its `wasm_js` feature. Choose one:
  - the wrapper enables `getrandom = { version = "0.4", features = ["wasm_js"] }` under a `[target.'cfg(target_arch = "wasm32")'.dependencies]` table; or
  - the wrapper builds `hpke` without default features and uses the `*_with_rng` APIs (for example `setup_sender_with_rng`, hpke 0.14.1 `src/setup.rs:120-124`), with randomness from `crypto.getRandomValues` in the worker. The workspace uses edition 2024 (`backend/Cargo.toml:21`), where a member cannot turn off an inherited dependency's default features, so this option also sets `default-features = false` on the workspace `hpke` entry (`backend/Cargo.toml:73`) and re-enables `getrandom` in `platform-crypto`, or the wrapper declares `hpke` directly.

  P34's getrandom 0.2 `js` entry is removed if nothing in the wrapper's wasm dependency tree still uses 0.2. The wasm build sets no `--cfg getrandom_backend` flag. The PR description includes the output of `cargo tree -p <wrapper crate> --target wasm32-unknown-unknown -e features -i getrandom@0.4` (`backend/Cargo.lock` holds getrandom 0.2, 0.3 and 0.4, so an unversioned `-i getrandom` is ambiguous) and the same check for any other getrandom version still reachable from the wrapper. `docs/DEVELOPMENT.md` (P3) gains one line on this.
- Hybrid-frame seal/open throughput and envelope size are benchmarked against the `HPK1` baseline from P73 (ADR 0001:35-36). Before this issue closes, the benchmark joins P73's harness and regression run, and the result and a target agreed with @AxolDad are recorded in `docs/BENCHMARKS.md`.

**Where.** `backend/Cargo.toml`, `backend/Cargo.lock`, `backend/crates/platform-crypto/src/lib.rs`, `backend/crates/platform-api/src/lib.rs` (`HPKE_SUITE`, `put_enrollment`), `backend/crates/platform-connectors/src/pipeline.rs`, `backend/crates/platform-connectors/src/bin/connector-worker.rs`, `backend/fuzz/`, the wrapper crate from P34, `docs/DEVELOPMENT.md`, `docs/BENCHMARKS.md`.

**Depends on:** P17, P73 (the harness and the `HPK1` baseline only; the hybrid benchmark joins them before this issue closes).

**Sequencing.** The `hpke` upgrade rewrites `backend/Cargo.toml` and `Cargo.lock` across dependency generations: land it after P69 merges, or before it starts, never concurrently. P73 records the X25519 baseline before this merges. While this issue is open, Dependabot PRs that move `hpke` across a major version are closed with a link here (P4).

**Security impact.** Implements the post-quantum KEM for every stored envelope (harvest-now-decrypt-later) with downgrade refusal.
**ADR.** Covered by P17.

---

### P36. Browser on the hybrid suite: hybrid keys, seal and open
**Labels:** build · area:crypto · area:frontend · javascript
**Size:** S-M · **Priority:** v1 blocker · **Target:** weeks 7-11

**Summary.** Definition-of-done item 1 requires the upload to be "encrypted in the browser under the hybrid post-quantum suite". After P34 and P35, the browser crypto core must generate, store and enroll hybrid keys and seal and open the hybrid frame. Today enrollment is gated on X25519 support (`frontend/src/lib/crypto/core.ts:160-168`, `worker.ts:59-60`, `protocol.ts:9-11`, `frontend/src/components/KeySetupGate.tsx:52-54`).

**Done when**
- The wasm core from P34 is rebuilt with the hybrid suite and seals and opens the new frame; the committed vectors pass in both directions (browser-sealed opens in Rust and the reverse), including a classical-only envelope refused once the hybrid suite is configured.
- Hybrid keypairs are generated, stored as P17 decided (for example the seed encrypted under a dedicated non-extractable AES-GCM key, decrypted only in the worker), and enrolled through the create-once flow from P33, recording the suite.
- The X25519-only gating and copy in `KeySetupGate.tsx` and `protocol.ts` are replaced; unsupported browsers get a clear message.
- Tests with `fake-indexeddb` cover key storage and reload.

**Where.** `frontend/src/lib/crypto/core.ts`, `worker.ts`, `protocol.ts`, `keystore.ts`; `frontend/src/components/KeySetupGate.tsx`; the wrapper crate from P34.

**Depends on:** P34, P35, P17, P33.

**Security impact.** Completes DoD item 1's hybrid requirement in the browser; changes where a private key lives (documented in P17).
**ADR.** Covered by P17.

---

### P37. Hybrid token signatures (Ed25519 + ML-DSA-65), if ADR 0006 chooses them
**Labels:** build · area:crypto · area:auth · rust
**Size:** M · **Priority:** v1 needed · **Target:** weeks 8-12

**Summary.** ADR 0001 moves signatures to Ed25519 + ML-DSA-65 at the `JwtVerifier` construction site. There is no signature type alias: `JwtVerifier` constructors (`backend/crates/platform-auth/src/verify.rs:27-46`) fix the algorithm, `TokenSigner` hardcodes RS256 (`sign.rs:49`), `jwks.rs` keeps RSA keys only (`jwks.rs:35-37`), and `jsonwebtoken` 10.4 has no ML-DSA and there is no standard JOSE algorithm for the hybrid. No definition-of-done item names signatures directly; they are needed so the "Hybrid post-quantum encryption" step can be marked Built (DoD item 3).

**Done when** (option (a) of P16: platform-issued hybrid tokens)
- The token format and library chosen in P16/#17 are implemented: a signer for the identity service (P29) and a verifier constructor wired in at the production construction site (`backend/crates/platform-api/src/main.rs`).
- The API refuses classical-only access tokens unless ADR 0001's explicit, logged, time-limited migration mode is on, with negative tests (classical-only, Ed25519-only, ML-DSA-only, tampered either half).
- A maximum-size token passes through the axum router (ML-DSA-65 signatures are about 3.3 KB; ADR 0001:35-36).
- The `jwt_verify` fuzz target covers the new format.
- `THREAT_MODEL.md` A4 ("Forge signatures"), the suite table in `ARCHITECTURE.md` and the `rsa` justification in `backend/deny.toml` match.

**If P16 chooses option (b)** (a superseding ADR limits hybrid signatures to long-lived material), this issue closes when that ADR is merged and the same three documents are updated.

**Where.** `backend/crates/platform-auth/src/{sign,verify,jwks,keygen}.rs`, `backend/crates/platform-api/src/main.rs`, `backend/fuzz/fuzz_targets/jwt_verify.rs`, `backend/deny.toml`, docs above.

**Depends on:** P16, P17, P28, P29 (option (a) only).

**Sequencing.** Coordinate with P29.

**Security impact.** Post-quantum token authenticity (A4).
**ADR.** Covered by P16 and P17.

---

## Dataset lifecycle (steward)

### P38. Steward dataset upload: backend route, storage layout and catalog registration
**Labels:** build · area:storage · area:disclosure · rust · needs-adr
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 4-10

**Summary.** The first draft pointed this at the drive code, which cannot produce a queryable dataset. Drive files are AES-GCM chunks under per-file keys wrapped by a non-extractable, browser-only KEK (`frontend/src/lib/crypto/drive.ts`, `docs/ARCHITECTURE.md:42-58`), so no enclave can open them. The query path reads only HPKE envelopes of Parquet listed by the newest committed snapshot manifest under `TenantPaths::connector_prefix` (`backend/crates/platform-storage/src/lib.rs:78-116`; ADR 0003), opened with `envelope_info` = `tenant-envelope-v1|{tenant}|{slug}|{object}` (`backend/crates/platform-api/src/query.rs:252-298`, `backend/crates/platform-connectors/src/pipeline.rs:59-64`), and the engine registers only Parquet. So steward upload is a new path, not a hardening of drive. The API sees only ciphertext (`VaultStore`: "opaque bytes"), so it can refuse only what it can check.

**Done when**
- An ADR (next free number) records the upload format. The storage layout reuses ADR 0003's versioned snapshots (objects under `snapshots/{version}/`, then a sealed manifest written last as the commit, then pruning of superseded snapshots), so a re-upload replaces rather than adds. Input is Parquet only for v1 (CSV conversion needs a Parquet writer in the browser and is proposed outside v1); the dataset namespace (a `ConnectorSlug` from a reserved namespace that cannot collide with connector slugs, or a new dataset id; `DatasetGrant`, `DatasetListing` and `AccessRequest` are keyed by connector today); one sealed object per dataset for v1, or several same-schema objects under a per-object size cap; the `info` binding for uploaded objects (shared with P34); and where the declared schema (column names and types) lives: either stored as plaintext next to the dataset, where the operator can see it, or sealed with the dataset, with the API comparing only a digest of it for the 422 mismatch check below. In both cases only the dictionary the steward chooses to publish (P59) is plaintext by design.
- An authenticated route accepts a sealed envelope and stores it only at the layout above, for the tenant taken from the token. It has its own `DefaultBodyLimit` (today only the drive router sets one, `backend/crates/platform-api/src/lib.rs:37, 263`), a documented maximum dataset size, set in `platform-config` with a safe default (an invalid value fails closed at startup), and a row cap declared by the client.
- It refuses, each with a test: an unauthenticated or non-access token (401); an envelope that is not `HPK1`/hybrid-framed (422); over the size limit (413); a declared schema that does not match the recorded one (422); a dataset id the steward does not hold.
- Re-upload replaces the current snapshot through ADR 0003's manifest-last commit; a partial upload is never listed or queried. `SnapshotWriter` (`backend/crates/platform-connectors/src/snapshot.rs`) seals plaintext on the server, so the upload route needs a variant that stores objects the browser already sealed and then commits the manifest and prunes as `SnapshotWriter::commit` does. Because the object `info` binding names the object id, the ADR says who chooses the id before the browser seals.
- `publish_listing` (`backend/crates/platform-api/src/research.rs`) refuses a dataset the steward does not hold. "Holds" is one function (the dataset has a committed snapshot under the steward's tenant), which the listing route in P39 reuses.
- P39 can list each snapshot's suite identifier, object sizes and write time without opening anything. The manifest is sealed to the tenant, so the API cannot read it without key release; the write time is already in the plaintext `SnapshotVersion` path segment (its `unix_nanos` prefix) and sizes come from the vault per object, so the ADR records where the suite identifier lives (for example a plaintext per-snapshot record written before the manifest), for connector snapshots too.
- `docs/THREAT_MODEL.md` "Metadata" (lines 143-144) names what the operator can now see for each uploaded dataset, published or not: the dataset id (part of the vault path), the declared row cap, the snapshot versions and write times (ADR 0003 already lists connector snapshot times there), any per-snapshot record the ADR adds and, if the ADR keeps it plaintext, the declared schema. If the schema is plaintext, the steward upload UI (P40) says so in one line before the steward uploads.
- A test in `backend/crates/platform-api/tests/research_api.rs` seeds the dataset through the new route (instead of calling `hpke_seal_to_tenant` directly), and a granted researcher's aggregate query over it succeeds, using `MultiTenantDevKeyProvider` until P50 lands.
- Steward-supplied Parquet is parsed in the enclave only after P69 merges: the `thrift` exception in `.github/workflows/dependency-review.yml:18-22` is justified only because "QuackXide only reads Parquet it wrote and sealed itself". The enclave refuses a schema mismatch with a distinct error, and P54 decides whether that refusal is charged.
- A fuzz target for the new route's body parsing is added to `.github/workflows/fuzz.yml`.
- `docs/ARCHITECTURE.md` gains a "steward upload" dataflow, separate from Drive (section 1): sealed Parquet from the browser, the upload route, the dataset namespace and storage layout (ADR 0003's snapshots) and catalog registration.

**Where.** `backend/crates/platform-api/src/lib.rs` (router), `backend/crates/platform-api/src/research.rs`, `backend/crates/platform-api/src/query.rs` (`decrypt_connector`), `backend/crates/platform-storage/src/lib.rs` (`TenantPaths`), `backend/crates/platform-connectors/src/snapshot.rs`, `backend/crates/platform-tenancy/src/catalog.rs`, `backend/crates/platform-api/tests/research_api.rs`, `backend/crates/platform-config/src/lib.rs`, `backend/fuzz/`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, new ADR.

**Depends on:** P14 (what the upload is sealed to), P69 (steward-supplied Parquet is parsed only after it merges).

**Sequencing.** Can start on the current `HPK1` frame with dev tokens and the local stack (P8); integrates with P28. Coordinate with P52: P52's input cap on decrypted bytes must be at least this issue's upload maximum, or both are set from one configuration value; P52's check before decryption refuses anything larger either way. P34 checkpoint A's wasm seal measurements (by week 5) give the ADR a measured bound for the maximum dataset size and for the choice between one object per dataset and a per-object size cap; P40 confirms or lowers it. P39 builds the listing route over this layout.

**Security impact.** Adds a new untrusted-input path into the enclave and a new storage format; keeps the operator unable to read uploads (A2) and keeps one committed snapshot per dataset, as ADR 0003 does for connectors (A1). Records the plaintext metadata the operator sees for every upload.
**ADR.** Required (storage format and public API).

---

### P39. Steward dataset listing route
**Labels:** build · area:storage · rust
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 7-10

**Summary.** Definition-of-done item 1 ends with the steward able to "see it stored as ciphertext", P40's publish form picks from stored datasets, and P42 deletes a dataset by id. No route lists a tenant's research datasets: the router (`backend/crates/platform-api/src/lib.rs:248-324`) has `GET /api/v1/drive/objects`, which lists drive objects only, and `GET /api/v1/catalog`, which lists only published listings. `PublishForm` takes a free-text connector slug (`frontend/src/components/research/PublishForm.tsx:19, 45-47`). Without a listing route the steward cannot see an upload after a reload or pick one to publish. Split from P38 to keep that issue within size M.

**Done when**
- An authenticated `GET` route lists every research dataset the caller holds under `tenants/{tid}/connectors/` (the layout from P38's ADR), with the tenant taken only from the token. That includes steward uploads (P38), connector-synced datasets and the dataset that P8 seeds and its README flow has the steward publish. "Holds" uses the same function as P38's `publish_listing` check, so the list and that check cannot disagree.
- Each entry gives: the dataset id; the current snapshot version (the newest manifest's version, read from its path without opening it) and the object ids under that snapshot; the object count and total ciphertext bytes of the current snapshot only, never the whole prefix, which can still hold superseded snapshots awaiting pruning (sizes from the existing `VaultStore::usage`, `backend/crates/platform-storage/src/lib.rs:189-190`, applied per object); the suite identifier; and the upload time. The upload time comes from the `SnapshotVersion` and the suite from the per-snapshot record P38's ADR defines, so the route never fetches objects to read frame headers or opens the manifest; if that is not possible, the upload time comes from the `last_modified` listing that P41 adds. No plaintext metadata appears beyond what P38's ADR already makes operator-visible.
- The response is bounded by a documented cap, the same one P41 sets for `list_objects` (whichever lands first sets it). A storage failure returns an error status (502 today, P41's classes once they land), never an empty list.
- Tests: an empty list; one entry after an upload; still one current snapshot after a re-upload; a partial upload, which is never listed; a superseded snapshot's objects, which are not counted; another tenant's datasets, which never appear (the same response as an empty list); a storage failure, which is an error, not an empty list.
- Each successful call emits `data.access` ok, as `list_objects` does (`backend/crates/platform-api/src/lib.rs:628-633`), asserted in `audit_coverage.rs` and ticked in P78.

**Where.** `backend/crates/platform-api/src/lib.rs` (router), `backend/crates/platform-api/src/research.rs`, `backend/crates/platform-storage/src/lib.rs`, `backend/crates/platform-api/tests/research_api.rs`, `backend/crates/platform-api/tests/audit_coverage.rs`.

**Depends on:** P38 (its ADR and the "holds" function used by `publish_listing` only).

**Sequencing.** Starts once P38's ADR is accepted (the snapshot layout itself is merged, ADR 0003). P40 (stored-dataset view and publish form) and P42 (delete action) use this route.

**Security impact.** Shows the steward only what the operator can already see (identifiers, sizes, suite, time) and never another tenant's datasets (A2).
**ADR.** Covered by P38 (upload layout and per-snapshot record) and ADR 0003 (snapshots).

---

### P40. Steward dataset upload: browser sealing and upload UI
**Labels:** build · area:frontend · area:crypto · javascript · needs-adr
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 6-11

**Summary.** The browser half of steward upload: a signed-in steward selects a Parquet file, the crypto worker seals it to the key decided by P14 with the server `tid` in the `info` binding (not the worker's random tenant id, `frontend/src/lib/crypto/worker.ts:62`), and the API stores the ciphertext (definition-of-done item 1). The browser has no HPKE seal today (P34).

**Done when**
- The steward selects a Parquet file; the browser reads the Parquet footer to check size and row count against the limits and to extract column names and types for the declared schema, and refuses a mismatch with the schema (or digest) that P38 recorded for an earlier upload of the same dataset before sealing. If P38 keeps the declared schema as plaintext, the form says so in one line before upload.
- Before code lands, the ADR below names the Parquet footer reader and where it runs. It is either a small JavaScript reader, preferably with no transitive runtime dependencies, under a licence compatible with Apache-2.0 OR MIT (`CONTRIBUTING.md:93-97`; the allow list in `backend/deny.toml:31-44`; not on the `deny-licenses` list in `.github/workflows/dependency-review.yml:27`), or the `parquet` crate's metadata reader built for wasm with `default-features = false` and without the workspace `arrow` feature (`backend/Cargo.toml:103`), kept out of P34's thin seal wrapper unless the code owner agrees to the growth. Either way the bundle-size cost is recorded in the ADR and in `docs/BENCHMARKS.md`.
- The reader reads only the tail of the file (`File.slice`). It runs on the UI thread or in a separate worker, and goes into the key-holding crypto worker (`docs/ARCHITECTURE.md:50-52`) only with the code owner's agreement. Its check is advisory: the enclave re-checks the schema (P38).
- Before sealing, the crypto worker obtains the recipient key P14 names for steward uploads and checks it as P14 specifies: for a stored enrollment, with P33's check; for the steward's own key, that the stored enrollment's key id matches the local key; for a release-service or KMS key, with the pinning or attestation check P14 names. A key that fails the check refuses the upload before any bytes are sealed, with a test.
- The crypto worker seals the bytes (never on the UI thread) with the session's verified `tid` and uploads them through the route from P38.
- `ResearchClient` gains a method for the P39 listing route. The steward sees each stored dataset as ciphertext (dataset id, object count, ciphertext size, suite, upload time) from that route, including after a reload, and the publish form picks from that list instead of the free-text slug (`frontend/src/components/research/PublishForm.tsx:19, 45-47`). If P59 has merged, the publish form pre-fills P59's data dictionary from the footer schema read here.
- Before closing, the upload uses the hybrid suite (P36); until then it may use the current `HPK1` frame.
- Component and worker tests cover: an oversized file; a malformed (non-Parquet) file; a footer length larger than the file or than a documented cap; a truncated footer; a schema mismatch; and an unauthorized upload (401/403 shown clearly). Each malformed case is refused before sealing.
- New form controls have associated labels and error messages use `role="alert"`.
- A cross-implementation test shows a browser-sealed upload opens with the backend's open path.
- The end-to-end upload path (file read, seal, upload) is benchmarked in a real browser at P38's documented maximum dataset size, which confirms or lowers that maximum. The result and a target agreed with @AxolDad are recorded in `docs/BENCHMARKS.md`, and the benchmark joins P73's harness and regression run (or the PR states why it can run only as a recorded manual run per release candidate).

**Where.** `frontend/src/lib/crypto/worker.ts`, `protocol.ts`, `core.ts`; new upload components under `frontend/src/components/research/`; `frontend/src/lib/research/client.ts`; `frontend/src/components/research/PublishForm.tsx`; `frontend/package.json` (if a JavaScript reader is chosen); `docs/adr/`; `docs/BENCHMARKS.md`.

**Depends on:** P38, P39, P34 (checkpoint A), P31, and P32, P33 and P36 to close (DoD item 1 requires a signed-in steward, a checked recipient key and the hybrid suite).

**Security impact.** Plaintext leaves the steward's device only as ciphertext bound to tenant, dataset and object (DoD item 1).
**ADR.** Required for the Parquet footer reader (`docs/adr/README.md:7-9`: a dependency that handles plaintext, since the footer carries the schema and column statistics of the steward's file). A short ADR in the same PR as the reader records the library and version (or the wasm build of `parquet` and its features), its licence, where it runs (UI thread, separate worker, or the crypto worker with the code owner's agreement) and its bundle-size cost. If P38's ADR is still Proposed, these can go there instead. The upload format and the suite are covered by P38 and P17.

**Notes.** `frontend/src/lib/crypto/` is code-owned.

---

### P41. Encrypted storage: production hardening of `ObjectStoreVault`
**Labels:** harden · area:storage · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 3-9

**Summary.** `VaultStore` is the trait; `ObjectStoreVault` is the GCS and in-memory implementation (`backend/crates/platform-storage/src/lib.rs`). Typed tenant paths and cross-tenant isolation are already Built and tested (`tenant_isolation_is_absolute` in `backend/crates/platform-api/tests/drive_api.rs`, `query_is_tenant_isolated` in `query_api.rs`, and in `platform-storage/src/lib.rs` the path tests at lines 301-384 and `listing_is_isolated_per_tenant_prefix` at lines 444-471); keep those as regression tests rather than new work. The real gaps: `new_gcs` silently inherits the `object_store` 0.12 defaults (10 retries within a 3-minute window, 30 s request and 5 s connect timeouts); every error other than `NotFound` becomes 502 (`StorageError`, `platform-storage/src/lib.rs:167-172`; `platform-api/src/lib.rs:112-118`); every `put` overwrites; an aborted drive upload leaves chunks with no manifest (chunks are written first and the manifest last, `frontend/src/lib/crypto/drive.ts`); and `delete_object` deletes the manifest first (`platform-api/src/lib.rs:699`) and returns on the first chunk error, so a retry gets 404 and the chunks are stranded.

**Done when**
- **First PR: conditional writes on `VaultStore` (size S, one named owner, merged by week 3-4; it needs nothing from P18).** P33's create-once enrollment needs it. It adds:
  - a create-only method implemented once over `put_opts(.., PutMode::Create)`, which `object_store` 0.12 sends to GCS as `x-goog-if-generation-match: 0` (`object_store` 0.12.5 `src/gcp/client.rs:402`) and which `InMemory` supports natively;
  - an update-if-version-matches method (`PutMode::Update` with the version from a prior read), only if P61's ADR picks versioned records in the vault and needs it. Connector snapshots need neither write: ADR 0003 writes each snapshot under a fresh version and commits it with a manifest written last;
  - `StorageError` variants for already-exists and precondition-failed. Today `map_err` (`backend/crates/platform-storage/src/lib.rs:235-240`) turns both into `Backend`, which `From<StorageError> for ApiError` (`backend/crates/platform-api/src/lib.rs:112-118`) makes a 502; the new variants map to 409;
  - the `Arc<dyn ObjectStore>` constructor from the next item, and tests on the in-memory backend plus a wrapped store that returns `object_store::Error::AlreadyExists` and `Precondition`. GCS behaviour is checked by a documented manual run against the P12 development bucket, because fake-gcs-server does not honour `ifGenerationMatch` (`object_store` 0.12.5 `src/gcp/mod.rs:305-306`).

  P33 and, if P61's ADR picks versioned records in the vault, P62 and P63 use these writes.
- `ObjectStoreVault` gains a constructor that takes an `Arc<dyn ObjectStore>`, and tests wrap a store to inject `object_store::Error` variants (and use `object_store::throttle::ThrottledStore` for latency) so each classification in `map_err` is covered. `FlakyVault` (`platform-api/tests/admin_api.rs:323-365`) moves into shared test support and can fail `put`, `get`, `delete` and `list`, with an outage test for each.
- `new_gcs` sets retries (`with_retry`) and request and connect timeouts (`with_client_options`) explicitly from `platform-config`, and an API call against a stalled backend fails within a documented bound. Because a `VaultStore` wrapper sits above the HTTP client, these settings are tested against a local GCS emulator (for example fake-gcs-server, which `object_store` supports via `gcs_base_url` and `disable_oauth`), or the test is documented as manual.
- `StorageError` also distinguishes retryable and fatal failures (the already-exists and precondition variants come from the first PR), and `ApiError` maps each to a documented status, with tests.
- `delete_object` can be retried after a partial failure (chunks deleted before the manifest, a tombstone, or deletion by prefix when the manifest is gone), with a test that injects a failure between chunk deletes. Absent objects still return an honest 404.
- A sweep deletes drive chunk prefixes that have no manifest and are older than a documented age longer than the longest allowed upload, so it never deletes an upload in progress. `VaultStore` gains a listing that returns `last_modified`. Tests cover an aborted upload, a delete that failed partway, and a recent upload the sweep must leave alone.
- `list_objects` is bounded: a documented cap, with the per-manifest GETs made concurrent or capped. Full pagination with frontend changes is proposed outside v1.
- Neither binary silently falls back to the in-memory vault (implemented through P18); the `StorageConfig` doc comment (`platform-config/src/lib.rs:93-94`, which says routes "refuse instead") is reconciled with behaviour. `GCP_PROJECT_ID` is used or removed.

**Where.** `backend/crates/platform-storage/src/lib.rs`, `backend/crates/platform-api/src/lib.rs` (`delete_object`, `list_objects`, `From<StorageError> for ApiError`), `backend/crates/platform-api/tests/drive_api.rs`, `admin_api.rs`, `backend/crates/platform-config/src/lib.rs`.

**Depends on:** P18 (startup-refusal item only).

**Sequencing.** The conditional-write PR merges first (by week 3-4); P33 waits on it. Everything else starts immediately. P39 uses this issue's listing cap and error classes once they land.

**Security impact.** Reliability of ciphertext storage; idempotent deletes; create-once writes that P33 relies on.
**ADR.** Not required.

**Notes.** Admin usage (`list_tenants`, `backend/crates/platform-api/src/admin.rs`) lists every object of every tenant per request; at most document the cost for v1.

---

### P42. Steward dataset deletion
**Labels:** build · area:storage · area:frontend · rust · javascript
**Size:** M · **Priority:** v1 needed · **Target:** weeks 9-13

**Summary.** A steward cannot delete a research dataset. The only data `DELETE` is `DELETE /api/v1/drive/objects/{id}`, which never touches `tenants/{steward}/connectors/{connector}/`. Unpublishing (`DELETE /api/v1/catalog/{listing_id}`) hides the listing but leaves every grant in place, and research queries check only for an active grant before decrypting the dataset's current snapshot. So a granted researcher can still query a withdrawn dataset, and a steward who uploads the wrong file cannot remove it.

**Done when**
- A steward-only endpoint deletes a dataset identified by (steward, connector or dataset id). It first revokes every grant on the dataset (a new `GrantRegistry::revoke_all(steward, connector)`; `revoke` works by grant id only) and unpublishes the listing, then deletes every object under the dataset's prefix, including every snapshot and manifest (ADR 0003), manifests first as `prune_superseded` does. A partial failure never leaves a dataset that is still queryable but half-deleted; the operation is idempotent and resumable, with a test that injects a storage failure partway.
- Deletion disables, or requires disabling, connector sync for that slug, so `run_sync` cannot repopulate it; a test shows a sync after deletion does not restore queryable data.
- Budget ledger entries are kept, so spend stays monotonic and re-granting cannot reset it.
- After deletion a research query gets the same refusal as an unknown dataset (no existence oracle), never an empty or stale result; a query already in flight fails closed. Another tenant gets the same 404 as for an unknown id. Tests in `tests/research_api.rs`.
- Object deletes are audited as `data.access` and grant and listing changes as `research.catalog`, asserted in `audit_coverage.rs`.
- The steward console has a delete action on each dataset listed by P39, with a confirmation step (reuse the two-step pattern in `frontend/src/components/research/IssuedGrantRow.tsx`) and a component test.

**Where.** `backend/crates/platform-api/src/research.rs`, `backend/crates/platform-tenancy/src/grants.rs`, `catalog.rs`, `backend/crates/platform-storage/src/lib.rs`, `backend/crates/platform-api/tests/`, `frontend/src/components/research/`.

**Depends on:** P38, P39.

**Sequencing.** Restart safety of revocation comes with P62.

**Security impact.** Lets a steward withdraw data and access completely (grant check, A1); no existence oracle.
**ADR.** Not required.

**Notes.** How long deleted ciphertext persists in backups is stated in P76. The maintainer adds a "Delete" row to the dataset lifecycle table in `docs/PROJECT_SCOPE.md` so this traces to scope.

---

## Research lifecycle (researcher)

### P43. Wire research access in the production binary, independently of key release
**Labels:** harden · area:disclosure · rust
**Size:** S-M · **Priority:** v1 blocker · **Target:** weeks 2-5

**Summary.** Catalog, access requests, grants and budgets need no key material, but they live on `ConnectorQueryService` and their handlers call `query_service(&state)?` (`backend/crates/platform-api/src/lib.rs:423-425`). `main.rs:68` sets `query: None`, so in the shipped binary every catalog, grant, budget and access-request route returns 503 until key release lands, and nothing in the portal past sign-in can run against the real binary for most of the semester.

**Done when**
- Either a `ResearchService` (grants, budgets, catalog, default budget, min cohort) becomes its own `AppState` field, so catalog, request, grant and budget routes depend only on it and return `ResearchUnavailable` (503) when it is `None`; or `main.rs` builds `ConnectorQueryService` with a key provider that always refuses (`QueryUnavailable`) plus `.with_research(..)`. Either way there is one source of truth: the grant the new routes create is the one `research_query` checks and charges (shared `Arc` stores).
- `main.rs` builds the research layer from `config.research` (`min_cohort_size`, `default_query_budget`, `pricing_currency`, already parsed in `backend/crates/platform-config/src/lib.rs:187-195`) over the in-memory stores, with a startup warning like the one for the in-memory vault; P62 swaps in durable stores. `min_cohort` still reaches the own-data query path. Attestation stays required, and the dev key providers and `require_attestation = false` are never used in this binary.
- State construction moves out of `main()` into a function tests can call. Existing tests change only to set the new field (or use a builder); no assertion changes.
- New tests: with research configured and no key provider, catalog, request, approve and grant routes return 200 while `POST /api/v1/query` and `/api/v1/research/query` still return 503; with research not configured, those routes return 503; the audit events in `audit_coverage.rs` still fire.
- The `AppState` doc comment (`lib.rs:51`), the startup log (`main.rs:41-45`) and the fail-closed list in `docs/ARCHITECTURE.md` are updated.

**Where.** `backend/crates/platform-api/src/{lib.rs,query.rs,research.rs,main.rs}`, `backend/crates/platform-api/tests/`, `docs/ARCHITECTURE.md`.

**Depends on:** none.

**Sequencing.** Coordinate with P8, which shares the wiring function.

**Security impact.** Grant and catalog decisions run in the shipped binary without any key path; queries stay fail-closed.
**ADR.** Not required.

---

### P44. Researcher portal: query form, result view and refusal states
**Labels:** build · area:frontend · javascript
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 3-12

**Summary.** The portal (`ResearchPortal`, `PublishForm`, `IssuedGrantRow`) already handles the catalog, access requests and their status, and steward approvals, top-ups and revocations. It cannot run a query: `ResearchClient` (`frontend/src/lib/research/client.ts:129-240`) has no method for `POST /api/v1/research/query`, and nothing in `frontend/src` calls it. It authenticates with a pasted token (`ResearchPortal.tsx:44`), and its `get()` helper maps every 503 to one message (`client.ts:148`).

**Done when**
- `ResearchClient` gains a research-query method that sends `{steward_tenant, connector, sql}` (`backend/crates/platform-api/src/query.rs:703-708`). The portal has a query form limited to the researcher's active grants (which supply `steward_tenant` and `connector`), shows the dataset's data dictionary and example query from P59 once P59 lands (until then, or if P59 moves to v1.1, the SQL table name, which is the connector slug double-quoted where needed, and a `SELECT COUNT(*) AS n` example), and has a result view showing the aggregate rows, `row_count`, `suppressed_rows`, `min_cohort` and `budget_remaining` (`query.rs:617-625`).
- Every refusal shows its own message, with a component test for each: 401; 403 (no active grant; revoked, unknown and foreign grants are deliberately indistinguishable); 422 (plan or disclosure rejection, with the reason from P60 once it lands); 429 (budget exhausted: ask the steward for a top-up); 400 (invalid steward or connector, or the query could not be executed); 502 (backend error); and 503, where the three causes ("enclave attestation unavailable", "confidential query not available", "research access not configured") are told apart by the error body, or by the stable `code` from P60, never by status alone.
- The budget is charged after the grant check and the attestation gate but before planning, and is not refunded (`query.rs:515-527`). After any refusal from the research-query route, the portal re-fetches the grant's budget and shows the actual remaining figure. It does not infer a charge from the status code: an invalid steward or connector (400, `backend/crates/platform-api/src/lib.rs:501-505`) and framework rejections of a malformed body are refused before the charge (`query.rs:522-524`), a 400 from `QueryError::Execution` (`query.rs:674`) comes after it, and P54 may move the charge point. Once P60 lands, the "this attempt was charged" wording keys off the stable `code` (`query_rejected` or `query_failed`); `malformed_request`, 403 and 503 refusals are shown as free.
- Errors are announced to assistive technology (`role="alert"`) and inputs have labels.
- The result view takes an already-decoded result object (a prop), not the HTTP response, so P56 can put the open step in front of it without rewriting the component; a component test renders it from a plain object.

**Where.** `frontend/src/lib/research/client.ts`, `frontend/src/components/research/`, `ResearchPortal.test.tsx` (mocking pattern).

**Depends on:** P8 (the local stack it closes on), P54 (the result contract only, agreed before the result view renders).

**Sequencing.** Component work mocks `ResearchClient` (as `ResearchPortal.test.tsx` does) and runs end to end on P8. This issue closes with the result view rendering the plaintext JSON response that `query.rs:617-625` returns today, on the local stack (P8) and in development builds. P32 removes the token paste field and its `VITE_DEV_JWT` prefill in release builds. P56 switches the result view to sealed results and makes a release build refuse an unsealed one (DoD item 2).

**Security impact.** Presents refusals without creating an oracle (same message for missing, revoked and unknown grants).
**ADR.** Not required.

---

### P45. Grant check: complete the refusal tests and audit coverage
**Labels:** harden · area:disclosure · rust · good first issue
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 2-5

**Summary.** `GrantRegistry` is steward-scoped and revocable. Grants have no expiry: `DatasetGrant` has no expiry field (`backend/crates/platform-tenancy/src/grants.rs:18-30`), so the first draft's "expired" case cannot be tested. Missing and revoked grants are already tested at the API (`backend/crates/platform-api/tests/research_api.rs`). What is missing: other-steward and other-connector refusals, byte-identical refusal bodies, and audit coverage. `audit_coverage.rs`'s `full_app` wires no research layer, so research endpoints return `ResearchUnavailable` there; and revoke, top-up and budget reads of an unknown or foreign grant return 404 with no audit event (`revoke_grant`, `top_up_budget`, `budget_state` in `query.rs`).

**Done when**
- API tests: a researcher holding a grant from steward A gets 403 on steward B's dataset with the same connector slug, and 403 on another of A's connectors. The grant check runs before any data access, so steward B needs no data.
- The 403 for a nonexistent (well-formed) steward or connector is byte-identical to the 403 for an existing but ungranted dataset. Malformed ids return 400 before the grant check; that is expected and not an oracle.
- Unknown grant ids and grant ids owned by another tenant get byte-identical 404 responses from `DELETE /api/v1/grants/{id}`, `GET /api/v1/grants/{id}/budget` and `POST /api/v1/grants/{id}/budget`, with tests comparing bodies, not only status. A steward's own revoked grant keeps its current behaviour (revoke is idempotent; budget and top-up still answer, because `list_for` includes revoked grants).
- Revoke then re-grant does not reset budget spend at the API level (the unit test exists in `budget.rs`).
- New `denied` audit events for a revoke, top-up or budget read of an unknown or foreign grant (identifiers only). Input-validation 400s are either audited or listed as out of scope.
- `audit_coverage.rs` wires `.with_research(ResearchStores { .. }, k, budget)` into `full_app` (as `research_app` does) and asserts: grant create (`tenant.provisioned` ok, detail `granted ...`), revoke (`tenant.provisioned` ok, detail `revoked ...`), the no-grant research denial (`auth.decision` denied), top-up (`research.budget` ok), budget exhaustion (`research.budget` denied), and the new denials. Create and revoke share kind and outcome, so match on `detail` via `capture.events()`; `contains()` matches only kind and outcome.
- `docs/ARCHITECTURE.md` records whether grant events stay under `tenant.provisioned` or move to a new `research.grant` kind, and its audit table and coverage list (rule 3) include grants and budgets.

**Where.** `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-api/src/lib.rs` (grant handlers), `backend/crates/platform-api/tests/research_api.rs`, `audit_coverage.rs`, `docs/ARCHITECTURE.md`.

**Depends on:** none.

**Sequencing.** Coordinate the `full_app` change with P46 and P79.

**Security impact.** Proves the grant check and the no-existence-oracle property (A1) and makes every grant decision auditable.
**ADR.** Not required.

**Notes.** Grant expiry is not in `docs/PROJECT_SCOPE.md` or the definition of done; it is proposed outside v1.

---

### P46. Test the attestation-refusal path on query and research routes
**Labels:** harden · area:enclave · rust · good first issue
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 1-3

**Summary.** No test runs the query or research routes with `require_attestation = true`. Every API test passes `DevAttestation::allow_insecure_dev()` with `require_attestation = false`, so the 503 `AttestationUnavailable` response, the `tee.attestation` "denied" event (`backend/crates/platform-api/src/query.rs:201-234`) and the documented claim that the gate runs before the budget charge (`docs/ARCHITECTURE.md:212-218`) are untested, and `gate_execution` (`backend/crates/platform-enclave/src/lib.rs:130-144`) has no unit tests.

**Done when**
- Unit tests in `platform-enclave` cover every branch of `gate_execution` with `require_attestation` true and false: SEV-SNP evidence, development evidence, and a provider error. Neither `DevAttestation` nor `SnpAttestation` produces `SevSnp` evidence, so add a small test-only `AttestationProvider` that returns `AttestationEvidence { platform: TeePlatform::SevSnp, .. }` (the fields are public).
- An API test builds `ConnectorQueryService` with `require_attestation = true` and `DevAttestation::strict()` (deterministic; do not use `SnpAttestation::new()`, whose result depends on the runner and will change with P48) and asserts `POST /api/v1/query` returns 503 "enclave attestation unavailable". A second case uses `allow_insecure_dev()` with `require_attestation = true` (the `Rejected` branch).
- A research test creates an active grant first (the grant check runs before the gate), asserts `POST /api/v1/research/query` returns 503, then reads the grant's budget and asserts `spent` is unchanged.
- Using the `ObservedKeys` wrapper in `tests/query_api.rs`, a test asserts no key was opened (`calls == 0`) after the 503.
- `audit_coverage.rs` asserts the `tee.attestation` denied event.
- The helpers that hard-code `false` (`research_api.rs`, `query_api.rs`, `full_app` in `audit_coverage.rs`) take a `require_attestation` and provider parameter.

**Where.** `backend/crates/platform-enclave/src/lib.rs` (tests), `backend/crates/platform-api/tests/query_api.rs`, `research_api.rs`, `audit_coverage.rs`.

**Depends on:** none.

**Sequencing.** First checklist item of P78.

**Security impact.** Proves the attestation gate fails closed and runs before any budget is charged or key opened.
**ADR.** Not required.

**Notes.** `platform-enclave` is code-owned.

---

### P47. SEV-SNP report verifier (portable, testable without hardware)
**Labels:** build · area:enclave · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 2-8

**Summary.** No verification code exists. `SnpAttestation` probes `/dev/sev-guest` and refuses (`backend/crates/platform-enclave/src/lib.rs:108-122`), and both gates accept any evidence whose self-reported `platform` is `SevSnp` without reading `report` or `nonce`: `gate_execution` (`lib.rs:130-144`, line 136) and `EnclavePipeline::attestation_gate` (`backend/crates/platform-connectors/src/pipeline.rs:87-141`, line 92). The nonce is generated by the attesting process itself (`backend/crates/platform-api/src/query.rs:201-203`). A check in the same process the operator runs does not by itself meet `THREAT_MODEL.md` A2 (lines 76-77), so the verifier must be reusable by the key-release relying party (P50).

**Done when**
- An `AttestationVerifier` seam in `platform-enclave`, separate from `AttestationProvider` (which today has only `produce_evidence`, `lib.rs:37-42`), built on an established, maintained SEV-SNP library (no hand-written parsing or signature code; `unsafe` is denied workspace-wide, `backend/Cargo.toml:27-28`; new crates pass `cargo deny check` and dependency review). Input: report bytes, certificate chain, expected nonce or REPORT_DATA, and policy. Output: a `VerifiedReport` (measurement, TCB, report data) that only the verifier can construct, or an error.
- It checks: the VCEK (or VLEK, whichever the platform uses) to ASK to ARK chain to pinned AMD roots; the report signature; revocation (CRL); REPORT_DATA against the layout from P14; guest policy (debug disallowed, migration agent off); a minimum reported TCB; and the measurement or workload policy through an interface whose expected values come from configuration (`platform-config`) and fail closed when missing. Tests use fixture values; P49 supplies production values.
- How AMD certificates are fetched, provisioned and cached is defined; an unreachable, expired or revoked chain fails closed, with tests.
- Hardware-free test support: a `test-support` Cargo feature on `platform-enclave`, enabled only from `[dev-dependencies]` (resolver 2 keeps it out of normal builds; not `cfg(test)`, which other crates' integration tests cannot see), generates a throwaway ARK to ASK to VCEK chain at test time (no key committed, `docs/DATA_POLICY.md` rule 3) and signs reports with chosen measurement, policy, TCB and REPORT_DATA. The trust root is a parameter only under `test-support`; a test shows a production verifier rejects a report signed by the synthetic chain. A CI step proves release binaries build without the feature.
- Negative tests (the synthetic chain first, then P12 phase B's recorded reports once captured (target week 4), and public sample reports whose source and licence are recorded per DATA_POLICY rule 4; P48 adds its own recorded reports to these tests when it lands, since it depends on this issue): valid; wrong nonce; wrong measurement; debug policy; TCB below minimum; bad signature; wrong or revoked chain. All pass under `cargo test --workspace` on `ubuntu-24.04-arm` and macOS.
- An `snp_report` fuzz target: a file in `backend/fuzz/fuzz_targets/`, a `[[bin]]` entry and a `platform-enclave` path dependency in `backend/fuzz/Cargo.toml`, and an entry in the matrix in `.github/workflows/fuzz.yml`.
- The SEV-SNP glossary terms (VCEK, launch measurement, TCB) are added to the guide from P3.
- The SEV-SNP verification library and the pinned AMD root certificates are named as trusted in `docs/THREAT_MODEL.md` "Out of scope: Correctness of the underlying libraries" (lines 119-121), next to the side-channels bullet that already relies on "the attestation chain" (lines 108-110). If the library's signature or certificate checks use a backend other than RustCrypto (for example OpenSSL), either configure it to use RustCrypto or name that backend in `CONTRIBUTING.md:45` in the same PR.

**Where.** `backend/crates/platform-enclave/src/lib.rs`, `backend/crates/platform-enclave/Cargo.toml`, `backend/crates/platform-config/src/lib.rs`, `backend/fuzz/`, `.github/workflows/fuzz.yml`, `docs/THREAT_MODEL.md` (and `CONTRIBUTING.md` if needed).

**Depends on:** P14 (REPORT_DATA layout, relying-party interface and workload-identity mechanism), and P12's phase B recorded reports to close.

**Sequencing.** Report parsing, AMD chain and signature checks start in week 2; the workload-policy interface and anything specific to a provider token wait for the workload-identity decision in P14.

**Security impact.** Replaces "trust the platform tag" with verified hardware evidence (A2, "Run a query outside a genuine enclave").
**ADR.** Covered by P14 (relying party, REPORT_DATA, workload identity).

---

### P48. SEV-SNP report acquisition on hardware and verified gates
**Labels:** build · area:enclave · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 4-10

**Summary.** Implement report acquisition inside a Confidential VM, record real fixtures, and make both gates act on verified evidence. Definition-of-done item 2 requires a query that "passes attestation on genuine SEV-SNP hardware".

**Done when**
- `SnpAttestation::produce_evidence` gets a real report through the configfs-tsm interface or a vetted crate, with the 64-byte REPORT_DATA supplied by the caller as P14 specifies. The change to the meaning of the existing `nonce` parameter (or a signature change) is recorded. Acquisition is compiled only for Linux x86_64; `cargo test --workspace` still passes on `ubuntu-24.04-arm` and macOS (`.github/workflows/ci.yml`).
- If P14's workload-identity decision adds evidence beyond the SNP report (for example a vTPM quote or a provider-issued token), it is acquired alongside the report and checked through P47's workload-policy interface.
- A dev binary (for example `cargo run -p platform-enclave --bin snp-report -- --nonce <hex>`) records a report and its certificate chain as fixtures under `backend/crates/platform-enclave/tests/fixtures/`, with a README recording machine type, zone, firmware/TCB, date, and the source and terms of the AMD certificates. Fixtures use a fixed test nonce and contain no keys or credentials. (The `scripts/check.sh` data guard does not match report binaries, so review is the control.) The recorder writes to the same path and README format as P12 phase B's captures; the PR shows that its output passes P47's verifier the same way P12's captures do, and replaces or keeps P12's files under the same README.
- `produce_evidence` keeps refusing in the production path until verification is wired into the gates; then `gate_execution`, `ConnectorQueryService::gate` (`query.rs:201-234`) and `EnclavePipeline::attestation_gate` act on `VerifiedReport` from P47 instead of `TeePlatform`, and none treats self-produced evidence tagged `SevSnp` as verified. A test shows SevSnp-tagged evidence with an empty, unsigned or wrong-nonce report is refused in both the query path and the sync path.
- `tee.attestation` events say verified or refused with a reason class and no report bytes; audit details say "verified", not "produced"; `audit_coverage.rs` covers them, including one API-level denied case.
- When `TEE_ATTESTATION_REQUIRED=true` (the default), the API and `connector-worker` refuse to start without the expected measurement and policy configuration.
- Hardware-only tests sit behind one documented feature or `#[ignore]` convention, so `cargo test --workspace` runs the right set on a Confidential VM and on hosted runners (the off-hardware fail-closed tests at `platform-enclave/src/lib.rs` and `platform-connectors/tests/pipeline_e2e.rs` skip when `/dev/sev-guest` is present).
- On a Confidential VM, a fresh report goes end to end (acquire, verify, apply policy) and the gate returns `SevSnp`; the run is recorded through P71 or a documented manual checklist.
- `docs/THREAT_MODEL.md` line 76 and the README "Status" section are updated.

**Where.** `backend/crates/platform-enclave/src/lib.rs`, `backend/crates/platform-enclave/Cargo.toml` (runtime dependencies for the recorder; `tokio` is a dev-dependency today), `backend/crates/platform-connectors/src/pipeline.rs`, `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-api/tests/audit_coverage.rs`, `docs/THREAT_MODEL.md`, `README.md`.

**Depends on:** P47, P12 (hardware), P14.

**Security impact.** Makes the attestation gate real on both query and sync paths (A2).
**ADR.** Covered by P14.

---

### P49. Enclave workload image and published attestation values
**Labels:** build · area:enclave · area:ops
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 4-9

**Summary.** The first draft made deployment depend on attestation while attestation's measurement policy needed deployment's image, a cycle. Split out the image: build the workload that runs inside the Confidential VM deterministically, and publish the values the measurement policy pins. Today `.github/workflows/release.yml` (lines 12, 26-43) builds bare binaries on `ubuntu-latest` and attests their provenance; the repository has no image definition or `deploy/` directory. On GCP Confidential VMs the SNP launch MEASUREMENT covers Google-supplied firmware, so a reproducible image digest does not equal MEASUREMENT; the workload is bound separately (for example measured boot or vTPM, or a key bound in REPORT_DATA), as P14 decides (P15 fixes what the image contains).

**Done when**
- The image definition lives in `deploy/`: base image pinned by digest, the `rust-toolchain.toml` toolchain, `cargo build --locked`, `SOURCE_DATE_EPOCH` and `--remap-path-prefix`.
- It contains only the production binaries chosen in P15 (today `platform-api` and `connector-worker`) and, if the frontend is served from inside the VM (P67), the released frontend bundle and any proxy P15 names; never `devtoken`, `query-demo` or the dev server from P8. Nothing in it sets `TEE_ATTESTATION_REQUIRED=false`, and a test proves `DevAttestation::allow_insecure_dev` is unreachable in the production configuration.
- The release workflow publishes the image digest with build provenance, plus the expected attestation values P14 chose: the firmware measurement allowlist (from the provider's signed firmware endorsements) and minimum TCB, and the binding that carries the workload identity into the evidence. P47's policy and P50's release check read these values.
- A documented minimal Confidential VM bring-up that P48 uses for its on-hardware check.
- `docs/` explains how anyone can rebuild the image and compare digests.

**Where.** New `deploy/`; `.github/workflows/release.yml`; `docs/`.

**Depends on:** P14, P15, P12.

**Security impact.** Gives the attestation policy something specific to pin, so a modified binary cannot obtain keys.
**ADR.** Covered by P14 and P15.

**Notes.** A CI job that rebuilds the image twice and compares digests (bit-for-bit reproducibility) is a stretch goal, promoted to v1 only if the ADR relies on third parties rebuilding the image.

---

### P50. Production key release into the attested enclave
**Labels:** build · area:enclave · area:crypto · rust
**Size:** M-L (pair) · **Priority:** v1 blocker · **Target:** weeks 6-12

**Summary.** Implements the custody and release design accepted in P14. Today no tenant private key exists outside the steward's browser: it is generated non-extractable (`frontend/src/lib/crypto/core.ts:171-180`), only its public half is enrolled, and `TenantKeypair` is dev/test only (`backend/crates/platform-crypto/src/lib.rs:203-217`). The only non-test `EnclaveKeyProvider` implementations keep keys in process memory (`DevKeyProvider`, `MultiTenantDevKeyProvider`, `backend/crates/platform-api/src/query.rs:49-113`). `gate()` discards the evidence (`query.rs:201-234`), so release cannot depend on it today. Key-release failures would surface as `ApiError::Backend`, a 502 "storage backend error" (`backend/crates/platform-api/src/lib.rs:132`).

**Done when**
- Key material comes only from the source P14 defines. No steward private key is exported from the browser, read from configuration or the environment, or held by the operator outside an attested enclave. `THREAT_MODEL.md:25` and `:72` are reconciled with the ADR.
- The enclave gets key material only by presenting a report verified (by P47's verifier, run by the relying party named in the ADR) that binds a fresh, relying-party-issued nonce and the enclave's ephemeral public key in REPORT_DATA; released material is wrapped to that ephemeral key. This changes `gate_execution` (which today returns only `TeePlatform`) and `EnclaveKeyProvider::open_envelope`.
- Negative tests: a valid report binding a different key; a stale, reused or mismatched nonce (nonce state lives in the relying party); a wrong measurement or workload identity (as P14 decides); an unreachable verifier or release service. Each is refused and fails closed.
- Key material is fetched once per query, not once per envelope (today `decrypt_connector` calls `open_envelope` per object, `query.rs:252-298`), held only in zeroize-on-drop types, and dropped when the query ends; any cache lifetime is set by the ADR. The `ObservedKeys` test wrapper (`backend/crates/platform-api/tests/query_api.rs`) is reworked for the new trait shape.
- Key-release failures map to a dedicated 503 `ApiError` variant (or `AttestationUnavailable`/`QueryUnavailable`), never `Backend`/502.
- Each release decision emits a new audit kind (for example `crypto.key_release`, ok, denied or failed, identifiers only), asserted in `audit_coverage.rs` with a production-provider test double; the audit table and coverage list in `docs/ARCHITECTURE.md` are updated.
- An in-process stand-in of the release service implements the recorded protocol for tests (issues nonces, checks reports with the P47 verifier, releases only on success).
- `DevKeyProvider` and `MultiTenantDevKeyProvider` sit behind the dev mechanism from P18 (not `#[cfg(test)]`: `query-demo` and the integration tests construct them), so the production binary cannot construct them.
- The key-release trait and production provider are code-owned (moved to `platform-enclave`, or covered by a CODEOWNERS entry from P4).
- Wrapping uses `TenantKem`, so the hybrid suite from P35 drops in; it uses the hybrid suite before this issue closes.

**Where.** `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-enclave/src/lib.rs`, `backend/crates/platform-crypto/src/lib.rs`, `backend/crates/platform-telemetry/src/lib.rs`, `backend/crates/platform-api/Cargo.toml`, `backend/crates/platform-api/tests/`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`; any release service the ADR introduces (new).

**Depends on:** P14, P47, P18 (dev-provider gating item), P48 (on-hardware validation), and P35 to close (hybrid wrapping).

**Sequencing.** Coordinate with P35.

**Security impact.** The central A2 control: only an attested enclave ever holds a key that opens steward data.
**ADR.** Covered by P14; record protocol details there.

---

### P51. Wire the production query service and engine settings in `platform-api`
**Labels:** build · area:enclave · area:ops · rust
**Size:** S-M · **Priority:** v1 blocker · **Target:** weeks 10-13

**Summary.** The integration step at the end of the enclave chain. `main.rs` sets `query: None` (`backend/crates/platform-api/src/main.rs:41-45, 64-70`), so query routes return 503. Engine settings must come from configuration, never from `EngineSettings::default()` (which is `ZkMode::Disabled` until P24), and `max_concurrent_queries` is hard-coded at 4 (`backend/crates/quackxide-engine/src/lib.rs:65-72`).

**Done when**
- `main.rs` builds `ConnectorQueryService` with the production `EnclaveKeyProvider` (P50), `SnpAttestation` with the P47 verifier, `require_attestation` from `config.features.tee_attestation_required`, and the research stores from P43 over the durable registries from P62, plus the durable tenant registry in place of `InMemoryTenantRegistry` (`main.rs:47-52`).
- `EngineSettings.zk` comes from `config.features.zk` (`FEATURE_ZK_ENABLED`), and `max_concurrent_queries` from a new configuration key (for example `QUERY_MAX_CONCURRENT`) parsed like the other `parse_u64` keys; an invalid or zero value fails startup. Documented in `backend/.env.example`.
- In production mode (P18), missing wiring (key provider, attestation, research stores, verification keys) stops startup with a non-zero exit and an audit event instead of serving 503; a configuration-matrix test covers each missing piece. Development mode keeps the existing 503 fail-closed path and its tests.
- In a production configuration no route returns `QueryUnavailable`, `ResearchUnavailable` or `AuthNotConfigured` because wiring is missing (DoD item 3). An integration test boots the production wiring with the release-service stand-in from P50, recorded reports from P48, and a test key set, and checks each formerly-503 route answers.
- The README "Status" key-release bullet (`README.md:152-153`), the ARCHITECTURE "Key-release trust boundary" paragraph (`docs/ARCHITECTURE.md:159-165`) and `docs/THREAT_MODEL.md:90` are updated.

**Where.** `backend/crates/platform-api/src/main.rs`, `backend/crates/platform-api/src/lib.rs`, `backend/crates/platform-config/src/lib.rs`, `backend/.env.example`, `backend/crates/platform-api/tests/`. Reference wiring: `backend/crates/platform-api/src/bin/query-demo.rs` (dev providers only; do not copy its `ZkMode::Disabled` or `require_attestation = false`).

**Depends on:** P50, P48, P62, P28, P24, P43.

**Security impact.** Closes DoD item 3 without weakening any default (ZK on, attestation required, no dev providers).
**ADR.** Not required.

---

### P52. Per-query resource limits that never spill plaintext
**Labels:** harden · area:engine · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 6-11

**Summary.** DataFusion runs inside `QueryScope`. Decrypted Parquet is held in zeroize-on-drop buffers (`SecretBytes`, and a wiped copy for the engine), but decoded Arrow arrays are not zeroized; `docs/THREAT_MODEL.md` records that as the residual "Unzeroized working memory", because clearing them would need `unsafe` (denied workspace-wide). So the first draft's "plaintext zeroized on every exit path" cannot be met as written. Every object of the dataset's current snapshot is decrypted (`backend/crates/platform-api/src/query.rs:252-298`) and eagerly decoded into a `MemTable` (`backend/crates/quackxide-engine/src/lib.rs:118-158`), then the query runs on a `SessionContext` whose `RuntimeEnv` replaces only the object-store registry (`NoObjectStores`, added by Code-Pause-Inc/QuackXide#22; `lib.rs:89-95`) and otherwise keeps DataFusion 49's defaults: an unbounded memory pool and an OS-temp disk manager. A memory limit without disabling the disk manager would spill plaintext to disk, against "Plaintext never persisted" (`THREAT_MODEL.md:73`). A global concurrency bound already exists (`max_concurrent_queries`, `plaintext_slot`).

**Done when**
- Limits come from `platform-config` with safe defaults, and invalid values fail closed: queue wait for a plaintext slot, query wall-clock time, operator memory, total decrypted input bytes (and object count), decoded rows and uncompressed bytes, and result rows and bytes.
- Input bound: before any key release or decryption, the summed ciphertext size of the dataset is checked (for example `VaultStore::usage` over the newest snapshot's objects, found from the manifest path without decrypting it; the whole `TenantPaths::connector_prefix` can still hold superseded snapshots awaiting pruning), and the cap is enforced again cumulatively inside the decrypt loop. Parquet footer metadata (row-group `num_rows`, uncompressed sizes) is checked against the decoded caps before any batch is decoded (the memory pool does not track `MemTable` input). A test uses a small, highly compressible Parquet file that would decode past the cap.
- Execution bound: the session's `RuntimeEnv` keeps its empty object-store registry and gains a memory limit and the disk manager disabled (`DiskManagerMode::Disabled` in DataFusion 49; re-check after P69). A test runs a memory-limited sort or aggregate and asserts a resources-exhausted error and no temp files (assert on the disk manager, for example `tmp_files_enabled() == false` and `used_disk_space() == 0`, not by scanning the OS temp directory).
- A wall-clock timeout bounds execution; on expiry the future is dropped, the slot released and the blobs zeroized. `register_parquet_many` decodes synchronously, so decode time is bounded by the input caps or moved to `spawn_blocking`.
- The slot wait is bounded and refuses with 503 through a new `ApiError` variant distinct from the missing-wiring `QueryUnavailable` (`Retry-After` optional; availability is not a v1 security goal, `THREAT_MODEL.md`). Whether a slot-wait timeout costs budget follows the order P54 chooses (today the charge comes before the slot, `query.rs:522-549`; under P54's options (a) and (c) the timeout is free, under (b) it is charged and documented), with a test.
- Results over the row or byte cap are refused with 422, not truncated.
- Resource-limit failures are not reported as the caller's SQL error (today every `QueryError::Execution` maps to 400 "query could not be executed", `query.rs:674`). Each new refusal has an `ApiError` mapping, an audit event, a negative test, and a stated budget rule (P54).
- Zeroization, scoped to what is possible without `unsafe`: every buffer holding decrypted Parquet or key material is `SecretBytes`/`ZeroizeOnDrop` on every exit path (error, timeout or cancellation, panic unwind; the release profile unwinds), with type-level `ZeroizeOnDrop` assertions (follow `decrypted_objects_zeroize_on_drop`), and tests that the plaintext slot is released after each kind of exit (follow `decryption_failure_midway_fails_closed_and_releases_the_slot`; the panic case injects a panicking `DisclosurePolicy` through `run_scoped` or a small test-only seam). The existing concurrency tests stay.
- `docs/THREAT_MODEL.md` states that rate limiting and per-tenant fairness are outside v1, and the "Unzeroized working memory" residual stays as written.

**Where.** `backend/crates/quackxide-engine/src/lib.rs`, `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-config/src/lib.rs`, `backend/.env.example`, `backend/crates/platform-api/tests/query_api.rs`, `docs/THREAT_MODEL.md`.

**Depends on:** P69 (the runtime and disk-manager APIs may change), P54 (the budget-order decision only).

**Sequencing.** Coordinate `EngineSettings` construction with P51. The input cap on decrypted bytes is at least P38's upload maximum, or both come from one configuration value. P53 follows as a separate PR by the same owner and moves the decoded-size checks into the scan.

**Security impact.** Prevents plaintext spill to disk under memory pressure (A2) and bounds plaintext lifetime.
**ADR.** Not required unless the limits add public API errors (maintainer's call).

**Notes.** Per-tenant concurrency, a SQL-length cap, a Parquet metadata-size cap and a zeroizing allocator for Arrow memory are proposed outside v1.

---

### P53. Decode only what the query needs: gate before decode, projected Parquet decode in `QueryScope`
**Labels:** harden · area:engine · rust
**Size:** S · **Priority:** v1 needed · **Owner:** P52's owner, as a follow-up PR · **Target:** weeks 9-12

**Summary.** `register_parquet_many` (`backend/crates/quackxide-engine/src/lib.rs:126-158`) decodes every column and row group of every object into a `MemTable`, and it runs before `sql()` plans or gates the query (`lib.rs:164-191`; called from `backend/crates/platform-api/src/query.rs:654-658`). So a query that the plan gate or the count-column check refuses has already decoded the whole dataset into Arrow memory, which is not zeroized (`docs/THREAT_MODEL.md:133-138`), and an accepted query decodes columns it never reads. This conflicts with the Efficiency goal in `docs/PROJECT_SCOPE.md:19` ("columnar storage and query pushdown keep decrypt-and-scan work to what the query needs"). Separately, a schema mismatch between objects surfaces from `MemTable::try_new` as `QueryError::Execution` (`lib.rs:151-152`), which `map_query_error` turns into 400 "query could not be executed" (`query.rs:673-674`), blaming the caller's SQL for a storage fault.

**Done when**
- `register_parquet_many` keeps its signature but registers a small `TableProvider` instead of a `MemTable`. At registration it reads only the Parquet footers (schema and row counts) from the existing `wiped_copy` buffers. It checks that every object's schema matches, and refuses a mismatch as `QueryError::Parquet` (5xx), never `QueryError::Execution`.
- Batches are decoded in `scan()` through `ParquetRecordBatchReaderBuilder::with_projection(ProjectionMask::roots(..))`, feeding an in-memory execution plan over the projected columns. No plaintext is copied into a non-zeroizing buffer other than the decoded Arrow arrays the "Unzeroized working memory" residual already covers.
- A test with a decode counter or a test seam shows that a query refused by the plan gate or the count-column check decodes no column chunks. This relies on statements being refused before anything executes (merged in Code-Pause-Inc/QuackXide#22).
- Errors raised while decoding during the scan keep their meaning: a corrupt stored object returns a backend error (5xx), never `QueryError::Execution` (400). A negative test uses an object with a valid footer and a corrupt data page.
- On the wide table from P9, a test shows that a two-column aggregate decodes only those columns.
- `tests/bypass.rs`, `tests/disclosure.rs` and `tests/engine_query.rs` pass unchanged, as do the zeroize-on-drop assertion (`decrypted_objects_zeroize_on_drop`, `backend/crates/platform-api/src/query.rs`) and the plaintext-slot release test (`decryption_failure_midway_fails_closed_and_releases_the_slot`, `backend/crates/platform-api/tests/query_api.rs`). `Drop` still releases the provider's buffers.
- P52's decoded-size caps are checked against the footer metadata of the projected columns before any decoding.
- The "`QueryScope` memory hygiene" paragraph of `docs/ARCHITECTURE.md` (line 146) describes the lazy path, and says that decryption is still whole-object in v1, because each object is one HPKE envelope (`query.rs:252-298`): projection reduces decode work, not decrypt work.

**Where.** `backend/crates/quackxide-engine/src/lib.rs`, `backend/crates/platform-api/src/query.rs` (`run_scoped`, `map_query_error`), `backend/crates/quackxide-engine/tests/`, `backend/crates/platform-api/tests/`, `docs/ARCHITECTURE.md`.

**Depends on:** P69 (the DataFusion `TableProvider` and Parquet APIs change), P52 (its decoded-size caps, which this issue checks against the projected footer metadata).

**Sequencing.** After P52 merges, by P52's owner, so the two do not rewrite `register_parquet_many` at the same time. `decrypt_connector` supplies only the current snapshot's objects (ADR 0003). Coordinate with P58, which rewrites the plan between the gate and `collect` to add auxiliary aggregates, so the scan projection must come from the final rewritten plan. P73 records latency and peak memory before and after.

**Security impact.** Shortens plaintext lifetime: a query the gate refuses never decodes data, and an accepted one decodes only the columns it reads.
**ADR.** Not required.

**Notes.** Row-group pruning, a DataFusion Parquet source over an object store, per-column encryption and running the gate before key release are proposed outside v1.

---

### P54. Disclosure control: threat-to-test traceability, budget charge order, k floor and result contract
**Labels:** harden · area:disclosure · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 3-10

**Summary.** The plan gate, genuine-count check, `MinCountThreshold` and budget ledger exist. Four gaps: (1) the first draft asked `tests/bypass.rs` to cover every attack class in the threat model, but grants and budgets live in `platform-tenancy`, which the engine crate does not depend on; (2) the budget is charged after the attestation gate but before the plaintext slot, key release and decryption (`backend/crates/platform-api/src/query.rs:515-550`), so capacity, storage, key-release and decode failures cost a unit, contradicting `docs/ARCHITECTURE.md:212-218` ("infrastructure failures never cost the researcher"); (3) `RESEARCH_MIN_COHORT_SIZE` is parsed with no floor (`backend/crates/platform-config/src/lib.rs:188`) and `MinCountThreshold` refuses only k < 1, so an operator setting k = 1 turns suppression off; (4) own-data and research results have different shapes (`query.rs:349-352` versus `589-597`), and P55 must know which fields are sealed.

**Done when**
- **Traceability.** `docs/THREAT_MODEL.md`'s A1 table gets a "Test" column (or this issue holds a checklist, if the maintainer prefers not to change the table), and every row names its tests: engine rows in `backend/crates/quackxide-engine/tests/` (`bypass.rs`, `disclosure.rs`, `engine_query.rs`); grant, revocation, budget and no-oracle rows in `backend/crates/platform-api/tests/research_api.rs` and `catalog_api.rs` (P45 owns new grant tests). Any row without a test gets one. Residual rows (differencing; extreme values until P58) are marked residual, not tested. The A1 rows added by Code-Pause-Inc/QuackXide#21, Code-Pause-Inc/QuackXide#22 and Code-Pause-Inc/QuackXide#24 are included. The bypass suite asserts that no accepted query shape produces overlapping groups.
- **Budget order.** The maintainer chooses and the issue records one of: (a) a read-only pre-check (`BudgetLedger::state`) before the slot refuses an exhausted grant with 429, and the atomic `charge` moves to after the slot, key release and decryption and before planning, so infrastructure failures are free and plan-gate probes still cost; if `charge` refuses after decryption because a concurrent query raced past the pre-check, the plaintext is dropped and the query returns 429 (note the trade-off: concurrent requests on a budget with one unit left can trigger decryption before being refused); or (c) refund on infrastructure error, which needs a ledger method and reverses the documented no-refund, monotonic-spend invariant ("no refunds", "Spend is monotonic per grant id") (`backend/crates/platform-tenancy/src/budget.rs:17-18`, `ARCHITECTURE.md`, `THREAT_MODEL.md` A1), so all three are updated; or (b) keep the current order and correct `docs/ARCHITECTURE.md:212-218`, the comment at `query.rs:517-521` and `THREAT_MODEL.md` to say that only grant, attestation and budget refusals are free. Tests either way: a failing key provider (adapt `ObservedKeys` from `tests/query_api.rs`) and `max_concurrent_queries = 0` each assert the documented budget outcome; a plan-gate rejection spends one unit.
- **Budget conformance.** A shared `budget_ledger_conformance(Arc<dyn BudgetLedger>)` helper in `platform-tenancy` opens a grant with limit L and spawns N > L concurrent `charge(grant, 1)` tasks on a multi-thread runtime, asserting exactly L successes, `BudgetError::Exhausted` for the rest, and `spent == L <= limit`. It runs against `InMemoryBudgetLedger` now and against the durable ledger in P62. (tokio is a dev-dependency of `platform-tenancy`, so keep it under `#[cfg(test)]` or behind a `test-util` feature.) Land this part as an early small PR.
- **k floor.** Research and ZK mode enforce a compile-time minimum k that configuration cannot lower; startup refuses a lower `RESEARCH_MIN_COHORT_SIZE` with a test, and the floor holds wherever the threshold is built (`ConnectorQueryService::with_min_cohort`/`threshold()`), not only in config parsing. Engine tests that use k = 2 build the threshold directly and are unaffected; `platform-api/tests/query_api.rs` (`.with_min_cohort(2)`) is updated. The floor is recorded in `THREAT_MODEL.md` A1.
- **Audit.** A refusal emits `engine.query` with outcome `denied` and a reason class (plan, count column, threshold configuration, execution, resource) carrying no SQL text; `failed` is kept for 5xx; `audit_coverage.rs` (which today asserts broken SQL gives `engine.query` failed) is updated. Applies to both own-data and research queries.
- **Result contract.** The field list for both endpoints is documented in `docs/ARCHITECTURE.md` (or a JSON schema under `docs/`) with an optional `schema_version`, and states which fields travel inside the sealed payload (P55) and which stay cleartext metadata. Agree it before P44 renders results and P55 builds the envelope. Zero-object datasets: either refuse with the same status as other refusals, or document and test the current behaviour (200, empty rows, budget charged); record whether `object_count` stays in research results. `suppressed_rows` stays in research responses: `docs/ARCHITECTURE.md:157,189` and `docs/PROJECT_SCOPE.md:52` specify it, and `research_api.rs:165`, `query_api.rs:190,201` and `catalog_api.rs:239` assert it. The field list records what it discloses. `MinCountThreshold` counts each row it drops (`backend/crates/quackxide-engine/src/disclosure.rs:53-78`), so with `GROUP BY` a non-zero count shows that some cohort below k matched the `WHERE` or `HAVING` predicate. On the bypass fixture with k=5, `SELECT dept, COUNT(*) AS n FROM people WHERE salary > 9000 GROUP BY dept` returns no rows with `suppressed_rows=1`, and `> 9001` returns no rows with `suppressed_rows=0`; at one unit per query (`RESEARCH_QUERY_COST`, `query.rs:141`), a binary search over the threshold recovers the single `ceo` salary in about 14 queries, within the default budget of 100 (`backend/crates/platform-config/src/lib.rs:17`). `docs/THREAT_MODEL.md` gains one sentence under the "Overlapping-query differencing" residual or the "Unlimited adaptive probing" row: suppression metadata leaks one bit per query about cohorts below k, the budget bounds it, and it is weaker than the accepted two-query differencing (a total over `WHERE dept <> 'legal'` minus a `GROUP BY dept` already gives that salary, as ADR 0002 records). A test pins the behaviour. Dropping the field is not offered for v1: it closes nothing while the differencing residual stands.

**Where.** `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-tenancy/src/budget.rs`, `backend/crates/platform-config/src/lib.rs`, `backend/crates/quackxide-engine/tests/`, `backend/crates/platform-api/tests/`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`.

**Depends on:** none.

**Sequencing.** The conformance helper lands early as its own PR.

**Security impact.** Makes the A1 claims traceable to tests, makes the documented budget semantics true, and stops configuration from disabling suppression.
**ADR.** Required if the result schema is declared a stable public API (maintainer's call).

---

### P55. Results sealed to the researcher inside the enclave
**Labels:** build · area:crypto · area:enclave · rust · needs-adr
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 8-13

**Summary.** Results leave as plaintext JSON (`query.rs:617-625`). Definition-of-done item 2 requires a result "sealed to the researcher's key". The query service runs inside `platform-api` (`query.rs:1-13`), so the boundary is the attested enclave as P15 defines it, not "the API". Three problems the first draft missed: the researcher's public key is read from the unsigned enrollment record that the operator-run API writes (`put_enrollment`, `backend/crates/platform-api/src/lib.rs:715-777`), so it can be substituted; HPKE base mode does not authenticate the sender, so an operator who sees the request could seal a forged result; and nothing binds a result to the request it answers.

**Done when**
- An ADR records the result envelope format and how the recipient key is authenticated. It chooses between: (i) a design in which the browser verifies attestation (for example a per-request key sent to an enclave the browser has verified); or (ii) for v1, recording operator key substitution and result forgery as residual risks in `THREAT_MODEL.md` A2 (row 73) and "Residual risks", with enrollment made non-silent (P33: create-once, audited rotation, fingerprint shown in the portal). Attested sender authentication (an enclave signing key bound in REPORT_DATA and checked by the browser) is proposed outside v1 unless the maintainer pulls it in.
- The enclave seals each research result through `TenantKem` (so it ships on the current suite and switches with P35) to the researcher's key from the source the ADR names. The HPKE `info` carries a versioned "result" role label (distinct from connector-data sealing), the grant id, a request nonce chosen by the researcher's browser, a hash of the SQL text, and the result schema version from P54, following the `envelope_info` pattern and shared with the browser (P34).
- No component outside the attested Confidential VM (load balancer, TLS-terminating proxy, operational logs, audit stream, object store) ever holds the result's aggregate row values, with a test on the logs and audit stream. The `engine.query` audit record keeps its count metadata (`rows=`, `suppressed=`, `budget_remaining=`, `query.rs:602-615`), which billing reads.
- Error responses (400, 401, 403, 404, 422, 429, 502, 503) stay unsealed and carry no result data or SQL echo, with a test.
- The own-data query endpoint (`POST /api/v1/query`) either seals the same way or the ADR records why not.
- Tests: a result opens only with the intended key; a different recipient key, a flipped byte, and a valid result replayed against another request nonce are refused; a key substituted in storage, from the source the ADR rules out, yields nothing the substitute can open (or the query is refused).
- `docs/THREAT_MODEL.md` A2 row "Read results at the API edge" and README "Status" ("Encrypted results") are updated.
- The research diagram in `docs/ARCHITECTURE.md` (lines 177-190, which today ends in "aggregate rows + suppressed_rows + budget_remaining") ends in a result sealed to the researcher's key and states what stays cleartext metadata. The query diagram (lines 117-129, which ends in "JSON result rows") is updated too, or notes that it stays unsealed, as the ADR decides.

**Where.** `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-api/src/lib.rs` (enrollment), `backend/crates/platform-crypto/src/lib.rs`, `docs/adr/`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `README.md`.

**Depends on:** P14, P15, P54 (result contract), P33, and P35 to close.

**Sequencing.** Developed and tested against the dev key providers; P50 is needed only for the final on-hardware run.

**Security impact.** Closes "Read results at the API edge" (A2) up to the residuals the ADR records.
**ADR.** Required (wire format and trust boundary).

---

### P56. Open sealed results in the researcher's browser
**Labels:** build · area:crypto · area:frontend · javascript
**Size:** S-M · **Priority:** v1 blocker · **Target:** weeks 10-13

**Summary.** The browser half of sealed results. The portal must show a result only after the crypto worker opens it, with the private key never leaving the worker.

**Done when**
- The research portal uses the crypto worker's existing tenant-key path (keygen in `frontend/src/lib/crypto/worker.ts`, enrollment through `frontend/src/lib/vault/httpVault.ts` and `PUT /api/v1/drive/enrollment`), on the hybrid suite (P36) and bound to the session `tid` (P33); no second "researcher keypair" is minted unless P14 says so.
- A researcher who opens the portal without an enrolled key goes through key setup in the crypto worker, with a `KeySetupGate`-style explanation and fingerprint: `ensureKeys` and enrollment are lifted out of the drive-only `init` path (`frontend/src/lib/crypto/worker.ts:73-95`, called from `DrivePanel.tsx`).
- The worker generates a fresh nonce per query and gains an "open research result" message in `protocol.ts`/`worker.ts`; the private key never leaves the worker. The portal (P44) renders only after a successful open, and a release build refuses to render an unsealed result.
- Tampered, wrongly addressed, replayed (nonce mismatch), unknown-version and classical-only envelopes are refused, with unit or component tests and the cross-implementation vectors from P34.
- A browser without the required key support is refused with a clear error and is never sent plaintext.
- What device loss means for a researcher's in-flight and future results is documented.
- Opening a sealed result in the browser is benchmarked; before this issue closes, the benchmark joins P73's harness and regression run (or the PR states why it can run only as a recorded manual run per release candidate), and the result and a target agreed with @AxolDad are recorded in `docs/BENCHMARKS.md`.

**Where.** `frontend/src/lib/crypto/worker.ts`, `protocol.ts`, `core.ts`; `frontend/src/lib/research/client.ts`; `frontend/src/components/research/`; `docs/BENCHMARKS.md`.

**Depends on:** P55, P34 (checkpoint B), P36, P44.

**Security impact.** Result plaintext exists only in the researcher's browser (DoD item 2).
**ADR.** Covered by P55.

**Notes.** `frontend/src/lib/crypto/` is code-owned.

---

### P57. Extreme values: decide the dominance and MIN/MAX policy, then apply it to MIN and MAX
**Labels:** build · area:disclosure · rust · needs-adr
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 3-7

**Summary.** `MIN` and `MAX` over a cohort of at least k still return one individual's value, and `docs/THREAT_MODEL.md` ("Extreme values") calls removing them or applying a dominance rule "a policy decision". `DisclosurePolicy::apply` sees only aggregated output batches with user-chosen aliases (`backend/crates/quackxide-engine/src/disclosure.rs:33-37`, called after `collect()`), so a dominance rule needs per-group contributor information the policy does not have today.

**Done when**
- An ADR, accepted by @AxolDad (code owner of `policy.rs` and `disclosure.rs`) before implementation merges, decides:
  - MIN/MAX: remove `min` and `max` from `PERMITTED_AGGREGATES` (`policy.rs:24`); release them only when at least t rows share the extreme value (needs a hidden per-group count); or top/bottom-coding;
  - the SUM/AVG rule and its parameters (for example (n,k)-dominance or p%); AVG is permitted and SUM = AVG × n because n is always released;
  - the unit of contribution (one row per individual, or an identifier column), negative values, and whether suppression drops the cell or the whole row, how it counts in `suppressed_rows`, and how derived columns such as `SUM(salary) / COUNT(*)` (`bypass.rs`, `count_arithmetic`) are handled;
  - whether the rule also applies to own-data ZK queries, which share the gate and `threshold()` (`backend/crates/platform-api/src/query.rs:194-198`);
  - how the engine obtains per-group contributions (plan-level resolution by position, as `verify_count_column` does, or hidden auxiliary aggregates removed before egress).
- The MIN/MAX choice is implemented. Existing bypass cases that use MIN/MAX (`sum_avg_min_max`, `group_by_id`, `having_value`) are updated deliberately, with the reason in the PR, and new cases cover the choice. They include the WHERE-walk shape that ADR 0002 records as still open: `MAX(salary)` with no filter, then `WHERE salary < <previous max>`, and id-range filters.
- The THREAT_MODEL residual and the `docs/PROJECT_SCOPE.md` row are rewritten to match.

**Where.** `docs/adr/`, `backend/crates/quackxide-engine/src/policy.rs`, `src/disclosure.rs`, `tests/bypass.rs`, `docs/THREAT_MODEL.md`, `docs/PROJECT_SCOPE.md`.

**Depends on:** P69 (code part only; its "bypass.rs passes unchanged" criterion must stay meaningful).

**Sequencing.** The ADR starts in week 1.

**Security impact.** Closes the MIN/MAX extreme-value residual (A1).
**ADR.** Required (disclosure gate).

---

### P58. Dominance rule for SUM and AVG
**Labels:** build · area:disclosure · area:engine · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 7-12

**Summary.** Implements the SUM/AVG part of the policy from P57.

**Done when**
- `QueryScope::sql` (`backend/crates/quackxide-engine/src/lib.rs:164-216`), after the allowlist check and before `collect`, adds hidden auxiliary aggregates per SUM/AVG argument column (for example the largest absolute contribution per group), carries them through any Projection, Sort and Limit the allowlist permits above the Aggregate (`policy.rs:36-40`), applies the rule, and strips them before egress so they are never serialized. Researchers never see auxiliary values; a test asserts they are absent from the response.
- Parameters live in `platform-config` (`ResearchConfig`) and `backend/.env.example`, following `RESEARCH_MIN_COHORT_SIZE`: a missing value takes a documented default that enforces the rule; an unparseable value fails config load; a degenerate value refuses every query at the engine (as `k < 1` does, `disclosure.rs:47-51`). Each case has a negative test. The rule is composed with `MinCountThreshold` in `threshold()` or through `CompositePolicy`.
- Bypass tests add a test-local cohort of at least K rows dominated by one outlier (the current fixture salaries are too even), a non-dominated group, and alias-renaming evasion attempts.
- `docs/THREAT_MODEL.md` documents the parameters and moves "Extreme values" to a Built control.

**Where.** `backend/crates/quackxide-engine/src/{lib.rs,disclosure.rs,policy.rs}`, `backend/crates/quackxide-engine/tests/bypass.rs`, `backend/crates/platform-api/src/query.rs`, `backend/crates/platform-config/src/lib.rs`, `docs/THREAT_MODEL.md`.

**Depends on:** P57, P69.

**Security impact.** Closes the SUM/AVG extreme-value residual (A1).
**ADR.** Covered by P57.

---

### P59. Data dictionary on published datasets
**Labels:** build · area:disclosure · area:frontend · rust · javascript
**Size:** S-M · **Priority:** v1 needed · **Target:** weeks 6-11

**Summary.** Researchers cannot see a dataset's columns. A listing carries only its slug, title, description, prices and budget (`DatasetListing`, `backend/crates/platform-tenancy/src/catalog.rs:21-38`); neither `ListingView` (`frontend/src/lib/research/client.ts`) nor `PublishListingRequest` (`backend/crates/platform-api/src/research.rs:38-51`) carries a schema. `DESCRIBE` is refused by the plan gate and still costs a unit. The SQL table name is the dataset slug (`query.rs:654-657`); a slug containing `-` or starting with a digit must be double-quoted. The server cannot derive a schema without decrypting, so the steward declares it.

**Done when**
- `DatasetListing`, listing details and `PublishListingRequest` carry a data dictionary: the exact SQL table name (quoted where needed) and, per column, name, type and an optional steward description. The API bounds and validates it like other listing text and refuses an oversized or malformed one, with a negative test.
- It is pre-filled and editable before publishing: for mapped connectors from the mapper's `ColumnSpec` list (exposed per connector kind); for uploads, if P40 has merged, from the footer schema the browser reads before sealing (otherwise P40 adds that pre-fill); otherwise entered by hand.
- The portal shows the dictionary on every published listing and on each authorized dataset, with a copyable example query using the correctly quoted table name and `COUNT(*) AS n`.
- Tests: publish-with-dictionary round trip, input refusal, a hyphenated or digit-leading slug queried with quotes, and portal rendering.
- If P62 has merged, the durable catalog persists the new fields; otherwise P62 does.

**Where.** `backend/crates/platform-tenancy/src/catalog.rs`, `backend/crates/platform-api/src/research.rs`, `backend/crates/platform-connectors/src/` (mappers), `frontend/src/lib/research/client.ts`, `frontend/src/components/research/`.

**Depends on:** none.

**Sequencing.** Coordinate with P40 and P61.

**Security impact.** Publishes schema metadata the steward chose to publish; no data values.
**ADR.** Not required.

**Notes.** A per-column classification and an enclave-side schema-mismatch check with a no-charge path are proposed outside v1.

---

### P60. Actionable refusals: typed reasons, stable error codes and a researcher SQL guide
**Labels:** harden · area:disclosure · rust · javascript
**Size:** M · **Priority:** v1 needed · **Target:** weeks 6-12

**Summary.** Every research query costs a unit once it passes the grant check and attestation gate, and rejections come back as one of a few fixed strings (`map_query_error`, `backend/crates/platform-api/src/query.rs:662-677`), so researchers spend budget learning the rules. `policy::is_aggregate_only` returns a bool; planning and runtime errors share `QueryError::Execution`. API error bodies are `{"error": "<message>"}` with no machine-readable code (`backend/crates/platform-api/src/lib.rs:121-158`), so clients must match message text to tell the three 503 causes apart.

**Done when**
- `policy::is_aggregate_only` returns a typed refusal reason (for example no aggregate, join, set operation, window, DISTINCT, subquery expression, aggregate over aggregate, row-generating operator, computed expression in or below an aggregate, aggregate not permitted, aggregate FILTER/ORDER BY, grouping sets, no table), and `QueryError::Disclosure` reasons become an enum. The allowlist itself does not change in this issue.
- `QueryError` separates `Planning` from `Execution`, classified by phase (possible now that statements are refused before anything executes, Code-Pause-Inc/QuackXide#22).
- Every `ApiError` body carries a stable machine-readable `code` (for example `attestation_unavailable`, `query_unavailable`, `research_unavailable`, `budget_exhausted`, `query_rejected`, `grant_refused`) plus a message from a fixed table. `grant_refused` is the same for missing, revoked and unknown grants and unknown datasets (no existence oracle). DataFusion or Arrow text is never echoed; a test shows a runtime error on a sentinel cell value never shows that value in the response.
- The `Json`, `Path` and `Bytes` extractors are wrapped (a small custom extractor implementing `FromRequest`/`FromRequestParts`; axum's `FromRequest` derive with `rejection(ApiError)` needs axum's `macros` feature, which the workspace does not enable, `backend/Cargo.toml:46`) so that every rejection, including the 413 from a body limit, becomes an `ApiError` with a JSON body, a fixed message and no serde text, plus its own stable code (for example `malformed_request`, `unsupported_media_type`, `payload_too_large`). Malformed bodies return 400, never 422, so 422 always means a plan or disclosure refusal (`query_rejected`). `ApiError::BadRequest` gets distinct codes: `malformed_request` for refusals before the budget charge (an invalid steward tenant id or connector slug, `backend/crates/platform-api/src/lib.rs:501-505`) and a separate code such as `query_failed` for `QueryError::Execution` (`query.rs:674`), which comes after the charge. P78's extractor-rejection test asserts the codes.
- `tests/bypass.rs` asserts the expected reason for each case instead of accepting any refusal; one test per reason code.
- `docs/RESEARCHER_GUIDE.md` covers the table-name and quoting rule; the genuine `COUNT(*) AS n` requirement; permitted aggregates and clauses; each refused construct with one example; suppression and `min_cohort`; the budget rule exactly as P54 decides it (including which refusals are free); and every status code and `code`. A test runs each fenced example in the guide against the bypass fixture (moved to `quackxide-engine/tests/common/mod.rs`) and checks the documented outcome, so the guide cannot drift.
- The portal shows the reason (P44).

**Where.** `backend/crates/quackxide-engine/src/policy.rs`, `src/lib.rs`, `tests/bypass.rs`; `backend/crates/platform-api/src/query.rs`, `src/lib.rs`; new `docs/RESEARCHER_GUIDE.md`; `frontend/src/lib/research/`.

**Depends on:** P69 (plan types change), P44 (the portal item only: the reason is shown in P44's refusal states).

**Security impact.** Error messages become a fixed vocabulary that cannot leak data values; refusal reasons describe the query, never the data.
**ADR.** Not required.

**Notes.** A free plan-check endpoint is proposed outside v1 (it changes the "probing costs budget" control).

---

## Platform: durability, edge and deployment

### P61. Durable registries, part 1: store ADR, backend-failure errors and conformance suites
**Labels:** build · area:storage · rust · needs-adr
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 2-6

**Summary.** `TenantRegistry`, `GrantRegistry`, `BudgetLedger` and `CatalogRegistry` (`backend/crates/platform-tenancy/src/`) have only in-memory implementations. The first draft said durable backends could be added "without touching call sites" (also `docs/PROJECT_SCOPE.md`, `docs/ARCHITECTURE.md:253-254`); that cannot hold: the error enums cannot report a backend outage, and two call sites match exhaustively: `query.rs` (`BudgetError`; today any charge error becomes 429 `BudgetExhausted` with "no ledger entry") and `research.rs:144-150` (`CatalogError`). The workspace has no database dependency (`backend/Cargo.toml`). Sign-in adds identity and session state (P29, P30); its conformance cases and durable backends are in P63.

**Done when**
- An ADR chooses the registry store (for example Postgres or Cloud SQL, SQLite on a persistent disk, or versioned records in the vault bucket, which would need the conditional write from P41) and records: how its tests run under `scripts/check.sh` (`cargo test --workspace`) and on the CI matrix including `macos-latest`, where service containers are unavailable (an embedded store, or gated tests in a dedicated Linux job); the mapping of the u64 counters and amounts (`limit`, `spent`, the saturating `top_up`, listing `*_cents`, `grant_budget`); schema versioning with forward-only migrations applied at startup and refusal to start on an unknown newer schema; the backup method (feeds P76); what an operator who can write the store can do (reset budgets, un-revoke grants, forge grants) and the matching `THREAT_MODEL.md` A2 row, expected to be a recorded residual risk with the closure path (steward-signed grants, ledger anti-rollback) proposed outside v1; and that the chosen crates pass `backend/deny.toml`.
- `TenancyError`, `BudgetError` and `CatalogError` gain a backend-unavailable variant. platform-api maps it to `ApiError::Backend` (502), never to `BudgetExhausted` (429) or `NotFound` (404), with a distinct audit detail. A test per registry injects a failing backend and asserts the 502; for the research-query charge path it also asserts the `research.budget` event does not say "exhausted" or "no ledger entry". Idempotent operations resolve uniqueness races internally; no speculative `Conflict` variant.
- A shared conformance suite in `platform-tenancy` (a `pub mod conformance` behind a `test-support` feature) is written once per trait, takes the trait object, and runs against every `InMemory*` type. It lifts the existing unit tests in `lib.rs`, `grants.rs`, `budget.rs` and `catalog.rs` and adds the cases the trait docs promise but no test checks: idempotent provision, grant create and re-grant (un-revokes), listing upsert, existing Pending access request returned; steward-only revoke, unpublish and resolve with "not yours" indistinguishable from "unknown"; budget `open` is insert-if-absent and a re-grant never resets spend; `spent` is monotonic; `top_up` saturates and never lowers the limit; and the concurrent `charge` test from P54 (whichever of P54's conformance PR and this issue lands first writes it; the other reuses it).
- The "without touching call sites" wording is removed from `docs/PROJECT_SCOPE.md` and `docs/ARCHITECTURE.md`.

**Where.** `backend/crates/platform-tenancy/src/{lib.rs,grants.rs,budget.rs,catalog.rs}`, `backend/crates/platform-tenancy/Cargo.toml`, `backend/crates/platform-api/src/query.rs`, `src/research.rs`, `src/admin.rs`, new ADR, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/PROJECT_SCOPE.md`.

**Depends on:** none.

**Sequencing.** Land after P27 if possible, so the trait contracts include its fix.

**Security impact.** Registry outages fail closed with an honest status; trait guarantees (no oracle, monotonic spend) become executable contracts every backend must pass.
**ADR.** Required (storage format).

---

### P62. Durable registries, part 2a: tenant, grant, budget and catalog backends
**Labels:** build · area:storage · rust
**Size:** M-L (pair; one PR per store) · **Priority:** v1 blocker · **Owner:** stream 4 · **Target:** weeks 5-10

**Summary.** Implement the store chosen in P61 for the tenant, grant, budget and catalog registries and wire it into the binaries (definition-of-done items 4 and 7). The identity and session stores are in P63, so key-release integration (P51) does not wait on sign-in (P29, P30).

**Done when**
- Durable `TenantRegistry`, `GrantRegistry`, `BudgetLedger` and `CatalogRegistry` (listings, access requests, and P59's data-dictionary fields, if P59 has merged) each pass the P61 conformance suite. Land them as separate PRs reusing the first one's pattern; P63 reuses it too.
- `BudgetLedger::charge` is an atomic conditional update: N concurrent charges from two store handles never push `spent` above `limit` and never lose an update.
- Restart tests write, close, reopen and read back for each store.
- Multi-registry writes converge after a partial failure: the direct grant path (`grants.create` idempotent, `budgets.open` insert-if-absent) is locked in with a fault-injection test, and the approval path keeps the P27 guarantees on the durable backend.
- A record the backend cannot parse, or one that is internally inconsistent (for example `spent > limit`), makes it fail closed, with a test.
- `main.rs` builds the durable tenant registry from configuration (keys documented in `backend/.env.example`), and the research stores used by P43 become durable. In production mode (P18) an in-memory tenant, grant, budget or catalog registry is refused at startup; startup and requests fail closed when the store is unreachable.
- The admin control-plane marker (`backend/crates/platform-api/src/admin.rs:43-45`, written on provisioning but never read back) is either used to rehydrate the registry on startup or removed with its comment.
- If the store is a server, a CI job runs the durable tests against the real service on Linux.
- README "Status" ("Durability") is updated.

**Where.** `backend/crates/platform-tenancy/src/` (new backend modules), `backend/crates/platform-api/src/main.rs`, `backend/crates/platform-config/src/lib.rs`, `backend/.env.example`, `.github/workflows/ci.yml` (if a service job is needed), `README.md`.

**Depends on:** P61, P18 (production-mode refusal item), P43 (research-store wiring item), P27 (approval-path item); P41's conditional-write PR only if P61's ADR picks versioned records in the vault.

**Sequencing.** P51 needs only this half of the durable registries.

**Security impact.** Grants, revocations and budgets survive restarts, so revocation and spend limits keep holding (A1).
**ADR.** Covered by P61.

---

### P63. Durable registries, part 2b: identity and session stores
**Labels:** build · area:storage · area:auth · rust
**Size:** M · **Priority:** v1 blocker · **Owner:** stream 1, paired with whoever built P62 · **Target:** weeks 9-12

**Summary.** ADR 0006 (P16) decides which identity and session state stays in-house: tenant membership and the admin allowlist (P29), TOTP enrollment, the last accepted step and failed-attempt counters, and refresh-token families (P30). P29 and P30 build that state behind traits with in-memory implementations. This issue makes it durable in the store P61 chose, reusing P62's pattern. It is separate from P62 so that the key-release path (P62, then P51) does not wait on sign-in; sign-in (P29, P30, this issue, P32) still gates P68 and P82 directly.

**Done when**
- The store traits for the identity and session state ADR 0006 keeps in-house get conformance cases in P61's `conformance` module, run against the in-memory implementations from P29 and P30. They cover at least: a TOTP step at or below the last accepted one is refused; reuse of a rotated refresh token revokes its family; a revoked family stays revoked; a disabled account stays disabled; tenant membership and the admin flag round-trip.
- Durable backends for those stores pass the same cases. TOTP secrets are encrypted at rest under a configured key, and a missing key fails closed.
- Restart tests: after a restart, a replayed TOTP step and a reused refresh token are still refused, and a revoked refresh family stays revoked.
- A record the backend cannot parse makes it fail closed, with a test.
- The stores are wired wherever ADR 0006 and P15 place the identity service (`backend/crates/platform-api/src/main.rs` or the identity service's own binary), from configuration documented in `backend/.env.example`. In production mode (P18) in-memory identity and session stores are refused at startup.

**Where.** `backend/crates/platform-tenancy/src/` (or wherever P29 puts the identity traits), the identity service from P29, `backend/crates/platform-api/src/main.rs` (if the identity service runs there), `backend/crates/platform-config/src/lib.rs`, `backend/.env.example`.

**Depends on:** P61, P29, P30, P18 (production-mode refusal item), P62 (its first PR only, whose backend pattern this issue reuses).

**Sequencing.** Reuses the backend pattern from P62's first PR; start once that PR has merged.

**Security impact.** TOTP replay protection, refresh-token revocation and account disablement survive restarts (A3).
**ADR.** Covered by P61 (store choice) and P16 (which state stays in-house).

---

### P64. Deployment observability: audit sink, metrics and alerts
**Labels:** build · area:ops
**Size:** S-M · **Priority:** v1 blocker · **Target:** weeks 11-14

**Summary.** Audit records go only to stdout through one JSON layer (`backend/crates/platform-telemetry/src/lib.rs:17-28`; the target is `SECURITY_AUDIT_EVENT`, `lib.rs:11-13`). The stream also carries the billing meter (`engine.query` events, `docs/ARCHITECTURE.md:223-224`). Production needs these records stored durably, apart from operational logs. (Making the stream immune to `RUST_LOG` is P25.) P75 builds a readiness check and a metrics endpoint, but nothing collects the metrics or alerts on them, and on a single VM nothing else notices a VM that is not ready.

**Done when**
- The deployment from P68 routes records whose target is `SECURITY_AUDIT_EVENT` to a durable sink separate from operational logs, configured in `deploy/` rather than by changing the emitter, with a documented retention period.
- An alert fires when audit records stop arriving or the sink rejects writes. The emitter stays non-blocking; the expected behaviour on sink failure is documented in `docs/ARCHITECTURE.md` ("Security telemetry").
- P75's metrics are collected over a path or port that is not public.
- At least two more alerts reach the maintainer: one for not-ready or the service being down, and one for the 5xx rate. Each alert has a stable name; P77 adds a runbook section per alert name. Other alerts (attestation or key-release refusal rate, certificate expiry) are optional; add certificate expiry only if TLS terminates inside the VM with self-managed certificates (P67).
- A deploy check shows a sample record of each `AuditKind` arrives with only the fields `audit_kind`, `tenant_id`, `outcome`, `detail`, and that operational records do not land there.
- `docs/ARCHITECTURE.md` names the sink and retention and gives the query for audit records and for `engine.query` metering records; P77's runbook links to it.
- `deploy/` grants the VM's service account (P68) write access to the sink, without read or delete; P68 leaves this grant to this issue.

**Where.** `deploy/` (including the sink grant), `docs/ARCHITECTURE.md`.

**Depends on:** P68, P25, P75.

**Security impact.** Security decisions remain reviewable after the fact; operators cannot lose them by changing log settings. A VM that is not ready or is failing gets noticed.
**ADR.** Not required.

**Notes.** Tamper evidence (hash chaining or signed checkpoints) is proposed outside v1.

---

### P65. HTTP edge hardening: security headers, CSP, timeouts, panic handling, and CORS if chosen
**Labels:** harden · area:ops · area:frontend · rust · javascript
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 6-11

**Summary.** `build_app` adds only `TraceLayer` (`backend/crates/platform-api/src/lib.rs:312-323`) although tower-http's `cors` feature is enabled (`backend/Cargo.toml:48`). There is no CORS policy, request timeout or panic-catching layer, responses carry no security headers, and the frontend has no CSP (`frontend/index.html`). A strict CSP is a primary control here: script injected into the page can drive the crypto worker to decrypt with the steward's non-extractable keys. (Development access is solved by the same-origin proxy in P7.)

**Done when**
- If P15 chose cross-origin: an exact-origin `CorsLayer` allowlist read from `platform-config`; no wildcard; empty or missing means no cross-origin access; preflight `OPTIONS` is answered before `require_tenant`/`require_admin` and is not audited as an auth denial. Tests: allowed origin, refused origin, preflight. If same-origin was chosen, this item is the documented decision.
- Every API response carries `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`; authenticated JSON adds `Cache-Control: no-store`. A test asserts them.
- `TimeoutLayer` and `CatchPanicLayer` (enabling the tower-http `timeout` and `catch-panic` features) are added; the timeout is consistent with P52; a panic returns a generic 500 with no internal detail and emits a telemetry event. Negative tests for both.
- The production frontend is served with a CSP as an HTTP response header (a `<meta>` tag cannot carry `frame-ancestors`): no inline script, `script-src 'self'` (plus `'wasm-unsafe-eval'` only if P34 needs it), `worker-src 'self'`, `connect-src` limited to `'self'`, the API and sign-in provider origins, `frame-ancestors 'none'`; HSTS is sent wherever TLS terminates. The same headers are configured for `vite preview` (`preview.headers`), the Vite dev server is unaffected, and a test or `scripts/check.sh` step verifies the headers on the production build.
- An oversized-body negative test exists for each route group (drive routes have a 5 MiB `DefaultBodyLimit`; axum defaults to 2 MB elsewhere).
- `docs/THREAT_MODEL.md` A3 gains a row "script injection in the app origin drives non-extractable keys" with CSP as its control.

**Where.** `backend/crates/platform-api/src/lib.rs` (`build_app`), `backend/Cargo.toml` (tower-http features), `backend/crates/platform-config/src/lib.rs`, `frontend/vite.config.ts`, `frontend/index.html`, `deploy/`, `docs/THREAT_MODEL.md`.

**Depends on:** P15.

**Sequencing.** This issue owns the header values and the middleware that sets them; P67 mounts static frontend serving behind that layer, and P68 deploys it. Under the week-3 capacity decision, timeouts and panic handling could be split off and deferred; the CSP, the security headers and any CORS allowlist cannot.

**Security impact.** Limits script injection against key-holding pages (A3) and keeps errors and panics from leaking detail.
**ADR.** Not required (the origin decision is in P15).

**Notes.** Per-tenant rate limiting is out of scope for v1 (availability is not a v1 security goal).

---

### P66. Deployable frontend release bundle (runtime configuration)
**Labels:** build · area:frontend · area:ops · javascript
**Size:** S-M · **Priority:** v1 blocker · **Target:** weeks 6-10

**Summary.** `VITE_*` values are compiled into the bundle (`frontend/src/config/brand.ts`), and `release.yml` builds through `scripts/check.sh` with none set. So the signed `frontend.tar.gz` runs the drive in local IndexedDB mode (`frontend/src/config/vault.ts:20-21`), calls `http://127.0.0.1:8080` (`brand.ts:39`) and carries the neutral brand. Any real deployment would have to rebuild it, which breaks deploying exactly the attested release artifact.

**Done when**
- The released bundle works for any deployment without a rebuild: vault mode is `http` in release builds and an unrecognized mode is refused rather than falling back to `local`; API calls are same-origin (relative paths) or the base URL comes from a same-origin runtime configuration file (it cannot come from `/api/v1/meta`, which needs the base URL to reach); name, domain, support email and ZK flag load at boot from `/api/v1/meta` (which already serves them from backend configuration, `backend/crates/platform-api/src/lib.rs:332-342`).
- If `/api/v1/meta` cannot be loaded at boot, the app shows an error state, never the localhost or neutral-brand fallbacks. Local IndexedDB mode stays available in Vite dev mode, so the README offline demo still works.
- Runtime configuration reaches the crypto worker through its init message rather than `import.meta.env` (`frontend/src/lib/crypto/worker.ts:31-39`).
- A check in `scripts/check.sh`, next to the white-label guard, fails if the bundle contains a localhost or `127.0.0.1` origin or a baked-in `VITE_DEV_JWT`/`VITE_ADMIN_JWT` value; it runs locally and in `release.yml`.
- `frontend/src/config/brand.test.ts` and a new vault-config test cover production defaults and refusals.
- If the team instead chooses per-deployment frontend builds, that decision is recorded in `docs/` and P68's provenance check covers only the backend binaries. P68's dependency on this issue then changes to that recorded decision in the same edit.

**Where.** `frontend/src/config/brand.ts`, `vault.ts`, `frontend/src/vite-env.d.ts`, `frontend/src/lib/crypto/worker.ts`, `scripts/check.sh`, `.github/workflows/release.yml`.

**Depends on:** P18, P7.

**Sequencing.** Relates to P31 (runtime configuration reaches the worker through its init message, next to the token message) and P32. P67 serves the released bundle.

**Security impact.** The deployed browser code is exactly the signed release artifact, with no development tokens or local fallbacks.
**ADR.** Not required.

---

### P67. Production HTTP edge: TLS termination and same-origin frontend hosting
**Labels:** build · area:ops · area:frontend · rust
**Size:** M if TLS terminates in-process; S if it terminates outside the VM · **Priority:** v1 blocker · **Target:** weeks 6-11

**Summary.** `platform-api` serves plain TCP (`tokio::net::TcpListener` and `axum::serve`, `backend/crates/platform-api/src/main.rs:72-76`). It has no static-file serving (the tower-http features are `trace`, `cors` and `limit`, `backend/Cargo.toml:48`), the router has only API routes (`backend/crates/platform-api/src/lib.rs:312-323`), and configuration has no certificate settings (`backend/crates/platform-config/src/lib.rs`; `BIND_ADDR` defaults to `127.0.0.1:8080`, line 161). The release ships `frontend.tar.gz` (`.github/workflows/release.yml:35`), but nothing serves it. P65, P66 and P68 all assume an HTTPS, same-origin edge that serves the signed frontend bundle with security headers. P15 decides where TLS terminates; this issue builds that edge.

**Maintainer prerequisite.** A domain or DNS name for a publicly trusted certificate on staging (P13), or a provider-managed hostname recorded in P15.

**Done when**
- TLS follows P15.
  - **If TLS terminates inside the Confidential VM:** `platform-api` serves HTTPS with the rustls-based stack P15 names (rustls is already in `backend/Cargo.lock` through `reqwest`), or a proxy does if P15 and P49 list it as part of the image. The certificate and private key reach the VM only at runtime, from the secret store through the attached service account or from ACME inside the VM, never through the image, the repository or the release. In production mode (P18) the binary refuses to start without a certificate. Plain HTTP is either not bound or only redirects.
  - **If TLS terminates outside the VM:** the terminator's configuration lives in `deploy/`, and `docs/THREAT_MODEL.md` lists what it sees (bearer tokens, SQL text, request metadata).
- The frontend bundle is served same-origin with the API, by `platform-api` or by the proxy above. If `platform-api` serves it, it uses tower-http's `fs` feature (`ServeDir`):
  - `index.html` at `/` with `Cache-Control: no-store`, and hashed assets with immutable caching;
  - correct MIME types for the crypto worker script and, if P34 ships WebAssembly, `application/wasm`;
  - no single-page-app fallback, because the frontend has no client-side routing (`frontend/package.json` depends only on `react` and `react-dom`): unknown non-API paths return 404.
- P65 owns the header values and the middleware that sets them. This issue mounts static serving behind that layer, and a test asserts that `index.html` carries the CSP and security headers.
- `/api`, `/admin` and `/healthz` behave as before.
- Tests use a placeholder `index.html` and do not wait for P66:
  - a TLS handshake against a certificate generated at test time, with no key or certificate committed (`docs/DATA_POLICY.md` rule 3);
  - the headers on `index.html`;
  - an unknown path returns 404, and `/api/*` and `/admin/*` responses are unchanged;
  - the static handler refuses path traversal.
- Any new test-only dependency (for example `rcgen`) passes `backend/deny.toml` and dependency review.
- **Certificate renewal.** If TLS terminates inside the VM with self-managed certificates: the binary picks up a renewed certificate on restart without a rebuild (hot reload is not required); a renewal procedure is drafted in `docs/` and its steps are checked locally against a short-lived certificate generated at test time (none committed, `docs/DATA_POLICY.md` rule 3); and certificate expiry is exported as a P75 metric or readiness input. If TLS terminates outside the VM (for example at a provider-managed edge), `docs/` records how the certificate is renewed (for example provider-managed renewal). In both cases P77 adds renewal to the runbook and exercises it on staging.

**Where.** `backend/crates/platform-api/src/{main.rs,lib.rs}`, `backend/Cargo.toml`, `backend/crates/platform-config/src/lib.rs`, `backend/.env.example`, `deploy/` (created by P12), `docs/THREAT_MODEL.md`.

**Depends on:** P15, P18, P65 (the header test only), P75 (the certificate-expiry metric or readiness input, only if TLS terminates in the VM with self-managed certificates).

**Sequencing.**
- Serves the released `frontend.tar.gz` that P66 makes deployable.
- Feeds P49 (the image contents, if the frontend or a proxy runs inside the VM) and P68.
- P77 later lists the TLS key and exercises its renewal.

**Security impact.** Decides which component sees tokens and SQL in transit, and keeps the TLS key out of artifacts.
**ADR.** Covered by P15, which names the component that holds the TLS private key. If P15 is Accepted without naming it, this issue's PR adds a short ADR for it (`docs/adr/README.md:7-9`) and takes the `needs-adr` label.

---

### P68. Production deployment on SEV-SNP Confidential VMs from the documentation
**Labels:** build · area:ops · area:enclave · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 9-14

**Summary.** There is no deployment. Deploy the topology decided in P15 onto GCP SEV-SNP Confidential VMs (the platform named in `backend/crates/platform-enclave/src/lib.rs:1-2`) from a clean project, using the scripts seeded in P12 and the image from P49. `platform-api` serves plain TCP today (`main.rs:72`), so anything outside the Confidential VM that terminates TLS would see tokens and SQL. P67 builds the TLS and frontend-serving edge that P15 decides on. Definition-of-done item 5 asks that "the system deploys reproducibly from this repository's documentation"; bit-for-bit reproducible builds are not required for v1.

**Done when**
- A documented procedure in `docs/` and `deploy/` deploys the system from a clean project: the image from P49, the frontend bundle from P66 (verified with `gh attestation verify` before deploy, alongside the binaries), the durable registry store (P62, P63), the identity service and its signing-key custody (P29), any key-release service from P50, and the sign-in provider's configuration captured as code or as exact steps (including the white-label settings from P29), with the production tenant created by this procedure (P13 sets up development and staging only).
- The deployed topology matches P15: which processes run in the Confidential VM and where TLS terminates. If anything outside the VM terminates TLS, `docs/THREAT_MODEL.md` records what it can see.
- Configuration comes from the environment in production mode (P18) and fails closed: `STORAGE_BUCKET`, registry configuration, verification keys, attestation policy values, and a real tenant key for `connector-worker` (if P19 keeps it). Security-relevant settings (`TEE_ATTESTATION_REQUIRED`, `FEATURE_ZK_ENABLED`, `RESEARCH_MIN_COHORT_SIZE`) are fixed in the build, covered by attestation, or bounded in code, never taken on trust from the host environment.
- Secrets come from a secret store, never from images, the repository or the release; no service-account key files. `deploy/` holds no project ids, domains or credentials; parameters come from committed templates.
- The frontend and API are served over HTTPS through the edge from P67, from the documented origin (same-origin or the allowlist from P65), with the CSP and security headers from P65; the deploy doc lists the exact header values.
- If the topology from P15 has a load balancer or managed instance group, its serving health check uses P75's readiness check, so a VM that is not ready gets no traffic. Auto-healing, if used, probes liveness (`/healthz`) with an initial delay, never readiness: a fail-closed not-ready state caused by a shared dependency such as the registry store would otherwise recreate every VM in a loop. Health-check callers are unauthenticated, so the readiness response they get carries no dependency detail (P75). On a single VM, not-ready is caught by the alert in P64.
- Runtime identities are least-privilege and documented in `deploy/`. The VM's attached service account gets only what the running services need: read, write and delete on its own vault bucket (delete is needed by P42); access to the registry store; read access to its own secrets; write access to logs and metrics (P64 adds the audit-sink grant); and the P50 key-release service if that is IAM-gated. It has no project-level editor or owner role. The vault bucket has public-access prevention and uniform bucket-level access enabled. No human, including the P12 team identities, has standing write or delete access to production buckets, registries or secrets, and the deploy record includes an IAM policy listing that shows it. P77 documents and exercises break-glass access, and every use of it is audited.
- After deploy, a smoke test signs in a synthetic steward and a synthetic researcher (the test identities from P13, `docs/DATA_POLICY.md`) and loads the portal; a fresh deploy passes attestation and key release end to end on genuine SEV-SNP hardware (recorded through P71 or the manual checklist).
- Teardown is scripted and documented.
- **DoD item 5, independent deploy (by week 13, so fixes land before P82).** A core-team member who did not write this procedure, preferably from outside stream 3, deploys into an empty project using only `docs/` and `deploy/`. The maintainer creates that project, its billing link, P12's budget alert and hard cost control, and the sign-in provider tenant or provider access the procedure needs (within the free-tier limits P13 records), and grants the deployer roles scoped to that project and tenant for the run only, revoked at teardown. This is a recorded exception to P12's "no access to other projects"; P12 gives students no project-creation or billing roles. Secrets and tenant values come from the secret stores exactly where the procedure says (P13), or are generated by the procedure; nothing else comes from the author. The deployer records every deviation, undocumented step (console clicks, local environment variables, provider settings) or ambiguity in a dated record under `docs/`. The run ends with this issue's smoke test and the scripted teardown, which leaves no VMs running. If any undocumented step was needed, the docs are fixed in a PR and the run is repeated, by the same or another non-author, until it completes with none. The record is P82's evidence for item 5.

**Where.** `deploy/`, `docs/`, `.github/workflows/release.yml`, `backend/.env.example`.

**Depends on:** P49, P15, P18, P62, P63, P65, P66, P12, P75, P67, P13, and P51 for the end-to-end hardware check.

**Security impact.** Puts the trust boundary into practice: plaintext only inside the attested VM, no dev paths, no secrets in artifacts, and no standing operator access to production data paths.
**ADR.** Covered by P15.

---

## Operations, performance and quality

### P69. DataFusion, Arrow, Parquet and `object_store` upgrade
**Labels:** harden · area:engine · rust · needs-adr
**Size:** M (pair) · **Priority:** v1 blocker · **Target:** start weeks 1-2 (paired from week 2, as "Weeks 1-3" assigns it), merge by about week 5

**Summary.** Move from DataFusion 49 to the current release together with Arrow, Parquet and `object_store` (Dependabot groups them, `.github/dependabot.yml`). This clears the `quick-xml` advisories ignored in `backend/deny.toml:16-20` and the `thrift` advisory allowed in `.github/workflows/dependency-review.yml:18-22`. The upgrade also touches `platform-storage` (`object_store` error mapping) and `platform-connectors`, and the separate fuzz lockfile (`backend/fuzz/Cargo.lock`, outside the workspace, `backend/Cargo.toml:17`) pins arrow/parquet 55, object_store 0.12, quick-xml and thrift independently; Dependabot ignores semver-major updates there.

**Done when**
- DataFusion, Arrow, Parquet and `object_store` are on current releases; `cargo tree -d` shows no duplicate major versions of them. `rust-version` in `backend/Cargo.toml` is raised to at least the highest MSRV of the upgraded crates (metadata only; `rust-toolchain.toml` pins 1.94.1).
- `quackxide-engine/tests/{bypass.rs,disclosure.rs,engine_query.rs}` pass with every SQL string, expected outcome and `Rows(n)` count unchanged. The only allowed change is `Unplannable` to `Rejected` (both refusals; for example `count_filter` and `filter_on_value` are unplannable today only because sqlparser 0.55 does not parse aggregate `FILTER`), and the PR lists each such case for the code owner. No refusal becomes `Rows`. "Unchanged" means against the suite on `main` at the time, including the cases Code-Pause-Inc/QuackXide#21 and Code-Pause-Inc/QuackXide#22 added.
- `PERMITTED_AGGREGATES` and the plan shapes `policy::is_aggregate_only` accepts (as tightened by Code-Pause-Inc/QuackXide#21) stay the same; edits to `policy.rs` and `disclosure.rs` are limited to API migration and listed in the PR.
- The PR records the diff of DataFusion's default scalar, aggregate, window and table functions between the old and new versions (taken from the session state); any new table function or I/O-capable function is flagged to the code owner.
- The quick-xml ignores (RUSTSEC-2026-0194, RUSTSEC-2026-0195) are removed from `backend/deny.toml`, and the thrift allowance (GHSA-2f9f-gq7v-9h6m) from `dependency-review.yml`. The `paste` (RUSTSEC-2024-0436) and `rustls-pemfile` (RUSTSEC-2025-0134) ignores are re-checked ("Revisit on each DataFusion upgrade") and removed or re-justified.
- `backend/fuzz/Cargo.lock` is regenerated and committed in the same PR; it no longer contains arrow/parquet 55, object_store 0.12 or the advisory versions of quick-xml and thrift. `cargo +nightly fuzz build` succeeds for all targets, and `cargo deny check advisories` passes in `backend/fuzz/` (the full check there fails today on licences, `libfuzzer-sys` is NCSA, which is out of scope).
- `cargo deny check` passes in `backend/`.
- If P73's query benchmark exists when this lands, the PR reports before and after numbers; otherwise it says no baseline was available.

**Where.** `backend/Cargo.toml`, `backend/Cargo.lock`, `backend/crates/quackxide-engine/`, `backend/crates/platform-storage/src/lib.rs`, `backend/crates/platform-connectors/`, `backend/fuzz/Cargo.lock` (and `Cargo.toml` only if needed), `backend/deny.toml`, `.github/workflows/dependency-review.yml`.

**Depends on:** P4 (the `/backend/deny.toml` CODEOWNERS fix lands first).

**Sequencing.** P25 first if possible, so the leak test checks the new engine. P52, P53, P57, P58 and P60 merge engine code after this; P38 parses steward Parquet only after this. The `hpke` upgrade in P35 must not be in flight at the same time. While this issue is open, Dependabot PRs that move these crates across a major version are closed with a link here (P4).

**Security impact.** Removes known advisories from the code that parses Parquet and object-store responses; keeps the disclosure gate's behaviour fixed across the upgrade.
**ADR.** Required (`docs/adr/README.md:7-9`: a dependency that handles plaintext). A short record of what the PR already gathers: the versions chosen, the default-function diff, the advisories cleared and the plan-shape check.

---

### P70. CI hygiene: locked builds, secret scanning, and fuzz targets compiled on every PR
**Labels:** harden · area:ops · good first issue
**Size:** S · **Priority:** team enablement · **Target:** weeks 2-5

**Summary.** `scripts/check.sh` runs `cargo check`, `clippy` and `test` without `--locked` (lines 14, 17, 20), so it can rewrite `Cargo.lock` before `release.yml`'s `--locked` build (`release.yml:26-30`). The fuzz crate sits outside the workspace (`backend/Cargo.toml:17`) and `fuzz.yml` runs only weekly or on dispatch (`fuzz.yml:3-6`), so a PR that changes `platform-crypto` or `platform-auth` can break the fuzz build unnoticed. `docs/DATA_POLICY.md` rule 3 (no credentials) is enforced only by review.

**Done when**
- Every cargo build, check, clippy, test and llvm-cov command in `scripts/check.sh` and `.github/workflows/ci.yml` uses `--locked` (not `cargo fmt`, which rejects it). `CONTRIBUTING.md` says to commit `Cargo.lock` with any `Cargo.toml` change.
- A CI job compiles every fuzz target on every PR (`cargo +nightly fuzz build` with a pinned nightly date, or `cargo check --manifest-path backend/fuzz/Cargo.toml --locked`), build only; `fuzz.yml` gains `--locked`; `CONTRIBUTING.md` says fuzz targets compile on every PR and run weekly. If the job is a required check, it skips inside the job (for example a paths-filter step), not with a workflow-level `paths:` filter. New targets are added by the issues that introduce the parsers (P47, P35, P28, P38).
- A secret scanner (the gitleaks CLI; the gitleaks-action wrapper needs a licence key on organization repositories) runs in a CI job, pinned like the other actions, and in `scripts/check.sh` only when installed. Test-only literals go in a committed allowlist. The "Enforcement" section of `docs/DATA_POLICY.md` lists it. The data-guard extension list is not widened to `.json` or `.pem` (it would break `package.json` and the public AMD certificate fixtures).
- Maintainer action: GitHub secret scanning and push protection are enabled in repository settings, and the maintainer adds the new jobs to the required checks once green.

**Where.** `scripts/check.sh`, `.github/workflows/ci.yml`, `.github/workflows/fuzz.yml`, `CONTRIBUTING.md`, `docs/DATA_POLICY.md`.

**Depends on:** none.

**Sequencing.** Land before P69 if possible.

**Security impact.** Lockfile integrity in releases; earlier detection of committed secrets and broken fuzz targets.
**ADR.** Not required.

**Notes.** `scripts/` and `.github/` are code-owned. A coverage floor (`cargo llvm-cov --fail-under-lines`, per-crate floors for the security crates, vitest thresholds) is optional and proposed outside v1 if time is short.

---

### P71. SEV-SNP hardware test job (manual and scheduled)
**Labels:** build · area:ops · area:enclave
**Size:** S-M · **Priority:** v1 needed · **Target:** weeks 8-13

**Summary.** CI uses GitHub-hosted runners only (`.github/workflows/ci.yml`), so no check runs SEV-SNP code. Run the hardware-only tests on a real Confidential VM, safely, from a public repository, so definition-of-done item 2 keeps holding as later changes land.

**Done when**
- Maintainer prerequisite: a workload identity pool restricted to this repository and a protected GitHub environment whose deployment rules allow only `main` and `v*` tags (required reviewers at the maintainer's choice), with the budget alert from P12.
- A workflow (for example `.github/workflows/snp-hardware.yml`) runs on `workflow_dispatch`, a weekly `schedule`, and as a reusable workflow (`workflow_call`); it never runs on `pull_request` or `pull_request_target`, and no self-hosted runner accepts public pull-request jobs.
- It authenticates to GCP through OIDC workload identity federation (job-level `id-token: write`) with no stored keys, creates an ephemeral Confidential VM from the P49 image, runs the hardware-only tests (behind the convention from P48) and, once P74 lands, its enclave-overhead benchmark, records results, and destroys the VM.
- Optionally, `release.yml` calls it and its build job `needs:` it, so a release cannot ship without a passing hardware run.
- Fallback if OIDC setup is blocked: a documented manual Confidential VM run recorded in the runbook.

**Where.** New workflow under `.github/workflows/`; `deploy/`; `docs/`.

**Depends on:** P12, P49, P48.

**Security impact.** Keeps the attestation path tested on real hardware without exposing cloud credentials to pull requests.
**ADR.** Not required.

**Notes.** `.github/` is code-owned.

---

### P72. Browser end-to-end tests in CI
**Labels:** build · area:frontend · area:ops · javascript · rust
**Size:** M · **Priority:** v1 needed · **Target:** stage A weeks 3-6, stage B grows to week 14

**Summary.** Every frontend test runs under Node or jsdom (`frontend/vite.config.ts:12-28`). No real browser runs the module crypto worker, Web Crypto, or IndexedDB key persistence, and nothing drives the real frontend against the real API binary. Definition-of-done items 1 and 2 are browser flows.

**Done when**
- **Stage A (no backend changes):** the crypto worker and keystore run in real browsers (Vitest browser mode or Playwright): the module worker starts; a device key is generated and stays non-extractable; it survives a reload through IndexedDB; a drive encrypt/decrypt round trip works; the capability probe reports correctly. Chromium on every PR as its own CI job (not in `scripts/check.sh`); Firefox and WebKit on pushes to `main` or nightly. `README.md` lists the supported browsers.
- **Stage B (lifecycle specs, added as features land):** a Linux CI job builds and boots the dev server from P8 (dev-only wiring that a production build refuses) and serves the production frontend build, then Playwright covers: steward signs in, uploads, and the stored object read straight from the vault is ciphertext (under the hybrid suite identifier after P36); researcher requests access, steward approves, researcher queries and sees `suppressed_rows` and `budget_remaining`, and (after P56) opens a sealed result; refusal paths (no grant, revoked grant, budget exhausted, expired session). Once P28 lands the job uses a local RS256 test issuer instead of HS256.
- Traces are kept as artifacts; the maintainer adds the jobs to the required checks once stable.

**Where.** `frontend/package.json` (dev dependency), `frontend/vite.config.ts` or a Playwright config, new `frontend/e2e/` (or similar), `.github/workflows/ci.yml`, `README.md`.

**Depends on:** P8, P40, P44, P32, P36, P56 (stage B only; stage A has none).

**Sequencing.** Stage B grows as those issues land. The maintainer may split stage A into its own issue so it closes in weeks 3-6.

**Security impact.** Proves the browser-side invariants (non-extractable keys, ciphertext-only upload, sealed results) in real browsers.
**ADR.** Not required.

---

### P73. Benchmarks: harness, method, targets and regression tracking (portable)
**Labels:** build · area:ops · rust · javascript
**Size:** M · **Priority:** v1 blocker · **Target:** native and query baselines by week 4, P34's figures by week 5, targets by week 8

**Summary.** No benchmarks exist. ADR 0001 says "Benchmarks must track the cost" of the hybrid suites (lines 35-36), so the classical baseline must be captured before P35 merges. Shared GitHub-hosted runners are too noisy to gate on absolute numbers.

**Done when**
- A stable-toolchain harness (for example `criterion` with `[[bench]] harness = false`, so the `--all-targets` check and clippy in `scripts/check.sh` compile it; new dev-dependencies pass `cargo deny check`) with the `HPK1`-era baselines: query latency in `quackxide-engine` at stated dataset sizes and object counts; native HPKE seal/open throughput and envelope size for the `HPK1` frame (`backend/crates/platform-crypto/src/lib.rs:136-201`); browser chunk encryption (`encryptPayload` in `frontend/src/lib/crypto/core.ts`) as a Vitest bench; and P34's bundle-size and load-time figures.
- The harness is built so later benchmarks plug into the same regression run. Each is added by the issue that enables it, before that issue closes, with its own target: P34 checkpoint A (wasm seal in the browser), P40 (the end-to-end upload path), P35 (the hybrid frame) and P56 (opening a sealed result).
- Data is generated at run time by the generator from P9 and never committed beyond small `fixtures/`.
- `docs/BENCHMARKS.md` records the method, results, the machine they were produced on, and the performance targets and regression threshold agreed with @AxolDad for these baselines (by week 8).
- Pull-request runs report only and never fail. A scheduled or recorded run on one fixed, described machine (a maintainer-provisioned runner or documented manual runs with committed results) fails or opens an issue when a regression exceeds the threshold; or base and head are compared in the same job with a written threshold.
- The X25519 baseline is recorded before P35 merges.

**Where.** New `benches/` in `backend/crates/quackxide-engine/` and `backend/crates/platform-crypto/` (code-owned), frontend bench files, new `docs/BENCHMARKS.md`, a scheduled workflow (code-owned).

**Depends on:** P9, P34 (checkpoint A's bundle-size and load-time figures only).

**Sequencing.** The X25519 baseline lands before P35 merges; P35 adds the hybrid numbers.

**Security impact.** None directly; makes the cost of the post-quantum suites and enclave visible.
**ADR.** Not required.

---

### P74. Enclave-overhead benchmark on SEV-SNP hardware
**Labels:** build · area:ops · area:enclave
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 12-14

**Summary.** Definition-of-done item 6 includes enclave overhead, which can only be measured on hardware.

**Done when**
- On a Confidential VM with attestation required and the production key provider, a per-query breakdown is recorded against synthetic datasets of fixed sizes and object counts: SNP report generation and verification, key release (count and time; today `open_envelope` runs once per object, `query.rs:290-296`), decrypt, DataFusion execute, and result sealing.
- The baseline is the same SQL over the same dataset on a non-confidential VM of the same size in the development configuration (a production configuration fails closed off-hardware).
- It runs through P71 or a documented manual procedure per release candidate, and results are committed to `docs/BENCHMARKS.md` with the hardware, commit and date. The results inform whether key release is per query or cached (P50).

**Where.** `docs/BENCHMARKS.md` (created in P73), benchmark code from P73, `deploy/`.

**Depends on:** P73, P68, P50, P48, P55.

**Security impact.** None directly.
**ADR.** Not required.

---

### P75. Readiness, operational metrics and graceful shutdown
**Labels:** build · area:ops · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 4-10

**Summary.** Structured JSON logs and the `SECURITY_AUDIT_EVENT` stream exist and are tested (`backend/crates/platform-telemetry/src/lib.rs`, `platform-api/tests/audit_coverage.rs`). `/healthz` is a static public liveness check (`backend/crates/platform-api/src/lib.rs:328-330`). There is no readiness check or metrics. `platform-api` shuts down only on Ctrl-C (`main.rs:80-82`); `connector-worker` handles no signal and `SyncScheduler::run` loops forever (`backend/crates/platform-connectors/src/worker.rs:32-42`).

**Done when**
- `/healthz` stays static, public and free of detail. A separate readiness check reports storage, registries, the attestation provider and the token verifier; it fails closed (a production configuration whose attestation or key provider still refuses reports not-ready), and it is either unreachable by unauthenticated callers or returns no dependency detail to them. Tests cover each dependency being down; registry and verification-key checks are added as P62 and P28 land.
- Operational metrics are exported for request count, latency, refusal count and plaintext-slot wait. Labels carry identifiers, outcomes and counts only: no key material, plaintext, filenames or SQL (`docs/ARCHITECTURE.md`, "Identifiers and outcomes only"), never the engine name, and no tenant-id labels (unbounded cardinality). The metrics endpoint is not exposed to unauthenticated callers. New dependencies pass `cargo deny check`.
- `shutdown_signal` also completes on SIGTERM (`tokio::signal::unix`), with a test. `connector-worker` gets a cancellation path so an in-flight sync either finishes its sealed write or leaves no partial object, with a test.

**Where.** `backend/crates/platform-api/src/lib.rs`, `src/main.rs`, `backend/crates/platform-connectors/src/worker.rs`, `src/bin/connector-worker.rs`, `backend/crates/platform-telemetry/`.

**Depends on:** none.

**Sequencing.** Works on P8; registry and key checks are added as P62 and P28 land. P67 adds a certificate-expiry metric (or readiness check) if TLS terminates in-process. P68 routes traffic on the readiness check, and P64 collects the metrics and alerts on them.

**Security impact.** Operability without leaking content through metrics or health detail.
**ADR.** Not required.

---

### P76. Backup and restore that preserve the security invariants
**Labels:** build · area:ops · area:storage · rust
**Size:** M · **Priority:** v1 blocker · **Target:** weeks 11-14

**Summary.** Definition-of-done item 7 requires that the system "can be backed up, restored, and operated from the runbook" without "a weakened invariant". A naive point-in-time restore would roll back budget spend (monotonic per grant, `docs/ARCHITECTURE.md:216-217`), revive revoked grants or reactivate suspended tenants. HPKE `info` binds tenant, slug and object (`docs/ARCHITECTURE.md:106-110`), so ciphertext must be restored to its exact paths.

**Done when**
- One documented procedure snapshots the vault (both `tenants/` and `control/`, `backend/crates/platform-storage/src/lib.rs:121-129`) and the registry store, including the identity and session stores (method from P61), to a consistent point, and restores them to the exact paths.
- A restore never lowers any grant's `spent`, never un-revokes a grant, never reactivates a suspended tenant, never revives a revoked refresh-token family or a disabled account, and never rolls back a TOTP last-accepted step (P63): either restored grants are frozen until the steward reviews them (default), or state is reconciled from the durable audit stream (P64). `engine.query` events carry researcher, steward and connector but no `grant_id`, so reconciliation maps by (steward, researcher, connector) or the event gains a `grant_id`.
- A restore drill on synthetic data in staging passes and is recorded; it proves a granted query on the restored system decrypts with keys obtained through the documented custody path (a restore whose ciphertext cannot be opened fails the drill).
- Backups hold ciphertext only; registry snapshots are access-controlled like the registries. RPO and RTO are documented, along with how long deleted data (P42) persists in backups.

**Where.** `deploy/`, `docs/`, runbook.

**Depends on:** P62, P63, P68, P41, P50.

**Security impact.** Restores cannot be used to reset budgets or revive revoked access (A1).
**ADR.** Not required (the backup method is in P61).

---

### P77. Key inventory, key rotation and the runbook
**Labels:** build · area:ops · area:crypto · documentation
**Size:** M-L (pair: the restart-and-failure drill can go to a second person, ideally from outside stream 3) · **Priority:** v1 blocker · **Target:** weeks 11-15

**Summary.** The first draft asked for "a key-rotation procedure" without naming keys. The only rotation test today is the RS256 JWKS overlap (`backend/crates/platform-auth/src/verify.rs:332-369`), and the verifier parses the JWKS once when built. `MOR_WEBHOOK_SECRET` is a single value (`backend/crates/platform-config/src/lib.rs:198`). Unwrapped drive DEKs are non-extractable (`frontend/src/lib/crypto/core.ts:98-113`), so the drive KEK cannot be rotated by re-wrapping. Blind-index keys have no defined source (`backend/crates/platform-crypto/src/lib.rs:118-130`). Definition-of-done item 7 also requires that the system "survives restarts and failures without data loss or a weakened invariant"; per-component failure tests exist across several issues, but nothing confirms them together on staging.

**Done when**
- `docs/` contains a key inventory of every key and secret the release uses: drive KEK and DEKs, the tenant HPKE key (hybrid after P35), the dataset key released by P50, the researcher result key (P55), platform token-signing keys and the verification key set, the key protecting TOTP secrets at rest, blind-index keys, `MOR_WEBHOOK_SECRET`, storage credentials, the TLS private key and certificate (P67), and `JWT_HS256_SECRET` (development only). For each: owner, where it lives, how it is backed up or recovered, and either a rotation procedure or a stated reason it is not rotated in v1 with the compromise response (for example: re-enroll, seal new data to the new key, and record re-seal as a residual risk). Browser-held drive keys are unrecoverable after loss by design, and the runbook says so.
- Rotation is exercised end to end in staging, following the runbook, for the token-signing key (publish, overlap, retire; with the reload or refresh path from P28) and the dataset key released by P50. `MOR_WEBHOOK_SECRET` gets a dual-secret overlap or a documented fail-closed cutover window. Each rotation emits audit events.
- A runbook in `docs/` covers deploy, rollback, rotate, restore, certificate renewal (P67), updating attestation measurements when platform firmware changes, querying the audit stream and pulling `engine.query` metering records during an incident (P64), a response section for each alert name from P64, break-glass access to production data paths (P68), including how each grant and use of that access is audited, fuzz-crash triage (`.github/workflows/fuzz.yml`), credential compromise, and an accidental data commit (pointing to `SECURITY.md` and `docs/DATA_POLICY.md`). Each procedure has been exercised once in staging and the run recorded (DoD item 7).
- The runbook has a **restart-and-failure drill** for DoD item 7: manual, scripted steps on the P68 staging deployment, with no failure-injection framework. Each scenario states the expected outcome and names the issue whose tests define it. A scenario applies only if the topology from P14, P15 and P16 contains that component.
  - Rolling restart with SIGTERM: in-flight requests complete or fail cleanly, and readiness reports not-ready until dependencies are back (P75).
  - `platform-api` killed during a steward upload: the previous version stays current, the partial upload is never listed or queried, and a retry succeeds (ADR 0003, P38).
  - Killed during an access approval: a retry converges, and no grant is live for a Pending or Denied request (P27, P62).
  - Killed during a research query: no plaintext or temp file is written (P52), and the budget outcome matches the order P54 chose.
  - `connector-worker` (if P19 keeps it) stopped mid-sync: no partial object, and the previous snapshot stays current (P75; ADR 0003's manifest-last commit).
  - Registry store unavailable, then restored: requests return 502, never 429 or 404, and the `research.budget` event does not say "exhausted"; startup refuses while the store is unreachable. After recovery no spend is lost or reset, a grant revoked before the outage stays revoked, and a replayed TOTP step is still refused (P61, P62, P63).
  - Object store unavailable or stalled: requests fail within the bound P41 documents, with P41's documented status for each `StorageError` class and no fallback to the in-memory vault; afterwards there are no stranded chunks or partial objects (P41).
  - Verification-key source or identity service unavailable: sign-in and refresh are refused (P29). A running API keeps verifying with the last good key set; an API restarted while the source is down returns 503 `AuthNotConfigured` and never falls back to HS256 (P28).
  - Key-release service or verifier unavailable: 503 through the dedicated variant, never 502, with a `crypto.key_release` failed event, and no budget charged unless P54's order says otherwise (P50, P54).
  - VM reboot: grants, revocations and `spent` are unchanged (P62); the first query afterwards gets a fresh attestation and key release, and no plaintext or key material persists across the reboot (P48, P50).
- The drill is run once on staging and the run is recorded. P82 cites that record and reruns only the scenarios touched by changes merged after it.

**Where.** New `docs/` runbook and key inventory; `backend/crates/platform-config/src/lib.rs` (webhook secret overlap if chosen); `backend/crates/platform-billing/` (`verify_paddle_signature`, called from `backend/crates/platform-api/src/admin.rs`, if dual-secret).

**Depends on:** P68, P76, P50, P28, P14, P64, and, for the restart-and-failure drill scenarios, P38 (steward upload), P52 (no plaintext spill) and P54 (budget order).

**Security impact.** Makes compromise response and key hygiene executable rather than aspirational.
**ADR.** Maintainer decides (key-rotation procedure).

---

## Quality gates, acceptance and release

### P78. A negative test and an audit assertion for every failure path (tracking)
**Labels:** harden · tracking · rust · javascript
**Size:** tracking (closes at release) · **Priority:** v1 blocker · **Owner:** one core-team member keeps the checklist; every stream adds its own tests

**Summary.** Definition-of-done item 8: "Every failure path has a negative test, and the audit-coverage test covers every new security decision". This is a checklist that runs all semester, not a single good first issue. Concrete work items are split out (P46, P45, P79); new refusals are tested in the issue that adds them (`CONTRIBUTING.md:49-51`). The 429 in scope means the research budget is exhausted (`ApiError::BudgetExhausted`); the repository has no request rate limiter.

**Done when**
- A checklist in this issue lists, per route module (drive, query, research/grants, catalog, admin/provisioning, webhook), the `ApiError` variants (`backend/crates/platform-api/src/lib.rs:88-110`) that module can actually return, each ticked when a negative test lands in `backend/crates/platform-api/tests/`. No full cross-product.
- The checklist also covers framework (axum extractor) rejections for each JSON or typed-path route: missing or wrong `Content-Type` (415 today), a JSON syntax error (400 today), a wrong field type or missing field (422 today), and a non-parsable typed path segment such as a non-numeric chunk index (`Path<(String, u32)>`, `backend/crates/platform-api/src/lib.rs:640, 672`; 400 today). Today these come from axum 0.8.9 (`backend/Cargo.lock:391-392`) with a plain-text body, outside `ApiError`. One table-driven test over all such routes is enough, using the P10 helpers; it asserts the status now, and the JSON body and `code` once P60 lands. Oversized bodies are owned by P65 and only ticked here.
- Every `audit_kind` in the `docs/ARCHITECTURE.md` audit table is asserted in `audit_coverage.rs` for its ok and denied (or miss) outcomes, or listed with a reason (for example `service.start`, emitted only from the binaries).
- Every refusal the frontend can receive renders a tested error state (P44, P32, P40).
- Every new security decision added by a v1 issue is ticked here when that issue's PR adds its test and audit assertion.
- `docs/ARCHITECTURE.md:319-331` (what the capture tests enforce) matches reality at release.

**Where.** `backend/crates/platform-api/tests/`, `backend/crates/quackxide-engine/tests/`, frontend `*.test.ts(x)`, `docs/ARCHITECTURE.md`.

**Depends on:** none (tracks the whole milestone).

**Sequencing.** The naming convention comes from P6.

**Security impact.** Definition-of-done item 8.
**ADR.** Not required.

---

### P79. Emit and assert audit events for refusals that are silent today
**Labels:** harden · area:disclosure · rust · good first issue
**Size:** S · **Priority:** v1 blocker · **Target:** weeks 3-7

**Summary.** Several refusals return the right status but emit no audit event, and several emitted events are never asserted. `audit_coverage.rs`'s `full_app` wires no research layer. (Grant create/revoke, the no-grant denial and grant-id refusals belong to P45.)

**Done when**
- These refusals emit an event (`denied` for a refused request, `miss` for a not-found probe, as `data.access` already does) carrying identifiers only, and `audit_coverage.rs` asserts each; existing status tests are extended rather than duplicated: `unpublish_listing` of a foreign or unknown listing and `resolve_access_request` of a foreign or already-resolved request (`backend/crates/platform-api/src/research.rs`; add the missing already-resolved status test); `request_access` not found or self-request; `create_grant` to self (`lib.rs`); admin `toggle_connector` with an unknown connector or tenant (`backend/crates/platform-api/src/admin.rs`); and a plaintext-slot or decrypt failure in `query` and `research_query` (`query.rs`; in the research path the budget is already charged at that point, so today the charge appears nowhere in the audit stream).
- These already-emitted events gain assertions: `research.budget` ok (top-up) and denied (exhaustion); `research.catalog` publish, unpublish, request, approve and deny; `connector.sync` ok (`backend/crates/platform-connectors/src/pipeline.rs`); research-mode `engine.query` ok and failed, asserting the detail carries `budget_remaining` and no SQL text.
- Outcome strings stay within the existing vocabulary (`ok`, `denied`, `miss`, `failed`); changing the plan-gate refusal from `failed` to `denied` is P54's decision.
- `docs/ARCHITECTURE.md` (audit table and rule 3 list) matches.

**Where.** `backend/crates/platform-api/src/research.rs`, `src/query.rs`, `src/lib.rs`, `src/admin.rs`, `backend/crates/platform-api/tests/audit_coverage.rs`, `docs/ARCHITECTURE.md`.

**Depends on:** none.

**Sequencing.** Coordinate the `full_app` change with P45 and P46 (whoever lands first adds `with_research`).

**Security impact.** Every security decision becomes reviewable after the fact (`SECURITY.md` treats "security decisions that emit no audit event" as in scope).
**ADR.** Not required.

---

### P80. Fix current documentation drift
**Labels:** documentation · good first issue
**Size:** S · **Priority:** team enablement · **Target:** weeks 1-3

**Summary.** Some statements in the docs are wrong today, independent of any new work. A newcomer can fix them while learning the system, with @AxolDad reviewing.

**Done when**
- `docs/THREAT_MODEL.md:6` names README's actual heading (`## Status`, `README.md:142`), not "Status and known limitations".
- The README "Status" list (`README.md:142-157`) adds only the gaps it omits: the steward upload path for research datasets, deployment, benchmarks, operations (health, metrics, backup, key rotation, runbook), the dominance rule, and the DataFusion `quick-xml`/`thrift` advisories. It keeps the pointer to `docs/PROJECT_SCOPE.md` rather than copying every row.
- `docs/ARCHITECTURE.md:241` lists all eight `PlatformConfig` sections (brand, server, storage, auth, connectors, research, billing, features), as in `backend/crates/platform-config/src/lib.rs:21-30`.
- `README.md:58-61` no longer implies connector syncs run in attested memory today (they are refused until SEV-SNP attestation exists, or run unattested in development), and `README.md:68-69` no longer implies a production blind-index search path (no ingest path writes a blind-index column).
- `docs/THREAT_MODEL.md:29` matches the code (fixed properly by P26; if this lands first, it states that only `Debug` is redacted today).
- "Production build" wording in `README.md:153` and `docs/PROJECT_SCOPE.md` follows the definition from P18 once it lands.
- `CONTRIBUTING.md:71-73` ("Design decisions") lists the same ADR triggers as `docs/adr/README.md:7-9`, including "a dependency that handles plaintext or keys".
- A CHANGELOG line is added under `[Unreleased]`.

**Where.** `README.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, `docs/PROJECT_SCOPE.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.

**Depends on:** none.

**Security impact.** Docs stop overstating built controls.
**ADR.** Not required.

**Notes.** The steward-key contradiction (`THREAT_MODEL.md:25` versus `:72`) is resolved by P14, not here.

---

### P81. Harden the release workflow
**Labels:** harden · area:ops
**Size:** S-M · **Priority:** v1 needed · **Target:** weeks 6-12

**Summary.** `release.yml` (43 lines) runs `scripts/check.sh` and every dependency's build scripts in the same job that holds `contents: write`, `id-token: write` and `attestations: write`; it publishes notes with `--generate-notes`, ignoring `CHANGELOG.md`; versions are not tied to the tag; there is no SBOM; and nothing verifies the attestations.

**Done when**
- Build and publish are separate jobs: the build job has `contents: read` and `persist-credentials: false`, runs `check.sh` and the builds, and hands off `dist/` with upload/download-artifact; only the publish job, which runs no dependency code, holds the write permissions, runs `attest-build-provenance`, and creates the release.
- One SBOM (CycloneDX or SPDX) for the Rust binaries and one for the frontend bundle are produced and attested.
- `release.yml` fails unless the tag, `[workspace.package] version` in `backend/Cargo.toml`, `version` in `frontend/package.json`, both lockfiles and the CHANGELOG heading agree, and fails if the build changes a committed lockfile. It publishes that CHANGELOG section as the release notes (`--notes-file`).
- The artifact list includes every binary P68 runs (and only those, per P19 and P15), and the image and expected attestation values from P49.
- `docs/RELEASING.md` lists the release steps, including `gh attestation verify` on each artifact.
- New actions are pinned to commit SHAs like the existing ones.

**Where.** `.github/workflows/release.yml`, new `docs/RELEASING.md`.

**Depends on:** P49 (image step only).

**Security impact.** Reduces supply-chain exposure of the release credentials and makes artifacts verifiable.
**ADR.** Not required.

**Notes.** `.github/` is code-owned. Deterministic packaging (`SOURCE_DATE_EPOCH`, sorted tar with fixed owner and mtime, `gzip -n`) is included if cheap; bit-for-bit reproducible builds are proposed outside v1.

---

### P82. v1.0 acceptance run and documentation gate
**Labels:** build · area:ops · documentation
**Size:** M · **Priority:** v1 blocker · **Owner:** @AxolDad with one core-team member as release owner · **Target:** weeks 12-15

**Summary.** The capstone. Every definition-of-done item is demonstrated with recorded evidence, and the docs describe the system as built (item 9). This issue checks; it does not build. Each feature issue updates its own docs, CHANGELOG line and ADR in its own PR (`CONTRIBUTING.md:71-77`).

**Done when**
- An acceptance checklist committed under `docs/` maps each definition-of-done item (1-10) to its evidence: test names, the benchmark report (P73, P74), the independent deploy record for item 5 (P68), the restore record (P76), runbook drill records (P77), and CI runs on `main`.
- Items 1, 2, 3 and 7 are run on the staging deployment on genuine SEV-SNP hardware: the browser end-to-end specs from P72 run once against the deployed system (or, if P72 moved to v1.1, a manual browser run of items 1-3 recorded under the checklist); a researcher's query passes attestation, receives the key only inside the enclave, and returns a disclosure-controlled sealed result opened in the browser; no route returns 503 for missing wiring; the restart-and-failure drill record from P77 is cited, and the scenarios touched by changes merged after it are rerun.
- No "to build" or "not wired" text remains in `README.md`, `docs/ARCHITECTURE.md` or `docs/THREAT_MODEL.md` (including the THREAT_MODEL status column and its "Unfinished controls" residual). Every row in the two lifecycle tables of `docs/PROJECT_SCOPE.md` reads Built; rows in "Across both lifecycles" may be descoped only by a maintainer-approved PR that changes `PROJECT_SCOPE.md`.
- `docs/ARCHITECTURE.md` matches the built system, not only free of "to build" text. The crate-boundaries table (lines 236-251) has one row for each member in `backend/Cargo.toml` `members`, with dev-only crates marked dev-only, and beside it a short list of the deployed binaries and services, checked against what P68 deploys and P81 releases: `platform-api`, `connector-worker` if P19 keeps it, any query worker from P15, the identity service from P29 if ADR 0006 chose one, and any key-release service from P50. Each dataflow diagram and the "Trust model in one paragraph" section describe the built path: steward upload is its own flow, separate from Drive (P38); sign-in, and token exchange if ADR 0006 chose it, is described (P29); the research flow, and the own-data query flow if P55 seals it, ends in a result sealed to the researcher's key, not plaintext rows (P55); key release and the authorization model match P14, P16, P50 and P51.
- `SECURITY.md` "Out of scope" (lines 39-43) no longer points at gaps that are now built.
- `scripts/check.sh` passes on `main` (item 10).

**Where.** New `docs/` acceptance checklist; `README.md`; `docs/`; `SECURITY.md`.

**Depends on:** every v1-blocker issue, plus every v1-needed issue still in the milestone after the week-3 capacity decision in P5, except P83, which depends on this issue.

**Sequencing.** Starts as soon as P68 has a staging environment.

**Security impact.** Confirms the invariants hold end to end before release.
**ADR.** Not required.

---

### P83. Cut and publish v1.0.0
**Labels:** harden · area:ops
**Size:** S · **Priority:** v1 needed · **Owner:** @AxolDad · **Target:** week 15

**Summary.** Versions are 0.1.0 in `backend/Cargo.toml` (`[workspace.package]`, inherited by every crate) and `frontend/package.json`; `SECURITY.md:45-47` says there has been no production release; `CHANGELOG.md` has only `[Unreleased]` and `[0.1.0]`.

**Done when**
- One release PR, reviewed under the normal rules, sets the version to 1.0.0 in `backend/Cargo.toml` and `frontend/package.json` (`npm version --no-git-tag-version`, so the lockfile stays in sync) and updates both lockfiles; moves `[Unreleased]` into `## [1.0.0] - <date>` with a Contributors subsection crediting the core team and every contributor (`docs/PROJECT_SCOPE.md`, "Team and timeline"); updates the link references at the end of `CHANGELOG.md`; updates `CONTRIBUTORS.md` and the README contributors line; and changes `SECURITY.md` "Supported versions" to name 1.0.x.
- `scripts/check.sh` is green on `main` at the release commit.
- The maintainer pushes tag `v1.0.0`; `release.yml` publishes the artifacts, and `gh attestation verify` succeeds on each one.
- The deployed system (P68) runs exactly the released artifacts.

**Where.** `backend/Cargo.toml`, `backend/Cargo.lock`, `frontend/package.json`, `frontend/package-lock.json`, `CHANGELOG.md`, `CONTRIBUTORS.md`, `README.md`, `SECURITY.md`.

**Depends on:** P82, P81.

**Security impact.** None beyond publishing verified artifacts.
**ADR.** Not required.

---

## Proposed outside v1.0 (for the maintainer's decision)

Not in the milestone. Each was raised in review and judged worthwhile but outside the release scope, or was moved out of a v1 issue to keep it finishable. If the maintainer pulls one in, it needs its own sizing and, where marked, an ADR.

- **Enforce connector toggles and the full billing lifecycle.** `TenantRecord.connectors` and the Paddle subscription states are recorded but not enforced beyond what P29 does for suspension. Needs a design for per-tenant worker jobs from the registry and a decision on whether researchers can query a suspended steward's data. (area:auth, rust)
- **Grammar-based fuzz target for the disclosure gate.** Move the bypass fixture and leak oracle into a shared module and fuzz `QueryScope::sql_json` with a small SQL grammar (aggregates, WHERE, GROUP BY including grouping sets, HAVING, subqueries, joins, statements), asserting no panic and no leak. Best after P69 and P58. (area:disclosure, rust)
- **Grant expiry.** Not in `docs/PROJECT_SCOPE.md`; would add a `DatasetGrant` field, a check in `find_active`, and a durable format. (needs-adr)
- **Attested result sender authentication.** An enclave signing key bound in REPORT_DATA, hybrid signatures on results, and verification of the SEV-SNP report and AMD chain in the researcher's browser, closing the forgery residual P55 records. (needs-adr, area:crypto, area:enclave)
- **Steward-signed grants and top-ups; anti-rollback for the budget ledger.** Closes the operator-forgery residual P61 records, including operator-issued tokens. (needs-adr)
- **Multi-device keys, key escrow and recovery.** v1 refuses a second device's key (P33); sync and recovery need their own design.
- **Zeroizing allocator for decoded Arrow memory.** Would need a reviewed `unsafe_code` exception or a vetted third-party allocator; today it is the documented "Unzeroized working memory" residual. (needs-adr)
- **Decrypt and decode less.** Row-group pruning by statistics and a DataFusion Parquet source over an object store (P53 does column projection only); per-column or per-row-group encryption (for example Parquet modular encryption), which is needed before decryption itself can be projected; and running the plan gate against the declared schema from P38 or P59 before key release. (area:engine; needs-adr for the encryption format)
- **Per-tenant concurrency, rate limiting, SQL-length and Parquet-metadata caps.** Availability controls; `docs/THREAT_MODEL.md` treats availability as outside v1.
- **Complementary suppression to re-allow grouping sets.** ADR 0002 refuses them; re-allowing needs secondary suppression. (needs-adr)
- **Differencing closure.** A perturbation `DisclosurePolicy` and a privacy-loss accountant replacing the constant per-query cost (`docs/THREAT_MODEL.md:127-132`). It must also cover `suppressed_rows` and whether released groups are present or absent; otherwise the count stays an exact channel after the aggregates are noised (P54). (needs-adr)
- **Free plan-check endpoint.** Lets researchers validate SQL without spending budget; changes the "probing costs budget" control, so it needs a published schema (P59) and a threat-model entry first.
- **Per-column data classification and an enclave-side schema-mismatch check with a no-charge path.** Extends P59.
- **CSV upload.** Needs a Parquet writer in the browser or an attested conversion step; v1 accepts Parquet only (P38).
- **Classical-to-hybrid migration mode and re-seal tool.** Needed only if classical production ciphertext ever exists; P17 records the v1 decision.
- **Bit-for-bit reproducible builds.** A CI job that rebuilds release artifacts and the image twice and compares digests (stretch in P49 and P81).
- **Full drive-object listing pagination.** Needs frontend changes; P41 only bounds the listing.
- **Coverage floor in CI.** `cargo llvm-cov --fail-under-lines` with higher per-crate floors for the security crates, plus vitest thresholds (optional part of P70).
- **Audit-stream tamper evidence.** Hash chaining or signed checkpoints on top of P64.
- **Automated accessibility checks.** axe-core in component tests and a retrofit of existing placeholder-only inputs (beyond P11).
- **Live connector sync, blind-index search, and charging catalog prices.** Deferred by default in P19.
