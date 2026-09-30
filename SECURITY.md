# Security Policy

QuackXide is security infrastructure, and reports of weaknesses in it are
welcome.

## Reporting a vulnerability

**Do not open a public issue, discussion, or pull request for a
vulnerability.** Report it privately by either:

* GitHub's private vulnerability reporting ("Report a vulnerability" under
  this repository's **Security** tab), or
* email to **Jeremy.Ryan@codepause.com** with "QuackXide security" in the
  subject.

Please include:

* the affected component (crate, frontend module, or document);
* the invariant or control it breaks (see `docs/THREAT_MODEL.md`);
* steps to reproduce, ideally as a failing test;
* the commit you tested against.

Reports are acknowledged, investigated, and fixed privately, and the
reporter is credited in `CHANGELOG.md` unless they ask not to be.

## In scope

* Any path by which a researcher, operator, administrator, or external
  party obtains record-level data or key material.
* Bypasses of the plan gate, genuine-count check, cohort suppression, query
  budget, grant check, attestation gate, or key-release gate.
* Cross-tenant access.
* Audit events that leak content, or security decisions that emit no audit
  event.
* Paths that fail open instead of closed.
* Real data or credentials committed to this repository (see
  `docs/DATA_POLICY.md`).

## Out of scope

The items listed under "Out of scope" in `docs/THREAT_MODEL.md`, and gaps
already listed as "to build" there and in `docs/PROJECT_SCOPE.md`, unless
the report shows that the path fails open.

## Supported versions

QuackXide has not had a production release. Security fixes land on `main`.
