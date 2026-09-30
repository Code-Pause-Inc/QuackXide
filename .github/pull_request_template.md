## What and why

<!-- What changed, and why. Link the issue or the step in docs/PROJECT_SCOPE.md. -->

## How it was tested

<!-- Tests added or changed. Name the failure paths covered. -->

## Checklist

- [ ] `scripts/check.sh` passes locally
- [ ] Every new refusal has a negative test
- [ ] Every new security decision emits a `SECURITY_AUDIT_EVENT` covered by `audit_coverage.rs`
- [ ] Fails closed on missing configuration, key material, or attestation
- [ ] No new cryptographic primitives; suites stay behind their type aliases
- [ ] Synthetic or public data only (`docs/DATA_POLICY.md`)
- [ ] Docs and `CHANGELOG.md` updated for user-visible changes
- [ ] Architectural decision recorded in `docs/adr/` if one was made
