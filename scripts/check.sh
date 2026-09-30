#!/usr/bin/env bash
# =============================================================================
# check.sh — full validation: backend fmt/check/clippy/test, frontend
# typecheck/test/build, the white-label guards, and the attribution guard.
# Must pass before every push.
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== backend: rustfmt =="
cargo fmt --manifest-path "$ROOT/backend/Cargo.toml" --all -- --check

echo "== backend: cargo check (workspace, all targets) =="
cargo check --manifest-path "$ROOT/backend/Cargo.toml" --workspace --all-targets

echo "== backend: clippy (warnings are errors) =="
cargo clippy --manifest-path "$ROOT/backend/Cargo.toml" --workspace --all-targets -- -D warnings

echo "== backend: cargo test =="
cargo test --manifest-path "$ROOT/backend/Cargo.toml" --workspace

echo "== frontend: clean install =="
(cd "$ROOT/frontend" && npm ci --no-audit --no-fund)

echo "== frontend: typecheck =="
(cd "$ROOT/frontend" && npm run typecheck)

echo "== frontend: unit tests =="
(cd "$ROOT/frontend" && npm test)

echo "== frontend: production build =="
(cd "$ROOT/frontend" && npm run build)

echo "== white-label guard: the engine name must not reach the shipped bundle =="
if grep -riq "quackxide" "$ROOT/frontend/dist"; then
    echo "FAIL: engine name leaked into the customer-facing bundle"
    exit 1
fi

echo "== config guard: domain references live only in env templates =="
# The deployment domain is configuration; any hit in source means it was
# hardcoded, breaking the dynamic-branding rule.
if grep -rn "yourdomain" "$ROOT/backend/crates" "$ROOT/frontend/src" 2>/dev/null; then
    echo "FAIL: hardcoded domain reference outside .env.example templates"
    exit 1
fi

echo "== config guard: neutral brand fallback lives only in the config seams =="
# The neutral default name may exist exactly where config defines it (and its
# tests); everywhere else must read it from configuration.
if grep -rn "Confidential Drive" "$ROOT/backend/crates" "$ROOT/frontend/src" 2>/dev/null \
    | grep -v "platform-config/src/lib.rs" \
    | grep -v "frontend/src/config/brand.ts" \
    | grep -v "frontend/src/config/brand.test.ts"; then
    echo "FAIL: brand fallback hardcoded outside the config seams"
    exit 1
fi

echo "== data guard: data files live only in fixtures/ (docs/DATA_POLICY.md) =="
if git -C "$ROOT" ls-files \
    | grep -iE '\.(csv|tsv|parquet|ndjson|jsonl|xlsx?|sav|dta|sas7bdat|xpt|rds|rdata|feather|arrow|avro|orc|vcf|bam|cram|fastq|dcm|hl7|sqlite|db)$' \
    | grep -v '/fixtures/'; then
    echo "FAIL: data file outside a fixtures/ directory"
    exit 1
fi

echo "== attribution guard: tools are never credited =="
"$ROOT/scripts/attribution-guard.sh" tree

echo "ALL CHECKS PASSED"
