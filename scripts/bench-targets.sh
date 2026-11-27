#!/usr/bin/env bash
# =============================================================================
# bench-targets.sh — the cargo arguments that run every bench target in the
# workspace that exists in this checkout, on one line
# (`-p <package> --bench <target> ...`), so a criterion bench added to any
# crate joins the `bench` job's comparison (docs/BENCHMARKS.md). Each must
# be a criterion bench (`harness = false`). Run from backend/.
# `--benches` would also run each library's test harness, which refuses
# criterion's flags. Needs jq.
# =============================================================================
set -euo pipefail
targets="$(cargo metadata --no-deps --format-version 1 --locked |
    jq -r '.packages[]
        | .name as $pkg
        | .targets[] | select(.kind == ["bench"])
        | "-p \($pkg) --bench \(.name)"' | paste -sd' ' -)"
[[ -n "$targets" ]] || { echo "bench-targets: no bench targets found" >&2; exit 1; }
echo "$targets"
