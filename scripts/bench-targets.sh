#!/usr/bin/env bash
# =============================================================================
# bench-targets.sh — the cargo arguments that run every criterion bench of
# platform-crypto and quackxide-engine that exists in this checkout, on one
# line (`-p <package> --bench <target> ...`). Run from backend/.
# `--benches` would also run each library's test harness, which refuses
# criterion's flags. Needs jq.
# =============================================================================
set -euo pipefail
targets="$(cargo metadata --no-deps --format-version 1 --locked |
    jq -r '.packages[]
        | select(.name == "platform-crypto" or .name == "quackxide-engine")
        | .name as $pkg
        | .targets[] | select(.kind == ["bench"])
        | "-p \($pkg) --bench \(.name)"' | paste -sd' ' -)"
[[ -n "$targets" ]] || { echo "bench-targets: no bench targets found" >&2; exit 1; }
echo "$targets"
