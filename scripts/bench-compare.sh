#!/usr/bin/env bash
# =============================================================================
# bench-compare.sh — judge criterion's base-vs-head comparison
# (docs/BENCHMARKS.md). A benchmark regresses when the lower bound of the 95 %
# confidence interval of its mean change is above the threshold, so the whole
# interval is a slowdown bigger than the threshold.
#
#   bench-compare.sh <criterion-dir> [threshold]   table on stdout; exit 1 if
#                                                 any benchmark regressed
#   bench-compare.sh selftest                      check the rule on fixtures
#
# The threshold is a fraction (default 0.10). Only benchmarks with a
# `change/estimates.json` under <criterion-dir> are judged: those criterion
# compared against a saved baseline in this run. Needs jq.
# =============================================================================
set -euo pipefail

usage() { echo "usage: bench-compare.sh <criterion-dir> [threshold] | selftest" >&2; exit 2; }

pct() { awk -v x="$1" 'BEGIN { printf "%+.1f %%", x * 100 }'; }

compare() {
    local dir="$1" threshold="$2" file id lower point upper verdict regressed=0 rows=0
    [[ -d "$dir" ]] || { echo "bench-compare: no such directory: $dir" >&2; return 2; }
    [[ "$threshold" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "bench-compare: bad threshold: $threshold" >&2; return 2; }
    command -v jq >/dev/null || { echo "bench-compare: needs jq" >&2; return 2; }

    echo "| Benchmark | Change | 95 % interval | Verdict |"
    echo "| --- | --- | --- | --- |"
    while IFS= read -r file; do
        id="${file#"$dir"/}"
        id="${id%/change/estimates.json}"
        read -r lower point upper < <(jq -r '.mean | "\(.confidence_interval.lower_bound) \(.point_estimate) \(.confidence_interval.upper_bound)"' "$file")
        if awk -v l="$lower" -v t="$threshold" 'BEGIN { exit !(l > t) }'; then
            verdict="regressed"
            regressed=1
        elif awk -v u="$upper" -v t="$threshold" 'BEGIN { exit !(u < -t) }'; then
            verdict="improved"
        else
            verdict="within threshold"
        fi
        echo "| \`$id\` | $(pct "$point") | $(pct "$lower") to $(pct "$upper") | $verdict |"
        rows=$((rows + 1))
    done < <(find "$dir" -path '*/change/estimates.json' | LC_ALL=C sort)
    [[ "$rows" -gt 0 ]] || echo "| (no compared benchmarks) | | | |"
    return "$regressed"
}

selftest() {
    local tmp
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    fixture() { # <dir> <id> <lower> <point> <upper>
        mkdir -p "$1/$2/change"
        printf '{"mean":{"confidence_interval":{"confidence_level":0.95,"lower_bound":%s,"upper_bound":%s},"point_estimate":%s}}\n' \
            "$3" "$5" "$4" >"$1/$2/change/estimates.json"
    }
    expect() { # <want-exit> <dir> <grep-pattern>
        local out status=0
        out="$(compare "$2" 0.10)" || status=$?
        [[ "$status" == "$1" ]] || { echo "FAIL: selftest: exit $status, want $1, for $2"; exit 1; }
        grep -qE "$3" <<<"$out" || { echo "FAIL: selftest: no '$3' in output for $2"; exit 1; }
    }

    fixture "$tmp/regressed" "g/slow" 0.12 0.15 0.18
    expect 1 "$tmp/regressed" '\| `g/slow` .*\| regressed \|'

    fixture "$tmp/improved" "g/fast" -0.25 -0.20 -0.15
    expect 0 "$tmp/improved" '\| `g/fast` .*\| improved \|'

    fixture "$tmp/noisy" "g/noisy" -0.05 0.07 0.20
    expect 0 "$tmp/noisy" '\| `g/noisy` .*\| within threshold \|'

    # A benchmark that is new at head has no change/ and is not judged.
    fixture "$tmp/new" "g/old" -0.01 0.00 0.01
    mkdir -p "$tmp/new/g/new/new"
    expect 0 "$tmp/new" '\| `g/old` '
    ! compare "$tmp/new" 0.10 | grep -q 'g/new' || { echo "FAIL: selftest: judged a benchmark with no change/"; exit 1; }

    mkdir -p "$tmp/empty"
    expect 0 "$tmp/empty" 'no compared benchmarks'

    echo "bench-compare selftest passed"
}

case "${1:-}" in
    selftest) selftest ;;
    "") usage ;;
    *) compare "$1" "${2:-0.10}" ;;
esac
