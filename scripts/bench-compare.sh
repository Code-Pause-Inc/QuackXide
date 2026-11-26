#!/usr/bin/env bash
# =============================================================================
# bench-compare.sh — judge a base-vs-head benchmark comparison
# (docs/BENCHMARKS.md). A benchmark regresses when the lower bound of the 95 %
# confidence interval of its mean change is above the threshold, so the whole
# interval is a slowdown bigger than the threshold.
#
#   bench-compare.sh <criterion-dir> [threshold]      criterion's comparison
#   bench-compare.sh vitest <base.json> <head.json> [threshold]
#                                                     two Vitest bench runs
#   bench-compare.sh selftest                         check the rule on fixtures
#
# Both print a Markdown table on stdout and exit 1 if any benchmark
# regressed, 2 if none could be judged or the input is unusable. The
# threshold is a fraction (default 0.10). Needs jq.
#
# Criterion: only benchmarks with a `change/estimates.json` under
# <criterion-dir> are judged, those criterion compared against a saved
# baseline in this run, with criterion's interval.
#
# Vitest: the JSON reports of two `vitest bench` runs (`npm run
# bench:browser`), tasks matched by name, so a name must not repeat within a
# run. Vitest reports no interval for the change, so it comes from each
# run's mean and standard error: the delta method for the ratio of two
# independent means, with the larger of the two runs' t critical values
# (that of the smaller sample). A task with one sample in either run, or in
# only one of the runs, is listed but not judged.
# =============================================================================
set -euo pipefail

usage() {
    echo "usage: bench-compare.sh <criterion-dir> [threshold] | vitest <base.json> <head.json> [threshold] | selftest" >&2
    exit 2
}

pct() { awk -v x="$1" 'BEGIN { printf "%+.1f %%", x * 100 }'; }

# A time in milliseconds, to three significant figures.
duration() {
    awk -v t="$1" 'BEGIN {
        if (t < 0.9995) printf "%.3g µs", t * 1000
        else if (t < 999.5) printf "%.3g ms", t
        else printf "%.3g s", t / 1000
    }'
}

# The rule, for both kinds of input: <lower> <upper> <threshold>.
verdict() {
    if awk -v l="$1" -v t="$3" 'BEGIN { exit !(l > t) }'; then
        echo "regressed"
    elif awk -v u="$2" -v t="$3" 'BEGIN { exit !(u < -t) }'; then
        echo "improved"
    else
        echo "within threshold"
    fi
}

usable() { # <threshold>
    [[ "$1" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "bench-compare: bad threshold: $1" >&2; return 2; }
    command -v jq >/dev/null || { echo "bench-compare: needs jq" >&2; return 2; }
}

compare() {
    local dir="$1" threshold="$2" file id values lower point upper result regressed=0 rows=0
    [[ -d "$dir" ]] || { echo "bench-compare: no such directory: $dir" >&2; return 2; }
    usable "$threshold" || return 2

    echo "| Benchmark | Change | 95 % interval | Verdict |"
    echo "| --- | --- | --- | --- |"
    while IFS= read -r file; do
        id="${file#"$dir"/}"
        id="${id%/change/estimates.json}"
        values="$(jq -r '.mean
            | [.confidence_interval.lower_bound, .point_estimate, .confidence_interval.upper_bound]
            | if all(type == "number") then map(tostring) | join(" ") else error("not numbers") end' \
            "$file" 2>/dev/null)" || { echo "bench-compare: unreadable estimates: $file" >&2; return 2; }
        read -r lower point upper <<<"$values"
        result="$(verdict "$lower" "$upper" "$threshold")"
        if [[ "$result" == regressed ]]; then regressed=1; fi
        echo "| \`$id\` | $(pct "$point") | $(pct "$lower") to $(pct "$upper") | $result |"
        rows=$((rows + 1))
    done < <(find "$dir" -path '*/change/estimates.json' | LC_ALL=C sort)
    if [[ "$rows" -eq 0 ]]; then
        echo "| (no compared benchmarks) | | | |"
        echo "bench-compare: no benchmark was compared; nothing to judge" >&2
        return 2
    fi
    return "$regressed"
}

compare_vitest() {
    local base="$1" head="$2" threshold="$3" file rows kind name b h point lower upper result regressed=0 judged=0
    for file in "$base" "$head"; do
        [[ -f "$file" ]] || { echo "bench-compare: no such file: $file" >&2; return 2; }
    done
    usable "$threshold" || return 2

    # One line per task name: kind, name, base mean, head mean, change, and
    # the change's interval. Every number is in the line, 0 where unused.
    rows="$(jq -nr --slurpfile base "$base" --slurpfile head "$head" '
        def stats:
            if (.mean | type) == "number" and .mean > 0
                and (.sem | type) == "number" and .sem >= 0
                and (.samplesCount | type) == "number" and .samplesCount >= 1
                and (.samplesCount < 2 or ((.critical | type) == "number" and .critical > 0))
            then {mean, sem, critical, n: .samplesCount}
            else error("unusable latency statistics") end;
        def tasks:
            [.[0].testResults[]?.assertionResults[]?.benchmarks[]?.tasks[]?]
            | if length == 0 then error("no benchmark results") else . end
            | if all(.name | type == "string") then . else error("a task without a name") end
            | if (map(.name) | unique | length) < length then error("a task name repeats") else . end
            | map({key: .name, value: (.latency | stats)}) | from_entries;
        ($base | tasks) as $b
        | ($head | tasks) as $h
        | ([$b, $h | keys[]] | unique)[] as $name
        | if ($b | has($name)) and ($h | has($name)) then
            $b[$name] as $x | $h[$name] as $y | ($y.mean / $x.mean) as $r
            | if $x.n < 2 or $y.n < 2 then ["single", $name, $x.mean, $y.mean, $r - 1, 0, 0]
              else
                ($r * ((($x.sem / $x.mean) | . * .) + (($y.sem / $y.mean) | . * .) | sqrt)) as $se
                | ([$x.critical, $y.critical] | max) as $t
                | ["judged", $name, $x.mean, $y.mean, $r - 1, $r - 1 - $t * $se, $r - 1 + $t * $se]
              end
          elif ($h | has($name)) then ["new", $name, 0, $h[$name].mean, 0, 0, 0]
          else ["gone", $name, $b[$name].mean, 0, 0, 0, 0]
          end
        | @tsv')" || { echo "bench-compare: unusable Vitest results: $base, $head" >&2; return 2; }

    echo "| Benchmark | Base mean | Head mean | Change | 95 % interval | Verdict |"
    echo "| --- | --- | --- | --- | --- | --- |"
    while IFS=$'\t' read -r kind name b h point lower upper; do
        case "$kind" in
            judged)
                result="$(verdict "$lower" "$upper" "$threshold")"
                if [[ "$result" == regressed ]]; then regressed=1; fi
                judged=$((judged + 1))
                echo "| \`$name\` | $(duration "$b") | $(duration "$h") | $(pct "$point") | $(pct "$lower") to $(pct "$upper") | $result |"
                ;;
            single) echo "| \`$name\` | $(duration "$b") | $(duration "$h") | $(pct "$point") | | not judged: one sample |" ;;
            new) echo "| \`$name\` | | $(duration "$h") | | | new at head, not judged |" ;;
            gone) echo "| \`$name\` | $(duration "$b") | | | | not at head |" ;;
        esac
    done <<<"$rows"
    if [[ "$judged" -eq 0 ]]; then
        echo "| (no judged benchmarks) | | | | | |"
        echo "bench-compare: no benchmark ran with more than one sample in both runs; nothing to judge" >&2
        return 2
    fi
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
        out="$(compare "$2" 0.10 2>/dev/null)" || status=$?
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
    local out
    out="$(compare "$tmp/new" 0.10)"
    ! grep -q 'g/new' <<<"$out" || { echo "FAIL: selftest: judged a benchmark with no change/"; exit 1; }

    mkdir -p "$tmp/empty"
    # Nothing compared is an error, never a pass.
    expect 2 "$tmp/empty" 'no compared benchmarks'

    # Malformed estimates are an error, never a verdict.
    mkdir -p "$tmp/null/g/x/change"
    echo '{"mean":{"confidence_interval":{"lower_bound":null,"upper_bound":0.01},"point_estimate":0}}' >"$tmp/null/g/x/change/estimates.json"
    expect 2 "$tmp/null" 'Benchmark'
    mkdir -p "$tmp/truncated/g/x/change"
    printf '{"mean":{"confidence_' >"$tmp/truncated/g/x/change/estimates.json"
    expect 2 "$tmp/truncated" 'Benchmark'

    # Vitest reports, in the shape `vitest bench --reporter=json` writes.
    vitest_run() { # <file> <name>=<mean>,<sem>,<critical>,<samples> ...
        local file="$1" spec name mean sem critical samples tasks=()
        shift
        for spec in "$@"; do
            name="${spec%%=*}"
            IFS=, read -r mean sem critical samples <<<"${spec#*=}"
            tasks+=("{\"name\":\"$name\",\"latency\":{\"mean\":$mean,\"sem\":$sem,\"critical\":$critical,\"samplesCount\":$samples}}")
        done
        printf '{"testResults":[{"assertionResults":[{"benchmarks":[{"tasks":[%s]}]}]}]}\n' \
            "$(IFS=,; echo "${tasks[*]}")" >"$file"
    }
    expect_vitest() { # <want-exit> <base> <head> <grep-pattern>
        local out status=0
        out="$(compare_vitest "$2" "$3" 0.10 2>/dev/null)" || status=$?
        [[ "$status" == "$1" ]] || { echo "FAIL: selftest: exit $status, want $1, for $3"; exit 1; }
        grep -qE "$4" <<<"$out" || { echo "FAIL: selftest: no '$4' in output for $3"; exit 1; }
    }
    vitest_run "$tmp/base.json" "slow=1,0.005,2,64" "fast=1,0.005,2,64" "noisy=1,0.005,2,64" \
        "few=1,0.005,2,64" "cold=6.6,0,12.7,1" "old=1,0.005,2,64"
    vitest_run "$tmp/head.json" "slow=1.2,0.006,2,64" "fast=0.7,0.004,2,64" "noisy=1.15,0.05,2,64" \
        "few=1.13,0.006,4.303,3" "cold=9.9,0,12.7,1" "new=1,0.005,2,64"
    # +20 %, interval 20 % +/- 2 * 1.2 * sqrt(0.005^2 + 0.005^2).
    expect_vitest 1 "$tmp/base.json" "$tmp/head.json" '^\| `slow` \| 1 ms \| 1\.2 ms \| \+20\.0 % \| \+18\.3 % to \+21\.7 % \| regressed \|$'
    expect_vitest 1 "$tmp/base.json" "$tmp/head.json" '^\| `fast` .*\| improved \|$'
    expect_vitest 1 "$tmp/base.json" "$tmp/head.json" '^\| `noisy` .*\| within threshold \|$'
    # Three samples at head: its t critical value (4.303) widens the interval
    # to +9.5 % to +16.5 %; the base's (2) would have flagged it.
    expect_vitest 1 "$tmp/base.json" "$tmp/head.json" '^\| `few` .*\| \+9\.5 % to \+16\.5 % \| within threshold \|$'
    # One sample has no interval: listed, never judged.
    expect_vitest 1 "$tmp/base.json" "$tmp/head.json" '^\| `cold` \| 6\.6 ms \| 9\.9 ms \| \+50\.0 % \| \| not judged: one sample \|$'
    expect_vitest 1 "$tmp/base.json" "$tmp/head.json" '^\| `new` \| \| 1 ms \| \| \| new at head, not judged \|$'
    expect_vitest 1 "$tmp/base.json" "$tmp/head.json" '^\| `old` \| 1 ms \| \| \| \| not at head \|$'

    vitest_run "$tmp/same.json" "a=0.0037,0.00005,2,64" "b=1.35,0.05,2,64"
    expect_vitest 0 "$tmp/same.json" "$tmp/same.json" '^\| `a` \| 3\.7 µs \| 3\.7 µs \| \+0\.0 % \| -3\.8 % to \+3\.8 % \| within threshold \|$'

    # Nothing judged is an error, never a pass.
    vitest_run "$tmp/cold-base.json" "cold=6.6,0,12.7,1"
    vitest_run "$tmp/cold-head.json" "cold=9.9,0,12.7,1"
    expect_vitest 2 "$tmp/cold-base.json" "$tmp/cold-head.json" 'no judged benchmarks'
    vitest_run "$tmp/other.json" "c=1,0.005,2,64"
    expect_vitest 2 "$tmp/same.json" "$tmp/other.json" 'no judged benchmarks'

    # Unusable input is an error, never a verdict.
    vitest_run "$tmp/repeat.json" "a=1,0.005,2,64" "a=1,0.005,2,64"
    vitest_run "$tmp/zero.json" "a=0,0,2,64"
    vitest_run "$tmp/null.json" "a=null,0.005,2,64"
    vitest_run "$tmp/nocritical.json" "a=1,0.005,null,64"
    echo '{"testResults":[]}' >"$tmp/none.json"
    printf '{"testResults":[{"assertion' >"$tmp/truncated.json"
    local bad status
    for bad in repeat zero null nocritical none truncated missing; do
        status=0
        compare_vitest "$tmp/same.json" "$tmp/$bad.json" 0.10 >/dev/null 2>&1 || status=$?
        [[ "$status" == 2 ]] || { echo "FAIL: selftest: exit $status, want 2, for $bad.json"; exit 1; }
    done

    echo "bench-compare selftest passed"
}

case "${1:-}" in
    selftest) selftest ;;
    vitest) [[ $# -ge 3 ]] || usage; compare_vitest "$2" "$3" "${4:-0.10}" ;;
    "") usage ;;
    *) compare "$1" "${2:-0.10}" ;;
esac
