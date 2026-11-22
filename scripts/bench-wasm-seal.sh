#!/usr/bin/env bash
# =============================================================================
# bench-wasm-seal.sh — the browser envelope seal benchmark (docs/BENCHMARKS.md,
# "Browser envelope seal"). Builds the wasm module and the frontend, generates
# synthetic Parquet with synth-data into frontend/bench-data/ (git-ignored),
# seals it in Chromium's worker (`npm run bench:seal`) and prints a
# Markdown report: bundle size, module load time, seal time and peak memory.
#
# Needs what scripts/build-wasm.sh needs, frontend dependencies (`npm ci`) and
# Playwright's Chromium (`npx playwright install chromium`). The largest size
# holds about five times its plaintext in memory at once; LARGE_ROWS picks a
# smaller one on a machine with less than 8 GiB free.
#
#   scripts/bench-wasm-seal.sh                 # report on stdout
#   scripts/bench-wasm-seal.sh > report.md
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="$ROOT/frontend/bench-data"

# Rows of synth-data's `wide` schema (seed 1) for about 1 MiB, 100 MiB and
# 1 GiB of Parquet. The report gives the exact byte counts.
SMALL_ROWS=4900
MEDIUM_ROWS=553000
LARGE_ROWS="${LARGE_ROWS:-5670000}"
LOADS=10

"$ROOT/scripts/build-wasm.sh" >&2
cargo build --manifest-path "$ROOT/backend/Cargo.toml" --locked --release -p synth-data >&2
(cd "$ROOT/frontend" && npm run build >&2)

rm -rf "$DATA"
mkdir -p "$DATA"
files=()
for spec in "1 MiB:$SMALL_ROWS:30" "100 MiB:$MEDIUM_ROWS:5" "1 GiB:$LARGE_ROWS:3"; do
    IFS=: read -r label rows iterations <<<"$spec"
    name="wide-seed1-rows$rows.parquet"
    "$ROOT/backend/target/release/synth-data" --schema wide --seed 1 --rows "$rows" --out "$DATA/$name" >/dev/null
    files+=("{\"label\":\"$label\",\"url\":\"/bench-data/$name\",\"schema\":\"wide\",\"seed\":1,\"rows\":$rows,\"iterations\":$iterations}")
done
printf '{"loads":%d,"files":[%s]}\n' "$LOADS" "$(IFS=,; echo "${files[*]}")" >"$DATA/manifest.json"

(cd "$ROOT/frontend" && npm run bench:seal >&2)

{
    lscpu | grep -E '^(Model name|CPU\(s\)):' | sed 's/  */ /g'
    free -h | awk '/^Mem:/ {print "Memory: " $2}'
    echo "Node: $(node -v)"
    echo "wasm-bindgen: $(wasm-bindgen --version | awk '{print $2}')"
    cargo tree --manifest-path "$ROOT/backend/Cargo.toml" --locked -p envelope-wasm \
        --target wasm32-unknown-unknown -e normal --prefix none \
        | grep -E '^(hpke|aes-gcm|x25519-dalek|curve25519-dalek) v' | awk '{print $1 ": " $2}' | sort -u
} >"$DATA/machine.txt"

node "$ROOT/frontend/scripts/seal-bench-report.mjs" "$DATA" "$ROOT/frontend/dist"
