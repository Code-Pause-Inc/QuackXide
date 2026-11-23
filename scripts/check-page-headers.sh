#!/usr/bin/env bash
# =============================================================================
# check-page-headers.sh — the page's response headers on a release build.
#
# Builds the frontend in release mode, serves it with `vite preview`, and
# checks `/`, `/index.html` and the crypto worker script: status, content
# type, exactly one Content-Security-Policy equal to
# backend/crates/platform-api/page-csp.txt, and the other three policy
# headers. Static files stay cacheable, so Cache-Control: no-store must be
# absent. With --smoke it then loads the page in Chromium and runs one
# wasm-backed worker operation under the policy (frontend/scripts/csp-smoke.mjs;
# needs `npx playwright install chromium`). Needs the wasm module
# (scripts/build-wasm.sh) and `npm ci` first.
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$ROOT/frontend"
OUT="dist-release"

smoke=false
case "${1:-}" in
    "") ;;
    --smoke) smoke=true ;;
    *) echo "usage: $0 [--smoke]" >&2; exit 2 ;;
esac

server_pid=""
log="$(mktemp)"
cleanup() {
    if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
    rm -rf "$FRONTEND/$OUT" "$log"
}
trap cleanup EXIT

# The approved trust inputs; the digest is syntactically valid and fake.
export VITE_VAULT_MODE=http
export VITE_API_BASE_URL=
export VITE_DEV_JWT=
export VITE_ADMIN_JWT=
export VITE_ATTESTATION_ISSUER=https://confidentialcomputing.googleapis.com
export VITE_ATTESTATION_JWKS_URL=https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com
export VITE_ATTESTATION_IMAGE_DIGESTS="sha256:$(printf '0%.0s' $(seq 64))"

cd "$FRONTEND"
rm -rf "$OUT"
echo "== release build =="
npx vite build --mode release --outDir "$OUT"

port="$(node -e 'const s=require("node:net").createServer().listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')"
base="http://127.0.0.1:$port"
npx vite preview --mode release --outDir "$OUT" --host 127.0.0.1 --port "$port" --strictPort >"$log" 2>&1 &
server_pid=$!
for _ in $(seq 100); do
    curl -sf -o /dev/null "$base/" && break
    if ! kill -0 "$server_pid" 2>/dev/null; then cat "$log"; echo "FAIL: vite preview exited"; exit 1; fi
    sleep 0.2
done
curl -sf -o /dev/null "$base/" || { cat "$log"; echo "FAIL: vite preview did not start"; exit 1; }

worker=""
for f in "$OUT"/assets/worker-*.js; do worker="${f#"$OUT"/}"; done
[ -n "$worker" ] || { echo "FAIL: no crypto worker script under $OUT/assets"; exit 1; }

expected_csp="$(cat "$ROOT/backend/crates/platform-api/page-csp.txt")"
fail=0
check() { # path content-type-prefix
    local path="$1" type="$2" head status
    head="$(curl -sS -D - -o /dev/null "$base$path" | tr -d '\r')"
    status="$(printf '%s\n' "$head" | awk 'NR==1 {print $2}')"
    [ "$status" = 200 ] || { echo "FAIL $path: status $status, want 200"; fail=1; }
    header_is "$path" "$head" Content-Type "$type" prefix
    header_is "$path" "$head" Content-Security-Policy "$expected_csp" exact
    header_is "$path" "$head" X-Content-Type-Options nosniff exact
    header_is "$path" "$head" Referrer-Policy no-referrer exact
    header_is "$path" "$head" X-Frame-Options DENY exact
    if printf '%s\n' "$head" | grep -iq '^cache-control:[[:space:]]*no-store'; then
        echo "FAIL $path: Cache-Control: no-store on a static file"; fail=1
    fi
}
header_is() { # path head name want exact|prefix
    local path="$1" head="$2" name="$3" want="$4" mode="$5" values count
    values="$(printf '%s\n' "$head" | awk -v n="$(printf '%s' "$name" | tr 'A-Z' 'a-z')" \
        'index(tolower($0), n ":") == 1 { sub(/^[^:]*:[ \t]*/, ""); print }')"
    count="$(printf '%s' "$values" | grep -c '^' || true)"
    if [ "$count" != 1 ]; then
        echo "FAIL $path: $name sent $count times, want exactly once"; fail=1; return
    fi
    if [ "$mode" = exact ] && [ "$values" != "$want" ]; then
        echo "FAIL $path: $name is '$values', want '$want'"; fail=1
    elif [ "$mode" = prefix ] && [ "${values#"$want"}" = "$values" ]; then
        echo "FAIL $path: $name is '$values', want '$want...'"; fail=1
    fi
}

echo "== page headers =="
check / "text/html"
check /index.html "text/html"
check "/$worker" "text/javascript"
[ "$fail" = 0 ] || exit 1
echo "page headers ok: /, /index.html, /$worker"

if $smoke; then
    echo "== browser smoke (Chromium) =="
    node scripts/csp-smoke.mjs "$base" "/$worker"
fi
