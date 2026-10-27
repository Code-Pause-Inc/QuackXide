#!/usr/bin/env bash
# =============================================================================
# build-wasm.sh — build the browser envelope module (backend/crates/envelope-wasm)
# into frontend/src/lib/crypto/wasm/, which is git-ignored. The frontend's
# typecheck, tests and build need it, so check.sh and CI run this first.
#
# Needs the wasm32-unknown-unknown target (rust-toolchain.toml installs it)
# and the wasm-bindgen CLI at exactly the version Cargo.lock pins:
#   cargo install --locked wasm-bindgen-cli --version <version>
# =============================================================================
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/frontend/src/lib/crypto/wasm"
CARGO_DIR="${CARGO_HOME:-$HOME/.cargo}"

want="$(grep -A1 '^name = "wasm-bindgen"$' "$ROOT/backend/Cargo.lock" | sed -n 's/^version = "\(.*\)"$/\1/p')"
if [ -z "$want" ]; then
    echo "FAIL: wasm-bindgen is not in backend/Cargo.lock"
    exit 1
fi
if ! command -v wasm-bindgen >/dev/null 2>&1; then
    echo "FAIL: wasm-bindgen CLI not found; run: cargo install --locked wasm-bindgen-cli --version $want"
    exit 1
fi
have="$(wasm-bindgen --version | awk '{print $2}')"
if [ "$have" != "$want" ]; then
    echo "FAIL: wasm-bindgen CLI is $have but Cargo.lock pins $want; run: cargo install --locked wasm-bindgen-cli --version $want"
    exit 1
fi

if command -v rustup >/dev/null 2>&1 \
    && ! (cd "$ROOT" && rustup target list --installed) | grep -qx wasm32-unknown-unknown; then
    echo "FAIL: the wasm32-unknown-unknown target is missing; run: rustup target add wasm32-unknown-unknown"
    exit 1
fi

# No debug info, and source paths remapped, so no local path (and so no
# repository name) reaches the shipped bundle.
RUSTFLAGS="--remap-path-prefix=$ROOT=. --remap-path-prefix=$CARGO_DIR=/cargo" \
    cargo build --manifest-path "$ROOT/backend/Cargo.toml" --locked \
    -p envelope-wasm --target wasm32-unknown-unknown --profile wasm

rm -rf "$OUT"
wasm-bindgen --target web --out-dir "$OUT" --out-name envelope \
    "$ROOT/backend/target/wasm32-unknown-unknown/wasm/envelope_wasm.wasm"
