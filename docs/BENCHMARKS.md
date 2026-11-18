# Benchmarks

What QuackXide measures, how, and the recorded baselines. ADR 0001 requires
benchmarks to track the cost of the hybrid post-quantum suites; this file
holds the classical `HPK1` baselines that the hybrid suite (#187) is
compared against: the native envelope code, and its wasm build sealing in
the browser ("Browser envelope seal" below).

## Running

From `backend/`:

```sh
# Each benchmark once, as a quick check that they run.
cargo bench -p platform-crypto --bench hpke --locked -- --test

# The full run.
cargo bench -p platform-crypto --bench hpke --locked -- --noplot
```

The benchmarks use [criterion](https://docs.rs/criterion) and live in
`backend/crates/platform-crypto/benches/`. The bench target sets
`test = true`, so `cargo test` in `scripts/check.sh` runs each benchmark
once, untimed: a failed seal or open, or the suite check, fails it.

## Method

* criterion's defaults: a warm-up, then 100 samples per benchmark. Times are
  the lower bound, estimate and upper bound of criterion's confidence
  interval for the time per operation.
* Built with the `bench` profile (optimised, as release builds are).
* `hpk1/keygen` times `TenantKeypair::generate`. `hpk1/seal/<size>` and
  `hpk1/open/<size>` time one `HPK1` envelope seal or open at three payload
  sizes: 32 B (a wrapped key), 4 KiB (a sealed query or result) and 4 MiB
  (a large object, such as a connector snapshot). Keys and the envelope to
  open are built outside the timed loop; open includes wiping the plaintext
  it returns. Every timed seal and open must succeed, and the `hpk1` IDs
  refuse to run on any other suite.
* The `bench` workflow (`.github/workflows/bench.yml`) runs these on pull
  requests that touch `backend/` or `rust-toolchain.toml`, and on demand,
  and writes the output to the job summary. Shared GitHub-hosted runners
  vary from run to run, so the numbers are a reference and never fail a
  pull request. On pushes to `main` it only builds them, to save the build
  cache that pull requests restore. Only that run saves a cache, so no
  saved cache holds benchmark results.

## Comparing a change

Compare on one machine, in one session, never against numbers from another
machine (including the table below):

```sh
# On main
cargo bench -p platform-crypto --bench hpke --locked -- --noplot --save-baseline main
# On the branch
cargo bench -p platform-crypto --bench hpke --locked -- --noplot --baseline-lenient main
```

criterion prints the change for each benchmark that exists on both sides and
whether it is significant. `--baseline` instead of `--baseline-lenient`
fails if the branch adds a benchmark.

This shows whether a change moved existing numbers. A new suite's cost
against `HPK1` is read side by side from one run: the hybrid suite (#187)
adds its own group next to `hpk1`, and both run together.

## `HPK1` baseline

Suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.

**Envelope size.** Each envelope is the plaintext plus 52 bytes: the 4-byte
`HPK1` magic, the 32-byte encapsulated X25519 key and the 16-byte AES-GCM
tag. The unit test `hpk1_envelope_overhead_is_52_bytes` in
`platform-crypto` pins it.

**Times.** Criterion's estimate from
[run 43373874498](https://github.com/Code-Pause-Inc/QuackXide/actions/runs/43373874498)
on a GitHub-hosted `ubuntu-latest` runner: AMD EPYC 9V45, 4 CPUs,
`rustc 1.94.1`, hpke 0.12.0, aes-gcm 0.10.3, x25519-dalek 2.0.1 and
curve25519-dalek 4.1.3. Crate upgrades move these numbers, so the workflow
prints these versions with the machine.

| Benchmark | Payload | Time | Throughput |
| --- | --- | --- | --- |
| `hpk1/keygen` | | 22.0 µs | |
| `hpk1/seal/32B` | 32 B | 80.2 µs | 390 KiB/s |
| `hpk1/open/32B` | 32 B | 55.9 µs | 559 KiB/s |
| `hpk1/seal/4KiB` | 4 KiB | 82.6 µs | 47.3 MiB/s |
| `hpk1/open/4KiB` | 4 KiB | 59.7 µs | 65.4 MiB/s |
| `hpk1/seal/4MiB` | 4 MiB | 5.70 ms | 702 MiB/s |
| `hpk1/open/4MiB` | 4 MiB | 3.43 ms | 1.14 GiB/s |

## Targets and regression threshold

**Proposed, needs @AxolDad.**

* No absolute targets until the hybrid numbers exist (#187), since the
  hybrid cost is what the targets are for.
* A regression check that benchmarks the base and head commits in the same
  job, on the same runner, and flags a benchmark only when criterion reports
  a significant change of more than 10 %. Comparing against the numbers
  recorded above would flag runner noise, which often exceeds 10 % between
  runs.

## Browser envelope seal

The steward's browser seals each uploaded dataset with the wasm build of the
same envelope code (`backend/crates/envelope-wasm`, behind
`frontend/src/lib/crypto/envelope.ts`). The seal is single-shot: the
plaintext, the ciphertext and the framed envelope are all in memory at once.

### Running

From the repository root, with what `scripts/build-wasm.sh` needs, the
frontend's dependencies and Playwright's Chromium
(`npx playwright install chromium` in `frontend/`):

```sh
scripts/bench-wasm-seal.sh > report.md
```

It builds the module and the frontend, writes synthetic Parquet with
`synth-data` (`wide` schema, seed 1) into `frontend/bench-data/`
(git-ignored), runs `frontend/src/lib/crypto/seal.browser.bench.ts` in
headless Chromium (`npm run bench:browser`, the vitest `bench` project) and
prints a Markdown report. The largest payload holds about five times its
size in memory; `LARGE_ROWS=553000` swaps it for a second 100 MiB run on a
machine with less than 8 GiB free.

The `wasm-seal` job of the `bench` workflow runs the same script on pull
requests that touch the module, the script or the backend, and on demand,
and writes the report to the job summary. Like the native benchmarks it
reports only and never fails on the numbers; it fails only if a seal fails
or an envelope is not 52 bytes longer than its plaintext.

### Method

* Each measurement runs in a fresh dedicated module worker
  (`frontend/src/lib/crypto/sealBench.worker.ts`), so each starts from a new
  module instance. That worker runs `envelope.ts` as the crypto worker does,
  without its keys, vault or protocol, and seals to a throwaway key under a
  `steward-upload-v1` `info` string.
* **Seal time** is `sealToTenant` from call to resolved promise: copying the
  plaintext into wasm memory, the seal, framing, and copying the envelope
  out. The payload is fetched before timing starts. 30 seals at 1 MiB, 5 at
  100 MiB and 3 at 1 GiB; the median and the fastest are reported.
* **Module peak** is the module's linear memory after the first seal. Linear
  memory only grows, so this is the module's high-water mark. The page also
  holds the plaintext and the returned envelope in JavaScript, so the tab
  needs about two payloads more than the module peak.
* **Load** is `loadEnvelopeModule()` in a fresh worker: fetch from the local
  test server, compile and instantiate, ten times. It excludes network
  transfer; the bundle sizes below give that.
* **Bundle size** is the module and the crypto worker chunk in
  `frontend/dist/assets/` from `npm run build`, raw and compressed.

### `HPK1` baseline

A documented manual run, on a 13th Gen Intel Core i7-1355U laptop (12
threads, 15 GiB, Linux under WSL2), Chromium 158.0.8127.18 (Playwright's
headless shell), Node 22.22.2, wasm-bindgen 0.2.126, hpke 0.12.0, aes-gcm
0.10.3, x25519-dalek 2.0.1 and curve25519-dalek 4.1.3.

| Bundle file | Size | gzip -9 | brotli -11 |
| --- | --- | --- | --- |
| `envelope_bg-*.wasm` | 95.5 KiB | 38.7 KiB | 31.8 KiB |
| `worker-*.js` (the crypto worker, with the module's glue) | 19.7 KiB | 6.7 KiB | 6.0 KiB |

Module load in a fresh worker: 4.2 ms for the first, a median of 3.1 ms for
the next nine. Linear memory after load: 1.1 MiB.

| Payload | Rows | Seals | Median | Fastest | Throughput | Module peak | Peak / payload |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1.0 MiB (1,049,471 B) | 4,900 | 30 | 23.2 ms | 22.4 ms | 43 MiB/s | 4.3 MiB | 4.31 |
| 99.5 MiB (104,321,566 B) | 553,000 | 5 | 1.99 s | 1.80 s | 50 MiB/s | 299.6 MiB | 3.01 |
| 1001.7 MiB (1,050,338,422 B) | 5,670,000 | 3 | 19.8 s | 19.6 s | 51 MiB/s | 3006.2 MiB | 3.00 |

Wasm has no AES instructions, so the seal runs at about 50 MiB/s, against
702 MiB/s natively at 4 MiB on a CI runner (above).

### What this bounds

* **The largest payload one seal can take.** The module's peak is three
  times the payload (the plaintext copy, the ciphertext and the framed
  envelope), and wasm32 linear memory stops at 4 GiB, so one seal takes at
  most about 1.33 GiB. In the run above, a 1.22 GiB payload
  (1,311,107,298 B, 7,090,000 rows) sealed with a 3.66 GiB module peak, and
  a 1.37 GiB payload (1,469,019,442 B, 7,940,000 rows) failed with
  `RuntimeError: unreachable`. The tab holds about five times the payload.
* **ADR 0012.** `DATASET_MAX_MIB` (default 64, at most 512) is inside that
  ceiling, so one object per upload needs no per-object cap for the seal's
  sake. At 512 MiB a seal takes about 10 s and the tab about 2.5 GiB; at the
  default 64 MiB, about 1.3 s and 320 MiB. P40 confirms or lowers the range
  on the whole upload path and on lower-memory devices.
* **A failed seal.** An allocation failure aborts the module
  (`panic = "abort"`), and the instance must not be used again. P40 refuses
  a file over the dataset limit before sealing it.

### Targets

**Proposed, needs @AxolDad.** On the machine above, in Chromium:

* a 100 MiB payload seals in under 3 s (now 1.99 s);
* the module's peak stays at most 3.1 times the payload at 100 MiB and above;
* the module stays under 64 KiB brotli-compressed (now 31.8 KiB), with room
  for the hybrid suite (#187).

The regression threshold is the one proposed above. Since these runs are
not criterion runs, base and head are compared by running the script on
each, on one machine, in one session.

## Still to come (#185)

* Query latency in `quackxide-engine` at stated dataset sizes and object
  counts, on data from `synth-data`.
* Browser chunk encryption (`encryptPayload` in
  `frontend/src/lib/crypto/core.ts`) as a Vitest bench.
* The regression check above, on a schedule as well as on pull requests.
