# Benchmarks

What QuackXide measures, how, and the recorded numbers. ADR 0001 requires
benchmarks to track the cost of the hybrid post-quantum suites; this file
holds the hybrid `HPK2` suite's numbers next to the classical `HPK1`
baseline, both from one run, and the `HPK1` wasm build sealing in the
browser ("Browser envelope seal" below).

## Running

From `backend/`:

```sh
# Each benchmark once, as a quick check that they run.
cargo bench -p platform-crypto -p quackxide-engine --bench hpke --bench query --locked -- --test

# The full run.
cargo bench -p platform-crypto -p quackxide-engine --bench hpke --bench query --locked -- --noplot
```

The benchmarks use [criterion](https://docs.rs/criterion) and live in
`backend/crates/platform-crypto/benches/` (envelope suites) and
`backend/crates/quackxide-engine/benches/` (queries). The envelope bench
target sets `test = true`, so `cargo test` in `scripts/check.sh` runs each
envelope benchmark once, untimed: a failed seal or open, or the suite
check, fails it. `quackxide-engine/tests/bench_queries.rs` checks that the
engine benchmarks' queries pass the disclosure gate.

## Method

* criterion's defaults: a warm-up, then 100 samples per benchmark. Times are
  the lower bound, estimate and upper bound of criterion's confidence
  interval for the time per operation.
* Built with the `bench` profile (optimised, as release builds are).
* One group per suite, `hpk1` and `hpk2`. `<suite>/keygen` times
  `TenantKeypair::generate`. `<suite>/seal/<size>` and `<suite>/open/<size>`
  time one envelope seal or open at three payload sizes: 32 B (a wrapped
  key), 4 KiB (a sealed query or result) and 4 MiB (a large object, such as
  a connector snapshot). Keys and the envelope to open are built outside the
  timed loop; open includes wiping the plaintext it returns. Every timed
  seal and open must succeed, and each group refuses to run on any suite
  but its own.
* `engine/<query>/<rows>` times one research-style query in `QueryScope`:
  register the Parquet, plan, execute and apply the disclosure gate
  (`MinCountThreshold { k: 5 }`), on a multi-thread tokio runtime as
  `platform-api` runs it. `count` is
  `SELECT region, COUNT(*) AS n FROM t GROUP BY region`, `filter` is
  `SELECT bucket, COUNT(*) AS n FROM t WHERE flag GROUP BY bucket`, over
  `synth-data`'s `wide` table at 10 000, 100 000 and 1 000 000 rows, and
  1 000 000 rows in 8 objects (`1000000x8`). The data is generated before
  timing. These use 40 samples in 11 s, since a 1 M-row query takes about
  0.1 s.
* The `bench` workflow (`.github/workflows/bench.yml`) runs these on pull
  requests that touch `backend/` or `rust-toolchain.toml`, and on demand,
  and writes the output to the job summary. Shared GitHub-hosted runners
  vary from run to run, so a single run's numbers are a reference; the
  regression check below compares the base and the head on one runner. On
  pushes to `main` it only builds them, to save the build cache that pull
  requests restore. Only that run saves a cache, so no saved cache holds
  benchmark results.

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

This shows whether a change moved existing numbers. One suite's cost
against another is read side by side from one run, where both groups run
together; never compare tables from different runs.

On a pull request, the `bench` workflow does this itself: it benchmarks the
base commit with `--save-baseline base`, then the head with
`--baseline-lenient base`, on the same runner, and
`scripts/bench-compare.sh` judges the result (below). A regression beyond
the threshold is flagged as a warning in the job summary; the job fails
only when the comparison itself cannot run (nothing compared, unreadable
estimates). It is not a required check. Run the script on your own
comparison with `scripts/bench-compare.sh backend/target/criterion` (needs
`jq`), starting from an empty `backend/target/criterion`: it judges every
earlier comparison it finds there.

## Suites

| Suite | Construction | Public key | Envelope overhead |
| --- | --- | --- | --- |
| `HPK1` | DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM | 32 B | 52 B: 4-byte magic, 32-byte encapsulated key, 16-byte tag |
| `HPK2` | X-Wing (ADR 0007), HKDF-SHA256, AES-256-GCM | 1216 B | 1140 B: 4-byte magic, 1120-byte encapsulated key, 16-byte tag |

The unit test `envelope_overhead_per_suite` in `platform-crypto` pins both
overheads.

## Times

Criterion's estimate, both suites from one run:
[run 44014510055](https://github.com/Code-Pause-Inc/QuackXide/actions/runs/44014510055)
of #228, with the server's X25519 basepoint table (`precomputed-tables`), on
a GitHub-hosted `ubuntu-latest` runner: AMD EPYC
7763, 4 CPUs, `rustc 1.94.1`, hpke 0.14.1, x-wing 0.1.1, ml-kem 0.3.4,
x25519-dalek 3.0.0, curve25519-dalek 5.0.0 and aes-gcm 0.11.1 (hpke's;
0.10.3 is `aead_seal`'s). Crate upgrades move these numbers, so the
workflow prints these versions with the machine. The numbers hold until
the benchmarked code changes; later runs of the same code differ only by
runner noise.

| Benchmark | Payload | `HPK1` time | `HPK2` time | `HPK1` throughput | `HPK2` throughput |
| --- | --- | --- | --- | --- | --- |
| `keygen` | | 18.3 µs | 105.9 µs | | |
| `seal/32B` | 32 B | 98.0 µs | 175.5 µs | 319 KiB/s | 178 KiB/s |
| `open/32B` | 32 B | 79.5 µs | 294.4 µs | 393 KiB/s | 106 KiB/s |
| `seal/4KiB` | 4 KiB | 99.9 µs | 177.4 µs | 39.1 MiB/s | 22.0 MiB/s |
| `open/4KiB` | 4 KiB | 82.1 µs | 296.6 µs | 47.6 MiB/s | 13.2 MiB/s |
| `seal/4MiB` | 4 MiB | 5.63 ms | 5.72 ms | 711 MiB/s | 699 MiB/s |
| `open/4MiB` | 4 MiB | 2.64 ms | 2.86 ms | 1.48 GiB/s | 1.37 GiB/s |

## Engine query times

Criterion's estimate from
[run 43414070024](https://github.com/Code-Pause-Inc/QuackXide/actions/runs/43414070024)
of #233, on a GitHub-hosted `ubuntu-latest` runner: AMD EPYC 7763, 4 CPUs,
`rustc 1.94.1`.

| Benchmark | Rows | Objects | `count` | `filter` |
| --- | --- | --- | --- | --- |
| `engine/<query>/10000` | 10 000 | 1 | 2.21 ms | 2.29 ms |
| `engine/<query>/100000` | 100 000 | 1 | 16.6 ms | 16.5 ms |
| `engine/<query>/1000000` | 1 000 000 | 1 | 204 ms | 198 ms |
| `engine/<query>/1000000x8` | 1 000 000 | 8 | 215 ms | 171 ms |

## Browser timings

`npm run bench:browser` (from `frontend/`) times chunk encryption and the
wasm envelope module's cold start in real browsers; `docs/TESTING.md`
describes the method. Each sample is a batch of calls lasting at least
50 ms, so p50 and p99 are over batch means, not single calls. The cold start
(the module's load plus its first seal) is one sample per page. The timings
run on the page's main thread; the app does this work in the crypto worker.

The wasm cold start was measured on the module before the attestation
verifier was linked.

From [run 44010807289](https://github.com/Code-Pause-Inc/QuackXide/actions/runs/44010807289)
of #232, started by hand, on GitHub-hosted `ubuntu-latest` runners (Ubuntu
26.04, 4 CPUs). Each browser ran as its own job on a different CPU, so read
each column on its own rather than across:

| | Chromium 158.0.8127.18 | Firefox 159.0 | WebKit 27.2 |
| --- | --- | --- | --- |
| CPU | AMD EPYC 9V45 | Intel Xeon 6975P-C | Intel Xeon 6973P-C |
| `encryptPayload` 4 KiB, p50 / p99 | 6.65 / 8.31 µs | 37.8 / 58.3 µs | 35.2 / 53.4 µs |
| `encryptPayload` 4 MiB, p50 / p99 | 4.58 / 12.3 ms | 5.56 / 6.28 ms | 1.19 / 1.58 ms |
| Wasm cold start (load + first seal) | 6.6 ms | 7 ms | 11 ms |

Not yet measured with the attestation verifier linked; the browser job
prints `wasm envelope module: N bytes, M gzipped`.

* Chromium's 4 MiB p99 is 2.7× its p50, so that run was noisy; take another
  run before setting a target from it.
* Firefox and WebKit report `performance.now()` to 1 ms, so their cold
  starts carry about ±1 ms, and each is a single sample.
* Like the backend numbers, these vary from run to run and are a reference,
  not a gate.

## Steward upload in the browser

The browser side of a steward upload (ADR 0014), timed end to end at the
upload limit (`DATASET_MAX_MIB`, 64 by default). It is a manual run, for
each release candidate: the upload needs a running API, which the browser
test job does not start. Its times depend on the machine it runs on, so
none are recorded here. The seal, most of its cost, is tracked on CI by the
browser envelope seal benchmark below.

**Method.** `synth-data --schema wide --seed 1 --rows 346000` writes the
largest such file whose sealed object fits 64 MiB: 66 968 978 bytes, 23
columns, a 4 905-byte footer. The page runs the app's own code in its dev
server, against a development build of `platform-api` on the same machine
(in-memory vault): the footer worker reads the footer, then the crypto
worker's upload operation checks the enrolled key, reads the file, seals it
and its manifest, and sends the body through the dev server's proxy. Six
uploads of the file in a row, each replacing the last; the first starts a
fresh crypto worker, so it includes the wasm module's cold start. The body
crosses loopback, so the steward's uplink, which a real upload waits on, is
not part of the measure.

Whatever the machine, the sealed object is 66 969 030 bytes, 52 more than
the file, and a file of 350 000 rows (67 691 400 bytes) is refused before
anything is read, sealed or sent.

The footer reader is a worker chunk of its own: 15 620 bytes minified,
5 147 gzipped, of which hyparquet's Thrift decoder is 1 327 bytes (636
gzipped). It adds nothing to the UI or crypto worker chunks (`npm run
build`).

**Target, proposed, needs @AxolDad:** on the machine the browser envelope
seal's targets are read on, in Chromium, the footer read within 100 ms and
the upload within 3 s once the module is loaded, at `DATASET_MAX_MIB`,
network excluded. The seal target, 100 MiB in under 3 s, covers most of it.

**To repeat it**, from `backend/`, write the file, then start the API:

```sh
cargo run -p synth-data -- --schema wide --seed 1 --rows 346000 --out ../frontend/node_modules/.cache/upload-bench.parquet
APP_ENV=development cargo run -p platform-api
```

From `frontend/` in a second terminal, start the dev server with a
development token:

```sh
VITE_VAULT_MODE=http VITE_DEV_JWT="$(cd ../backend && APP_ENV=development cargo run -q -p platform-api --features dev --bin devtoken 2>/dev/null)" npm run dev
```

Open `http://localhost:5173` (the Drive tab enrolls the browser's key),
switch to the Research tab, and run this in the browser console:

```js
const { readFooterInWorker } = await import("/src/lib/datasets/footerClient.ts");
const { DriveWorkerClient } = await import("/src/lib/crypto/workerClient.ts");
const token = document.querySelector('input[type="password"]').value;
const blob = await (await fetch("/node_modules/.cache/upload-bench.parquet")).blob();
const file = new File([blob], "bench.parquet");
const client = new DriveWorkerClient();
await client.setSession(token);
let current = null;
for (let i = 0; i < 6; i += 1) {
  const t0 = performance.now();
  const reading = await readFooterInWorker(file);
  const t1 = performance.now();
  const stored = await client.uploadDataset({
    file,
    dataset: "upload_bench",
    schema: reading.schema,
    rowCap: reading.rows,
    currentVersion: current,
    maxBytes: 64 * 1024 * 1024,
  });
  current = stored.version;
  console.log(`footer ${Math.round(t1 - t0)} ms, upload ${Math.round(performance.now() - t1)} ms`);
}
client.terminate();
```

## Targets and regression threshold

Agreed with the maintainer (2026-11-23).

**Regression threshold.** A benchmark regresses when the lower bound of the
95 % confidence interval of its mean change against the base commit is
above +10 %, so the whole interval is a slowdown of more than 10 %. The
`bench` job flags it as a warning in the job summary and does not fail on
it.
Comparing against the numbers recorded above instead would flag runner
noise, which often exceeds 10 % between runs.

**Targets**, on a GitHub-hosted `ubuntu-latest` runner, read against the
recorded tables:

* `hpk2/keygen` at most 1 ms.
* `hpk2/seal/4KiB` and `hpk2/open/4KiB` at most 1 ms each.
* `hpk2/seal/4MiB` and `hpk2/open/4MiB` at most 20 ms each.
* The hybrid suite's cost: `hpk2` at most 4× `hpk1` for seal and open
  from 32 B to 4 KiB, and at most 1.25× at 4 MiB, in the same run. Key
  generation is held to the absolute 1 ms above, not a ratio.
* Engine queries, `count` and `filter` alike: at most 4 ms at 10 000 rows,
  25 ms at 100 000 rows, and 350 ms at 1 000 000 rows in one or eight
  objects (about 1.5× the recorded times, rounded up).

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
(git-ignored), runs `frontend/src/lib/crypto/seal.browser.perf.ts` in
headless Chromium (`npm run bench:seal`, the vitest `seal` project) and
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
711 MiB/s natively at 4 MiB on a CI runner (above).

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

Agreed with the maintainer (2026-11-23). On the machine above, in Chromium:

* a 100 MiB payload seals in under 3 s (now 1.99 s);
* the module's peak stays at most 3.1 times the payload at 100 MiB and above;
* the module stays under 64 KiB brotli-compressed (now 31.8 KiB), with room
  for the hybrid suite (#187).

The regression threshold is the one above. Since these runs are
not criterion runs, base and head are compared by running the script on
each, on one machine, in one session.

## Still to come (#185)

* A regression run for the browser timings above.
