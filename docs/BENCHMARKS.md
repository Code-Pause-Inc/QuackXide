# Benchmarks

What QuackXide measures, how, and the recorded numbers. ADR 0001 requires
benchmarks to track the cost of the hybrid post-quantum suites; this file
holds the hybrid `HPK2` suite's numbers next to the classical `HPK1`
baseline, both from one run.

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
* One group per suite, `hpk1` and `hpk2`. `<suite>/keygen` times
  `TenantKeypair::generate`. `<suite>/seal/<size>` and `<suite>/open/<size>`
  time one envelope seal or open at three payload sizes: 32 B (a wrapped
  key), 4 KiB (a sealed query or result) and 4 MiB (a large object, such as
  a connector snapshot). Keys and the envelope to open are built outside the
  timed loop; open includes wiping the plaintext it returns. Every timed
  seal and open must succeed, and each group refuses to run on any suite
  but its own.
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

This shows whether a change moved existing numbers. One suite's cost
against another is read side by side from one run, where both groups run
together; never compare tables from different runs.

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

## Browser timings

`npm run bench:browser` (from `frontend/`) times chunk encryption and the
wasm envelope module's cold start in real browsers; `docs/TESTING.md`
describes the method. Each sample is a batch of calls lasting at least
50 ms, so p50 and p99 are over batch means, not single calls. The cold start
(the module's load plus its first seal) is one sample per page. The timings
run on the page's main thread; the app does this work in the crypto worker.

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

The wasm envelope module is 97 838 bytes, 39 200 gzipped.

* Chromium's 4 MiB p99 is 2.7× its p50, so that run was noisy; take another
  run before setting a target from it.
* Firefox and WebKit report `performance.now()` to 1 ms, so their cold
  starts carry about ±1 ms, and each is a single sample.
* Like the backend numbers, these vary from run to run and are a reference,
  not a gate.

## Steward upload in the browser

The browser side of a steward upload (ADR 0014), timed end to end at the
upload limit (`DATASET_MAX_MIB`, 64 by default). It is a recorded manual
run: the upload needs a running API, which the browser test job does not
start, so it is repeated by hand for each release candidate. The seal,
most of its cost, joins the regression run through the wasm seal benchmark
(#171's checkpoint A, #255).

**Method.** `synth-data --schema wide --seed 1 --rows 346000` writes the
largest such file whose sealed object fits 64 MiB: 66 968 978 bytes, 23
columns, a 4 905-byte footer. The page runs the app's own code in its dev
server, against a development build of `platform-api` on the same machine
(in-memory vault): the footer worker reads the footer, then the crypto
worker's upload operation checks the enrolled key, reads the file, seals it
and its manifest, and sends the body through the dev server's proxy. Six
uploads of the file in a row, each replacing the last; the first starts a
fresh crypto worker, so it includes the wasm module's cold start. Reading
the file and sealing it are also timed alone, on the page's main thread.

**Results**, 2026-11-21, Apple M4 (10 cores, 16 GiB), Chromium 156.0.8078.75:

| Step | First | Then (median of 5) |
| --- | --- | --- |
| Footer read, in a fresh worker each time | 11 ms | 6 ms |
| Upload: key check, read, seal, manifest, send, stored | 1 455 ms | 606 ms |
| Reading the 63.9 MiB file alone | 7 ms | 7 ms |
| Sealing it alone (`HPK1`) | 1 378 ms | 552 ms |

* The sealed object is 66 969 030 bytes, 52 more than the file. A file of
  350 000 rows (67 691 400 bytes) is refused in 1 ms, before anything is
  read, sealed or sent.
* The seal is about 90 % of the browser's work, about 116 MiB/s here. #255
  measured about 50 MiB/s on an i7-1355U, which puts this file's seal near
  1.3 s there. The key check, the manifest, the body and the loopback send
  took about 50 ms together. Over a real network the send takes what the
  steward's uplink takes, about 5 s at 100 Mbit/s; that is not measured.
* The seal is single-shot, so the file, its envelope and the module's
  copies are in memory at once; #255 measures the module's peak at about
  three times the payload, about 200 MB here.
* Nothing in the browser path argues for lowering `DATASET_MAX_MIB` from
  64.

The footer reader is a worker chunk of its own: 14 914 bytes minified,
4 938 gzipped, of which hyparquet's Thrift decoder is 1 327 bytes (636
gzipped). It adds nothing to the UI or crypto worker chunks (`npm run
build` on the change that added it).

**Target, proposed, needs @AxolDad:** in Chromium on a laptop of the
i7-1355U class or better, the footer read within 100 ms, and the upload
within 3 s once the module is loaded, at `DATASET_MAX_MIB`, network
excluded.

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

**Proposed, needs @AxolDad.**

* No absolute targets yet; the hybrid numbers above are the input for
  them.
* A regression check that benchmarks the base and head commits in the same
  job, on the same runner, and flags a benchmark only when criterion reports
  a significant change of more than 10 %. Comparing against the numbers
  recorded above would flag runner noise, which often exceeds 10 % between
  runs.

## Still to come (#185)

* Query latency in `quackxide-engine` at stated dataset sizes and object
  counts, on data from `synth-data`.
* Targets and a regression run for the browser timings above.
* Wasm seal throughput and peak memory in the crypto worker at large sizes
  (#171's checkpoint A benchmark).
* The regression check above, on a schedule as well as on pull requests.
