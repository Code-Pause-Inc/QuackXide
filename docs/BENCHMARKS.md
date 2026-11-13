# Benchmarks

What QuackXide measures, how, and the recorded numbers. ADR 0001 requires
benchmarks to track the cost of the hybrid post-quantum suites; this file
holds the hybrid `HPK2` suite's numbers next to the classical `HPK1`
baseline, both from one run.

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
`scripts/bench-compare.sh` judges the result (below). The job fails when a
benchmark regressed; it is not a required check. Run the script on your own
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

## Targets and regression threshold

**Regression threshold.** A benchmark regresses when the lower bound of the
95 % confidence interval of its mean change against the base commit is
above +10 %, so the whole interval is a slowdown of more than 10 %.
Comparing against the numbers recorded above instead would flag runner
noise, which often exceeds 10 % between runs.

**Targets**, on a GitHub-hosted `ubuntu-latest` runner, read against the
recorded tables:

* `hpk2/keygen` at most 1 ms.
* `hpk2/seal/4KiB` and `hpk2/open/4KiB` at most 1 ms each.
* `hpk2/seal/4MiB` and `hpk2/open/4MiB` at most 20 ms each.
* The hybrid suite's cost: `hpk2` at most 4× `hpk1` for key generation and
  for seal and open from 32 B to 4 KiB, and at most 1.25× at 4 MiB, in the
  same run.
* Engine queries, `count` and `filter` alike: at most 4 ms at 10 000 rows,
  25 ms at 100 000 rows, and 350 ms at 1 000 000 rows in one or eight
  objects (about 1.5× the recorded times, rounded up).

## Still to come (#185)

* Targets and a regression run for the browser timings above.
* Wasm seal throughput and peak memory in the crypto worker at large sizes
  (#171's checkpoint A benchmark).
