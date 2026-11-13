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
`backend/crates/quackxide-engine/benches/` (queries). `scripts/check.sh` compiles them
(`cargo check` and `clippy` with `--all-targets`) but does not run them.

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
* The `bench` workflow (`.github/workflows/bench.yml`) runs on pull requests
  that touch `backend/`, and on demand, and writes the output to the job
  summary.

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
[run 43391725261](https://github.com/Code-Pause-Inc/QuackXide/actions/runs/43391725261)
of #228's HPK2 change, on a GitHub-hosted `ubuntu-latest` runner: AMD EPYC
7763, 4 CPUs, `rustc 1.94.1`. The numbers hold until the benchmarked code
changes; later runs of the same code differ only by runner noise.

| Benchmark | Payload | `HPK1` time | `HPK2` time | `HPK1` throughput | `HPK2` throughput |
| --- | --- | --- | --- | --- | --- |
| `keygen` | | 33.2 µs | 121.3 µs | | |
| `seal/32B` | 32 B | 125.6 µs | 189.7 µs | 249 KiB/s | 165 KiB/s |
| `open/32B` | 32 B | 93.3 µs | 308.3 µs | 335 KiB/s | 101 KiB/s |
| `seal/4KiB` | 4 KiB | 128.2 µs | 191.8 µs | 30.5 MiB/s | 20.4 MiB/s |
| `open/4KiB` | 4 KiB | 95.9 µs | 310.8 µs | 40.7 MiB/s | 12.6 MiB/s |
| `seal/4MiB` | 4 MiB | 5.63 ms | 5.71 ms | 711 MiB/s | 701 MiB/s |
| `open/4MiB` | 4 MiB | 2.65 ms | 2.87 ms | 1.47 GiB/s | 1.36 GiB/s |

## Engine query times

From this PR's CI run: TBD.

| Benchmark | Rows | Objects | `count` | `filter` |
| --- | --- | --- | --- | --- |
| `engine/<query>/10000` | 10 000 | 1 | TBD | TBD |
| `engine/<query>/100000` | 100 000 | 1 | TBD | TBD |
| `engine/<query>/1000000` | 1 000 000 | 1 | TBD | TBD |
| `engine/<query>/1000000x8` | 1 000 000 | 8 | TBD | TBD |

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
* Engine queries: TBD, set from the first recorded run at about 1.5× its
  times.

## Still to come (#185)

* Browser chunk encryption (`encryptPayload` in
  `frontend/src/lib/crypto/core.ts`) as a Vitest bench.
* The wasm envelope build's bundle size and load time (#171).
