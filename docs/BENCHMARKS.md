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
* Browser chunk encryption (`encryptPayload` in
  `frontend/src/lib/crypto/core.ts`) as a Vitest bench.
* The wasm envelope build's bundle size and load time (#171).
* The regression check above, on a schedule as well as on pull requests.
