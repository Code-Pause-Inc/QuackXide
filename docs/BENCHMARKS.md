# Benchmarks

What QuackXide measures, how, and the recorded baselines. ADR 0001 requires
benchmarks to track the cost of the hybrid post-quantum suites; this file
holds the classical `HPK1` baseline that the hybrid suite (#187) is compared
against.

## Running

From `backend/`:

```sh
# Each benchmark once, as a quick check that they run.
cargo bench -p platform-crypto --bench hpke --locked -- --test

# The full run.
cargo bench -p platform-crypto --bench hpke --locked -- --noplot
```

The benchmarks use [criterion](https://docs.rs/criterion) and live in
`backend/crates/platform-crypto/benches/`. `scripts/check.sh` compiles them
(`cargo check` and `clippy` with `--all-targets`) but does not run them.

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
  requests that touch `backend/`, and on demand, and writes the output to
  the job summary. Shared GitHub-hosted runners vary from run to run, so the
  numbers are a reference and never fail a pull request.

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

**Times.** Machine: GitHub-hosted `ubuntu-latest` runner (CPU and
toolchain as the run's job summary records them), run TBD.

| Benchmark | Payload | Time | Throughput |
| --- | --- | --- | --- |
| `hpk1/keygen` | | TBD | |
| `hpk1/seal/32B` | 32 B | TBD | TBD |
| `hpk1/open/32B` | 32 B | TBD | TBD |
| `hpk1/seal/4KiB` | 4 KiB | TBD | TBD |
| `hpk1/open/4KiB` | 4 KiB | TBD | TBD |
| `hpk1/seal/4MiB` | 4 MiB | TBD | TBD |
| `hpk1/open/4MiB` | 4 MiB | TBD | TBD |

## Targets and regression threshold

**Proposed, needs @AxolDad.**

* No absolute targets until the hybrid numbers exist (#187), since the
  hybrid cost is what the targets are for.
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
