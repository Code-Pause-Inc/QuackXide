//! Cost of the tenant envelope suites, `HPK1` (X25519) and `HPK2` (X-Wing):
//! key generation, seal and open. Both run in one invocation so their
//! numbers compare. Method and recorded numbers: `docs/BENCHMARKS.md`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use platform_crypto::{EnvelopeSuite, TenantKeypair, hpke_seal_to_tenant, info};

/// Wrapped key, sealed query or result, large object (a connector snapshot).
const PAYLOADS: [(&str, usize); 3] = [("32B", 32), ("4KiB", 4 * 1024), ("4MiB", 4 * 1024 * 1024)];

const SUITES: [(EnvelopeSuite, &str); 2] =
    [(EnvelopeSuite::Hpk1, "hpk1"), (EnvelopeSuite::Hpk2, "hpk2")];

fn suites(c: &mut Criterion) {
    for (suite, name) in SUITES {
        let mut group = c.benchmark_group(name);
        group.bench_function("keygen", |b| b.iter(|| TenantKeypair::generate(suite)));

        let keypair = TenantKeypair::generate(suite);
        let recipient = keypair.public_key();
        let info = info::research_result(suite, "bench-tenant", "bench-query");

        for (label, len) in PAYLOADS {
            let plaintext = vec![0xA5u8; len];
            group.throughput(Throughput::Bytes(len as u64));
            group.bench_with_input(
                BenchmarkId::new("seal", label),
                &plaintext,
                |b, plaintext| {
                    b.iter(|| {
                        hpke_seal_to_tenant(&recipient, black_box(&info), black_box(plaintext))
                            .expect("seal")
                    })
                },
            );

            let envelope = hpke_seal_to_tenant(&recipient, &info, &plaintext).expect("seal");
            // Each group's IDs name its suite; fail rather than time another one.
            assert_eq!(EnvelopeSuite::of_envelope(&envelope).expect("suite"), suite);
            group.bench_with_input(BenchmarkId::new("open", label), &envelope, |b, envelope| {
                b.iter(|| {
                    keypair
                        .open_envelope(black_box(&info), black_box(envelope))
                        .expect("open")
                })
            });
        }
        group.finish();
    }
}

criterion_group!(benches, suites);
criterion_main!(benches);
