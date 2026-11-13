//! Cost of the `HPK1` tenant envelope: key generation, seal and open.
//! Method, recorded numbers and how to compare a change: `docs/BENCHMARKS.md`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use platform_crypto::{EnvelopeSuite, TenantKeypair, hpke_seal_to_tenant, info};

/// Wrapped key, sealed query or result, large object (a connector snapshot).
const PAYLOADS: [(&str, usize); 3] = [("32B", 32), ("4KiB", 4 * 1024), ("4MiB", 4 * 1024 * 1024)];

fn hpk1(c: &mut Criterion) {
    let mut group = c.benchmark_group("hpk1");
    group.bench_function("keygen", |b| b.iter(TenantKeypair::generate));

    let keypair = TenantKeypair::generate();
    let recipient = keypair.public_key();
    let info = info::research_result("bench-tenant", "bench-query");

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
        // These IDs are the HPK1 baseline; fail rather than time another suite under them.
        assert_eq!(
            EnvelopeSuite::of_envelope(&envelope).expect("suite"),
            EnvelopeSuite::Hpk1
        );
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

criterion_group!(benches, hpk1);
criterion_main!(benches);
