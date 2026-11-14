//! Research-style query latency in `QueryScope`: register the decrypted
//! Parquet, plan, execute and apply the disclosure gate, as a research query
//! pays for it. Data comes from `synth-data`'s `wide` table. Method and
//! recorded numbers: `docs/BENCHMARKS.md`.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use platform_core::ZkMode;
use quackxide_engine::{EngineSettings, MinCountThreshold, QueryScope};
use synth_data::{SchemaName, Spec};

const QUERIES: [(&str, &str); 2] = [
    (
        "count",
        "SELECT region, COUNT(*) AS n FROM t GROUP BY region",
    ),
    (
        "filter",
        "SELECT bucket, COUNT(*) AS n FROM t WHERE flag GROUP BY bucket",
    ),
];

/// Seed 1, `rows` rows, in `objects` equal Parquet objects (seeds 1..=objects).
fn dataset(rows: usize, objects: usize) -> Vec<Vec<u8>> {
    (1..=objects as u64)
        .map(|seed| {
            synth_data::parquet_bytes(&Spec::new(SchemaName::Wide, seed, rows / objects))
                .expect("wide table")
        })
        .collect()
}

fn engine(c: &mut Criterion) {
    // Multi-thread, default worker count: as platform-api runs DataFusion.
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let datasets = [
        ("10000", dataset(10_000, 1)),
        ("100000", dataset(100_000, 1)),
        ("1000000", dataset(1_000_000, 1)),
        ("1000000x8", dataset(1_000_000, 8)),
    ];

    let mut group = c.benchmark_group("engine");
    // The 1 M-row cases take ~0.1 s each; 40 samples fit in 11 s (criterion's
    // own estimate), where the default 100 in 5 s cannot.
    group
        .sample_size(40)
        .measurement_time(Duration::from_secs(11));
    for (query_name, query) in QUERIES {
        for (label, blobs) in &datasets {
            let blobs: Vec<&[u8]> = blobs.iter().map(Vec::as_slice).collect();
            group.bench_with_input(BenchmarkId::new(query_name, label), &blobs, |b, blobs| {
                b.iter(|| {
                    let mut scope = QueryScope::new(EngineSettings {
                        zk: ZkMode::Disabled,
                        max_concurrent_queries: 1,
                    });
                    scope
                        .register_parquet_many("t", black_box(blobs))
                        .expect("register");
                    scope.set_disclosure(Arc::new(MinCountThreshold { k: 5 }));
                    runtime
                        .block_on(scope.sql(black_box(query)))
                        .expect("query")
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, engine);
criterion_main!(benches);
