//! The research-style queries `benches/query.rs` times must pass the
//! disclosure gate and return rows, so the bench never times a refusal.

use std::sync::Arc;

use platform_core::ZkMode;
use quackxide_engine::{EngineSettings, MinCountThreshold, QueryScope};
use synth_data::{SchemaName, Spec};

const QUERIES: [&str; 2] = [
    "SELECT region, COUNT(*) AS n FROM t GROUP BY region",
    "SELECT bucket, COUNT(*) AS n FROM t WHERE flag GROUP BY bucket",
];

#[tokio::test]
async fn bench_queries_pass_the_disclosure_gate() {
    let parquet = synth_data::parquet_bytes(&Spec::new(SchemaName::Wide, 1, 10_000)).expect("wide");
    for query in QUERIES {
        let mut scope = QueryScope::new(EngineSettings {
            zk: ZkMode::Disabled,
            max_concurrent_queries: 1,
        });
        scope
            .register_parquet_many("t", &[&parquet])
            .expect("register");
        scope.set_disclosure(Arc::new(MinCountThreshold { k: 5 }));
        let batches = scope.sql(query).await.expect(query);
        let rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        assert!(rows > 0, "{query} returned no rows");
    }
}
