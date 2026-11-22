//! The research-style queries timed by `benches/query.rs` and checked by
//! `tests/bench_queries.rs`, so the two cannot drift apart.

pub const QUERIES: [(&str, &str); 2] = [
    (
        "count",
        "SELECT region, COUNT(*) AS n FROM t GROUP BY region",
    ),
    (
        "filter",
        "SELECT bucket, COUNT(*) AS n FROM t WHERE flag GROUP BY bucket",
    ),
];
