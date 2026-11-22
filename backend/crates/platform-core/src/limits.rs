//! Per-query resource limits: how long a query may wait for and hold
//! plaintext, how much it may decrypt, decode and return, and how much
//! memory its operators may use. `platform-config` reads them from the
//! environment (`QUERY_*`, and `DATASET_MAX_MIB` for the input), bounds
//! each one and refuses to start on an invalid value.

use std::fmt;
use std::time::Duration;

const MIB: u64 = 1024 * 1024;

/// Limits on one confidential query. Every limit is finite: there is no
/// value that turns one off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryLimits {
    /// Longest a query waits for a plaintext slot ([`QueryLimit::SlotWait`]).
    /// Zero takes a slot only if one is free at once.
    pub slot_wait: Duration,
    /// Longest a query holds plaintext, from taking its slot through
    /// decryption, decoding, execution and serializing the result
    /// ([`QueryLimit::Time`]).
    pub timeout: Duration,
    /// Memory pool for one query's operators: sorts, aggregations and the
    /// like ([`QueryLimit::Memory`]). Nothing spills to disk, so an operator
    /// that needs more fails the query.
    pub memory_bytes: u64,
    /// Most ciphertext bytes of a snapshot's objects that one query
    /// decrypts ([`QueryLimit::InputBytes`]).
    pub max_input_bytes: u64,
    /// Most objects of a snapshot that one query decrypts
    /// ([`QueryLimit::InputObjects`]).
    pub max_input_objects: u64,
    /// Most rows a query decodes, as the Parquet footers report them,
    /// summed over the snapshot's objects and the query's table scans
    /// ([`QueryLimit::DecodedRows`]).
    pub max_decoded_rows: u64,
    /// Most uncompressed bytes the Parquet footers may report for the
    /// columns a query reads, summed over the snapshot's objects and the
    /// query's table scans, and most Arrow memory those scans' decoded
    /// batches may hold ([`QueryLimit::DecodedBytes`]).
    pub max_decoded_bytes: u64,
    /// Most rows a result returns, after disclosure control
    /// ([`QueryLimit::ResultRows`]).
    pub max_result_rows: u64,
    /// Most bytes of JSON a result's rows serialize to
    /// ([`QueryLimit::ResultBytes`]).
    pub max_result_bytes: u64,
}

impl Default for QueryLimits {
    /// Placeholders until the query benchmarks measure them, as
    /// `DATASET_MAX_MIB`'s default is. The input default is that key's
    /// default.
    fn default() -> Self {
        Self {
            slot_wait: Duration::from_secs(10),
            timeout: Duration::from_secs(60),
            memory_bytes: 256 * MIB,
            max_input_bytes: 64 * MIB,
            max_input_objects: 64,
            max_decoded_rows: 10_000_000,
            max_decoded_bytes: 1024 * MIB,
            max_result_rows: 10_000,
            max_result_bytes: 4 * MIB,
        }
    }
}

impl QueryLimits {
    /// The most memory one query can hold at once under these limits: its
    /// operators' pool, the columns it decodes (up to this limit, plus the
    /// list columns of the batch that crosses it), three copies of its
    /// input (the ciphertext, the plaintext the query service keeps, and
    /// the engine's copy for the decoder) and two of its result (the JSON
    /// and the rows parsed from it). Only the pool is enforced as memory;
    /// the size limits bound the rest. `platform-config` refuses to start
    /// when this, times the concurrent queries, exceeds
    /// `QUERY_TOTAL_MEMORY_MIB`.
    pub fn worst_case_bytes(&self) -> u64 {
        self.memory_bytes
            .saturating_add(self.max_decoded_bytes)
            .saturating_add(self.max_input_bytes.saturating_mul(3))
            .saturating_add(self.max_result_bytes.saturating_mul(2))
    }
}

/// The limit a query exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryLimit {
    SlotWait,
    Time,
    InputBytes,
    InputObjects,
    DecodedRows,
    DecodedBytes,
    Memory,
    ResultRows,
    ResultBytes,
}

impl QueryLimit {
    /// Stable name for audit records and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            QueryLimit::SlotWait => "slot_wait",
            QueryLimit::Time => "time",
            QueryLimit::InputBytes => "input_bytes",
            QueryLimit::InputObjects => "input_objects",
            QueryLimit::DecodedRows => "decoded_rows",
            QueryLimit::DecodedBytes => "decoded_bytes",
            QueryLimit::Memory => "memory",
            QueryLimit::ResultRows => "result_rows",
            QueryLimit::ResultBytes => "result_bytes",
        }
    }
}

impl fmt::Display for QueryLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_worst_case_counts_every_copy_a_query_holds() {
        // The pool, the decoded table, three copies of the input and two of
        // the result: 256 + 1024 + 3 × 64 + 2 × 4 MiB.
        assert_eq!(QueryLimits::default().worst_case_bytes(), 1480 * MIB);
        let unbounded = QueryLimits {
            max_decoded_bytes: u64::MAX,
            ..QueryLimits::default()
        };
        assert_eq!(unbounded.worst_case_bytes(), u64::MAX);
    }
}
