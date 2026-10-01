//! Statistical disclosure control for zero-knowledge and research results.
//!
//! Queries in `ZkMode::Enabled` (research always runs in it) pass two gates:
//! the plan-level aggregate-only allowlist (`policy::is_aggregate_only`) and
//! a [`DisclosurePolicy`] applied to the aggregate rows before egress.
//! [`MinCountThreshold`] suppresses every row whose cohort is smaller than
//! `k`, so grouping by a unique key cannot rebuild the dataset row by row.
//!
//! Every such query must include `COUNT(*) AS n`. [`verify_count_column`]
//! checks at the plan level that `n` is a genuine COUNT, so a literal
//! `9999 AS n` cannot defeat suppression. The aggregate-only allowlist
//! guarantees every other aggregate reads exactly the rows `n` counts:
//! nothing can inflate a cohort or isolate an individual in it.
//!
//! Each input row belongs to exactly one released group: the allowlist
//! refuses grouping sets, so no result holds a subtotal beside its parts.
//! Thresholds bound single-query disclosure only; differencing across
//! overlapping queries is limited by the per-grant query budget.

use arrow::array::{Array, BooleanArray, Int64Array, RecordBatch};
use arrow::compute::filter_record_batch;
use datafusion::logical_expr::{Expr, LogicalPlan};

use crate::QueryError;
use crate::policy::{aggregate_call, is_non_null_literal};

/// Result rows after disclosure control, plus what was withheld.
pub struct DisclosureOutcome {
    pub batches: Vec<RecordBatch>,
    pub suppressed_rows: usize,
}

/// A result-egress policy. Implementations may suppress, aggregate further,
/// or perturb; they see only aggregate rows, never raw data.
pub trait DisclosurePolicy: Send + Sync {
    fn apply(&self, batches: Vec<RecordBatch>) -> Result<DisclosureOutcome, QueryError>;
}

/// Built-in threshold suppression: drop every result row with `n < k`.
/// A `k` below 1 is a misconfiguration and refuses every result.
pub struct MinCountThreshold {
    pub k: i64,
}

impl DisclosurePolicy for MinCountThreshold {
    fn apply(&self, batches: Vec<RecordBatch>) -> Result<DisclosureOutcome, QueryError> {
        if self.k < 1 {
            return Err(QueryError::Disclosure(
                "minimum cohort size is not configured".into(),
            ));
        }
        let mut out = Vec::with_capacity(batches.len());
        let mut suppressed = 0usize;
        for batch in batches {
            let Some((index, _)) = batch.schema().column_with_name("n") else {
                return Err(QueryError::Disclosure(
                    "results must include COUNT(*) AS n".into(),
                ));
            };
            let counts = batch
                .column(index)
                .as_any()
                .downcast_ref::<Int64Array>()
                .ok_or_else(|| {
                    QueryError::Disclosure("column n must be a COUNT aggregate".into())
                })?;

            let mask: BooleanArray = (0..counts.len())
                .map(|i| Some(!counts.is_null(i) && counts.value(i) >= self.k))
                .collect();
            let kept = filter_record_batch(&batch, &mask)
                .map_err(|e| QueryError::Serialize(e.to_string()))?;
            suppressed += batch.num_rows() - kept.num_rows();
            out.push(kept);
        }
        Ok(DisclosureOutcome {
            batches: out,
            suppressed_rows: suppressed,
        })
    }
}

/// Runs several policies in order, summing their suppressed rows.
pub struct CompositePolicy(pub Vec<Box<dyn DisclosurePolicy>>);

impl DisclosurePolicy for CompositePolicy {
    fn apply(&self, batches: Vec<RecordBatch>) -> Result<DisclosureOutcome, QueryError> {
        let mut current = batches;
        let mut suppressed = 0usize;
        for policy in &self.0 {
            let outcome = policy.apply(current)?;
            current = outcome.batches;
            suppressed += outcome.suppressed_rows;
        }
        Ok(DisclosureOutcome {
            batches: current,
            suppressed_rows: suppressed,
        })
    }
}

/// Plan-level verification that output column `n` is a genuine COUNT
/// aggregate. Rejects both a missing `n` and a spoofed one (`9999 AS n`).
pub fn verify_count_column(plan: &LogicalPlan) -> Result<(), QueryError> {
    let has_n = plan.schema().fields().iter().any(|f| f.name() == "n");
    if !has_n {
        return Err(QueryError::Disclosure(
            "queries must include COUNT(*) AS n (the cohort size)".into(),
        ));
    }
    ensure_n_is_count(plan)
}

/// True when `expr` is `COUNT(*)` (or `COUNT` of a non-null literal) with no
/// `DISTINCT` or `FILTER`: the number of rows in the cohort.
fn is_count_aggregate(expr: &Expr) -> bool {
    aggregate_call(expr).is_some_and(|agg| {
        agg.func.name() == "count"
            && !agg.params.distinct
            && agg.params.filter.is_none()
            && agg.params.args.iter().all(is_non_null_literal)
    })
}

/// True when `expr`, evaluated over `input`, is a column reference that
/// resolves to a COUNT output of an `Aggregate` below. Resolution is by
/// plan position, never by column name: a source column named `count(x)`
/// is not a count.
fn resolves_to_count(expr: &Expr, input: &LogicalPlan) -> bool {
    match expr {
        Expr::Alias(alias) => resolves_to_count(&alias.expr, input),
        Expr::Column(column) => input
            .schema()
            .maybe_index_of_column(column)
            .is_some_and(|index| output_is_count(input, index)),
        _ => false,
    }
}

/// True when output field `index` of `plan` is a genuine COUNT aggregate.
fn output_is_count(plan: &LogicalPlan, index: usize) -> bool {
    match plan {
        LogicalPlan::Projection(projection) => projection
            .expr
            .get(index)
            .is_some_and(|expr| resolves_to_count(expr, projection.input.as_ref())),
        // Output order is the group columns (plus any grouping id), then
        // one column per aggregate expression.
        LogicalPlan::Aggregate(aggregate) => {
            let Ok(group_len) = aggregate.group_expr_len() else {
                return false;
            };
            index
                .checked_sub(group_len)
                .and_then(|i| aggregate.aggr_expr.get(i))
                .is_some_and(is_count_aggregate)
        }
        // Schema-preserving wrappers: field `index` passes through unchanged.
        LogicalPlan::Filter(f) => output_is_count(f.input.as_ref(), index),
        LogicalPlan::Sort(s) => output_is_count(s.input.as_ref(), index),
        LogicalPlan::Limit(l) => output_is_count(l.input.as_ref(), index),
        LogicalPlan::SubqueryAlias(s) => output_is_count(s.input.as_ref(), index),
        _ => false,
    }
}

fn ensure_n_is_count(plan: &LogicalPlan) -> Result<(), QueryError> {
    // Every output field named `n` must be a count; the threshold reads
    // whichever one it finds first.
    let all_counts = plan
        .schema()
        .fields()
        .iter()
        .enumerate()
        .filter(|(_, field)| field.name() == "n")
        .all(|(index, _)| output_is_count(plan, index));
    if all_counts {
        Ok(())
    } else {
        Err(QueryError::Disclosure(
            "column n must be produced by COUNT(*), not a computed value".into(),
        ))
    }
}
