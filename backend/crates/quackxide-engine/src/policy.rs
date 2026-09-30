//! Zero-knowledge query policy.
//!
//! With `ZkMode::Enabled` the engine permits only aggregate-shaped results.
//! The check inspects the DataFusion logical plan, not the SQL text, and is
//! an allowlist: one `Aggregate` over one table scan, wrapped in
//! projections, filters, sorts, limits, and aliases. Joins, set operations,
//! windows, `DISTINCT`, `VALUES`, subquery expressions, and aggregates that
//! return member values (`array_agg`, `string_agg`, `first_value`, …) are
//! refused rather than analysed. The `COUNT(*) AS n` and minimum-cohort
//! gates in [`crate::disclosure`] apply on top of this one.
//!
//! It bounds what leaves the enclave; it complements, not replaces,
//! attestation and envelope encryption.

use datafusion::common::tree_node::TreeNodeRecursion;
use datafusion::logical_expr::expr::AggregateFunction;
use datafusion::logical_expr::{Expr, LogicalPlan};

/// Aggregates that return one summary value per group.
pub const PERMITTED_AGGREGATES: &[&str] = &["count", "sum", "avg", "min", "max"];

/// True when the plan's output is a single permitted aggregation over whole
/// table columns, so no raw value can reach the result.
pub fn is_aggregate_only(plan: &LogicalPlan) -> bool {
    !has_subqueries(plan)
        && match plan {
            LogicalPlan::Aggregate(aggregate) => {
                aggregate.aggr_expr.iter().all(is_permitted_aggregate)
                    && rows_reach_unchanged(&aggregate.input)
            }
            LogicalPlan::Projection(_)
            | LogicalPlan::Filter(_)
            | LogicalPlan::Sort(_)
            | LogicalPlan::Limit(_)
            | LogicalPlan::SubqueryAlias(_) => single_input(plan).is_some_and(is_aggregate_only),
            _ => false,
        }
}

/// Below the aggregate every row reaches it unchanged: filters may drop
/// rows, projections may only rename columns, and nothing may add rows.
fn rows_reach_unchanged(plan: &LogicalPlan) -> bool {
    !has_subqueries(plan)
        && match plan {
            LogicalPlan::TableScan(_) => true,
            LogicalPlan::Projection(projection) => {
                projection.expr.iter().all(is_column) && rows_reach_unchanged(&projection.input)
            }
            LogicalPlan::Filter(_)
            | LogicalPlan::Sort(_)
            | LogicalPlan::Limit(_)
            | LogicalPlan::SubqueryAlias(_) => single_input(plan).is_some_and(rows_reach_unchanged),
            _ => false,
        }
}

/// A permitted function over plain columns or literals, with no `FILTER`
/// or ordering, so it cannot be narrowed to a subset of its group.
fn is_permitted_aggregate(expr: &Expr) -> bool {
    aggregate_call(expr).is_some_and(|agg| {
        PERMITTED_AGGREGATES.contains(&agg.func.name())
            && agg.params.filter.is_none()
            && agg.params.order_by.is_empty()
            && agg
                .params
                .args
                .iter()
                .all(|arg| is_column(arg) || is_non_null_literal(arg))
    })
}

fn single_input(plan: &LogicalPlan) -> Option<&LogicalPlan> {
    match plan.inputs()[..] {
        [input] => Some(input),
        _ => None,
    }
}

fn has_subqueries(plan: &LogicalPlan) -> bool {
    !matches!(
        plan.apply_subqueries(|_| Ok(TreeNodeRecursion::Stop)),
        Ok(TreeNodeRecursion::Continue)
    )
}

pub(crate) fn aggregate_call(expr: &Expr) -> Option<&AggregateFunction> {
    match expr {
        Expr::Alias(alias) => aggregate_call(&alias.expr),
        Expr::AggregateFunction(agg) => Some(agg),
        _ => None,
    }
}

fn is_column(expr: &Expr) -> bool {
    match expr {
        Expr::Alias(alias) => is_column(&alias.expr),
        Expr::Column(_) => true,
        _ => false,
    }
}

pub(crate) fn is_non_null_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Literal(value, _) if !value.is_null())
}
