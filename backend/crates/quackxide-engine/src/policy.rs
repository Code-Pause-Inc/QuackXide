//! Zero-knowledge query policy.
//!
//! With `ZkMode::Enabled` the engine permits only aggregate-shaped results.
//! The check inspects the DataFusion logical plan, not the SQL text, and is
//! an allowlist: one `Aggregate` over one table scan, wrapped in
//! projections, filters, sorts, limits, and aliases. Below the aggregate
//! only filters and column renames may appear, so it reads every matching
//! row. Joins, set operations, windows, grouping sets (`ROLLUP`, `CUBE`,
//! `GROUPING SETS`), sorts or limits below the aggregate, `DISTINCT`,
//! `VALUES`, subquery expressions, and aggregates that return member values
//! (`array_agg`, `string_agg`, `first_value`, …) are refused rather than
//! analysed. Grouping sets put subtotal rows beside group rows, so one
//! result could be differenced to recover a suppressed cohort. The `COUNT(*) AS n` and minimum-cohort
//! gates in [`crate::disclosure`] apply on top of this one.
//!
//! [`expressions_cannot_fail`] adds a third check on the analyzed plan:
//! every expression must be one that cannot fail at runtime, so a query's
//! outcome (error or result) never depends on rows that suppression would
//! hide (ADR 0011).
//!
//! It bounds what leaves the enclave; it complements, not replaces,
//! attestation and envelope encryption.

use std::sync::Arc;

use arrow::array::{RecordBatch, RecordBatchOptions};
use arrow::datatypes::{DataType, Schema};
use datafusion::common::tree_node::{TreeNode, TreeNodeRecursion};
use datafusion::common::{DFSchema, ScalarValue};
use datafusion::logical_expr::execution_props::ExecutionProps;
use datafusion::logical_expr::expr::{AggregateFunction, Cast};
use datafusion::logical_expr::physical_planning_context::PhysicalPlanningContext;
use datafusion::logical_expr::{BinaryExpr, Expr, ExprSchemable, LogicalPlan, Operator};
use datafusion::physical_expr::create_physical_expr;

/// Aggregates that return one summary value per group.
pub const PERMITTED_AGGREGATES: &[&str] = &["count", "sum", "avg", "min", "max"];

/// True when the plan's output is a single permitted aggregation over whole
/// table columns, so no raw value can reach the result.
pub fn is_aggregate_only(plan: &LogicalPlan) -> bool {
    !has_subqueries(plan)
        && match plan {
            LogicalPlan::Aggregate(aggregate) => {
                !aggregate.group_expr.iter().any(is_grouping_set)
                    && aggregate.aggr_expr.iter().all(is_permitted_aggregate)
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

/// Longest `LIKE`/`ILIKE` pattern, in characters. Arrow compiles a pattern
/// to a regex when a row reaches it, and a longer one can exceed the regex
/// size limit, failing only for some data.
pub const MAX_LIKE_PATTERN_CHARS: usize = 1000;

/// Scalar functions that cannot fail on any input.
const TOTAL_FUNCTIONS: &[&str] = &["coalesce", "nullif", "lower", "upper"];

/// True when no expression in the analyzed (type-coerced) plan can fail at
/// runtime. It must see the analyzed plan: coercion inserts casts, such as
/// a string to an integer, that fail on some values. Unknown expression
/// kinds count as able to fail.
pub fn expressions_cannot_fail(analyzed: &LogicalPlan) -> bool {
    let may_fail = analyzed.exists(|node| {
        let schema = match node.inputs()[..] {
            [input] => input.schema(),
            _ => node.schema(),
        };
        Ok(!node
            .expressions()
            .iter()
            .all(|expr| expr_cannot_fail(expr, schema)))
    });
    matches!(may_fail, Ok(false))
}

fn expr_cannot_fail(expr: &Expr, schema: &DFSchema) -> bool {
    matches!(
        expr.exists(|e| Ok(!node_cannot_fail(e, schema) || !constant_evaluates(e))),
        Ok(false)
    )
}

/// A subtree without columns runs as a scalar, which can fail where the
/// same operation on a column wraps (negating `i64::MIN`). Evaluate it here,
/// so whether it fails cannot depend on the data.
fn constant_evaluates(expr: &Expr) -> bool {
    if matches!(expr, Expr::Literal(..)) || !expr.column_refs().is_empty() {
        return true;
    }
    match expr.exists(|e| Ok(matches!(e, Expr::AggregateFunction(_)))) {
        Ok(true) => return true,
        Ok(false) => {}
        Err(_) => return false,
    }
    let Ok(physical) = create_physical_expr(
        expr,
        &DFSchema::empty(),
        &ExecutionProps::new(),
        &PhysicalPlanningContext::default(),
    ) else {
        return false;
    };
    let options = RecordBatchOptions::new().with_row_count(Some(1));
    RecordBatch::try_new_with_options(Arc::new(Schema::empty()), vec![], &options)
        .is_ok_and(|batch| physical.evaluate(&batch).is_ok())
}

/// The rule for one expression node; its children are checked separately.
fn node_cannot_fail(expr: &Expr, schema: &DFSchema) -> bool {
    match expr {
        Expr::Alias(_)
        | Expr::Column(_)
        | Expr::Literal(..)
        | Expr::Not(_)
        | Expr::IsNull(_)
        | Expr::IsNotNull(_)
        | Expr::IsTrue(_)
        | Expr::IsFalse(_)
        | Expr::IsUnknown(_)
        | Expr::IsNotTrue(_)
        | Expr::IsNotFalse(_)
        | Expr::IsNotUnknown(_)
        | Expr::Between(_)
        | Expr::Case(_)
        | Expr::TryCast(_)
        // Its arguments are plain columns or literals (`is_permitted_aggregate`).
        | Expr::AggregateFunction(_) => true,
        Expr::BinaryExpr(binary) => binary_cannot_fail(binary, schema),
        // Integer minus wraps on a column but fails on a constant `i64::MIN`,
        // and projection merging can turn one into the other. `0 - x` wraps on both.
        Expr::Negative(inner) => type_of(inner, schema) == Some(DataType::Float64),
        Expr::Like(like) => like_pattern_cannot_fail(&like.pattern),
        Expr::InList(in_list) => in_list.list.iter().all(|item| match item {
            Expr::Literal(..) => true,
            Expr::Cast(cast) => matches!(*cast.expr, Expr::Literal(..)) && cast_cannot_fail(cast, schema),
            _ => false,
        }),
        Expr::Cast(cast) => cast_cannot_fail(cast, schema),
        Expr::ScalarFunction(function) => TOTAL_FUNCTIONS.contains(&function.name()),
        _ => false,
    }
}

fn binary_cannot_fail(binary: &BinaryExpr, schema: &DFSchema) -> bool {
    use Operator::*;
    let left = type_of(&binary.left, schema);
    let right = type_of(&binary.right, schema);
    match binary.op {
        Eq | NotEq | Lt | LtEq | Gt | GtEq | And | Or | IsDistinctFrom | IsNotDistinctFrom
        | StringConcat => true,
        // Integer arithmetic wraps and float arithmetic follows IEEE 754.
        Plus | Minus | Multiply => left == right && is_wrapping_number(left.as_ref()),
        Divide | Modulo => match (left, right) {
            (Some(DataType::Float64), Some(DataType::Float64)) => true,
            (Some(DataType::Int64), Some(DataType::Int64)) => is_safe_int_divisor(&binary.right),
            _ => false,
        },
        _ => false,
    }
}

/// A string literal, possibly cast to the column's string type, no longer
/// than [`MAX_LIKE_PATTERN_CHARS`].
fn like_pattern_cannot_fail(pattern: &Expr) -> bool {
    let literal = match pattern {
        Expr::Cast(cast) => cast.expr.as_ref(),
        other => other,
    };
    match literal {
        Expr::Literal(value, _) => value
            .try_as_str()
            .is_some_and(|s| s.is_none_or(|s| s.chars().count() <= MAX_LIKE_PATTERN_CHARS)),
        _ => false,
    }
}

/// A cast of a literal is a constant, checked by [`constant_evaluates`]; a
/// column only by a conversion that accepts every value.
fn cast_cannot_fail(cast: &Cast, schema: &DFSchema) -> bool {
    let to = cast.field.data_type();
    if matches!(cast.expr.as_ref(), Expr::Literal(..)) {
        return true;
    }
    let Some(from) = type_of(&cast.expr, schema) else {
        return false;
    };
    from == *to
        || (from == DataType::Int64 && *to == DataType::Float64)
        || (is_string(to)
            && (is_string(&from)
                || matches!(
                    from,
                    DataType::Boolean | DataType::Int64 | DataType::Float64
                )))
}

/// `i64::MIN / -1` overflows, and zero divides by zero.
fn is_safe_int_divisor(expr: &Expr) -> bool {
    matches!(expr, Expr::Literal(ScalarValue::Int64(Some(v)), _) if *v != 0 && *v != -1)
}

fn is_wrapping_number(data_type: Option<&DataType>) -> bool {
    matches!(data_type, Some(DataType::Int64 | DataType::Float64))
}

fn is_string(data_type: &DataType) -> bool {
    matches!(
        data_type,
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View
    )
}

fn type_of(expr: &Expr, schema: &DFSchema) -> Option<DataType> {
    expr.get_type(schema).ok()
}

/// Below the aggregate every row reaches it unchanged: filters may drop
/// rows, projections may only rename columns, and nothing may add rows or
/// pick rows by position (no sort or limit).
fn rows_reach_unchanged(plan: &LogicalPlan) -> bool {
    !has_subqueries(plan)
        && match plan {
            LogicalPlan::TableScan(_) => true,
            LogicalPlan::Projection(projection) => {
                projection.expr.iter().all(is_column) && rows_reach_unchanged(&projection.input)
            }
            LogicalPlan::Filter(_) | LogicalPlan::SubqueryAlias(_) => {
                single_input(plan).is_some_and(rows_reach_unchanged)
            }
            _ => false,
        }
}

/// `ROLLUP`, `CUBE` and `GROUPING SETS` group the same rows more than once.
fn is_grouping_set(expr: &Expr) -> bool {
    match expr {
        Expr::Alias(alias) => is_grouping_set(&alias.expr),
        Expr::GroupingSet(_) => true,
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
