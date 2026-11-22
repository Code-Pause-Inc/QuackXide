//! The p% rule for sums and means (ADR 0015).
//!
//! A `SUM` or `AVG` over a cohort of at least *k* rows is still close to
//! one row's value when one or two rows hold most of the total. For each
//! group and each argument `x` of a `SUM(x)` or `AVG(x)`, let *T* be the
//! sum of the absolute values of the group's non-null `x`, and
//! *x*₁ ≥ *x*₂ the two largest absolute values. The group's sums and means
//! of `x` are sensitive when *T* − *x*₁ − *x*₂ < (*p* / 100) · *x*₁: anyone
//! who knows the second-largest value, subtracting it from the total,
//! learns the largest to within *p* percent. A sensitive cell is released
//! as null, and the row keeps `n` and its other cells.
//!
//! [`mask_dominated`] applies the rule inside the plan, after the plan has
//! passed the gate and before it runs. It adds one hidden aggregate per
//! argument to the plan's one `Aggregate`, which keeps *T*, *x*₁ and *x*₂
//! for each group and returns whether the group's cells may be released.
//! A projection placed directly above the `Aggregate` replaces each `SUM`
//! and `AVG` of a group that may not be released with null, and drops the
//! hidden columns. Every operator above it (`HAVING`, derived columns,
//! `ORDER BY`, `LIMIT`, outer queries) reads the masked value, and no
//! hidden value reaches egress. No session registers the hidden aggregate,
//! so SQL cannot call it.
//!
//! The rule runs in double precision, which cannot fail. Integer values of
//! ordinary size are exact; for others, near the boundary *T* is a few
//! times *x*₁, so rounding moves the decision by a negligible fraction of
//! *x*₁. A value that is not a finite number (NaN or infinity in a float
//! column), or a total that overflows, makes the group's cells sensitive.
//! One row is one contribution: the cohort threshold counts rows too.

use std::mem::size_of;
use std::sync::Arc;

use arrow::array::{Array, ArrayRef, AsArray, BooleanArray, Float64Array};
use arrow::buffer::BooleanBuffer;
use arrow::compute::cast;
use arrow::datatypes::{DataType, Field, FieldRef, Float64Type};
use datafusion::common::tree_node::{Transformed, TreeNode};
use datafusion::common::{Column, DFSchema, DataFusionError, ScalarValue, plan_err};
use datafusion::logical_expr::expr::{AggregateFunction, Case};
use datafusion::logical_expr::function::{AccumulatorArgs, StateFieldsArgs};
use datafusion::logical_expr::utils::format_state_name;
use datafusion::logical_expr::{
    Accumulator, Aggregate, AggregateUDF, AggregateUDFImpl, EmitTo, Expr, ExprSchemable,
    GroupsAccumulator, LogicalPlan, Projection, Signature, Volatility,
};

use crate::QueryError;
use crate::policy::aggregate_call;

/// The p% rule's parameter. `p` is an integer percent; below 1 is a
/// misconfiguration, and a scope with such a rule refuses every gated
/// query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PercentRule {
    pub p: u64,
}

impl PercentRule {
    /// Refuses a rule that would release every sum ([`QueryError::Disclosure`]).
    pub(crate) fn check(self) -> Result<Self, QueryError> {
        if self.p < 1 {
            return Err(QueryError::Disclosure(
                "the dominance rule is not configured".into(),
            ));
        }
        Ok(self)
    }
}

/// True for the aggregates the rule masks: `SUM` and `AVG`, since
/// `SUM = AVG × n` and `n` is always released.
pub(crate) fn is_masked(call: &AggregateFunction) -> bool {
    matches!(call.func.name(), "sum" | "avg")
}

/// Masks dominated sums and means in a plan that passed the gate
/// (`policy::is_aggregate_only`), which holds exactly one `Aggregate`. A
/// `SUM` or `AVG` with `DISTINCT`, or over a type with no magnitude
/// (intervals), is refused with [`QueryError::ZkPolicy`].
pub(crate) fn mask_dominated(
    plan: LogicalPlan,
    rule: PercentRule,
) -> Result<LogicalPlan, QueryError> {
    let mut aggregates = 0usize;
    let mut refusal = None;
    let rewritten = plan.transform_up(|node| {
        let LogicalPlan::Aggregate(aggregate) = node else {
            return Ok(Transformed::no(node));
        };
        aggregates += 1;
        match mask_aggregate(aggregate, rule) {
            Ok(masked) => Ok(Transformed::yes(masked)),
            Err(err) => {
                refusal = Some(err);
                plan_err!("the dominance rule refused the plan")
            }
        }
    });
    if let Some(err) = refusal {
        return Err(err);
    }
    match rewritten {
        Ok(rewritten) if aggregates == 1 => Ok(rewritten.data),
        // The gate admits one aggregate; anything else is not masked.
        Ok(_) => Err(QueryError::ZkPolicy),
        Err(_) => Err(QueryError::Execution(crate::ExecutionStage::Plan)),
    }
}

/// `aggregate`, with a hidden releasability aggregate per `SUM` or `AVG`
/// argument, under a projection that masks and keeps `aggregate`'s schema.
fn mask_aggregate(aggregate: Aggregate, rule: PercentRule) -> Result<LogicalPlan, QueryError> {
    // Each argument once: AVG(x) takes the decision of SUM(x).
    let mut arguments: Vec<Expr> = Vec::new();
    for expr in &aggregate.aggr_expr {
        let call = aggregate_call(expr).ok_or(QueryError::ZkPolicy)?;
        if !is_masked(call) {
            continue;
        }
        let [argument] = call.params.args.as_slice() else {
            return Err(QueryError::ZkPolicy);
        };
        let data_type = argument
            .get_type(aggregate.input.schema().as_ref())
            .map_err(|_| QueryError::Execution(crate::ExecutionStage::Plan))?;
        if call.params.distinct || !has_magnitude(&data_type) {
            return Err(QueryError::ZkPolicy);
        }
        if !arguments.contains(argument) {
            arguments.push(argument.clone());
        }
    }
    if arguments.is_empty() {
        return Ok(LogicalPlan::Aggregate(aggregate));
    }

    let planning = |_: DataFusionError| QueryError::Execution(crate::ExecutionStage::Plan);
    let schema = Arc::clone(&aggregate.schema);
    let group_len = aggregate.group_expr_len().map_err(planning)?;
    let names = hidden_names(&schema, arguments.len());
    let releasable = Arc::new(AggregateUDF::from(Releasable::new(rule)));
    let mut aggr_expr = aggregate.aggr_expr.clone();
    for (argument, name) in arguments.iter().zip(&names) {
        let call = AggregateFunction::new_udf(
            Arc::clone(&releasable),
            vec![argument.clone()],
            false,
            None,
            vec![],
            None,
        );
        aggr_expr.push(Expr::AggregateFunction(call).alias(name));
    }
    let extended = Aggregate::try_new(
        Arc::clone(&aggregate.input),
        aggregate.group_expr.clone(),
        aggr_expr,
    )
    .map_err(planning)?;

    // The original columns, in order, each SUM and AVG released only where
    // its argument's hidden aggregate says so (a null says no).
    let masks = schema
        .iter()
        .enumerate()
        .map(|(index, (qualifier, field))| {
            let column = Expr::Column(Column::from((qualifier, field)));
            let hidden = index
                .checked_sub(group_len)
                .and_then(|i| aggregate.aggr_expr.get(i))
                .and_then(aggregate_call)
                .filter(|call| is_masked(call))
                .and_then(|call| {
                    arguments
                        .iter()
                        .position(|a| call.params.args.first() == Some(a))
                });
            match hidden {
                None => column,
                Some(i) => {
                    let released = Expr::Column(Column::new_unqualified(&names[i]));
                    Expr::Case(Case::new(
                        None,
                        vec![(Box::new(released), Box::new(column))],
                        None,
                    ))
                    .alias_qualified(qualifier.cloned(), field.name())
                }
            }
        });
    let projection =
        Projection::try_new(masks.collect(), Arc::new(LogicalPlan::Aggregate(extended)))
            .map_err(planning)?;
    // Everything above the aggregate resolves its columns by qualifier and
    // name, so the projection must give back the aggregate's own.
    if !same_columns(&schema, &projection.schema) {
        return Err(QueryError::Execution(crate::ExecutionStage::Plan));
    }
    Ok(LogicalPlan::Projection(projection))
}

/// Names for `count` hidden columns that no column of `schema` has.
fn hidden_names(schema: &DFSchema, count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let mut name = format!("__releasable_{i}");
            while schema.fields().iter().any(|field| field.name() == &name) {
                name.insert(0, '_');
            }
            name
        })
        .collect()
}

fn same_columns(expected: &DFSchema, actual: &DFSchema) -> bool {
    expected.fields().len() == actual.fields().len()
        && expected
            .iter()
            .zip(actual.iter())
            .all(|((q1, f1), (q2, f2))| {
                q1 == q2 && f1.name() == f2.name() && f1.data_type() == f2.data_type()
            })
}

/// Types whose values have a magnitude the rule can weigh: numbers and
/// durations. An interval's parts have none between them.
fn has_magnitude(data_type: &DataType) -> bool {
    match data_type {
        DataType::Int8
        | DataType::Int16
        | DataType::Int32
        | DataType::Int64
        | DataType::UInt8
        | DataType::UInt16
        | DataType::UInt32
        | DataType::UInt64
        | DataType::Float16
        | DataType::Float32
        | DataType::Float64
        | DataType::Decimal32(_, _)
        | DataType::Decimal64(_, _)
        | DataType::Decimal128(_, _)
        | DataType::Decimal256(_, _)
        | DataType::Duration(_) => true,
        DataType::Dictionary(_, values) => has_magnitude(values),
        _ => false,
    }
}

/// One group's contributions to a sum: the total of their absolute values
/// and the two largest.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Contributions {
    total: f64,
    first: f64,
    second: f64,
}

impl Contributions {
    /// Adds one row's absolute value. NaN stands for a value with no
    /// magnitude, and makes the total, and so the group, sensitive.
    fn add(&mut self, magnitude: f64) {
        self.total += magnitude;
        self.place(magnitude);
    }

    fn place(&mut self, magnitude: f64) {
        if magnitude > self.first {
            self.second = self.first;
            self.first = magnitude;
        } else if magnitude > self.second {
            self.second = magnitude;
        }
    }

    fn merge(&mut self, other: Contributions) {
        self.total += other.total;
        self.place(other.first);
        self.place(other.second);
    }

    /// The p% rule: 100 · (*T* − *x*₁ − *x*₂) ≥ *p* · *x*₁. Multiplied out,
    /// so a boundary that is exact in integers stays exact. Every part must
    /// be finite, so a non-finite contribution, or a side that overflows,
    /// masks the group. A group with no contributions, or only zeros, is
    /// releasable.
    fn releasable(self, rule: PercentRule) -> bool {
        let Contributions {
            total,
            first,
            second,
        } = self;
        // Not finite if any part is not.
        let remainder = (total - first - second) * 100.0;
        let bound = first * rule.p as f64;
        remainder.is_finite() && bound.is_finite() && remainder >= bound
    }
}

/// A batch of state rows, as [`state_arrays`] writes them.
struct States<'a>([&'a Float64Array; 3]);

impl<'a> States<'a> {
    fn of(states: &'a [ArrayRef]) -> Result<Self, DataFusionError> {
        let part = |index: usize| {
            states
                .get(index)
                .and_then(|array| array.as_primitive_opt::<Float64Type>())
        };
        match (part(0), part(1), part(2)) {
            (Some(total), Some(first), Some(second)) => Ok(Self([total, first, second])),
            _ => plan_err!("releasable state has three Float64 parts"),
        }
    }

    fn len(&self) -> usize {
        self.0[0].len()
    }

    /// Row `row`'s contributions. A missing part never comes from `state`;
    /// it counts as a value with no magnitude.
    fn row(&self, row: usize) -> Contributions {
        let part = |array: &Float64Array| {
            if array.is_valid(row) {
                array.value(row)
            } else {
                f64::NAN
            }
        };
        let [total, first, second] = self.0;
        Contributions {
            total: part(total),
            first: part(first),
            second: part(second),
        }
    }
}

/// The three state columns for `groups`, in order.
fn state_arrays(groups: &[Contributions]) -> Vec<ArrayRef> {
    let column = |part: fn(&Contributions) -> f64| -> ArrayRef {
        Arc::new(Float64Array::from_iter_values(groups.iter().map(part)))
    };
    vec![
        column(|c| c.total),
        column(|c| c.first),
        column(|c| c.second),
    ]
}

/// Calls `each(row, magnitude)` for every row of `values` that `filter`
/// keeps and that is not null. A value with no `f64` form gives NaN.
fn for_each_magnitude(
    values: &ArrayRef,
    filter: Option<&BooleanArray>,
    mut each: impl FnMut(usize, f64),
) -> Result<(), DataFusionError> {
    let present = values.logical_nulls();
    let numbers = cast(values.as_ref(), &DataType::Float64)?;
    let numbers = numbers.as_primitive::<Float64Type>();
    if filter.is_none() && present.is_none() && numbers.null_count() == 0 {
        for (row, value) in numbers.values().iter().enumerate() {
            each(row, value.abs());
        }
        return Ok(());
    }
    for row in 0..values.len() {
        let kept = filter.is_none_or(|filter| filter.is_valid(row) && filter.value(row));
        if !kept || present.as_ref().is_some_and(|nulls| nulls.is_null(row)) {
            continue;
        }
        each(
            row,
            if numbers.is_valid(row) {
                numbers.value(row).abs()
            } else {
                f64::NAN
            },
        );
    }
    Ok(())
}

/// The hidden aggregate: whether a group's contributions to `SUM(x)` and
/// `AVG(x)` may be released under `rule`. Never null.
#[derive(Debug, PartialEq, Eq, Hash)]
struct Releasable {
    rule: PercentRule,
    signature: Signature,
}

impl Releasable {
    fn new(rule: PercentRule) -> Self {
        Self {
            rule,
            // Any one argument, uncoerced: `mask_dominated` has checked its
            // type, and the accumulators convert it to `f64` themselves.
            signature: Signature::any(1, Volatility::Immutable),
        }
    }
}

impl AggregateUDFImpl for Releasable {
    fn name(&self) -> &str {
        "releasable"
    }

    fn signature(&self) -> &Signature {
        &self.signature
    }

    fn return_type(&self, _: &[DataType]) -> Result<DataType, DataFusionError> {
        Ok(DataType::Boolean)
    }

    fn accumulator(&self, _: AccumulatorArgs) -> Result<Box<dyn Accumulator>, DataFusionError> {
        Ok(Box::new(ReleasableAccumulator {
            rule: self.rule,
            contributions: Contributions::default(),
        }))
    }

    fn state_fields(&self, args: StateFieldsArgs) -> Result<Vec<FieldRef>, DataFusionError> {
        Ok(["total", "first", "second"]
            .into_iter()
            .map(|part| {
                Arc::new(Field::new(
                    format_state_name(args.name, part),
                    DataType::Float64,
                    true,
                ))
            })
            .collect())
    }

    fn groups_accumulator_supported(&self, _: AccumulatorArgs) -> bool {
        true
    }

    fn create_groups_accumulator(
        &self,
        _: AccumulatorArgs,
    ) -> Result<Box<dyn GroupsAccumulator>, DataFusionError> {
        Ok(Box::new(ReleasableGroups {
            rule: self.rule,
            groups: Vec::new(),
        }))
    }
}

/// [`Releasable`] for one group (an aggregate with no `GROUP BY`).
#[derive(Debug)]
struct ReleasableAccumulator {
    rule: PercentRule,
    contributions: Contributions,
}

impl Accumulator for ReleasableAccumulator {
    fn update_batch(&mut self, values: &[ArrayRef]) -> Result<(), DataFusionError> {
        let Some(values) = values.first() else {
            return plan_err!("releasable takes one argument");
        };
        for_each_magnitude(values, None, |_, magnitude| {
            self.contributions.add(magnitude);
        })
    }

    fn evaluate(&mut self) -> Result<ScalarValue, DataFusionError> {
        Ok(ScalarValue::Boolean(Some(
            self.contributions.releasable(self.rule),
        )))
    }

    fn size(&self) -> usize {
        size_of::<Self>()
    }

    fn state(&mut self) -> Result<Vec<ScalarValue>, DataFusionError> {
        let Contributions {
            total,
            first,
            second,
        } = self.contributions;
        Ok(vec![
            ScalarValue::Float64(Some(total)),
            ScalarValue::Float64(Some(first)),
            ScalarValue::Float64(Some(second)),
        ])
    }

    fn merge_batch(&mut self, states: &[ArrayRef]) -> Result<(), DataFusionError> {
        let states = States::of(states)?;
        for row in 0..states.len() {
            self.contributions.merge(states.row(row));
        }
        Ok(())
    }
}

/// [`Releasable`] for every group of a `GROUP BY`, with constant state per
/// group.
struct ReleasableGroups {
    rule: PercentRule,
    groups: Vec<Contributions>,
}

impl GroupsAccumulator for ReleasableGroups {
    fn update_batch(
        &mut self,
        values: &[ArrayRef],
        group_indices: &[usize],
        opt_filter: Option<&BooleanArray>,
        total_num_groups: usize,
    ) -> Result<(), DataFusionError> {
        let Some(values) = values.first() else {
            return plan_err!("releasable takes one argument");
        };
        self.groups
            .resize(total_num_groups, Contributions::default());
        let groups = &mut self.groups;
        for_each_magnitude(values, opt_filter, |row, magnitude| {
            groups[group_indices[row]].add(magnitude);
        })
    }

    fn evaluate(&mut self, emit_to: EmitTo) -> Result<ArrayRef, DataFusionError> {
        let rule = self.rule;
        let groups = emit_to.take_needed(&mut self.groups);
        let released = BooleanBuffer::collect_bool(groups.len(), |i| groups[i].releasable(rule));
        Ok(Arc::new(BooleanArray::new(released, None)))
    }

    fn state(&mut self, emit_to: EmitTo) -> Result<Vec<ArrayRef>, DataFusionError> {
        Ok(state_arrays(&emit_to.take_needed(&mut self.groups)))
    }

    fn merge_batch(
        &mut self,
        values: &[ArrayRef],
        group_indices: &[usize],
        total_num_groups: usize,
    ) -> Result<(), DataFusionError> {
        let states = States::of(values)?;
        self.groups
            .resize(total_num_groups, Contributions::default());
        for (row, &group) in group_indices.iter().enumerate() {
            self.groups[group].merge(states.row(row));
        }
        Ok(())
    }

    fn convert_to_state(
        &self,
        values: &[ArrayRef],
        opt_filter: Option<&BooleanArray>,
    ) -> Result<Vec<ArrayRef>, DataFusionError> {
        let Some(values) = values.first() else {
            return plan_err!("releasable takes one argument");
        };
        let mut rows = vec![Contributions::default(); values.len()];
        for_each_magnitude(values, opt_filter, |row, magnitude| {
            rows[row].add(magnitude);
        })?;
        Ok(state_arrays(&rows))
    }

    fn size(&self) -> usize {
        size_of::<Self>() + self.groups.capacity() * size_of::<Contributions>()
    }
}

#[cfg(test)]
mod tests {
    use arrow::array::{DurationMillisecondArray, Int64Array, UInt64Array};
    use arrow::datatypes::IntervalUnit;

    use super::*;

    const P10: PercentRule = PercentRule { p: 10 };

    fn of(values: &[f64]) -> Contributions {
        let mut group = Contributions::default();
        for value in values {
            group.add(value.abs());
        }
        group
    }

    #[test]
    fn the_rule_masks_one_or_two_dominant_rows() {
        // ADR 0015's examples: the `ceo` with the six `eng` rows (9001 is
        // 94% of the total), and the two `legal` rows with them.
        let eng = [100.0, 101.0, 102.0, 103.0, 104.0, 105.0];
        let ceo_eng: Vec<f64> = eng.iter().copied().chain([9001.0]).collect();
        let legal_eng: Vec<f64> = eng.iter().copied().chain([7001.0, 7002.0]).collect();
        assert!(of(&eng).releasable(P10));
        assert!(!of(&ceo_eng).releasable(P10));
        assert!(!of(&legal_eng).releasable(P10));
    }

    #[test]
    fn the_boundary_is_p_percent_of_the_largest() {
        // T − x₁ − x₂ = 10, x₁ = 100: exactly 10% is releasable.
        assert!(of(&[100.0, 50.0, 4.0, 6.0]).releasable(P10));
        assert!(!of(&[100.0, 50.0, 4.0, 5.0]).releasable(P10));
        // A larger p protects more.
        assert!(!of(&[100.0, 50.0, 4.0, 6.0]).releasable(PercentRule { p: 11 }));
        assert!(!of(&[1.0; 3]).releasable(PercentRule { p: u64::MAX }));
    }

    #[test]
    fn fewer_than_three_values_are_sensitive_unless_all_zero() {
        assert!(!of(&[5.0]).releasable(P10));
        assert!(!of(&[5.0, 5.0]).releasable(P10));
        assert!(of(&[0.0, 0.0]).releasable(P10));
        assert!(of(&[]).releasable(P10));
        assert!(of(&[5.0, 5.0, 5.0]).releasable(P10));
    }

    #[test]
    fn negative_values_count_by_magnitude() {
        // Offsetting gains and losses cannot hide a large one: the sum is
        // 14, but 5000 and −4990 dominate it.
        assert!(!of(&[5000.0, -4990.0, 1.0, 1.0, 1.0, 1.0]).releasable(P10));
        assert!(!of(&[-5000.0, 10.0, 11.0, 12.0, 13.0, 14.0]).releasable(P10));
        assert!(of(&[-100.0, -101.0, -102.0, 103.0]).releasable(P10));
    }

    #[test]
    fn values_that_are_not_finite_numbers_are_sensitive() {
        for poison in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(
                !of(&[1.0, 2.0, 3.0, 4.0, poison]).releasable(P10),
                "{poison}"
            );
        }
        // A finite total that overflows is not a number either.
        assert!(!of(&[f64::MAX, f64::MAX, f64::MAX, f64::MAX]).releasable(P10));
    }

    #[test]
    fn merging_partial_states_matches_one_pass() {
        let values = [3.0, -9.0, 4.0, 1.0, -5.0, 9.0, 2.0, 6.0];
        for split in 0..=values.len() {
            let (left, right) = values.split_at(split);
            let mut merged = of(left);
            merged.merge(of(right));
            assert_eq!(merged, of(&values), "split at {split}");
        }
        // Ties keep both.
        assert_eq!(of(&[4000.0, 4000.0, 1.0]).second, 4000.0);
    }

    fn boolean_values(array: &ArrayRef) -> Vec<Option<bool>> {
        array.as_boolean().iter().collect()
    }

    /// Three groups: one even, one dominated, one empty; a null row and a
    /// filtered row contribute nothing.
    #[test]
    fn groups_accumulator_emits_in_group_order_and_merges() {
        let values: ArrayRef = Arc::new(Int64Array::from(vec![
            Some(10),
            Some(11),
            Some(9000),
            Some(12),
            None,
            Some(1),
            Some(1),
            Some(1_000_000),
        ]));
        let groups = [0, 0, 1, 0, 1, 1, 1, 0];
        let filter = BooleanArray::from(vec![true, true, true, true, true, true, true, false]);
        let mut partial = ReleasableGroups {
            rule: P10,
            groups: Vec::new(),
        };
        partial
            .update_batch(&[Arc::clone(&values)], &groups, Some(&filter), 3)
            .expect("update");
        let state = partial.state(EmitTo::All).expect("state");
        assert!(partial.groups.is_empty(), "state resets the accumulator");

        // Merge the state into group indices shifted by one, then emit the
        // first two groups and the rest.
        let mut fin = ReleasableGroups {
            rule: P10,
            groups: Vec::new(),
        };
        fin.merge_batch(&state, &[1, 2, 3], 4).expect("merge");
        let first = fin.evaluate(EmitTo::First(2)).expect("first two");
        assert_eq!(boolean_values(&first), [Some(true), Some(true)]);
        let rest = fin.evaluate(EmitTo::All).expect("rest");
        assert_eq!(boolean_values(&rest), [Some(false), Some(true)]);

        // Each row as its own group: one value is always sensitive, a null
        // or a filtered row releases nothing to mask.
        let rows = partial
            .convert_to_state(&[values], Some(&filter))
            .expect("rows");
        let mut each = ReleasableGroups {
            rule: P10,
            groups: Vec::new(),
        };
        each.merge_batch(&rows, &[0, 1, 2, 3, 4, 5, 6, 7], 8)
            .expect("merge rows");
        let released = each.evaluate(EmitTo::All).expect("each");
        assert_eq!(
            boolean_values(&released),
            [false, false, false, false, true, false, false, true].map(Some)
        );
    }

    #[test]
    fn single_group_accumulator_merges_its_state() {
        let mut left = ReleasableAccumulator {
            rule: P10,
            contributions: Contributions::default(),
        };
        let values: ArrayRef = Arc::new(Int64Array::from(vec![100, 101, 102]));
        left.update_batch(&[values]).expect("update");
        let state: Vec<ArrayRef> = left
            .state()
            .expect("state")
            .into_iter()
            .map(|value| value.to_array().expect("array"))
            .collect();
        let mut right = ReleasableAccumulator {
            rule: P10,
            contributions: Contributions::default(),
        };
        let outlier: ArrayRef = Arc::new(Int64Array::from(vec![9001]));
        right.update_batch(&[outlier]).expect("update");
        assert_eq!(
            right.evaluate().expect("one"),
            ScalarValue::Boolean(Some(false))
        );
        right.merge_batch(&state).expect("merge");
        assert_eq!(
            right.evaluate().expect("four"),
            ScalarValue::Boolean(Some(false))
        );
        left.update_batch(&[Arc::new(Int64Array::from(vec![103, 104]))])
            .expect("more");
        assert_eq!(
            left.evaluate().expect("five"),
            ScalarValue::Boolean(Some(true))
        );
    }

    #[test]
    fn every_type_with_a_magnitude_converts_and_intervals_do_not() {
        let signed = Int64Array::from(vec![1, -2, 3]);
        let as_type = |data_type: DataType| cast(&signed, &data_type).expect("cast");
        for values in [
            as_type(DataType::Int8),
            Arc::new(UInt64Array::from(vec![1, 2, 3])),
            as_type(DataType::Float16),
            as_type(DataType::Decimal128(10, 2)),
            as_type(DataType::Decimal256(40, 3)),
            Arc::new(DurationMillisecondArray::from(vec![1, -2, 3])),
            as_type(DataType::Dictionary(
                Box::new(DataType::Int32),
                Box::new(DataType::Float32),
            )),
        ] {
            let data_type = values.data_type().clone();
            assert!(has_magnitude(&data_type), "{data_type}");
            let mut seen = Vec::new();
            for_each_magnitude(&values, None, |_, magnitude| seen.push(magnitude))
                .expect("magnitudes");
            assert_eq!(seen, [1.0, 2.0, 3.0], "{data_type}");
        }
        for unit in [
            IntervalUnit::YearMonth,
            IntervalUnit::DayTime,
            IntervalUnit::MonthDayNano,
        ] {
            assert!(!has_magnitude(&DataType::Interval(unit)), "{unit:?}");
        }
        assert!(!has_magnitude(&DataType::Utf8));
        assert!(!has_magnitude(&DataType::Boolean));
    }

    #[test]
    fn a_rule_below_one_percent_is_refused() {
        assert!(matches!(
            PercentRule { p: 0 }.check(),
            Err(QueryError::Disclosure(_))
        ));
        assert_eq!(P10.check().expect("valid"), P10);
    }
}
