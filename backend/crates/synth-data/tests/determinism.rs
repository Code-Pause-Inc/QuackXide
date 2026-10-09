//! The generator's guarantees, checked on decoded Parquet: the same spec
//! gives the same rows, the cohort sits on both sides of k with one dominated
//! group, every value is obviously fake, and each refused spec writes
//! nothing.
//!
//! Comparisons are on decoded record batches, never on file bytes: parquet-rs
//! writes its own version into the file metadata.

use std::collections::{BTreeMap, BTreeSet};

use arrow::array::{Array, AsArray, RecordBatch};
use arrow::compute::concat_batches;
use arrow::datatypes::{Float64Type, Int64Type};
use bytes::Bytes;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use synth_data::{
    BATCH_ROWS, DEFAULT_K, Error, MAX_K, MIN_K, SchemaName, Spec, batches, cohort, parquet_bytes,
    wide, write_parquet,
};

// ── determinism ──────────────────────────────────────────────────────────────

#[test]
fn same_seed_gives_identical_decoded_batches() {
    for spec in [
        Spec::new(SchemaName::Cohort, 7, 20_000),
        Spec::new(SchemaName::Cohort, 7, 20_000).with_k(5),
        Spec::new(SchemaName::Wide, 7, 20_000),
    ] {
        let first = decoded(&spec);
        let second = decoded(&spec);
        assert!(!first.is_empty());
        assert!(first == second, "same seed, different rows: {spec:?}");
    }
}

#[test]
fn a_different_seed_gives_different_rows() {
    for schema in SchemaName::ALL {
        let one = decoded(&Spec::new(schema, 1, 500));
        let two = decoded(&Spec::new(schema, 2, 500));
        assert!(one != two, "{schema}: seeds 1 and 2 gave the same rows");
    }
}

#[test]
fn the_parquet_file_holds_exactly_the_generated_rows() {
    for schema in SchemaName::ALL {
        let spec = Spec::new(schema, 3, 2 * BATCH_ROWS + 5);
        let generated: Vec<RecordBatch> = batches(&spec)
            .expect("valid spec")
            .collect::<Result<_, _>>()
            .expect("generated batches");
        let sizes: Vec<usize> = generated.iter().map(RecordBatch::num_rows).collect();
        assert_eq!(sizes, [BATCH_ROWS, BATCH_ROWS, 5]);
        let written = decoded(&spec);
        assert!(
            concat(&generated) == concat(&written),
            "{schema}: rows changed in Parquet"
        );
    }
}

// ── cohort shape ─────────────────────────────────────────────────────────────

#[test]
fn cohort_groups_sit_on_both_sides_of_k() {
    for (k, rows) in [
        (MIN_K, cohort::min_rows(MIN_K)),
        (5, 1_000),
        (DEFAULT_K, cohort::min_rows(DEFAULT_K)),
        (DEFAULT_K, 5_003),
    ] {
        let batch = one_batch(&Spec::new(SchemaName::Cohort, 11, rows).with_k(k));
        let sizes = group_sizes(&batch);
        assert_eq!(sizes.values().sum::<usize>(), rows);
        for (condition, planned) in cohort::planned_groups(k) {
            assert_eq!(sizes.get(condition), Some(&planned), "k = {k}, {condition}");
        }
        assert!(sizes[cohort::BELOW_K] < k, "k = {k}");
        assert!(sizes[cohort::SINGLETON] < k, "k = {k}");
        assert_eq!(sizes[cohort::AT_K], k);
        assert!(sizes[cohort::ABOVE_K] > k, "k = {k}");
        assert!(sizes[cohort::DOMINATED] >= k, "k = {k}");
        for condition in cohort::COMMON {
            assert!(
                sizes[condition] >= k,
                "k = {k}, {condition}: {}",
                sizes[condition]
            );
        }
        let expected = cohort::planned_groups(k).len() + cohort::COMMON.len();
        assert_eq!(sizes.len(), expected, "unexpected conditions: {sizes:?}");
    }
}

#[test]
fn one_person_dominates_the_dominated_group() {
    for k in [MIN_K, 5, DEFAULT_K, 50] {
        let rows = cohort::min_rows(k) + 37;
        let batch = one_batch(&Spec::new(SchemaName::Cohort, 5, rows).with_k(k));
        for (condition, costs) in costs_by_condition(&batch) {
            let sum: i64 = costs.iter().sum();
            let top = *costs.iter().max().expect("groups are never empty");
            if condition == cohort::DOMINATED {
                // One person holds more than 95% of the group's sum.
                assert!(top * 20 > sum * 19, "k = {k}: top cost {top} of {sum}");
                assert_eq!(costs.iter().filter(|&&cost| cost == top).count(), 1);
            } else if costs.len() >= 2 {
                // Elsewhere nobody holds as much as 2/(m + 1) of the sum.
                let m = costs.len() as i64;
                assert!(
                    top * (m + 1) < 2 * sum,
                    "k = {k}, {condition}: {top} of {sum}"
                );
            }
        }
    }
}

// ── obviously fake values ────────────────────────────────────────────────────

#[test]
fn cohort_values_are_obviously_fake() {
    let rows = 2_000;
    let batch = one_batch(&Spec::new(SchemaName::Cohort, 9, rows));
    let ids = strings(&batch, "person_id");
    let emails = strings(&batch, "email");
    for (id, email) in ids.iter().zip(&emails) {
        let digits = id.strip_prefix('p').expect("ids start with p");
        assert!(
            digits.len() >= 7 && digits.bytes().all(|b| b.is_ascii_digit()),
            "{id}"
        );
        assert_eq!(*email, format!("{id}@cohort.example"));
    }
    assert_eq!(
        ids.iter().collect::<BTreeSet<_>>().len(),
        rows,
        "person ids repeat"
    );
    assert!(
        ints(&batch, "age")
            .iter()
            .all(|age| (18..=90).contains(age))
    );
    let unusual = ints(&batch, "cost_cents")
        .iter()
        .filter(|cost| !(100_000..200_000).contains(*cost))
        .count();
    assert_eq!(
        unusual, 1,
        "only the dominant person's cost leaves $1,000 to $2,000"
    );
}

#[test]
fn wide_values_are_obviously_fake() {
    let rows = 3_000;
    let batch = one_batch(&Spec::new(SchemaName::Wide, 9, rows));
    assert!(ints(&batch, "row_id").iter().copied().eq(0..rows as i64));
    for (row, email) in strings(&batch, "email").iter().enumerate() {
        assert_eq!(*email, format!("u{row:09}@wide.example"));
    }
    assert!(
        strings(&batch, "region")
            .iter()
            .all(|region| wide::REGIONS.contains(region))
    );
    let buckets = 0..wide::BUCKETS as i64;
    assert!(
        ints(&batch, "bucket")
            .iter()
            .all(|bucket| buckets.contains(bucket))
    );
    for i in 0..wide::INT_MEASURES {
        let values = ints(&batch, &format!("i{i:02}"));
        assert!(values.iter().all(|v| (0..1_000_000).contains(v)), "i{i:02}");
    }
    for i in 0..wide::FLOAT_MEASURES {
        let values = floats(&batch, &format!("f{i:02}"));
        assert!(
            values
                .iter()
                .all(|&v| (0.0..100_000.0).contains(&v) && whole_cents(v)),
            "f{i:02}"
        );
    }
}

#[test]
fn schemas_have_the_documented_columns() {
    assert_eq!(
        column_names(SchemaName::Cohort),
        ["person_id", "email", "condition", "age", "cost_cents"]
    );
    let names = column_names(SchemaName::Wide);
    assert_eq!(names.len(), 23);
    assert_eq!(names.len(), 5 + wide::INT_MEASURES + wide::FLOAT_MEASURES);
    assert_eq!(names[..5], ["row_id", "email", "region", "bucket", "flag"]);
    assert_eq!((names[5].as_str(), names[22].as_str()), ("i00", "f05"));
}

// ── refusals: one test each ──────────────────────────────────────────────────

#[test]
fn unknown_schema_names_are_refused() {
    for name in ["bogus", "", "Cohort", "wide "] {
        match name.parse::<SchemaName>() {
            Err(Error::UnknownSchema(got)) => assert_eq!(got, name),
            other => panic!("{name:?}: expected UnknownSchema, got {other:?}"),
        }
    }
    for schema in SchemaName::ALL {
        assert_eq!(schema.name().parse::<SchemaName>().ok(), Some(schema));
    }
}

#[test]
fn k_outside_its_range_is_refused() {
    for k in [0, MIN_K - 1, MAX_K + 1] {
        let error = refusal(Spec::new(SchemaName::Cohort, 1, 1_000).with_k(k));
        assert!(error.to_string().contains(&format!("got {k}")), "{error}");
        match error {
            Error::InvalidK { k: got } => assert_eq!(got, k),
            other => panic!("k = {k}: expected InvalidK, got {other:?}"),
        }
    }
}

#[test]
fn too_few_cohort_rows_are_refused() {
    for k in [MIN_K, 5, DEFAULT_K] {
        let min = cohort::min_rows(k);
        assert_eq!(min, 9 * k + 1);
        match refusal(Spec::new(SchemaName::Cohort, 1, min - 1).with_k(k)) {
            Error::TooFewRows {
                schema,
                rows,
                min: needed,
            } => {
                assert_eq!((schema, rows, needed), (SchemaName::Cohort, min - 1, min));
            }
            other => panic!("k = {k}: expected TooFewRows, got {other:?}"),
        }
        assert!(
            Spec::new(SchemaName::Cohort, 1, min)
                .with_k(k)
                .validate()
                .is_ok()
        );
    }
}

#[test]
fn zero_wide_rows_are_refused() {
    match refusal(Spec::new(SchemaName::Wide, 1, 0)) {
        Error::TooFewRows { schema, rows, min } => {
            assert_eq!((schema, rows, min), (SchemaName::Wide, 0, 1));
        }
        other => panic!("expected TooFewRows, got {other:?}"),
    }
    assert!(Spec::new(SchemaName::Wide, 1, 1).validate().is_ok());
}

#[test]
fn wide_ignores_k() {
    assert!(
        Spec::new(SchemaName::Wide, 1, 10)
            .with_k(0)
            .validate()
            .is_ok()
    );
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Decodes the Parquet that `spec` writes, the way the engine reads it.
fn decoded(spec: &Spec) -> Vec<RecordBatch> {
    let parquet = parquet_bytes(spec).expect("valid spec");
    ParquetRecordBatchReaderBuilder::try_new(Bytes::from(parquet))
        .expect("Parquet footer")
        .build()
        .expect("Parquet reader")
        .collect::<Result<_, _>>()
        .expect("decoded batches")
}

/// The decoded output of `spec` as one batch.
fn one_batch(spec: &Spec) -> RecordBatch {
    concat(&decoded(spec))
}

fn concat(parts: &[RecordBatch]) -> RecordBatch {
    concat_batches(&parts[0].schema(), parts).expect("batches share a schema")
}

/// Every refusal happens at every entry point and before any output.
fn refusal(spec: Spec) -> Error {
    assert!(spec.validate().is_err(), "validate accepted {spec:?}");
    assert!(batches(&spec).is_err(), "batches accepted {spec:?}");
    let mut out: Vec<u8> = Vec::new();
    let error = write_parquet(&spec, &mut out).expect_err("write_parquet accepted it");
    assert!(out.is_empty(), "a refused spec wrote {} bytes", out.len());
    error
}

fn column_names(schema: SchemaName) -> Vec<String> {
    let schema = schema.arrow_schema();
    schema
        .fields()
        .iter()
        .map(|field| field.name().clone())
        .collect()
}

fn strings<'a>(batch: &'a RecordBatch, name: &str) -> Vec<&'a str> {
    let column = batch.column_by_name(name).expect(name).as_string::<i32>();
    assert_eq!(column.null_count(), 0, "{name} has nulls");
    column.iter().flatten().collect()
}

fn ints<'a>(batch: &'a RecordBatch, name: &str) -> &'a [i64] {
    batch
        .column_by_name(name)
        .expect(name)
        .as_primitive::<Int64Type>()
        .values()
}

fn floats<'a>(batch: &'a RecordBatch, name: &str) -> &'a [f64] {
    batch
        .column_by_name(name)
        .expect(name)
        .as_primitive::<Float64Type>()
        .values()
}

/// At most two decimal places.
fn whole_cents(value: f64) -> bool {
    let cents = value * 100.0;
    (cents - cents.round()).abs() < 1e-6
}

/// Rows per `condition`.
fn group_sizes(batch: &RecordBatch) -> BTreeMap<&str, usize> {
    let mut sizes = BTreeMap::new();
    for condition in strings(batch, "condition") {
        *sizes.entry(condition).or_default() += 1;
    }
    sizes
}

/// `cost_cents` per `condition`.
fn costs_by_condition(batch: &RecordBatch) -> BTreeMap<&str, Vec<i64>> {
    let mut costs: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    let conditions = strings(batch, "condition");
    for (condition, &cost) in conditions.into_iter().zip(ints(batch, "cost_cents")) {
        costs.entry(condition).or_default().push(cost);
    }
    costs
}
