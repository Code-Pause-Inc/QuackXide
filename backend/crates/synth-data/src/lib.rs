//! Seeded synthetic Parquet for tests, benchmarks and demos.
//!
//! Dev-only. Every value is invented: ids are sequential, emails use the
//! reserved `.example` domain, and nothing comes from real people
//! (`docs/DATA_POLICY.md`). Two schemas, chosen by [`SchemaName`]:
//!
//! * [`cohort`]: a health-style table built around a cohort threshold `k`
//!   (default [`DEFAULT_K`]), with groups on both sides of it and one group
//!   dominated by a single person.
//! * [`wide`]: 23 mixed-type columns for throughput benchmarks.
//!
//! For a given version of this crate, the same [`Spec`] (schema, seed, rows,
//! k) always gives the same rows. Randomness comes only from ChaCha8 keyed by
//! the seed, and values use integer arithmetic plus correctly rounded
//! division, so they also match across platforms. Compare decoded record
//! batches, not Parquet bytes: parquet-rs writes its version into the file
//! metadata.
//!
//! Write large outputs to a gitignored directory such as `backend/target/`.
//! Small committed outputs go under `fixtures/`, with their schema and
//! generation command recorded next to them.

use std::fmt;
use std::io::Write;
use std::str::FromStr;

use arrow::datatypes::SchemaRef;
use arrow::error::ArrowError;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::errors::ParquetError;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

/// Default cohort threshold. Mirrors `DEFAULT_MIN_COHORT_SIZE` in
/// `platform-config` and `RESEARCH_MIN_COHORT_SIZE` in `backend/.env.example`;
/// this crate cannot depend on `platform-config`, so change them together.
pub const DEFAULT_K: usize = 11;

/// Smallest `k` the cohort accepts, so its k - 1 group has a row.
pub const MIN_K: usize = 2;

/// Largest `k` the cohort accepts. It keeps every size and cost far inside
/// `i64`.
pub const MAX_K: usize = 1_000_000;

/// Rows per record batch. The generated values do not depend on it.
pub const BATCH_ROWS: usize = 8192;

// Key tags that give the cohort's row layout and the row values separate
// ChaCha8 streams.
const LAYOUT_STREAM: u64 = 1;
const VALUES_STREAM: u64 = 2;

/// A table this crate can generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaName {
    /// See [`cohort`].
    Cohort,
    /// See [`wide`].
    Wide,
}

impl SchemaName {
    /// Every schema, in the order the command line lists them.
    pub const ALL: [SchemaName; 2] = [SchemaName::Cohort, SchemaName::Wide];

    /// The name used on the command line and in fixture records.
    pub fn name(self) -> &'static str {
        match self {
            SchemaName::Cohort => "cohort",
            SchemaName::Wide => "wide",
        }
    }

    /// The Arrow schema of every batch.
    pub fn arrow_schema(self) -> SchemaRef {
        match self {
            SchemaName::Cohort => cohort::schema(),
            SchemaName::Wide => wide::schema(),
        }
    }
}

impl fmt::Display for SchemaName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.name())
    }
}

impl FromStr for SchemaName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SchemaName::ALL
            .into_iter()
            .find(|schema| schema.name() == s)
            .ok_or_else(|| Error::UnknownSchema(s.to_owned()))
    }
}

/// What to generate. For a given version of this crate, the same spec always
/// gives the same rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    /// Which table.
    pub schema: SchemaName,
    /// Seeds every random choice.
    pub seed: u64,
    /// Total rows.
    pub rows: usize,
    /// Threshold the cohort's group sizes are built around. `wide` ignores
    /// it.
    pub k: usize,
}

impl Spec {
    /// A spec with the default threshold, [`DEFAULT_K`].
    pub fn new(schema: SchemaName, seed: u64, rows: usize) -> Self {
        Self {
            schema,
            seed,
            rows,
            k: DEFAULT_K,
        }
    }

    /// The same spec with threshold `k`.
    pub fn with_k(self, k: usize) -> Self {
        Self { k, ..self }
    }

    /// Refuses a cohort `k` outside [`MIN_K`]..=[`MAX_K`], and too few rows:
    /// the cohort needs [`cohort::min_rows`], `wide` at least one.
    pub fn validate(&self) -> Result<(), Error> {
        let min = match self.schema {
            SchemaName::Cohort => {
                if !(MIN_K..=MAX_K).contains(&self.k) {
                    return Err(Error::InvalidK { k: self.k });
                }
                cohort::min_rows(self.k)
            }
            SchemaName::Wide => 1,
        };
        if self.rows < min {
            return Err(Error::TooFewRows {
                schema: self.schema,
                rows: self.rows,
                min,
            });
        }
        Ok(())
    }
}

/// Validates `spec` and returns its batches, built as they are read.
pub fn batches(spec: &Spec) -> Result<Batches, Error> {
    spec.validate()?;
    let layout = match spec.schema {
        SchemaName::Cohort => Layout::Cohort(cohort::Plan::new(spec)),
        SchemaName::Wide => Layout::Wide,
    };
    Ok(Batches {
        schema: spec.schema.arrow_schema(),
        rows: spec.rows,
        next_row: 0,
        values: chacha(spec.seed, VALUES_STREAM),
        layout,
    })
}

/// Writes `spec` to `out` as one Parquet file, a batch at a time, with
/// parquet-rs's default writer settings.
pub fn write_parquet<W: Write + Send>(spec: &Spec, out: W) -> Result<(), Error> {
    let source = batches(spec)?;
    let mut writer = ArrowWriter::try_new(out, source.schema(), None)?;
    for batch in source {
        writer.write(&batch?)?;
    }
    writer.close()?;
    Ok(())
}

/// `spec` as in-memory Parquet, for example for
/// `QueryScope::register_parquet` or for sealing in a test.
pub fn parquet_bytes(spec: &Spec) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    write_parquet(spec, &mut buf)?;
    Ok(buf)
}

/// Batches of at most [`BATCH_ROWS`] rows, built on demand so large outputs
/// stream straight into the Parquet writer.
pub struct Batches {
    schema: SchemaRef,
    rows: usize,
    next_row: usize,
    values: ChaCha8Rng,
    layout: Layout,
}

enum Layout {
    Cohort(cohort::Plan),
    Wide,
}

impl Batches {
    /// The Arrow schema of every batch.
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }
}

impl Iterator for Batches {
    type Item = Result<RecordBatch, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_row >= self.rows {
            return None;
        }
        let rows = self.next_row..self.next_row.saturating_add(BATCH_ROWS).min(self.rows);
        self.next_row = rows.end;
        let columns = match &self.layout {
            Layout::Cohort(plan) => plan.columns(&mut self.values, rows),
            Layout::Wide => wide::columns(&mut self.values, rows),
        };
        let batch = RecordBatch::try_new(self.schema.clone(), columns);
        Some(batch.map_err(Error::from))
    }
}

/// Why a spec was refused or could not be written.
#[derive(Debug)]
pub enum Error {
    /// Not one of [`SchemaName::ALL`].
    UnknownSchema(String),
    /// A cohort `k` outside [`MIN_K`]..=[`MAX_K`].
    InvalidK { k: usize },
    /// Fewer rows than the schema needs.
    TooFewRows {
        schema: SchemaName,
        rows: usize,
        min: usize,
    },
    /// Building a record batch failed.
    Arrow(ArrowError),
    /// Writing Parquet failed, including I/O errors from the output.
    Parquet(ParquetError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownSchema(name) => {
                write!(f, "unknown schema {name:?}; expected one of:")?;
                for schema in SchemaName::ALL {
                    write!(f, " {schema}")?;
                }
                Ok(())
            }
            Error::InvalidK { k } => write!(f, "k must be in {MIN_K}..={MAX_K}, got {k}"),
            Error::TooFewRows { schema, rows, min } => {
                write!(
                    f,
                    "the {schema} schema needs at least {min} rows, got {rows}"
                )
            }
            Error::Arrow(e) => write!(f, "building a record batch failed: {e}"),
            Error::Parquet(e) => write!(f, "writing Parquet failed: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Arrow(e) => Some(e),
            Error::Parquet(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ArrowError> for Error {
    fn from(e: ArrowError) -> Self {
        Error::Arrow(e)
    }
}

impl From<ParquetError> for Error {
    fn from(e: ParquetError) -> Self {
        Error::Parquet(e)
    }
}

/// ChaCha8 keyed by the seed and a stream tag, little-endian. Output depends
/// only on the ChaCha8 algorithm, not on how a `rand` release expands seeds.
fn chacha(seed: u64, stream: u64) -> ChaCha8Rng {
    let mut key = [0u8; 32];
    key[..8].copy_from_slice(&seed.to_le_bytes());
    key[8..16].copy_from_slice(&stream.to_le_bytes());
    ChaCha8Rng::from_seed(key)
}

/// Uniform in `0..n` for `n > 0`, by rejection sampling, so the result is
/// exact and fixed by the ChaCha8 stream.
fn below(rng: &mut ChaCha8Rng, n: u64) -> u64 {
    // Rejecting values under 2^64 mod n leaves a whole number of copies of
    // 0..n to reduce.
    let reject_under = n.wrapping_neg() % n;
    loop {
        let x = rng.next_u64();
        if x >= reject_under {
            return x % n;
        }
    }
}

/// Fisher-Yates shuffle.
fn shuffle(labels: &mut [u8], rng: &mut ChaCha8Rng) {
    for i in (1..labels.len()).rev() {
        let j = below(rng, i as u64 + 1) as usize;
        labels.swap(i, j);
    }
}

pub mod cohort {
    //! The `cohort` schema: one row per invented person, built around a
    //! cohort threshold `k`.
    //!
    //! Columns: `person_id` (Utf8, `p0000001`), `email` (Utf8,
    //! `p0000001@cohort.example`), `condition` (Utf8), `age` (Int64, 18 to
    //! 90) and `cost_cents` (Int64). `GROUP BY condition` gives:
    //!
    //! | `condition` | Rows | Under `MinCountThreshold { k }` |
    //! | --- | --- | --- |
    //! | [`BELOW_K`] | k - 1 | Suppressed |
    //! | [`AT_K`] | k | Released (the smallest released size) |
    //! | [`ABOVE_K`] | k + 1 | Released |
    //! | [`SINGLETON`] | 1 | Suppressed |
    //! | [`DOMINATED`] | 2k | Released, though one person holds over 95% of `SUM(cost_cents)` |
    //! | Each of [`COMMON`] | At least k; they share the remaining rows | Released |
    //!
    //! Everyone else has `cost_cents` in `100_000..200_000` ($1,000 to
    //! $2,000), so in any other group of m >= 2 people no one holds as much
    //! as 2/(m + 1) of the sum. Rows are shuffled, so group membership does
    //! not follow `person_id` order.

    use std::ops::Range;
    use std::sync::Arc;

    use arrow::array::{ArrayRef, Int64Builder, StringBuilder};
    use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
    use rand_chacha::ChaCha8Rng;

    use super::{LAYOUT_STREAM, Spec, below, chacha, shuffle};

    /// k - 1 rows: suppressed.
    pub const BELOW_K: &str = "lupus";
    /// Exactly k rows: the smallest released group.
    pub const AT_K: &str = "celiac";
    /// k + 1 rows: released.
    pub const ABOVE_K: &str = "gout";
    /// One row: suppressed. The hand-built test cohort uses the same label.
    pub const SINGLETON: &str = "rare_disease";
    /// 2k rows, one of whom holds over 95% of the group's `cost_cents`.
    pub const DOMINATED: &str = "transplant";
    /// Conditions that share the remaining rows, at least k each.
    pub const COMMON: [&str; 4] = ["flu", "asthma", "diabetes", "hypertension"];

    // Per-row labels index this table: the planned groups in
    // `planned_sizes` order, then `COMMON`.
    const CONDITIONS: [&str; 9] = [
        BELOW_K, AT_K, ABOVE_K, SINGLETON, DOMINATED, COMMON[0], COMMON[1], COMMON[2], COMMON[3],
    ];
    const DOMINATED_LABEL: u8 = 4;
    const COMMON_LABELS: [u8; 4] = [5, 6, 7, 8];

    const AGE_MIN: i64 = 18;
    const AGE_SPAN: u64 = 73;
    const COST_MIN_CENTS: i64 = 100_000;
    const COST_SPAN_CENTS: u64 = 100_000;
    // Exclusive upper bound of every cost but the dominant one.
    const COST_LIMIT_CENTS: i64 = COST_MIN_CENTS + COST_SPAN_CENTS as i64;
    // The dominant cost is this many times the most that everyone else in
    // the group could hold together, so its share of the sum is over 19/20.
    const DOMINANCE_FACTOR: i64 = 19;

    /// The five planned groups and their sizes for threshold `k`.
    pub fn planned_groups(k: usize) -> [(&'static str, usize); 5] {
        let sizes = planned_sizes(k);
        std::array::from_fn(|i| (CONDITIONS[i], sizes[i]))
    }

    /// Fewest rows for threshold `k`: the planned groups plus k rows for each
    /// common group, which is 9k + 1.
    pub fn min_rows(k: usize) -> usize {
        planned_sizes(k)
            .into_iter()
            .fold(COMMON.len().saturating_mul(k), usize::saturating_add)
    }

    fn planned_sizes(k: usize) -> [usize; 5] {
        [
            k.saturating_sub(1),
            k,
            k.saturating_add(1),
            1,
            k.saturating_mul(2),
        ]
    }

    pub(crate) fn schema() -> SchemaRef {
        Arc::new(Schema::new(vec![
            Field::new("person_id", DataType::Utf8, false),
            Field::new("email", DataType::Utf8, false),
            Field::new("condition", DataType::Utf8, false),
            Field::new("age", DataType::Int64, false),
            Field::new("cost_cents", DataType::Int64, false),
        ]))
    }

    /// Each row's condition, and who the dominant person is.
    pub(crate) struct Plan {
        labels: Vec<u8>,
        dominant_row: usize,
        dominant_cost: i64,
    }

    impl Plan {
        /// `spec` must already be validated.
        pub(crate) fn new(spec: &Spec) -> Self {
            let sizes = planned_sizes(spec.k);
            let mut labels = Vec::with_capacity(spec.rows);
            for (label, size) in (0u8..).zip(sizes) {
                labels.resize(labels.len() + size, label);
            }
            let common_rows = spec.rows - labels.len();
            labels.extend(COMMON_LABELS.into_iter().cycle().take(common_rows));
            shuffle(&mut labels, &mut chacha(spec.seed, LAYOUT_STREAM));

            let dominant_row = labels
                .iter()
                .position(|&label| label == DOMINATED_LABEL)
                .expect("the dominated group has 2k rows");
            let others = sizes[usize::from(DOMINATED_LABEL)] - 1;
            let dominant_cost = DOMINANCE_FACTOR * others as i64 * COST_LIMIT_CENTS;
            Self {
                labels,
                dominant_row,
                dominant_cost,
            }
        }

        pub(crate) fn columns(&self, rng: &mut ChaCha8Rng, rows: Range<usize>) -> Vec<ArrayRef> {
            let n = rows.len();
            let mut person_id = StringBuilder::with_capacity(n, n * 8);
            let mut email = StringBuilder::with_capacity(n, n * 24);
            let mut condition = StringBuilder::with_capacity(n, n * 12);
            let mut age = Int64Builder::with_capacity(n);
            let mut cost_cents = Int64Builder::with_capacity(n);
            for row in rows {
                // One fixed draw order per row, so values do not depend on
                // the batch size.
                age.append_value(AGE_MIN + below(rng, AGE_SPAN) as i64);
                let drawn = COST_MIN_CENTS + below(rng, COST_SPAN_CENTS) as i64;
                let cost = if row == self.dominant_row {
                    self.dominant_cost
                } else {
                    drawn
                };
                cost_cents.append_value(cost);
                let number = row + 1;
                let id = format!("p{number:07}");
                email.append_value(format!("{id}@cohort.example"));
                person_id.append_value(id);
                condition.append_value(CONDITIONS[usize::from(self.labels[row])]);
            }
            vec![
                Arc::new(person_id.finish()),
                Arc::new(email.finish()),
                Arc::new(condition.finish()),
                Arc::new(age.finish()),
                Arc::new(cost_cents.finish()),
            ]
        }
    }
}

pub mod wide {
    //! The `wide` schema: 23 mixed-type columns for throughput benchmarks.
    //!
    //! `row_id` (Int64, `0..rows`), `email` (Utf8, `u000000042@wide.example`),
    //! `region` (Utf8, one of [`REGIONS`]), `bucket` (Int64, `0..BUCKETS`),
    //! `flag` (Boolean), `i00` to `i11` (Int64, `0..1_000_000`) and `f00` to
    //! `f05` (Float64, two decimal places, below 100,000). Grouping by
    //! `region` gives about rows / 8 per group and by `bucket` about
    //! rows / 100, so at benchmark sizes no group falls below k.

    use std::ops::Range;
    use std::sync::Arc;

    use arrow::array::{ArrayRef, BooleanBuilder, Float64Builder, Int64Builder, StringBuilder};
    use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
    use rand_chacha::ChaCha8Rng;
    use rand_chacha::rand_core::RngCore;

    use super::below;

    /// Values of `region`.
    pub const REGIONS: [&str; 8] = [
        "north", "south", "east", "west", "central", "coastal", "highland", "island",
    ];
    /// `bucket` takes values in `0..BUCKETS`.
    pub const BUCKETS: u64 = 100;
    /// Int64 measure columns, named `i00` onward.
    pub const INT_MEASURES: usize = 12;
    /// Float64 measure columns, named `f00` onward.
    pub const FLOAT_MEASURES: usize = 6;

    const INT_SPAN: u64 = 1_000_000;
    const FLOAT_SPAN_CENTS: u64 = 10_000_000;

    pub(crate) fn schema() -> SchemaRef {
        let mut fields = vec![
            Field::new("row_id", DataType::Int64, false),
            Field::new("email", DataType::Utf8, false),
            Field::new("region", DataType::Utf8, false),
            Field::new("bucket", DataType::Int64, false),
            Field::new("flag", DataType::Boolean, false),
        ];
        for i in 0..INT_MEASURES {
            fields.push(Field::new(format!("i{i:02}"), DataType::Int64, false));
        }
        for i in 0..FLOAT_MEASURES {
            fields.push(Field::new(format!("f{i:02}"), DataType::Float64, false));
        }
        Arc::new(Schema::new(fields))
    }

    pub(crate) fn columns(rng: &mut ChaCha8Rng, rows: Range<usize>) -> Vec<ArrayRef> {
        let n = rows.len();
        let mut row_id = Int64Builder::with_capacity(n);
        let mut email = StringBuilder::with_capacity(n, n * 24);
        let mut region = StringBuilder::with_capacity(n, n * 8);
        let mut bucket = Int64Builder::with_capacity(n);
        let mut flag = BooleanBuilder::with_capacity(n);
        let mut ints: Vec<Int64Builder> = (0..INT_MEASURES)
            .map(|_| Int64Builder::with_capacity(n))
            .collect();
        let mut floats: Vec<Float64Builder> = (0..FLOAT_MEASURES)
            .map(|_| Float64Builder::with_capacity(n))
            .collect();
        for row in rows {
            // One fixed draw order per row, so values do not depend on the
            // batch size.
            row_id.append_value(row as i64);
            email.append_value(format!("u{row:09}@wide.example"));
            region.append_value(REGIONS[below(rng, REGIONS.len() as u64) as usize]);
            bucket.append_value(below(rng, BUCKETS) as i64);
            flag.append_value((rng.next_u32() & 1) == 1);
            for measure in &mut ints {
                measure.append_value(below(rng, INT_SPAN) as i64);
            }
            for measure in &mut floats {
                // Whole cents, then one correctly rounded division.
                measure.append_value(below(rng, FLOAT_SPAN_CENTS) as f64 / 100.0);
            }
        }
        let mut columns: Vec<ArrayRef> = vec![
            Arc::new(row_id.finish()),
            Arc::new(email.finish()),
            Arc::new(region.finish()),
            Arc::new(bucket.finish()),
            Arc::new(flag.finish()),
        ];
        columns.extend(ints.iter_mut().map(|b| Arc::new(b.finish()) as ArrayRef));
        columns.extend(floats.iter_mut().map(|b| Arc::new(b.finish()) as ArrayRef));
        columns
    }
}
