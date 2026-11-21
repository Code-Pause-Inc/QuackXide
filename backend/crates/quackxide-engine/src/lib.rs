//! quackxide-engine: the zero-trust query engine core.
//!
//! Deployments are white-labeled: the engine name may appear in crate names,
//! logs, and engineering docs, never in customer-facing strings. Public
//! naming flows from `platform-config::BrandConfig`, and `scripts/check.sh`
//! enforces this on the shipped frontend bundle.
//!
//! A [`QueryScope`] owns a DataFusion `SessionContext` over Parquet
//! decrypted inside the attested enclave. Two paths:
//!
//! * **Ciphertext scan**: equality over a blind-index column ([`blind`]);
//!   the engine never sees plaintext.
//! * **In-enclave analytics**: SQL over the decrypted data, which lives only
//!   for the scope's lifetime. In `ZkMode::Enabled` the [`policy`] gate
//!   restricts results to aggregates, and [`disclosure`] requires a genuine
//!   `COUNT(*) AS n` and suppresses cohorts below the minimum size.
//!
//! Registering a table reads only its Parquet footers. A query decodes the
//! columns it reads, and no others, once its plan has passed every gate.
//!
//! A scope enforces its share of the [`QueryLimits`]: the footers of the
//! columns a query reads must fit the decode limits before any of them is
//! decoded, operators run in a fixed memory pool with nothing spilled to
//! disk, and a result over the row or byte limit is refused, never
//! truncated.

use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use arrow::array::{RecordBatch, RecordBatchOptions};
use arrow::datatypes::{DataType, Schema, SchemaRef};
use async_trait::async_trait;
use bytes::Bytes;
use datafusion::catalog::{Session, TableProvider};
use datafusion::common::config::ConfigOptions;
use datafusion::common::{DataFusionError, exec_err, internal_err};
use datafusion::dataframe::DataFrame;
use datafusion::datasource::memory::MemorySourceConfig;
use datafusion::execution::SessionStateBuilder;
use datafusion::execution::disk_manager::{DiskManagerBuilder, DiskManagerMode};
use datafusion::execution::memory_pool::GreedyMemoryPool;
use datafusion::execution::object_store::ObjectStoreRegistry;
use datafusion::execution::runtime_env::{RuntimeEnv, RuntimeEnvBuilder};
use datafusion::logical_expr::{Expr, TableType};
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::coop::CooperativeExec;
use datafusion::physical_plan::execution_plan::SchedulingType;
use datafusion::physical_plan::{ExecutionPlan, replace_children_if_necessary};
use datafusion::prelude::{SQLOptions, SessionConfig, SessionContext};
use futures::StreamExt;
use object_store::ObjectStore;
use parquet::arrow::ProjectionMask;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReader,
    ParquetRecordBatchReaderBuilder,
};
use parquet::file::metadata::{ParquetMetaData, ParquetStatisticsPolicy};
use platform_core::{ColumnType, DeclaredSchema, ZkMode};
use platform_crypto::{SecretBytes, ZeroizingWriter};
use url::Url;

pub mod blind;
pub mod disclosure;
pub mod policy;

pub use blind::blind_index_hex;
pub use disclosure::{DisclosurePolicy, MinCountThreshold};
pub use platform_core::{QueryLimit, QueryLimits};

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("parquet decode failed while {0}")]
    Parquet(ParquetStage),
    #[error("query failed while {0}")]
    Execution(ExecutionStage),
    #[error("result serialization failed: {0}")]
    Serialize(String),
    #[error("query rejected: row-level egress is not permitted in zero-knowledge mode")]
    ZkPolicy,
    #[error("query rejected by disclosure control: {0}")]
    Disclosure(String),
    #[error("query rejected: only read-only queries are permitted")]
    StatementNotAllowed,
    /// The decrypted data does not match what the steward declared for it.
    /// Names the check, never a column.
    #[error("dataset does not match its declared {0}")]
    DeclarationMismatch(Declaration),
    /// The query needs more than one of its [`QueryLimits`] allows: too
    /// much to decode, more memory than the scope's pool, or too large a
    /// result.
    #[error("query exceeded its {0} limit")]
    LimitExceeded(QueryLimit),
}

/// Which part of a steward's declaration the data failed
/// ([`QueryError::DeclarationMismatch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declaration {
    Schema,
    RowCap,
}

impl fmt::Display for Declaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Declaration::Schema => "schema",
            Declaration::RowCap => "row cap",
        })
    }
}

/// Where decoding a Parquet blob failed. Holds no upstream message, which
/// could quote the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParquetStage {
    Metadata,
    /// The objects of one table do not share their columns.
    Schema,
    Reader,
    Batch,
}

impl fmt::Display for ParquetStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParquetStage::Metadata => "reading metadata",
            ParquetStage::Schema => "matching the objects' schemas",
            ParquetStage::Reader => "building the reader",
            ParquetStage::Batch => "decoding a batch",
        })
    }
}

/// Where loading, planning or running a query failed. Holds no upstream
/// message: DataFusion errors can quote SQL literals, and Arrow cast errors
/// quote cell values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStage {
    LoadTable,
    Plan,
    Execute,
}

impl fmt::Display for ExecutionStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ExecutionStage::LoadTable => "loading the table",
            ExecutionStage::Plan => "planning",
            ExecutionStage::Execute => "executing",
        })
    }
}

/// No `Default`: every caller chooses the ZK mode explicitly.
#[derive(Debug, Clone)]
pub struct EngineSettings {
    /// Platform default comes from `FEATURE_ZK_ENABLED`; callers may override
    /// it per scope.
    pub zk: ZkMode,
    pub max_concurrent_queries: usize,
    /// Per-query limits. A scope applies the memory, decode and result
    /// limits; the query service applies the slot wait, the time limit and
    /// the input limits before anything reaches a scope.
    pub limits: QueryLimits,
}

/// RAII scope for one query session.
///
/// Each table keeps the engine's zeroizing copy of its decrypted Parquet and
/// the footers parsed from it. A query decodes from them only the columns
/// it reads, into Arrow arrays its plan holds until the query ends. `Drop`
/// deregisters every table, releasing those copies (wiped as they go), so
/// decrypted data does not outlive the scope. The caller's decrypted input
/// stays its own.
///
/// The scope's runtime holds no object store, so no plan reaches the host's
/// files, and has no disk: its memory pool is
/// [`QueryLimits::memory_bytes`], and an operator that would spill to a
/// temporary file fails with [`QueryLimit::Memory`] instead, so decrypted
/// rows never reach the disk.
pub struct QueryScope {
    ctx: SessionContext,
    settings: EngineSettings,
    tables: Vec<String>,
    disclosure: Option<Arc<dyn DisclosurePolicy>>,
    /// Rows withheld by disclosure control in the most recent query.
    last_suppressed_rows: AtomicUsize,
}

impl QueryScope {
    pub fn new(settings: EngineSettings) -> Self {
        // `sql` gives each query a decode budget of its own. A plan built
        // through the context directly shares this one for the scope's
        // lifetime, so no scan goes unbudgeted.
        let config =
            SessionConfig::new().with_extension(Arc::new(DecodeBudget::new(&settings.limits)));
        let state = SessionStateBuilder::new()
            .with_config(config)
            .with_runtime_env(scope_runtime(&settings.limits))
            .with_default_features()
            .with_physical_optimizer_rule(Arc::new(YieldEveryBatch))
            .build();
        Self {
            ctx: SessionContext::new_with_state(state),
            settings,
            tables: Vec::new(),
            disclosure: None,
            last_suppressed_rows: AtomicUsize::new(0),
        }
    }

    /// Attach a result-egress disclosure policy. Required in
    /// `ZkMode::Enabled`; attaching one also activates the aggregate-only
    /// and `COUNT(*) AS n` plan requirements.
    pub fn set_disclosure(&mut self, policy: Arc<dyn DisclosurePolicy>) {
        self.disclosure = Some(policy);
    }

    pub fn last_suppressed_rows(&self) -> usize {
        self.last_suppressed_rows.load(Ordering::Relaxed)
    }

    pub fn settings(&self) -> &EngineSettings {
        &self.settings
    }

    /// Register in-enclave decrypted Parquet as `table`. Returns the rows
    /// its footer reports.
    pub fn register_parquet(&mut self, table: &str, parquet: &[u8]) -> Result<usize, QueryError> {
        self.register_parquet_many(table, std::slice::from_ref(&parquet))
    }

    /// Register several Parquet blobs as one table, one partition per blob.
    /// Zero blobs is a no-op returning 0. Returns the rows the footers
    /// report.
    ///
    /// Only the footers are read here; nothing is decoded until a query
    /// reads the table (see [`sql`](Self::sql)). Every blob must have the
    /// first one's columns (names, types and nullability, in order), or
    /// the table is refused as [`QueryError::Parquet`]: the stored data is
    /// at fault, not the caller. The rows the footers report, summed, must
    /// fit [`QueryLimits::max_decoded_rows`], since every query decodes
    /// every row of the columns it reads
    /// ([`QueryError::LimitExceeded`]).
    pub fn register_parquet_many(
        &mut self,
        table: &str,
        blobs: &[&[u8]],
    ) -> Result<usize, QueryError> {
        self.register(table, blobs, None)
    }

    /// As [`register_parquet_many`](Self::register_parquet_many), for a
    /// dataset whose shape a steward declared (ADR 0012). Each blob's schema
    /// must match `schema` (names in order, and [`ColumnType`] families),
    /// and the rows its footer reports, summed, must not exceed `row_cap`,
    /// both checked here, from the footers. Each scan counts the rows it
    /// decodes against `row_cap` again. A failure is
    /// [`QueryError::DeclarationMismatch`], which takes precedence over a
    /// decode limit.
    pub fn register_parquet_declared(
        &mut self,
        table: &str,
        blobs: &[&[u8]],
        schema: &DeclaredSchema,
        row_cap: u64,
    ) -> Result<usize, QueryError> {
        self.register(table, blobs, Some((schema, row_cap)))
    }

    fn register(
        &mut self,
        table: &str,
        blobs: &[&[u8]],
        declared: Option<(&DeclaredSchema, u64)>,
    ) -> Result<usize, QueryError> {
        if blobs.is_empty() {
            return Ok(0);
        }
        let row_cap = declared.map(|(_, row_cap)| row_cap);

        // Footers only: no column is decoded here.
        let mut objects: Vec<ParquetObject> = Vec::with_capacity(blobs.len());
        let mut rows = 0u64;
        for blob in blobs {
            let object = ParquetObject::read_footer(blob)?;
            if let Some((declared_schema, _)) = declared
                && !matches_declared(object.schema(), declared_schema)
            {
                return Err(QueryError::DeclarationMismatch(Declaration::Schema));
            }
            if let Some(first) = objects.first()
                && !same_columns(first.schema(), object.schema())
            {
                return Err(QueryError::Parquet(ParquetStage::Schema));
            }
            rows = rows.saturating_add(object.rows);
            objects.push(object);
        }
        // The declaration first: data unlike it is a stored fault, whatever
        // its size.
        if row_cap.is_some_and(|cap| rows > cap) {
            return Err(QueryError::DeclarationMismatch(Declaration::RowCap));
        }
        if rows > self.settings.limits.max_decoded_rows {
            return Err(QueryError::LimitExceeded(QueryLimit::DecodedRows));
        }

        let table_provider = ParquetTable::new(objects, rows, row_cap);
        self.ctx
            .register_table(table, Arc::new(table_provider))
            .map_err(|_| QueryError::Execution(ExecutionStage::LoadTable))?;
        self.tables.push(table.to_owned());
        Ok(usize::try_from(rows).unwrap_or(usize::MAX))
    }

    /// Run SQL over the registered tables. In `ZkMode::Enabled`, or with a
    /// disclosure policy attached, the plan must pass the aggregate-only
    /// allowlist and carry a genuine `COUNT(*) AS n`, a disclosure policy is
    /// required, and results pass through it before egress. A result with
    /// more rows than [`QueryLimits::max_result_rows`] after disclosure
    /// control is refused, as is a query whose operators run out of the
    /// scope's memory pool. Without a disclosure policy the result is
    /// refused as soon as it passes the row limit, and the plan stops.
    ///
    /// Nothing is decoded until every check above that comes before
    /// execution has passed. Each table scan in the plan then decodes, from
    /// every object, only the columns the query reads. Before it decodes
    /// any, the rows and uncompressed bytes the footers report for those
    /// columns, summed over the query's scans (a table read twice counts
    /// twice), must fit [`QueryLimits::max_decoded_rows`] and
    /// [`QueryLimits::max_decoded_bytes`], since the memory pool does not
    /// track decoded columns. Decoding is synchronous, so these limits also
    /// bound how long it runs. A refusal is [`QueryError::LimitExceeded`]; a
    /// stored object that fails to decode is [`QueryError::Parquet`], never
    /// an error in the caller's SQL.
    ///
    /// Dropping the returned future stops the plan at its next batch
    /// boundary: every operator yields to the runtime as it produces batches
    /// (`YieldEveryBatch`), so a time limit applied around this call is
    /// enforced while the plan runs.
    pub async fn sql(&self, query: &str) -> Result<Vec<RecordBatch>, QueryError> {
        self.last_suppressed_rows.store(0, Ordering::Relaxed);

        // The query's own decode budget, which every scan in its plan draws
        // on.
        let mut query_state = self.ctx.state();
        query_state
            .config_mut()
            .set_extension(Arc::new(DecodeBudget::new(&self.settings.limits)));

        // Plan without executing, then refuse anything but a read-only query
        // in every mode. `SessionContext::execute_logical_plan` would run
        // DDL, `SET` and `PREPARE` while turning a plan into a DataFrame; it
        // only wraps a read-only plan, which is a query, as this does.
        let plan = query_state
            .create_logical_plan(query)
            .await
            .map_err(|err| datafusion_error(ExecutionStage::Plan, &err))?;
        read_only()
            .verify_plan(&plan)
            .map_err(|_| QueryError::StatementNotAllowed)?;
        let df = DataFrame::new(query_state, plan);

        let gated = self.settings.zk.is_enabled() || self.disclosure.is_some();
        if gated {
            if !policy::is_aggregate_only(df.logical_plan()) {
                return Err(QueryError::ZkPolicy);
            }
            disclosure::verify_count_column(df.logical_plan())?;
            // Coercion inserts casts that can fail, so check the analyzed plan
            // (ADR 0011).
            let state = self.ctx.state();
            let analyzed = state
                .analyzer()
                .execute_and_check(df.logical_plan().clone(), state.config_options(), |_, _| {})
                .map_err(|err| datafusion_error(ExecutionStage::Plan, &err))?;
            if !policy::expressions_cannot_fail(&analyzed) {
                return Err(QueryError::ZkPolicy);
            }
        }
        let disclosure = match (&self.disclosure, gated) {
            (Some(policy), _) => Some(policy),
            (None, false) => None,
            (None, true) => {
                return Err(QueryError::Disclosure(
                    "zero-knowledge mode requires a disclosure policy".into(),
                ));
            }
        };

        // The pool does not track rows collected for the result. Without a
        // disclosure policy those rows are the result, so the query stops at
        // the first row over the limit. A policy has to see the whole
        // aggregate, whose groups the pool held while they were computed.
        let max_rows = self.settings.limits.max_result_rows;
        let mut stream = df
            .execute_stream()
            .await
            .map_err(|err| datafusion_error(ExecutionStage::Execute, &err))?;
        let mut batches = Vec::new();
        let mut rows = 0u64;
        while let Some(batch) = stream.next().await {
            let batch = batch.map_err(|err| datafusion_error(ExecutionStage::Execute, &err))?;
            rows = rows.saturating_add(u64::try_from(batch.num_rows()).unwrap_or(u64::MAX));
            if disclosure.is_none() && rows > max_rows {
                return Err(QueryError::LimitExceeded(QueryLimit::ResultRows));
            }
            batches.push(batch);
        }
        drop(stream);

        let batches = match disclosure {
            None => batches,
            Some(policy) => {
                let outcome = policy.apply(batches)?;
                self.last_suppressed_rows
                    .store(outcome.suppressed_rows, Ordering::Relaxed);
                outcome.batches
            }
        };
        // Refused rather than cut short: a partial result would look whole.
        let rows: usize = batches.iter().map(RecordBatch::num_rows).sum();
        if u64::try_from(rows).unwrap_or(u64::MAX) > max_rows {
            return Err(QueryError::LimitExceeded(QueryLimit::ResultRows));
        }
        Ok(batches)
    }

    /// Run a query and serialize its result rows to JSON. A result whose
    /// JSON would exceed [`QueryLimits::max_result_bytes`] is refused; the
    /// serializer stops at the limit rather than finishing first.
    pub async fn sql_json(&self, query: &str) -> Result<serde_json::Value, QueryError> {
        let batches = self.sql(query).await?;
        let max_bytes =
            usize::try_from(self.settings.limits.max_result_bytes).unwrap_or(usize::MAX);
        rows_to_json(&batches, max_bytes)
    }
}

impl Drop for QueryScope {
    fn drop(&mut self) {
        for table in &self.tables {
            let _ = self.ctx.deregister_table(table.as_str());
        }
    }
}

/// Whether a decoded Arrow schema is the one a steward declared: the same
/// column names in the same order, each of the declared type family. A
/// column of a type no family covers never matches.
fn matches_declared(actual: &Schema, declared: &DeclaredSchema) -> bool {
    let columns = declared.columns();
    actual.fields().len() == columns.len()
        && actual.fields().iter().zip(columns).all(|(field, column)| {
            field.name() == &column.name
                && column_type_of(field.data_type()) == Some(column.column_type)
        })
}

/// Whether two objects' schemas have the same columns: names, types and
/// nullability, in order. Their metadata may differ.
fn same_columns(first: &Schema, other: &Schema) -> bool {
    first.fields().len() == other.fields().len()
        && first.fields().iter().zip(other.fields()).all(|(a, b)| {
            a.name() == b.name()
                && a.data_type() == b.data_type()
                && a.is_nullable() == b.is_nullable()
        })
}

/// The declared type family an Arrow type belongs to, if any.
pub fn column_type_of(data_type: &DataType) -> Option<ColumnType> {
    Some(match data_type {
        DataType::Boolean => ColumnType::Boolean,
        DataType::Int8 => ColumnType::Int8,
        DataType::Int16 => ColumnType::Int16,
        DataType::Int32 => ColumnType::Int32,
        DataType::Int64 => ColumnType::Int64,
        DataType::UInt8 => ColumnType::Uint8,
        DataType::UInt16 => ColumnType::Uint16,
        DataType::UInt32 => ColumnType::Uint32,
        DataType::UInt64 => ColumnType::Uint64,
        DataType::Float32 => ColumnType::Float32,
        DataType::Float64 => ColumnType::Float64,
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Utf8View => ColumnType::String,
        DataType::Date32 | DataType::Date64 => ColumnType::Date,
        DataType::Timestamp(_, _) => ColumnType::Timestamp,
        DataType::Decimal32(_, _)
        | DataType::Decimal64(_, _)
        | DataType::Decimal128(_, _)
        | DataType::Decimal256(_, _) => ColumnType::Decimal,
        DataType::Dictionary(_, values) => return column_type_of(values),
        _ => return None,
    })
}

/// Decoder input owned by a zeroize-on-drop buffer, so the engine's copy of
/// the decrypted Parquet is wiped once the last reference (including any
/// zero-copy slice the decoder kept) is released.
fn wiped_copy(blob: &[u8]) -> Bytes {
    Bytes::from_owner(WipedParquet(SecretBytes::new(blob.to_vec())))
}

/// The engine's copy of one decrypted Parquet object ([`wiped_copy`]).
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct WipedParquet(SecretBytes);

impl AsRef<[u8]> for WipedParquet {
    fn as_ref(&self) -> &[u8] {
        self.0.expose()
    }
}

/// A table over decrypted Parquet objects, one partition per object.
/// Registering it reads only the footers. Each scan decodes the columns it
/// reads, once the footers show they fit the query's [`DecodeBudget`], into
/// an in-memory plan that lives as long as the query's.
struct ParquetTable {
    /// The first object's schema, whose columns every object shares.
    schema: SchemaRef,
    objects: Vec<ParquetObject>,
    /// Rows the footers report, summed.
    rows: u64,
    /// The most rows the steward declared, for a declared dataset.
    row_cap: Option<u64>,
}

impl fmt::Debug for ParquetTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the objects: their bytes and footers come from the data.
        f.debug_struct("ParquetTable")
            .field("objects", &self.objects.len())
            .finish_non_exhaustive()
    }
}

impl ParquetTable {
    /// `objects` must be non-empty and share the first one's columns.
    fn new(objects: Vec<ParquetObject>, rows: u64, row_cap: Option<u64>) -> Self {
        let schema = objects
            .first()
            .map(|object| Arc::clone(object.schema()))
            .unwrap_or_else(|| Arc::new(Schema::empty()));
        Self {
            schema,
            objects,
            rows,
            row_cap,
        }
    }

    /// Every object's `columns` (indices into the table's schema, in the
    /// order the scan asks for them) as batches of `schema`, one partition
    /// per object. Nothing is decoded until `budget` has taken the rows the
    /// footers report and the uncompressed bytes they report for these
    /// columns.
    fn decode(
        &self,
        columns: &[usize],
        schema: &SchemaRef,
        budget: &DecodeBudget,
    ) -> Result<Vec<Vec<RecordBatch>>, ScanFault> {
        // The reader returns the columns it reads in file order.
        let mut roots = columns.to_vec();
        roots.sort_unstable();
        roots.dedup();
        let mut order = Vec::with_capacity(columns.len());
        for column in columns {
            let position = roots
                .binary_search(column)
                .map_err(|_| ScanFault::Parquet(ParquetStage::Reader))?;
            order.push(position);
        }

        let bytes = self.objects.iter().fold(0u64, |sum, object| {
            sum.saturating_add(object.column_bytes(&roots))
        });
        budget.take(self.rows, bytes)?;

        let mut partitions = Vec::with_capacity(self.objects.len());
        let mut decoded = 0u64;
        for object in &self.objects {
            let mut object_rows = 0u64;
            let mut batches = Vec::new();
            for batch in object.reader(&roots)? {
                let batch = batch.map_err(|_| ScanFault::Parquet(ParquetStage::Batch))?;
                let rows = u64::try_from(batch.num_rows()).unwrap_or(u64::MAX);
                object_rows = object_rows.saturating_add(rows);
                decoded = decoded.saturating_add(rows);
                // Decoded rows are counted again: past the declared cap the
                // data is unlike its declaration, and past what its footer
                // reported, which the limits were checked against, the
                // object is malformed.
                if self.row_cap.is_some_and(|cap| decoded > cap) {
                    return Err(ScanFault::Declaration(Declaration::RowCap));
                }
                if object_rows > object.rows {
                    return Err(ScanFault::Parquet(ParquetStage::Batch));
                }
                let arrays = order
                    .iter()
                    .map(|&position| batch.columns().get(position).cloned())
                    .collect::<Option<Vec<_>>>()
                    .ok_or(ScanFault::Parquet(ParquetStage::Batch))?;
                let options = RecordBatchOptions::new().with_row_count(Some(batch.num_rows()));
                let batch = RecordBatch::try_new_with_options(Arc::clone(schema), arrays, &options)
                    .map_err(|_| ScanFault::Parquet(ParquetStage::Batch))?;
                batches.push(batch);
            }
            partitions.push(batches);
        }
        Ok(partitions)
    }
}

#[async_trait]
impl TableProvider for ParquetTable {
    fn schema(&self) -> SchemaRef {
        Arc::clone(&self.schema)
    }

    fn table_type(&self) -> TableType {
        TableType::Base
    }

    /// DataFusion calls this while it builds the physical plan from the
    /// final logical plan, which [`QueryScope::sql`] does only once the plan
    /// has passed every gate: the columns decoded are the ones that run.
    async fn scan(
        &self,
        state: &dyn Session,
        projection: Option<&Vec<usize>>,
        _filters: &[Expr],
        _limit: Option<usize>,
    ) -> datafusion::common::Result<Arc<dyn ExecutionPlan>> {
        let Some(budget) = state.config().get_extension::<DecodeBudget>() else {
            return internal_err!("a scan outside a query scope's session");
        };
        let columns = match projection {
            Some(columns) => columns.clone(),
            None => (0..self.schema.fields().len()).collect(),
        };
        let schema = Arc::new(self.schema.project(&columns)?);
        let partitions = self.decode(&columns, &schema, &budget)?;
        Ok(MemorySourceConfig::try_new_exec(&partitions, schema, None)?)
    }
}

/// One decrypted Parquet object: the engine's zeroizing copy and its
/// parsed footer.
struct ParquetObject {
    /// The decoder's input ([`wiped_copy`]).
    bytes: Bytes,
    /// The footer, parsed without its column statistics (whose minimum and
    /// maximum are values from the data), and the Arrow schema it gives.
    footer: ArrowReaderMetadata,
    /// Rows the footer reports.
    rows: u64,
}

impl ParquetObject {
    /// Reads `blob`'s footer, and nothing else, from the engine's own copy.
    fn read_footer(blob: &[u8]) -> Result<Self, QueryError> {
        let bytes = wiped_copy(blob);
        let options =
            ArrowReaderOptions::new().with_column_stats_policy(ParquetStatisticsPolicy::SkipAll);
        let footer = ArrowReaderMetadata::load(&bytes, options)
            .map_err(|_| QueryError::Parquet(ParquetStage::Metadata))?;
        let rows = footer_rows(footer.metadata())?;
        Ok(Self {
            bytes,
            footer,
            rows,
        })
    }

    fn schema(&self) -> &SchemaRef {
        self.footer.schema()
    }

    /// Uncompressed bytes the footer reports for the column chunks of the
    /// root columns `roots` (sorted), which [`footer_rows`] has checked.
    fn column_bytes(&self, roots: &[usize]) -> u64 {
        let metadata = self.footer.metadata();
        let descr = metadata.file_metadata().schema_descr();
        let mut bytes = 0u64;
        for group in metadata.row_groups() {
            for (leaf, column) in group.columns().iter().enumerate() {
                if roots
                    .binary_search(&descr.get_column_root_idx(leaf))
                    .is_ok()
                {
                    let size = u64::try_from(column.uncompressed_size()).unwrap_or(u64::MAX);
                    bytes = bytes.saturating_add(size);
                }
            }
        }
        bytes
    }

    /// A reader of the root columns `roots` (sorted) and no others.
    fn reader(&self, roots: &[usize]) -> Result<ParquetRecordBatchReader, ScanFault> {
        let descr = self.footer.metadata().file_metadata().schema_descr();
        let root_columns = descr.root_schema().get_fields().len();
        if roots.iter().any(|&root| root >= root_columns) {
            return Err(ScanFault::Parquet(ParquetStage::Reader));
        }
        let mask = ProjectionMask::roots(descr, roots.iter().copied());
        ParquetRecordBatchReaderBuilder::new_with_metadata(self.bytes.clone(), self.footer.clone())
            .with_projection(mask)
            .build()
            .map_err(|_| ScanFault::Parquet(ParquetStage::Reader))
    }
}

/// What the table scans of one query may decode, as the footers report it:
/// every row, and the uncompressed bytes of the columns each scan reads,
/// summed over the query's scans. [`QueryScope::sql`] gives each query its
/// own, in the session config its scans see.
#[derive(Debug)]
struct DecodeBudget {
    max_rows: u64,
    max_bytes: u64,
    /// Rows and bytes the query's scans have taken.
    taken: Mutex<(u64, u64)>,
}

impl DecodeBudget {
    fn new(limits: &QueryLimits) -> Self {
        Self {
            max_rows: limits.max_decoded_rows,
            max_bytes: limits.max_decoded_bytes,
            taken: Mutex::new((0, 0)),
        }
    }

    /// Takes one scan's `rows` and `bytes`, or refuses the scan if the
    /// query's scans would then pass either decode limit.
    fn take(&self, rows: u64, bytes: u64) -> Result<(), ScanFault> {
        let mut taken = self.taken.lock().unwrap_or_else(PoisonError::into_inner);
        let total = (taken.0.saturating_add(rows), taken.1.saturating_add(bytes));
        if total.0 > self.max_rows {
            return Err(ScanFault::Limit(QueryLimit::DecodedRows));
        }
        if total.1 > self.max_bytes {
            return Err(ScanFault::Limit(QueryLimit::DecodedBytes));
        }
        *taken = total;
        Ok(())
    }
}

/// A refusal or failure while a scan decodes. It crosses DataFusion's
/// planner as an external error, and [`datafusion_error`] reports it as
/// itself, never as the caller's SQL. Holds no upstream message.
#[derive(Debug, Clone, Copy, thiserror::Error)]
enum ScanFault {
    #[error("parquet decode failed while {0}")]
    Parquet(ParquetStage),
    #[error("dataset does not match its declared {0}")]
    Declaration(Declaration),
    #[error("query exceeded its {0} limit")]
    Limit(QueryLimit),
}

impl From<ScanFault> for QueryError {
    fn from(fault: ScanFault) -> Self {
        match fault {
            ScanFault::Parquet(stage) => QueryError::Parquet(stage),
            ScanFault::Declaration(declaration) => QueryError::DeclarationMismatch(declaration),
            ScanFault::Limit(limit) => QueryError::LimitExceeded(limit),
        }
    }
}

impl From<ScanFault> for DataFusionError {
    fn from(fault: ScanFault) -> Self {
        DataFusionError::External(Box::new(fault))
    }
}

/// Serialize record batches to a JSON array of row objects.
pub fn batches_to_json(batches: &[RecordBatch]) -> Result<serde_json::Value, QueryError> {
    rows_to_json(batches, usize::MAX)
}

/// [`batches_to_json`], refusing JSON longer than `max_bytes`
/// ([`QueryLimit::ResultBytes`]).
fn rows_to_json(
    batches: &[RecordBatch],
    max_bytes: usize,
) -> Result<serde_json::Value, QueryError> {
    let refs: Vec<&RecordBatch> = batches.iter().filter(|b| b.num_rows() > 0).collect();
    // Rows serialize to plaintext JSON; growth and drop wipe each copy.
    let mut buf = CappedWriter {
        buf: ZeroizingWriter::with_capacity(0),
        remaining: max_bytes,
        exceeded: false,
    };
    let written = {
        let mut writer = arrow::json::ArrayWriter::new(&mut buf);
        writer.write_batches(&refs).and_then(|()| writer.finish())
    };
    if buf.exceeded {
        return Err(QueryError::LimitExceeded(QueryLimit::ResultBytes));
    }
    written.map_err(|e| QueryError::Serialize(e.to_string()))?;
    if buf.buf.is_empty() {
        return Ok(serde_json::Value::Array(Vec::new()));
    }
    serde_json::from_slice(buf.buf.into_secret().expose())
        .map_err(|e| QueryError::Serialize(e.to_string()))
}

/// A [`ZeroizingWriter`] that refuses a write past `remaining` bytes. The
/// JSON writer flushes every few kilobytes, so it stops near the limit.
struct CappedWriter {
    buf: ZeroizingWriter,
    remaining: usize,
    exceeded: bool,
}

impl Write for CappedWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.len() > self.remaining {
            self.exceeded = true;
            return Err(io::Error::other("result size limit reached"));
        }
        self.remaining -= data.len();
        self.buf.write_all(data)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.buf.flush()
    }
}

/// A DataFusion failure, with no upstream text. A [`ScanFault`] anywhere in
/// the chain is reported as itself. Running out of the scope's memory pool,
/// or needing a temporary file the scope does not have, is the memory
/// limit. Neither is the caller's SQL.
fn datafusion_error(stage: ExecutionStage, err: &DataFusionError) -> QueryError {
    let mut source: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(error) = source {
        if let Some(fault) = error.downcast_ref::<ScanFault>() {
            return QueryError::from(*fault);
        }
        source = error.source();
    }
    match err.find_root() {
        DataFusionError::ResourcesExhausted(_) => QueryError::LimitExceeded(QueryLimit::Memory),
        _ => QueryError::Execution(stage),
    }
}

/// The scope's runtime: no object stores, a fixed memory pool, and no disk.
/// DataFusion spills sorts and aggregations to temporary files under memory
/// pressure; with the disk manager disabled, an operator that runs out of
/// pool fails with `ResourcesExhausted` instead of writing decrypted rows to
/// the host's disk.
fn scope_runtime(limits: &QueryLimits) -> Arc<RuntimeEnv> {
    let pool_bytes = usize::try_from(limits.memory_bytes).unwrap_or(usize::MAX);
    RuntimeEnvBuilder::new()
        .with_object_store_registry(Arc::new(NoObjectStores))
        .with_memory_pool(Arc::new(GreedyMemoryPool::new(pool_bytes)))
        .with_disk_manager_builder(
            DiskManagerBuilder::default().with_mode(DiskManagerMode::Disabled),
        )
        .build_arc()
        .expect("a runtime with no object store and no disk always builds")
}

/// Rows a Parquet footer reports: the larger of the file's count and its
/// row groups' sum. A negative count or size anywhere in the footer is
/// malformed metadata.
fn footer_rows(metadata: &ParquetMetaData) -> Result<u64, QueryError> {
    let size =
        |value: i64| u64::try_from(value).map_err(|_| QueryError::Parquet(ParquetStage::Metadata));
    let mut rows = 0u64;
    for group in metadata.row_groups() {
        rows = rows.saturating_add(size(group.num_rows())?);
        size(group.total_byte_size())?;
        for column in group.columns() {
            size(column.uncompressed_size())?;
        }
    }
    let file_rows = size(metadata.file_metadata().num_rows())?;
    Ok(rows.max(file_rows))
}

/// Makes every operator yield to the runtime as it produces batches.
///
/// A time limit stops a query by dropping its future, which takes effect
/// only when the plan returns to the runtime, and a plan's partitions run
/// on tasks of their own that stop the same way. DataFusion consumes the
/// task's cooperative budget only at scans and exchanges, so a join that
/// reads each input once could otherwise run to the end with its time
/// limit long past and its slot already released. Each batch any operator
/// produces now consumes budget, so the plan stops at its next batch
/// boundary.
#[derive(Debug)]
struct YieldEveryBatch;

impl PhysicalOptimizerRule for YieldEveryBatch {
    fn optimize(
        &self,
        plan: Arc<dyn ExecutionPlan>,
        _config: &ConfigOptions,
    ) -> Result<Arc<dyn ExecutionPlan>, DataFusionError> {
        cooperate(plan, false)
    }

    fn name(&self) -> &str {
        "yield_every_batch"
    }

    fn schema_check(&self) -> bool {
        true
    }
}

/// Wraps `plan` and every operator below it in a [`CooperativeExec`],
/// except operators that already consume budget themselves: each
/// `CooperativeExec`, the operator directly under one (`wrapped`), and any
/// that DataFusion reports as cooperative.
fn cooperate(
    plan: Arc<dyn ExecutionPlan>,
    wrapped: bool,
) -> Result<Arc<dyn ExecutionPlan>, DataFusionError> {
    let is_wrapper = plan.is::<CooperativeExec>();
    let children = plan
        .children()
        .into_iter()
        .map(|child| cooperate(Arc::clone(child), is_wrapper))
        .collect::<Result<Vec<_>, _>>()?;
    let plan = replace_children_if_necessary(plan, children)?;
    let cooperative = plan.properties().scheduling_type == SchedulingType::Cooperative;
    Ok(if is_wrapper || wrapped || cooperative {
        plan
    } else {
        Arc::new(CooperativeExec::new(plan))
    })
}

/// Queries only: no DDL, DML, `COPY` or session statements.
fn read_only() -> SQLOptions {
    SQLOptions::new()
        .with_allow_ddl(false)
        .with_allow_dml(false)
        .with_allow_statements(false)
}

/// An object-store registry that holds nothing. Tables are in-memory, so a
/// scope never needs a store; DataFusion's default registers `file://`,
/// which would let a plan read or write the host's disk.
#[derive(Debug)]
struct NoObjectStores;

impl ObjectStoreRegistry for NoObjectStores {
    fn register_store(
        &self,
        _url: &Url,
        _store: Arc<dyn ObjectStore>,
    ) -> Option<Arc<dyn ObjectStore>> {
        None
    }

    fn get_store(&self, url: &Url) -> Result<Arc<dyn ObjectStore>, DataFusionError> {
        exec_err!("no object store is available in a query scope: {url}")
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use arrow::array::Int64Array;
    use arrow::datatypes::{Field, SchemaRef};
    use datafusion::catalog::streaming::StreamingTable;
    use datafusion::execution::memory_pool::MemoryLimit;
    use datafusion::execution::{SendableRecordBatchStream, TaskContext};
    use datafusion::physical_plan::stream::RecordBatchStreamAdapter;
    use datafusion::physical_plan::streaming::PartitionStream;
    use parquet::arrow::ArrowWriter;
    use parquet::basic::{Compression, ZstdLevel};
    use parquet::file::properties::WriterProperties;

    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn scope_with(zk: ZkMode, limits: QueryLimits) -> QueryScope {
        QueryScope::new(EngineSettings {
            zk,
            max_concurrent_queries: 1,
            limits,
        })
    }

    /// One `Int64` column `v` holding `values`, as Parquet.
    fn int_parquet(values: Int64Array, props: Option<WriterProperties>) -> Vec<u8> {
        let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(values)]).expect("batch");
        let mut buf = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut buf, schema, props).expect("writer");
        writer.write(&batch).expect("write");
        writer.close().expect("close");
        buf
    }

    #[test]
    fn scope_cannot_reach_the_local_filesystem() {
        use datafusion::execution::object_store::ObjectStoreUrl;
        let scope = scope_with(ZkMode::Enabled, QueryLimits::default());
        let local = ObjectStoreUrl::local_filesystem();
        assert!(scope.ctx.runtime_env().object_store(&local).is_err());
    }

    #[test]
    fn scope_has_a_fixed_pool_and_no_disk() {
        let limits = QueryLimits {
            memory_bytes: 3 * MIB,
            ..QueryLimits::default()
        };
        let scope = scope_with(ZkMode::Enabled, limits);
        let runtime = scope.ctx.runtime_env();
        assert!(matches!(
            runtime.memory_pool.memory_limit(),
            datafusion::execution::memory_pool::MemoryLimit::Finite(bytes) if bytes == 3 * 1024 * 1024
        ));
        assert!(!runtime.disk_manager.tmp_files_enabled());
    }

    /// A sort or aggregation that outgrows the pool fails the query with the
    /// memory limit. It cannot spill: the disk manager is disabled and
    /// nothing was written.
    #[tokio::test]
    async fn memory_limit_fails_operators_without_spilling() {
        let parquet = int_parquet(Int64Array::from_iter_values(0..200_000), None);
        let queries = [
            "SELECT v FROM t ORDER BY v DESC",
            "SELECT v, COUNT(*) AS n FROM t GROUP BY v",
        ];

        let tight = QueryLimits {
            memory_bytes: 64 * 1024,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, tight);
        // The decoded table is outside the pool.
        assert_eq!(
            scope.register_parquet("t", &parquet).expect("register"),
            200_000
        );
        for sql in queries {
            let err = scope.sql(sql).await.expect_err(sql);
            assert!(
                matches!(err, QueryError::LimitExceeded(QueryLimit::Memory)),
                "{sql}: {err:?}"
            );
        }
        let disk = &scope.ctx.runtime_env().disk_manager;
        assert!(!disk.tmp_files_enabled());
        assert_eq!(disk.used_disk_space(), 0);
        assert_eq!(disk.spilling_progress().active_files_count, 0);

        // The same queries run within the default pool (both return a row
        // per value, so the result limit is raised to fit).
        let roomy = QueryLimits {
            max_result_rows: 200_000,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, roomy);
        scope.register_parquet("t", &parquet).expect("register");
        for sql in queries {
            let rows: usize = scope
                .sql(sql)
                .await
                .unwrap_or_else(|err| panic!("{sql}: {err:?}"))
                .iter()
                .map(RecordBatch::num_rows)
                .sum();
            assert_eq!(rows, 200_000, "{sql}");
        }
    }

    /// `parquet` with every page overwritten and its footer intact, so
    /// decoding any column fails and reading the footer does not. Pages run
    /// from the leading magic to the footer, which ends with its length and
    /// the trailing magic.
    fn pages_wiped(parquet: &[u8]) -> Vec<u8> {
        let footer_len = u32::from_le_bytes(
            parquet[parquet.len() - 8..parquet.len() - 4]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        let mut wiped = parquet.to_vec();
        let pages_end = parquet.len() - 8 - footer_len;
        wiped[4..pages_end].fill(0xA5);
        wiped
    }

    const SUM_V: &str = "SELECT SUM(v) AS s FROM t";

    /// A million zeros, plain-encoded and compressed: a few kilobytes on
    /// disk that decode to 8 MB. Its pages are overwritten, so decoding any
    /// of it would fail: a limit refusal shows nothing was decoded. The row
    /// limit refuses the table from its footer; the byte limit refuses a
    /// query from the footer of the column it reads.
    #[tokio::test]
    async fn decode_limits_refuse_a_compressible_dataset_from_its_footer() {
        let props = WriterProperties::builder()
            .set_dictionary_enabled(false)
            .set_compression(Compression::ZSTD(ZstdLevel::default()))
            .build();
        let parquet = int_parquet(Int64Array::from(vec![0; 1_000_000]), Some(props));
        assert!(parquet.len() < 64 * 1024, "{} bytes", parquet.len());
        let pages_wiped = pages_wiped(&parquet);

        let rows_over = QueryLimits {
            max_decoded_rows: 999_999,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, rows_over);
        let err = scope
            .register_parquet("t", &pages_wiped)
            .expect_err("over the row limit");
        assert!(
            matches!(err, QueryError::LimitExceeded(QueryLimit::DecodedRows)),
            "{err:?}"
        );

        let bytes_over = QueryLimits {
            max_decoded_bytes: MIB,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, bytes_over);
        assert_eq!(
            scope.register_parquet("t", &pages_wiped).expect("footer"),
            1_000_000
        );
        let err = scope.sql(SUM_V).await.expect_err("over the byte limit");
        assert!(
            matches!(err, QueryError::LimitExceeded(QueryLimit::DecodedBytes)),
            "{err:?}"
        );

        // Within both limits the intact file decodes, and the wiped one fails
        // to: the refusals above came before any decoding.
        let fits = QueryLimits {
            max_decoded_rows: 1_000_000,
            max_decoded_bytes: 16 * MIB,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, fits);
        scope.register_parquet("t", &parquet).expect("fits");
        let rows = scope.sql_json(SUM_V).await.expect("decodes");
        assert_eq!(rows, serde_json::json!([{ "s": 0 }]));
        let mut scope = scope_with(ZkMode::Disabled, fits);
        scope.register_parquet("t", &pages_wiped).expect("footer");
        assert!(matches!(
            scope.sql(SUM_V).await,
            Err(QueryError::Parquet(
                ParquetStage::Batch | ParquetStage::Reader
            ))
        ));
    }

    /// Every scan of a query counts toward the decode limits: a self-join
    /// reads the table twice. Each query has a budget of its own, so the
    /// scope runs the single scan again.
    #[tokio::test]
    async fn every_scan_of_a_query_counts_toward_the_decode_limits() {
        let parquet = int_parquet(Int64Array::from_iter_values(0..1_000), None);
        let self_join = "SELECT COUNT(*) AS n FROM t a JOIN t b ON a.v = b.v";
        for (limits, limit) in [
            (
                QueryLimits {
                    max_decoded_rows: 1_999,
                    ..QueryLimits::default()
                },
                QueryLimit::DecodedRows,
            ),
            (
                QueryLimits {
                    max_decoded_bytes: column_bytes(&parquet) * 2 - 1,
                    ..QueryLimits::default()
                },
                QueryLimit::DecodedBytes,
            ),
        ] {
            let mut scope = scope_with(ZkMode::Disabled, limits);
            scope.register_parquet("t", &parquet).expect("register");
            for _ in 0..2 {
                let rows = scope.sql_json(SUM_V).await.expect("one scan fits");
                assert_eq!(rows, serde_json::json!([{ "s": 499_500 }]));
            }
            let err = scope.sql(self_join).await.expect_err("two scans");
            assert!(
                matches!(err, QueryError::LimitExceeded(found) if found == limit),
                "{err:?}"
            );
        }

        // Both scans fit when the limits allow two.
        let limits = QueryLimits {
            max_decoded_rows: 2_000,
            max_decoded_bytes: column_bytes(&parquet) * 2,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, limits);
        scope.register_parquet("t", &parquet).expect("register");
        let rows = scope.sql_json(self_join).await.expect("two scans fit");
        assert_eq!(rows, serde_json::json!([{ "n": 1_000 }]));
    }

    /// Uncompressed bytes `parquet`'s footer reports for its column chunks.
    fn column_bytes(parquet: &[u8]) -> u64 {
        let object = ParquetObject::read_footer(parquet).expect("footer");
        let roots: Vec<usize> = (0..object.schema().fields().len()).collect();
        object.column_bytes(&roots)
    }

    /// Objects of one table must share their columns. Unlike ones are a
    /// stored fault (a Parquet failure, 5xx), never the caller's SQL.
    #[test]
    fn objects_with_unlike_columns_are_refused_as_a_parquet_failure() {
        let ints = int_parquet(Int64Array::from(vec![1, 2]), None);
        let renamed = {
            let schema = Arc::new(Schema::new(vec![Field::new("w", DataType::Int64, false)]));
            let values = Arc::new(Int64Array::from(vec![3]));
            parquet_of(RecordBatch::try_new(schema, vec![values]).expect("batch"))
        };
        let nullable = {
            let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, true)]));
            let values = Arc::new(Int64Array::from(vec![Some(3), None]));
            parquet_of(RecordBatch::try_new(schema, vec![values]).expect("batch"))
        };
        let wider = {
            let schema = Arc::new(Schema::new(vec![
                Field::new("v", DataType::Int64, false),
                Field::new("w", DataType::Int64, false),
            ]));
            let values = Arc::new(Int64Array::from(vec![3]));
            parquet_of(RecordBatch::try_new(schema, vec![values.clone(), values]).expect("batch"))
        };
        for other in [&renamed, &nullable, &wider] {
            let mut scope = scope_with(ZkMode::Disabled, QueryLimits::default());
            let err = scope
                .register_parquet_many("t", &[ints.as_slice(), other.as_slice()])
                .expect_err("unlike columns");
            assert!(
                matches!(err, QueryError::Parquet(ParquetStage::Schema)),
                "{err:?}"
            );
        }

        let mut scope = scope_with(ZkMode::Disabled, QueryLimits::default());
        assert_eq!(
            scope
                .register_parquet_many("t", &[ints.as_slice(), ints.as_slice()])
                .expect("alike"),
            4
        );
    }

    fn parquet_of(batch: RecordBatch) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut buf, batch.schema(), None).expect("writer");
        writer.write(&batch).expect("write");
        writer.close().expect("close");
        buf
    }

    /// The table's `Debug` names no value from the data, which a plan's
    /// debug output would otherwise carry. Its footer keeps no column
    /// statistics, whose minimum and maximum are values from the data.
    #[tokio::test]
    async fn the_table_formats_and_keeps_no_values_from_the_data() {
        let schema = Arc::new(Schema::new(vec![Field::new(
            "secret",
            DataType::Utf8,
            false,
        )]));
        let values = Arc::new(arrow::array::StringArray::from(vec!["MARKER-31337"]));
        let parquet = parquet_of(RecordBatch::try_new(schema, vec![values]).expect("batch"));
        let mut scope = scope_with(ZkMode::Disabled, QueryLimits::default());
        scope.register_parquet("t", &parquet).expect("register");

        let table = scope.ctx.table_provider("t").await.expect("table");
        let formatted = format!("{table:?}");
        assert!(!formatted.contains("MARKER"), "{formatted}");
        let table = table
            .downcast_ref::<ParquetTable>()
            .expect("a ParquetTable");
        let footer = format!("{:?}", table.objects[0].footer.metadata());
        assert!(!footer.contains("MARKER"), "{footer}");
        assert!(
            table.objects[0]
                .footer
                .metadata()
                .row_groups()
                .iter()
                .flat_map(|group| group.columns())
                .all(|column| column.statistics().is_none())
        );
    }

    /// Dropping the scope releases each table, with the engine's copy of
    /// the decrypted Parquet it holds (wiped on drop, by type), once queries
    /// have decoded from it.
    #[tokio::test]
    async fn dropping_the_scope_releases_its_tables() {
        let parquet = int_parquet(Int64Array::from_iter_values(0..1_000), None);
        let mut scope = scope_with(ZkMode::Disabled, QueryLimits::default());
        scope.register_parquet("t", &parquet).expect("register");
        scope.sql(SUM_V).await.expect("query");
        let table = Arc::downgrade(&scope.ctx.table_provider("t").await.expect("table"));
        assert!(table.upgrade().is_some());
        drop(scope);
        assert!(table.upgrade().is_none(), "the table outlived its scope");
    }

    /// A single partition of `batches` batches of `rows` rows each (`v`,
    /// `Int64`), counting the batches it hands out.
    #[derive(Debug)]
    struct CountedBatches {
        schema: SchemaRef,
        batches: usize,
        rows: i64,
        produced: Arc<AtomicUsize>,
    }

    impl PartitionStream for CountedBatches {
        fn schema(&self) -> &SchemaRef {
            &self.schema
        }

        fn execute(&self, _ctx: Arc<TaskContext>) -> SendableRecordBatchStream {
            let (schema, produced, rows) = (self.schema.clone(), self.produced.clone(), self.rows);
            let batches = futures::stream::iter((0..self.batches).map(move |_| {
                produced.fetch_add(1, Ordering::SeqCst);
                let values = Arc::new(Int64Array::from_iter_values(0..rows));
                Ok(RecordBatch::try_new(schema.clone(), vec![values])?)
            }));
            Box::pin(RecordBatchStreamAdapter::new(self.schema.clone(), batches))
        }
    }

    /// Without a disclosure policy the collected rows are the result, and
    /// the pool does not track them: the query stops reading at the first
    /// row over the limit instead of collecting everything first.
    #[tokio::test]
    async fn an_ungated_result_stops_at_the_row_limit() {
        let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
        let produced = Arc::new(AtomicUsize::new(0));
        let source = CountedBatches {
            schema: schema.clone(),
            batches: 1_000,
            rows: 100,
            produced: produced.clone(),
        };
        let table = StreamingTable::try_new(schema, vec![Arc::new(source)]).expect("table");
        let limits = QueryLimits {
            max_result_rows: 250,
            ..QueryLimits::default()
        };
        let scope = scope_with(ZkMode::Disabled, limits);
        scope
            .ctx
            .register_table("t", Arc::new(table))
            .expect("register");

        let err = scope.sql("SELECT v FROM t").await.expect_err("over");
        assert!(
            matches!(err, QueryError::LimitExceeded(QueryLimit::ResultRows)),
            "{err:?}"
        );
        // The third batch passes the limit.
        assert_eq!(produced.load(Ordering::SeqCst), 3);
    }

    /// A time limit drops the query's future. A cross join reads each input
    /// once and then works without reading again, so only
    /// [`YieldEveryBatch`] makes it stop: the call returns at the limit, and
    /// the tasks running its partitions stop too, releasing everything they
    /// held in the pool.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_time_limit_stops_a_running_plan() {
        let parquet = int_parquet(Int64Array::from_iter_values(0..80_000), None);
        let mut scope = scope_with(ZkMode::Disabled, QueryLimits::default());
        scope.register_parquet("t", &parquet).expect("register");
        let pool = scope.ctx.runtime_env().memory_pool.clone();

        // 6.4 billion pairs: about a minute of work on four threads.
        let started = Instant::now();
        let ran = tokio::time::timeout(
            Duration::from_millis(500),
            scope.sql("SELECT COUNT(*) AS n FROM t a CROSS JOIN t b WHERE a.v + b.v >= 0"),
        )
        .await;
        assert!(ran.is_err(), "the plan finished within the limit");
        let stopped = started.elapsed();
        assert!(
            stopped < Duration::from_secs(5),
            "returned after {stopped:?}"
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while pool.reserved() > 0 {
            assert!(
                Instant::now() < deadline,
                "{} bytes still reserved: the plan is still running",
                pool.reserved()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Every operator in a scope's plan consumes budget as it produces
    /// batches: each is a `CooperativeExec`, sits directly under one, or is
    /// cooperative itself, and no wrapper wraps another.
    #[tokio::test]
    async fn every_operator_in_a_plan_yields() {
        fn check(plan: &Arc<dyn ExecutionPlan>, wrapped: bool) {
            let is_wrapper = plan.is::<CooperativeExec>();
            assert!(!(is_wrapper && wrapped), "a wrapper wraps a wrapper");
            let cooperative = plan.properties().scheduling_type == SchedulingType::Cooperative;
            assert!(
                is_wrapper || wrapped || cooperative,
                "{} does not yield",
                plan.name()
            );
            for child in plan.children() {
                check(child, is_wrapper);
            }
        }

        let mut scope = scope_with(ZkMode::Disabled, QueryLimits::default());
        let parquet = int_parquet(Int64Array::from_iter_values(0..1_000), None);
        scope.register_parquet("t", &parquet).expect("register");
        let sql = "SELECT a.v % 7 AS g, COUNT(*) AS n FROM t a JOIN t b ON a.v = b.v \
                   CROSS JOIN t c WHERE a.v + c.v >= 0 GROUP BY g ORDER BY g";
        let plan = scope
            .ctx
            .sql(sql)
            .await
            .expect("plan")
            .create_physical_plan()
            .await
            .expect("physical plan");
        check(&plan, false);
    }

    /// `SET` on a runtime key would give the scope a temporary directory or
    /// a larger pool, so no-spill rests on refusing it. After the refusals
    /// the runtime is as built: a sort that outgrows the pool fails with the
    /// memory limit and writes nothing.
    #[tokio::test]
    async fn refused_runtime_settings_leave_the_scope_unable_to_spill() {
        let dir = std::env::temp_dir().join(format!("qx-spill-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let tight = QueryLimits {
            memory_bytes: 64 * 1024,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, tight);
        let parquet = int_parquet(Int64Array::from_iter_values(0..200_000), None);
        scope.register_parquet("t", &parquet).expect("register");

        for set in [
            format!(
                "SET datafusion.runtime.temp_directory = '{}'",
                dir.display()
            ),
            "SET datafusion.runtime.max_temp_directory_size = '1G'".to_owned(),
            "SET datafusion.runtime.memory_limit = '1G'".to_owned(),
        ] {
            let err = scope.sql(&set).await.expect_err(&set);
            assert!(
                matches!(err, QueryError::StatementNotAllowed),
                "{set}: {err:?}"
            );
        }

        let err = scope
            .sql("SELECT v FROM t ORDER BY v DESC")
            .await
            .expect_err("outgrows the pool");
        assert!(
            matches!(err, QueryError::LimitExceeded(QueryLimit::Memory)),
            "{err:?}"
        );
        let runtime = scope.ctx.runtime_env();
        assert!(matches!(
            runtime.memory_pool.memory_limit(),
            MemoryLimit::Finite(bytes) if bytes == 64 * 1024
        ));
        assert!(!runtime.disk_manager.tmp_files_enabled());
        assert_eq!(runtime.disk_manager.used_disk_space(), 0);
        let written = std::fs::read_dir(&dir).expect("scratch dir").count();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(written, 0);
    }

    #[test]
    fn decoder_input_zeroizes_on_drop() {
        // The engine's copy of the decrypted Parquet, which the decoder's
        // `Bytes` own, is wiped on every exit path.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<WipedParquet>();
    }
}
