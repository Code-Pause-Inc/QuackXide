//! quackxide-engine: the zero-trust query engine core.
//!
//! Deployments are white-labeled: the engine name may appear in crate names,
//! logs, and engineering docs, never in customer-facing strings. Public
//! naming flows from `platform-config::BrandConfig`, and `scripts/check.sh`
//! enforces this on the shipped frontend bundle.
//!
//! A [`QueryScope`] owns a DataFusion `SessionContext` over Arrow frames
//! decoded from Parquet decrypted inside the attested enclave. Two paths:
//!
//! * **Ciphertext scan**: equality over a blind-index column ([`blind`]);
//!   the engine never sees plaintext.
//! * **In-enclave analytics**: SQL over the decrypted frames, which live only
//!   for the scope's lifetime. In `ZkMode::Enabled` the [`policy`] gate
//!   restricts results to aggregates, and [`disclosure`] requires a genuine
//!   `COUNT(*) AS n` and suppresses cohorts below the minimum size.
//!
//! A scope enforces its share of the [`QueryLimits`]: the Parquet footers
//! must fit the decode limits before anything is decoded, operators run in
//! a fixed memory pool with nothing spilled to disk, and a result over the
//! row or byte limit is refused, never truncated.

use std::fmt;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arrow::array::{Array, AsArray, RecordBatch};
use arrow::compute::cast;
use arrow::datatypes::{DataType, FieldRef, Schema, SchemaRef};
use bytes::Bytes;
use datafusion::common::config::ConfigOptions;
use datafusion::common::{DataFusionError, exec_err};
use datafusion::datasource::MemTable;
use datafusion::execution::SessionStateBuilder;
use datafusion::execution::disk_manager::{DiskManagerBuilder, DiskManagerMode};
use datafusion::execution::memory_pool::GreedyMemoryPool;
use datafusion::execution::object_store::ObjectStoreRegistry;
use datafusion::execution::runtime_env::{RuntimeEnv, RuntimeEnvBuilder};
use datafusion::physical_optimizer::PhysicalOptimizerRule;
use datafusion::physical_plan::coop::CooperativeExec;
use datafusion::physical_plan::execution_plan::SchedulingType;
use datafusion::physical_plan::{ExecutionPlan, replace_children_if_necessary};
use datafusion::prelude::{SQLOptions, SessionConfig, SessionContext};
use futures::StreamExt;
use object_store::ObjectStore;
use parquet::arrow::arrow_reader::{
    ArrowReaderMetadata, ArrowReaderOptions, ParquetRecordBatchReaderBuilder,
};
use parquet::file::metadata::ParquetMetaData;
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
    Reader,
    Batch,
}

impl fmt::Display for ParquetStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ParquetStage::Metadata => "reading metadata",
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
    Prepare,
    Execute,
}

impl fmt::Display for ExecutionStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ExecutionStage::LoadTable => "loading the table",
            ExecutionStage::Plan => "planning",
            ExecutionStage::Prepare => "preparing the plan",
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
/// `Drop` deregisters every table, releasing the Arrow buffers so decrypted
/// frames do not outlive the query. The decrypted Parquet input stays owned
/// (and zeroized) by the caller.
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
        let state = SessionStateBuilder::new()
            .with_config(SessionConfig::new())
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

    /// Decode in-enclave decrypted Parquet and register it as `table`.
    /// Returns the row count.
    pub fn register_parquet(&mut self, table: &str, parquet: &[u8]) -> Result<usize, QueryError> {
        self.register_parquet_many(table, std::slice::from_ref(&parquet))
    }

    /// Register several Parquet blobs as one table, one partition per blob.
    /// All blobs must share a schema. Zero blobs is a no-op returning 0.
    ///
    /// Every blob's footer is read before any batch is decoded: the rows
    /// and uncompressed bytes they report, summed, must fit
    /// [`QueryLimits::max_decoded_rows`] and
    /// [`QueryLimits::max_decoded_bytes`], since the memory pool does not
    /// track the decoded table. Both are counted again as batches decode:
    /// the rows, and the Arrow memory each batch holds, since a footer
    /// understates a column that dictionary or run-length encoding shrinks.
    /// Top-level string and binary columns are measured before they expand,
    /// so the decoded table can pass the byte limit only by the other
    /// columns of the batch that crosses it. Either refusal is
    /// [`QueryError::LimitExceeded`]. Decoding is synchronous, so these
    /// limits also bound how long it runs.
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
    /// both checked before any batch is decoded. Decoded rows are counted
    /// against `row_cap` again. A failure is
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
        let limits = self.settings.limits;
        let row_cap = declared.map(|(_, row_cap)| row_cap);
        // Each row count is checked against the declaration first: data
        // unlike its declaration is a stored fault, whatever its size.
        let check_rows = |rows: u64| {
            if row_cap.is_some_and(|cap| rows > cap) {
                Err(QueryError::DeclarationMismatch(Declaration::RowCap))
            } else if rows > limits.max_decoded_rows {
                Err(QueryError::LimitExceeded(QueryLimit::DecodedRows))
            } else {
                Ok(())
            }
        };

        // Every footer first: nothing is decoded until the whole dataset is
        // known to match its declaration and fit the decode limits.
        let mut readers = Vec::with_capacity(blobs.len());
        let mut footer_rows = 0u64;
        let mut footer_bytes = 0u64;
        for blob in blobs {
            let input = wiped_copy(blob);
            let reader = ParquetRecordBatchReaderBuilder::try_new(input.clone())
                .map_err(|_| QueryError::Parquet(ParquetStage::Metadata))?;
            if let Some((declared_schema, _)) = declared
                && !matches_declared(reader.schema(), declared_schema)
            {
                return Err(QueryError::DeclarationMismatch(Declaration::Schema));
            }
            let (rows, bytes) = footer_size(reader.metadata())?;
            footer_rows = footer_rows.saturating_add(rows);
            footer_bytes = footer_bytes.saturating_add(bytes);
            readers.push((input, reader.schema().clone(), reader.metadata().clone()));
        }
        check_rows(footer_rows)?;
        if footer_bytes > limits.max_decoded_bytes {
            return Err(QueryError::LimitExceeded(QueryLimit::DecodedBytes));
        }

        let mut schema = None;
        let mut partitions: Vec<Vec<RecordBatch>> = Vec::with_capacity(readers.len());
        let mut rows = 0u64;
        let mut bytes = 0u64;
        for (input, file_schema, metadata) in readers {
            schema.get_or_insert_with(|| file_schema.clone());
            // String and binary columns decode as views, so a value the file
            // repeats is held once until its expanded size is known to fit
            // (`expand_views`).
            let options = ArrowReaderOptions::new().with_schema(view_hint(&file_schema));
            let metadata = ArrowReaderMetadata::try_new(metadata, options)
                .map_err(|_| QueryError::Parquet(ParquetStage::Reader))?;
            let mut batches = Vec::new();
            for batch in ParquetRecordBatchReaderBuilder::new_with_metadata(input, metadata)
                .with_batch_size(DECODE_BATCH_ROWS)
                .build()
                .map_err(|_| QueryError::Parquet(ParquetStage::Reader))?
            {
                let batch = batch.map_err(|_| QueryError::Parquet(ParquetStage::Batch))?;
                rows = rows.saturating_add(u64::try_from(batch.num_rows()).unwrap_or(u64::MAX));
                check_rows(rows)?;
                let batch = expand_views(
                    &batch,
                    &file_schema,
                    limits.max_decoded_bytes.saturating_sub(bytes),
                )?;
                // Buffer capacity, so shared or spare capacity counts too:
                // this can only overstate the table.
                bytes = bytes.saturating_add(
                    u64::try_from(batch.get_array_memory_size()).unwrap_or(u64::MAX),
                );
                if bytes > limits.max_decoded_bytes {
                    return Err(QueryError::LimitExceeded(QueryLimit::DecodedBytes));
                }
                batches.push(batch);
            }
            partitions.push(batches);
        }

        let schema = schema.expect("non-empty blobs yield a schema");
        let mem = MemTable::try_new(schema, partitions)
            .map_err(|_| QueryError::Execution(ExecutionStage::LoadTable))?;
        self.ctx
            .register_table(table, Arc::new(mem))
            .map_err(|_| QueryError::Execution(ExecutionStage::LoadTable))?;
        self.tables.push(table.to_owned());
        Ok(usize::try_from(rows).unwrap_or(usize::MAX))
    }

    /// Run SQL over the registered frames. In `ZkMode::Enabled`, or with a
    /// disclosure policy attached, the plan must pass the aggregate-only
    /// allowlist and carry a genuine `COUNT(*) AS n`, a disclosure policy is
    /// required, and results pass through it before egress. A result with
    /// more rows than [`QueryLimits::max_result_rows`] after disclosure
    /// control is refused, as is a query whose operators run out of the
    /// scope's memory pool. Without a disclosure policy the result is
    /// refused as soon as it passes the row limit, and the plan stops.
    ///
    /// Dropping the returned future stops the plan at its next batch
    /// boundary: every operator yields to the runtime as it produces batches
    /// (`YieldEveryBatch`), so a time limit applied around this call is
    /// enforced while the plan runs.
    pub async fn sql(&self, query: &str) -> Result<Vec<RecordBatch>, QueryError> {
        self.last_suppressed_rows.store(0, Ordering::Relaxed);

        // Plan without executing, then refuse anything but a read-only query
        // in every mode: DataFusion runs DDL, `SET` and `PREPARE` while
        // turning a plan into a DataFrame, before any gate below sees it.
        let plan = self
            .ctx
            .state()
            .create_logical_plan(query)
            .await
            .map_err(|err| datafusion_error(ExecutionStage::Plan, &err))?;
        read_only()
            .verify_plan(&plan)
            .map_err(|_| QueryError::StatementNotAllowed)?;
        let df = self
            .ctx
            .execute_logical_plan(plan)
            .await
            .map_err(|err| datafusion_error(ExecutionStage::Prepare, &err))?;

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

/// A DataFusion failure, with no upstream text. Running out of the scope's
/// memory pool, or needing a temporary file the scope does not have, is
/// the memory limit, not the caller's SQL.
fn datafusion_error(stage: ExecutionStage, err: &DataFusionError) -> QueryError {
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

/// Rows per decoded batch: the Parquet reader's default. String and binary
/// columns are checked against [`QueryLimits::max_decoded_bytes`] before
/// they expand ([`expand_views`]). The other columns are counted once
/// decoded: most have a fixed width, so a batch of them is small, but a
/// string or binary column inside a list or struct expands first. The pages
/// themselves are not bounded here: a page decompresses whole, to the size
/// its own header states, and a `DELTA_BYTE_ARRAY` page rebuilds each
/// value from its predecessor's prefix, so it can copy up to its own size
/// once per row.
const DECODE_BATCH_ROWS: usize = 1024;

/// A top-level string or binary column, which decodes as a view first.
fn is_plain_bytes(data_type: &DataType) -> bool {
    matches!(
        data_type,
        DataType::Utf8 | DataType::LargeUtf8 | DataType::Binary | DataType::LargeBinary
    )
}

/// The view type a top-level column decodes as: its own kind of view for a
/// string or binary column, or for a dictionary of one (as the file's
/// embedded Arrow schema may declare it). `None` for every other column.
fn byte_view(data_type: &DataType) -> Option<DataType> {
    match data_type {
        DataType::Utf8 | DataType::LargeUtf8 => Some(DataType::Utf8View),
        DataType::Binary | DataType::LargeBinary => Some(DataType::BinaryView),
        DataType::Dictionary(_, values) if is_plain_bytes(values) => byte_view(values),
        _ => None,
    }
}

/// The file's schema with each top-level string or binary column, plain or
/// dictionary, read as a view array of that kind. Views point into the
/// pages and dictionaries they came from, so a value the file's dictionary
/// holds once is not copied once per row, even where a batch crosses into
/// another row group or from dictionary-encoded pages to plain ones (where
/// a dictionary array would be expanded inside the reader).
fn view_hint(schema: &Schema) -> SchemaRef {
    let fields: Vec<FieldRef> = schema
        .fields()
        .iter()
        .map(|field| match byte_view(field.data_type()) {
            Some(view) => Arc::new(field.as_ref().clone().with_data_type(view)),
            None => field.clone(),
        })
        .collect();
    Arc::new(Schema::new_with_metadata(fields, schema.metadata().clone()))
}

/// `batch`, decoded under [`view_hint`], with its view columns cast back to
/// the file's own types. A dictionary column is rebuilt from the views,
/// each distinct value once. A plain column expands, so it is measured
/// first: refused when the plain columns would take more than `budget`
/// bytes. Either kind is refused as malformed when its values could need
/// more than 32-bit offsets allow, which the cast could not represent.
fn expand_views(
    batch: &RecordBatch,
    file_schema: &SchemaRef,
    budget: u64,
) -> Result<RecordBatch, QueryError> {
    let narrow = |values: &DataType| matches!(values, DataType::Utf8 | DataType::Binary);
    let mut expanded = 0u64;
    let mut too_long = false;
    for (column, field) in batch.columns().iter().zip(file_schema.fields()) {
        match field.data_type() {
            plain if is_plain_bytes(plain) => {
                let size = plain_size(column.as_ref(), plain)?;
                expanded = expanded.saturating_add(size);
                too_long |= narrow(plain) && size > i32::MAX as u64;
            }
            DataType::Dictionary(_, values) if narrow(values) => {
                too_long |= distinct_bound(column.as_ref()) > i32::MAX as u64;
            }
            _ => {}
        }
    }
    if expanded > budget {
        return Err(QueryError::LimitExceeded(QueryLimit::DecodedBytes));
    }
    if too_long {
        return Err(QueryError::Parquet(ParquetStage::Batch));
    }
    let columns = batch
        .columns()
        .iter()
        .zip(file_schema.fields())
        .map(|(column, field)| {
            if byte_view(field.data_type()).is_some() {
                cast(column, field.data_type())
                    .map_err(|_| QueryError::Parquet(ParquetStage::Batch))
            } else {
                Ok(column.clone())
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    RecordBatch::try_new(file_schema.clone(), columns)
        .map_err(|_| QueryError::Parquet(ParquetStage::Batch))
}

/// The most bytes a view column's distinct values can take: a value is
/// either inline in its view (at most 12 bytes) or in one of the column's
/// data buffers, so their sizes and 12 bytes a row bound it.
fn distinct_bound(column: &dyn Array) -> u64 {
    let buffers = if let Some(views) = column.as_string_view_opt() {
        views.data_buffers()
    } else if let Some(views) = column.as_binary_view_opt() {
        views.data_buffers()
    } else {
        return u64::try_from(column.get_array_memory_size()).unwrap_or(u64::MAX);
    };
    let held = buffers
        .iter()
        .map(|buffer| u64::try_from(buffer.len()).unwrap_or(u64::MAX))
        .fold(0u64, u64::saturating_add);
    let rows = u64::try_from(column.len()).unwrap_or(u64::MAX);
    held.saturating_add(rows.saturating_mul(12))
}

/// Bytes a string or binary view column takes once expanded to `plain`:
/// its values, one offset per row, and the validity bitmap. Each view
/// records its value's length, so nothing is expanded to measure it.
fn plain_size(column: &dyn Array, plain: &DataType) -> Result<u64, QueryError> {
    let views = match plain {
        DataType::Utf8 | DataType::LargeUtf8 => column.as_string_view_opt().map(|a| a.views()),
        DataType::Binary | DataType::LargeBinary => column.as_binary_view_opt().map(|a| a.views()),
        _ => None,
    }
    .ok_or(QueryError::Parquet(ParquetStage::Batch))?;
    let offset_width = match plain {
        DataType::LargeUtf8 | DataType::LargeBinary => 8,
        _ => 4,
    };
    let mut size = 0u64;
    for (row, view) in views.iter().enumerate() {
        if column.is_valid(row) {
            // A view's low 32 bits are its value's length.
            size = size.saturating_add(u64::from(*view as u32));
        }
    }
    let rows = u64::try_from(column.len()).unwrap_or(u64::MAX);
    Ok(size
        .saturating_add(rows.saturating_add(1).saturating_mul(offset_width))
        .saturating_add(rows.div_ceil(8)))
}

/// Rows and uncompressed bytes a Parquet footer reports. Rows are the larger
/// of the file's count and its row groups' sum; bytes, per row group, the
/// larger of its total and its column chunks' sum. A negative size is
/// malformed metadata.
fn footer_size(metadata: &ParquetMetaData) -> Result<(u64, u64), QueryError> {
    let size =
        |value: i64| u64::try_from(value).map_err(|_| QueryError::Parquet(ParquetStage::Metadata));
    let mut rows = 0u64;
    let mut bytes = 0u64;
    for group in metadata.row_groups() {
        rows = rows.saturating_add(size(group.num_rows())?);
        let mut columns = 0u64;
        for column in group.columns() {
            columns = columns.saturating_add(size(column.uncompressed_size())?);
        }
        bytes = bytes.saturating_add(size(group.total_byte_size())?.max(columns));
    }
    let file_rows = size(metadata.file_metadata().num_rows())?;
    Ok((rows.max(file_rows), bytes))
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

    use arrow::array::{Int64Array, StringArray};
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

    /// A million zeros, plain-encoded and compressed: a few kilobytes on
    /// disk that decode to 8 MB. Its pages are overwritten, so decoding any
    /// of it would fail: a limit refusal shows nothing was decoded.
    #[test]
    fn decode_limits_refuse_a_compressible_dataset_from_its_footer() {
        let props = WriterProperties::builder()
            .set_dictionary_enabled(false)
            .set_compression(Compression::ZSTD(ZstdLevel::default()))
            .build();
        let parquet = int_parquet(Int64Array::from(vec![0; 1_000_000]), Some(props));
        assert!(parquet.len() < 64 * 1024, "{} bytes", parquet.len());

        // Pages run from the leading magic to the footer, which ends with
        // its length and the trailing magic.
        let footer_len = u32::from_le_bytes(
            parquet[parquet.len() - 8..parquet.len() - 4]
                .try_into()
                .expect("4 bytes"),
        ) as usize;
        let mut pages_wiped = parquet.clone();
        let pages_end = parquet.len() - 8 - footer_len;
        pages_wiped[4..pages_end].fill(0xA5);

        for (limits, limit) in [
            (
                QueryLimits {
                    max_decoded_bytes: MIB,
                    ..QueryLimits::default()
                },
                QueryLimit::DecodedBytes,
            ),
            (
                QueryLimits {
                    max_decoded_rows: 999_999,
                    ..QueryLimits::default()
                },
                QueryLimit::DecodedRows,
            ),
        ] {
            let mut scope = scope_with(ZkMode::Enabled, limits);
            let err = scope
                .register_parquet("t", &pages_wiped)
                .expect_err("over the limit");
            assert!(
                matches!(err, QueryError::LimitExceeded(found) if found == limit),
                "{err:?}"
            );
        }

        // Within both limits the intact file decodes, and the wiped one fails
        // to: the refusals above came before any decoding.
        let fits = QueryLimits {
            max_decoded_rows: 1_000_000,
            max_decoded_bytes: 16 * MIB,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Enabled, fits);
        assert_eq!(
            scope.register_parquet("t", &parquet).expect("fits"),
            1_000_000
        );
        let mut scope = scope_with(ZkMode::Enabled, fits);
        assert!(matches!(
            scope.register_parquet("t", &pages_wiped),
            Err(QueryError::Parquet(_))
        ));
    }

    /// One kibibyte string in every one of 20,000 rows, dictionary-encoded
    /// (the writer's default) and compressed: its footer reports a few
    /// kilobytes, and it decodes to about 20 MiB of strings. The footer
    /// check passes it, so the decode limit must refuse it while decoding.
    #[test]
    fn the_decode_limit_counts_what_decoding_produces() {
        const ROWS: usize = 20_000;
        let value = "x".repeat(1024);
        let schema = Arc::new(Schema::new(vec![Field::new("s", DataType::Utf8, false)]));
        let strings = StringArray::from_iter_values(std::iter::repeat_n(value.as_str(), ROWS));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(strings)]).expect("batch");
        let props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::default()))
            .build();
        let mut parquet = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut parquet, schema, Some(props)).expect("writer");
        writer.write(&batch).expect("write");
        writer.close().expect("close");

        // The footer understates the decoded strings a thousandfold.
        let footer =
            ParquetRecordBatchReaderBuilder::try_new(Bytes::from(parquet.clone())).expect("footer");
        let (_, footer_bytes) = footer_size(footer.metadata()).expect("sizes");
        assert!(footer_bytes < 256 * 1024, "{footer_bytes} bytes");

        let tight = QueryLimits {
            max_decoded_bytes: 4 * MIB,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, tight);
        let err = scope.register_parquet("t", &parquet).expect_err("refused");
        assert!(
            matches!(err, QueryError::LimitExceeded(QueryLimit::DecodedBytes)),
            "{err:?}"
        );

        // Under a limit with room for the decoded strings it registers.
        let roomy = QueryLimits {
            max_decoded_bytes: 64 * MIB,
            ..QueryLimits::default()
        };
        let mut scope = scope_with(ZkMode::Disabled, roomy);
        assert_eq!(scope.register_parquet("t", &parquet).expect("fits"), ROWS);
    }

    /// A string column in which `repeats` rows hold one `big`-byte value
    /// and, unless `row_group` splits the file, 24 distinct 1 MiB values
    /// follow. The file's dictionary holds the repeated value once; the 24
    /// overflow an 8 MiB dictionary page, so the rest of the chunk is written
    /// plain. Built as a dictionary: as plain strings the rows would not fit
    /// an Arrow array. With `arrow_schema` the file declares the column a
    /// dictionary, as Arrow writers do by default; without it the column
    /// reads back as ordinary strings.
    fn repeated_value_parquet(
        big: usize,
        repeats: usize,
        row_group: Option<usize>,
        arrow_schema: bool,
    ) -> Vec<u8> {
        let mut values = vec!["x".repeat(big)];
        let mut keys = vec![0i32; repeats];
        if row_group.is_none() {
            for (key, first) in (1..=24).zip('a'..) {
                values.push(format!("{first}{}", "x".repeat((1 << 20) - 1)));
                keys.push(key);
            }
        }
        let strings = arrow::array::DictionaryArray::try_new(
            arrow::array::Int32Array::from(keys),
            Arc::new(StringArray::from(values)),
        )
        .expect("dictionary");
        let schema = Arc::new(Schema::new(vec![Field::new(
            "s",
            strings.data_type().clone(),
            false,
        )]));
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(strings)]).expect("batch");
        // A dictionary page larger than the writer's 1 MiB default, as any
        // file may carry, keeps the repeated value dictionary-encoded.
        let props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::default()))
            .set_dictionary_page_size_limit(8 << 20)
            .set_write_batch_size(1)
            .set_max_row_group_row_count(row_group)
            .build();
        let options = parquet::arrow::arrow_writer::ArrowWriterOptions::new()
            .with_properties(props)
            .with_skip_arrow_metadata(!arrow_schema);
        let mut parquet = Vec::new();
        let mut writer =
            ArrowWriter::try_new_with_options(&mut parquet, schema, options).expect("writer");
        writer.write(&batch).expect("write");
        writer.close().expect("close");
        parquet
    }

    /// A value the file's dictionary holds once, repeated until one batch of
    /// it expands past 2 GiB, is refused from its measured size before it
    /// expands, including where the batch crosses from the dictionary to
    /// plain pages or into another row group. Read as a dictionary array,
    /// either crossing expands it inside the reader, which overflows instead.
    #[test]
    fn a_repeated_value_is_refused_before_it_expands() {
        let limits = QueryLimits {
            max_decoded_bytes: 64 * MIB,
            ..QueryLimits::default()
        };
        // 1000 rows of 3 MiB, then plain pages; two row groups of 512 rows
        // of 5 MiB.
        let files = [
            (repeated_value_parquet(3 << 20, 1000, None, false), 1),
            (repeated_value_parquet(5 << 20, 1024, Some(512), false), 2),
        ];
        for (parquet, row_groups) in files {
            let file = Bytes::from(parquet.clone());
            let footer = ParquetRecordBatchReaderBuilder::try_new(file.clone()).expect("footer");
            assert_eq!(footer.metadata().num_row_groups(), row_groups);
            let (_, footer_bytes) = footer_size(footer.metadata()).expect("sizes");
            assert!(footer_bytes < limits.max_decoded_bytes, "{footer_bytes}");

            // Under the hint the first batch holds each value once, and its
            // expanded size is measured without expanding it.
            let file_schema = footer.schema().clone();
            let options = ArrowReaderOptions::new().with_schema(view_hint(&file_schema));
            let metadata =
                ArrowReaderMetadata::try_new(footer.metadata().clone(), options).expect("hint");
            let first = ParquetRecordBatchReaderBuilder::new_with_metadata(file, metadata)
                .with_batch_size(DECODE_BATCH_ROWS)
                .build()
                .expect("reader")
                .next()
                .expect("a batch")
                .expect("decoded");
            assert_eq!(first.num_rows(), DECODE_BATCH_ROWS);
            assert_eq!(first.column(0).data_type(), &DataType::Utf8View);
            let held = u64::try_from(first.get_array_memory_size()).expect("size");
            assert!(held < 64 * MIB, "{held} bytes held");
            let expanded = plain_size(first.column(0).as_ref(), &DataType::Utf8).expect("size");
            assert!(expanded > 2048 * MIB, "{expanded} bytes expanded");

            let mut scope = scope_with(ZkMode::Disabled, limits);
            let err = scope.register_parquet("t", &parquet).expect_err("refused");
            assert!(
                matches!(err, QueryError::LimitExceeded(QueryLimit::DecodedBytes)),
                "{err:?}"
            );
        }
    }

    /// The same files declaring the column a dictionary, as Arrow writers do
    /// by default: it registers as the dictionary it is, each value held
    /// once, where read as a dictionary array either crossing would expand
    /// it inside the reader and overflow.
    #[test]
    fn a_declared_dictionary_is_not_expanded() {
        let limits = QueryLimits {
            max_decoded_bytes: 64 * MIB,
            ..QueryLimits::default()
        };
        let files = [
            repeated_value_parquet(3 << 20, 1000, None, true),
            repeated_value_parquet(5 << 20, 1024, Some(512), true),
        ];
        for parquet in files {
            let footer = ParquetRecordBatchReaderBuilder::try_new(Bytes::from(parquet.clone()))
                .expect("footer");
            let declared = footer.schema().field(0).data_type().clone();
            assert!(matches!(declared, DataType::Dictionary(_, _)), "{declared}");
            assert_eq!(byte_view(&declared), Some(DataType::Utf8View));

            let mut scope = scope_with(ZkMode::Disabled, limits);
            assert_eq!(scope.register_parquet("t", &parquet).expect("fits"), 1024);
        }
    }

    /// A string column registers with its own type, not as the view it
    /// decodes through.
    #[test]
    fn string_columns_keep_their_type() {
        let schema = Arc::new(Schema::new(vec![
            Field::new("s", DataType::Utf8, true),
            Field::new("b", DataType::LargeBinary, false),
        ]));
        let strings = StringArray::from(vec![Some("a"), None, Some("a")]);
        let binary = arrow::array::LargeBinaryArray::from_iter_values([b"x", b"y", b"x"]);
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(strings), Arc::new(binary)])
            .expect("batch");
        let mut parquet = Vec::new();
        let mut writer = ArrowWriter::try_new(&mut parquet, schema.clone(), None).expect("writer");
        writer.write(&batch).expect("write");
        writer.close().expect("close");

        let file = Bytes::from(parquet);
        let footer = ParquetRecordBatchReaderBuilder::try_new(file.clone()).expect("footer");
        let file_schema = footer.schema().clone();
        let options = ArrowReaderOptions::new().with_schema(view_hint(&file_schema));
        let metadata =
            ArrowReaderMetadata::try_new(footer.metadata().clone(), options).expect("hint");
        let decoded = ParquetRecordBatchReaderBuilder::new_with_metadata(file, metadata)
            .build()
            .expect("reader")
            .next()
            .expect("a batch")
            .expect("decoded");
        assert_eq!(decoded.column(0).data_type(), &DataType::Utf8View);
        assert_eq!(decoded.column(1).data_type(), &DataType::BinaryView);
        // The null row's length is not counted: "a", "a", four 4-byte
        // offsets and a bitmap byte; for the binary column three 1-byte
        // values, four 8-byte offsets and a bitmap byte.
        let strings = 2 + 4 * 4 + 1;
        let binary = 3 + 4 * 8 + 1;
        assert_eq!(
            plain_size(decoded.column(0).as_ref(), &DataType::Utf8).expect("size"),
            strings
        );
        assert_eq!(
            plain_size(decoded.column(1).as_ref(), &DataType::LargeBinary).expect("size"),
            binary
        );
        // Three views' inline bytes, and the small page buffer they came from.
        let bound = distinct_bound(decoded.column(0).as_ref());
        assert!((3 * 12..1024).contains(&bound), "{bound}");
        let expanded = expand_views(&decoded, &file_schema, u64::MAX).expect("expands");
        assert_eq!(expanded, batch);
        let err = expand_views(&decoded, &file_schema, strings + binary - 1).expect_err("over");
        assert!(
            matches!(err, QueryError::LimitExceeded(QueryLimit::DecodedBytes)),
            "{err:?}"
        );
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
