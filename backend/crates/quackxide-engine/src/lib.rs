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

use arrow::array::RecordBatch;
use arrow::datatypes::{DataType, Schema};
use bytes::Bytes;
use datafusion::common::{DataFusionError, exec_err};
use datafusion::datasource::MemTable;
use datafusion::execution::disk_manager::{DiskManagerBuilder, DiskManagerMode};
use datafusion::execution::memory_pool::GreedyMemoryPool;
use datafusion::execution::object_store::ObjectStoreRegistry;
use datafusion::execution::runtime_env::{RuntimeEnv, RuntimeEnvBuilder};
use datafusion::prelude::{SQLOptions, SessionConfig, SessionContext};
use object_store::ObjectStore;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
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
        let runtime = scope_runtime(&settings.limits);
        Self {
            ctx: SessionContext::new_with_config_rt(SessionConfig::new(), runtime),
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
    /// track the decoded table. Decoded rows are counted against the row
    /// limit again. Either refusal is [`QueryError::LimitExceeded`].
    /// Decoding is synchronous, so these limits also bound how long it runs.
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
            let reader = ParquetRecordBatchReaderBuilder::try_new(wiped_copy(blob))
                .map_err(|_| QueryError::Parquet(ParquetStage::Metadata))?;
            if let Some((declared_schema, _)) = declared
                && !matches_declared(reader.schema(), declared_schema)
            {
                return Err(QueryError::DeclarationMismatch(Declaration::Schema));
            }
            let (rows, bytes) = footer_size(reader.metadata())?;
            footer_rows = footer_rows.saturating_add(rows);
            footer_bytes = footer_bytes.saturating_add(bytes);
            readers.push(reader);
        }
        check_rows(footer_rows)?;
        if footer_bytes > limits.max_decoded_bytes {
            return Err(QueryError::LimitExceeded(QueryLimit::DecodedBytes));
        }

        let mut schema = None;
        let mut partitions: Vec<Vec<RecordBatch>> = Vec::with_capacity(readers.len());
        let mut rows = 0u64;
        for reader in readers {
            schema.get_or_insert_with(|| reader.schema().clone());
            let mut batches = Vec::new();
            for batch in reader
                .build()
                .map_err(|_| QueryError::Parquet(ParquetStage::Reader))?
            {
                let batch = batch.map_err(|_| QueryError::Parquet(ParquetStage::Batch))?;
                rows = rows.saturating_add(u64::try_from(batch.num_rows()).unwrap_or(u64::MAX));
                check_rows(rows)?;
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
    /// scope's memory pool.
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

        let batches = df
            .collect()
            .await
            .map_err(|err| datafusion_error(ExecutionStage::Execute, &err))?;

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
        if u64::try_from(rows).unwrap_or(u64::MAX) > self.settings.limits.max_result_rows {
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
    use arrow::array::Int64Array;
    use arrow::datatypes::Field;
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

    #[test]
    fn decoder_input_zeroizes_on_drop() {
        // The engine's copy of the decrypted Parquet, which the decoder's
        // `Bytes` own, is wiped on every exit path.
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<WipedParquet>();
    }
}
