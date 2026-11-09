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

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arrow::array::RecordBatch;
use arrow::datatypes::{DataType, Schema};
use bytes::Bytes;
use datafusion::common::{DataFusionError, exec_err};
use datafusion::datasource::MemTable;
use datafusion::execution::object_store::ObjectStoreRegistry;
use datafusion::execution::runtime_env::RuntimeEnv;
use datafusion::prelude::{SQLOptions, SessionConfig, SessionContext};
use object_store::ObjectStore;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use platform_core::{ColumnType, DeclaredSchema, ZkMode};
use platform_crypto::{SecretBytes, ZeroizingWriter};
use url::Url;

pub mod blind;
pub mod disclosure;
pub mod policy;

pub use blind::blind_index_hex;
pub use disclosure::{DisclosurePolicy, MinCountThreshold};

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
}

/// RAII scope for one query session.
///
/// `Drop` deregisters every table, releasing the Arrow buffers so decrypted
/// frames do not outlive the query. The decrypted Parquet input stays owned
/// (and zeroized) by the caller.
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
        let runtime = RuntimeEnv {
            object_store_registry: Arc::new(NoObjectStores),
            ..RuntimeEnv::default()
        };
        Self {
            ctx: SessionContext::new_with_config_rt(SessionConfig::new(), Arc::new(runtime)),
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
    pub fn register_parquet_many(
        &mut self,
        table: &str,
        blobs: &[&[u8]],
    ) -> Result<usize, QueryError> {
        self.register(table, blobs, None)
    }

    /// As [`register_parquet_many`](Self::register_parquet_many), for a
    /// dataset whose shape a steward declared (ADR 0011). Each blob's schema
    /// must match `schema` (names in order, and [`ColumnType`] families),
    /// and the rows its footer reports, summed, must not exceed `row_cap`,
    /// both checked before any batch is decoded. Decoded rows are counted
    /// against `row_cap` again. A failure is
    /// [`QueryError::DeclarationMismatch`].
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
        let mut schema = None;
        let mut partitions: Vec<Vec<RecordBatch>> = Vec::with_capacity(blobs.len());
        let mut rows = 0usize;
        let mut footer_rows = 0u64;
        for blob in blobs {
            let reader = ParquetRecordBatchReaderBuilder::try_new(wiped_copy(blob))
                .map_err(|_| QueryError::Parquet(ParquetStage::Metadata))?;
            if let Some((declared_schema, row_cap)) = declared {
                if !matches_declared(reader.schema(), declared_schema) {
                    return Err(QueryError::DeclarationMismatch(Declaration::Schema));
                }
                let blob_rows = u64::try_from(reader.metadata().file_metadata().num_rows())
                    .map_err(|_| QueryError::Parquet(ParquetStage::Metadata))?;
                footer_rows = footer_rows.saturating_add(blob_rows);
                if footer_rows > row_cap {
                    return Err(QueryError::DeclarationMismatch(Declaration::RowCap));
                }
            }
            schema.get_or_insert_with(|| reader.schema().clone());
            let batches: Vec<RecordBatch> = reader
                .build()
                .map_err(|_| QueryError::Parquet(ParquetStage::Reader))?
                .collect::<Result<_, _>>()
                .map_err(|_| QueryError::Parquet(ParquetStage::Batch))?;
            rows += batches.iter().map(RecordBatch::num_rows).sum::<usize>();
            partitions.push(batches);
        }
        if let Some((_, row_cap)) = declared
            && u64::try_from(rows).unwrap_or(u64::MAX) > row_cap
        {
            return Err(QueryError::DeclarationMismatch(Declaration::RowCap));
        }

        let schema = schema.expect("non-empty blobs yield a schema");
        let mem = MemTable::try_new(schema, partitions)
            .map_err(|_| QueryError::Execution(ExecutionStage::LoadTable))?;
        self.ctx
            .register_table(table, Arc::new(mem))
            .map_err(|_| QueryError::Execution(ExecutionStage::LoadTable))?;
        self.tables.push(table.to_owned());
        Ok(rows)
    }

    /// Run SQL over the registered frames. In `ZkMode::Enabled`, or with a
    /// disclosure policy attached, the plan must pass the aggregate-only
    /// allowlist and carry a genuine `COUNT(*) AS n`, a disclosure policy is
    /// required, and results pass through it before egress.
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
            .map_err(|_| QueryError::Execution(ExecutionStage::Plan))?;
        read_only()
            .verify_plan(&plan)
            .map_err(|_| QueryError::StatementNotAllowed)?;
        let df = self
            .ctx
            .execute_logical_plan(plan)
            .await
            .map_err(|_| QueryError::Execution(ExecutionStage::Prepare))?;

        let gated = self.settings.zk.is_enabled() || self.disclosure.is_some();
        if gated {
            if !policy::is_aggregate_only(df.logical_plan()) {
                return Err(QueryError::ZkPolicy);
            }
            disclosure::verify_count_column(df.logical_plan())?;
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
            .map_err(|_| QueryError::Execution(ExecutionStage::Execute))?;

        match disclosure {
            None => Ok(batches),
            Some(policy) => {
                let outcome = policy.apply(batches)?;
                self.last_suppressed_rows
                    .store(outcome.suppressed_rows, Ordering::Relaxed);
                Ok(outcome.batches)
            }
        }
    }

    /// Run a query and serialize its result rows to JSON.
    pub async fn sql_json(&self, query: &str) -> Result<serde_json::Value, QueryError> {
        batches_to_json(&self.sql(query).await?)
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
    struct Wiped(SecretBytes);
    impl AsRef<[u8]> for Wiped {
        fn as_ref(&self) -> &[u8] {
            self.0.expose()
        }
    }
    Bytes::from_owner(Wiped(SecretBytes::new(blob.to_vec())))
}

/// Serialize record batches to a JSON array of row objects.
pub fn batches_to_json(batches: &[RecordBatch]) -> Result<serde_json::Value, QueryError> {
    let refs: Vec<&RecordBatch> = batches.iter().filter(|b| b.num_rows() > 0).collect();
    // Rows serialize to plaintext JSON; growth and drop wipe each copy.
    let mut buf = ZeroizingWriter::with_capacity(0);
    {
        let mut writer = arrow::json::ArrayWriter::new(&mut buf);
        writer
            .write_batches(&refs)
            .map_err(|e| QueryError::Serialize(e.to_string()))?;
        writer
            .finish()
            .map_err(|e| QueryError::Serialize(e.to_string()))?;
    }
    if buf.is_empty() {
        return Ok(serde_json::Value::Array(Vec::new()));
    }
    serde_json::from_slice(buf.into_secret().expose())
        .map_err(|e| QueryError::Serialize(e.to_string()))
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
    use super::*;

    #[test]
    fn scope_cannot_reach_the_local_filesystem() {
        use datafusion::execution::object_store::ObjectStoreUrl;
        let scope = QueryScope::new(EngineSettings {
            zk: ZkMode::Enabled,
            max_concurrent_queries: 1,
        });
        let local = ObjectStoreUrl::local_filesystem();
        assert!(scope.ctx.runtime_env().object_store(&local).is_err());
    }
}
