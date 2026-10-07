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

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arrow::array::RecordBatch;
use bytes::Bytes;
use datafusion::common::{DataFusionError, exec_err};
use datafusion::datasource::MemTable;
use datafusion::execution::object_store::ObjectStoreRegistry;
use datafusion::execution::runtime_env::RuntimeEnv;
use datafusion::prelude::{SQLOptions, SessionConfig, SessionContext};
use object_store::ObjectStore;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use platform_core::ZkMode;
use platform_crypto::SecretBytes;
use url::Url;

pub mod blind;
pub mod disclosure;
pub mod policy;

pub use blind::blind_index_hex;
pub use disclosure::{DisclosurePolicy, MinCountThreshold};

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("parquet decode failed: {0}")]
    Parquet(String),
    #[error("query planning/execution failed: {0}")]
    Execution(String),
    #[error("result serialization failed: {0}")]
    Serialize(String),
    #[error("query rejected: row-level egress is not permitted in zero-knowledge mode")]
    ZkPolicy,
    #[error("query rejected by disclosure control: {0}")]
    Disclosure(String),
    #[error("query rejected: only read-only queries are permitted")]
    StatementNotAllowed,
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
        if blobs.is_empty() {
            return Ok(0);
        }
        let mut schema = None;
        let mut partitions: Vec<Vec<RecordBatch>> = Vec::with_capacity(blobs.len());
        let mut rows = 0usize;
        for blob in blobs {
            let reader = ParquetRecordBatchReaderBuilder::try_new(wiped_copy(blob))
                .map_err(|e| QueryError::Parquet(e.to_string()))?;
            schema.get_or_insert_with(|| reader.schema().clone());
            let batches: Vec<RecordBatch> = reader
                .build()
                .map_err(|e| QueryError::Parquet(e.to_string()))?
                .collect::<Result<_, _>>()
                .map_err(|e| QueryError::Parquet(e.to_string()))?;
            rows += batches.iter().map(RecordBatch::num_rows).sum::<usize>();
            partitions.push(batches);
        }

        let schema = schema.expect("non-empty blobs yield a schema");
        let mem = MemTable::try_new(schema, partitions)
            .map_err(|e| QueryError::Execution(e.to_string()))?;
        self.ctx
            .register_table(table, Arc::new(mem))
            .map_err(|e| QueryError::Execution(e.to_string()))?;
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
            .map_err(|e| QueryError::Execution(e.to_string()))?;
        read_only()
            .verify_plan(&plan)
            .map_err(|_| QueryError::StatementNotAllowed)?;
        let df = self
            .ctx
            .execute_logical_plan(plan)
            .await
            .map_err(|e| QueryError::Execution(e.to_string()))?;

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
            .map_err(|e| QueryError::Execution(e.to_string()))?;

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
    let mut buf = Vec::new();
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
    serde_json::from_slice(&buf).map_err(|e| QueryError::Serialize(e.to_string()))
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
