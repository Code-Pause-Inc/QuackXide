//! DEV ONLY (feature `dev`): the research wiring shared by the `devstack`
//! server and the API integration tests, so the two cannot drift apart; the
//! steward upload sealing shared by the `seal-upload` tool and the tests,
//! which seals as the browser does; and the checks a dev-only server runs
//! before it starts.
//!
//! Nothing here is confidential. The vault is in memory, tenant keys are held
//! in process memory, and the grant, budget and catalog registries are in
//! memory. By default the query service runs on the simulated TEE: an
//! in-process signer issues Confidential Space-shaped tokens, the production
//! verifier checks them, and the key-release stand-in releases tenant keys
//! only to a token that passes. Release builds do not enable the `dev`
//! feature, so none of this is compiled into them.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use platform_config::PlatformConfig;
use platform_connectors::pipeline::PipelineError;
use platform_connectors::snapshot::{SnapshotManifest, SnapshotWriter, manifest_info, object_info};
use platform_connectors::upload::{UploadHeader, encode_upload_body};
use platform_core::{
    ConnectorSlug, DeclaredColumn, DeclaredSchema, ObjectId, SnapshotVersion, TenantId,
};
use platform_crypto::{TenantKeypair, TenantPublicKey, hpke_seal_to_tenant};
use platform_enclave::AttestationProvider;
use platform_enclave::simulated_token::{
    SIMULATED_IMAGE_DIGEST, SimulatedClaims, SimulatedTokenProvider, TokenSigner,
};
use platform_enclave::token::ReleasePolicy;
use platform_storage::{ObjectStoreVault, VaultStore};
use quackxide_engine::EngineSettings;
use synth_data::{SchemaName, Spec};
use zeroize::Zeroizing;

use crate::key_release::{
    AttestedKeyProvider, EnclaveIdentity, InProcessKeyReleaseClient, KeyReleaseRelyingParty,
    StaticKeySource,
};
use crate::query::{ConnectorQueryService, MultiTenantDevKeyProvider};
use crate::research::ResearchService;

/// Process-environment variable a dev-only server requires, set to `1`.
pub const OPT_IN_VAR: &str = "DEVSTACK_ALLOW_INSECURE";

/// Issuer of the in-process simulated attestation tokens.
const SIM_ISSUER: &str = "urn:devstack:sim";

/// An in-memory vault and the tenant keys that open it, held in process
/// memory. [`DevResearchStack::query_service`] turns it into the
/// research-enabled query service.
pub struct DevResearchStack {
    vault: Arc<dyn VaultStore>,
    keys: Vec<(TenantId, TenantKeypair)>,
}

impl DevResearchStack {
    /// An empty in-memory vault and no tenant keys.
    pub fn new() -> Self {
        Self::with_vault(Arc::new(ObjectStoreVault::new_in_memory()))
    }

    /// `vault` and no tenant keys, for tests that inject storage faults.
    pub fn with_vault(vault: Arc<dyn VaultStore>) -> Self {
        Self {
            vault,
            keys: Vec::new(),
        }
    }

    /// The vault, for `AppState`.
    pub fn vault(&self) -> Arc<dyn VaultStore> {
        self.vault.clone()
    }

    /// Keeps `keypair` as `tenant`'s key without writing anything, so
    /// research queries can open data that arrives later, such as a steward
    /// upload through `PUT /api/v1/datasets/{dataset}`.
    pub fn register_key(&mut self, tenant: TenantId, keypair: TenantKeypair) {
        self.keys.push((tenant, keypair));
    }

    /// Seals `parquet` to `keypair` and commits it as `tenant`'s snapshot of
    /// `connector`, as a connector sync does. Queries read only the newest
    /// committed snapshot (ADR 0003). The keypair is kept, so research
    /// queries can open the snapshot.
    pub async fn commit_snapshot(
        &mut self,
        tenant: TenantId,
        keypair: TenantKeypair,
        connector: &ConnectorSlug,
        dataset: &str,
        parquet: &[u8],
    ) -> Result<SnapshotVersion, PipelineError> {
        let public_key = keypair.public_key();
        let mut snapshot =
            SnapshotWriter::begin(&*self.vault, tenant, &public_key, connector.clone());
        snapshot.put(dataset, parquet).await?;
        let version = snapshot.commit().await?;
        self.keys.push((tenant, keypair));
        Ok(version)
    }

    /// The query service with research queries on through `research` (give
    /// `AppState::research` the same `Arc`), on the simulated TEE. Each query
    /// attests with a simulated token, and the in-process key-release
    /// stand-in releases the tenant's key only after that token verifies.
    pub fn query_service(
        self,
        settings: EngineSettings,
        research: Arc<ResearchService>,
    ) -> ConnectorQueryService {
        let signer = Arc::new(TokenSigner::generate(
            SIM_ISSUER,
            SimulatedClaims::default(),
        ));
        let policy = ReleasePolicy {
            allowed_image_digests: vec![SIMULATED_IMAGE_DIGEST.into()],
        };
        let attestation = Arc::new(SimulatedTokenProvider::in_process(
            signer.clone(),
            policy.clone(),
        ));
        let relying_party = Arc::new(KeyReleaseRelyingParty::new(
            Arc::new(StaticKeySource(signer.jwks())),
            signer.issuer(),
            policy,
        ));
        for (tenant, keypair) in &self.keys {
            relying_party.insert_tenant_key(*tenant, keypair);
        }
        let identity = Arc::new(EnclaveIdentity::generate());
        let keys = Arc::new(AttestedKeyProvider::new(
            identity.clone(),
            attestation.clone(),
            Arc::new(InProcessKeyReleaseClient(relying_party)),
        ));
        // Simulated tokens never satisfy required attestation.
        ConnectorQueryService::new(self.vault, keys, attestation, settings, false)
            .with_research(research)
            .with_enclave_identity(identity)
    }

    /// The query service with research queries on through `research`, with
    /// the attestation gate's provider and whether it requires hardware
    /// evidence. Tenant keys open straight from process memory, with no key
    /// release.
    pub fn query_service_with_attestation(
        self,
        settings: EngineSettings,
        research: Arc<ResearchService>,
        attestation: Arc<dyn AttestationProvider>,
        require_attestation: bool,
    ) -> ConnectorQueryService {
        let mut keys = MultiTenantDevKeyProvider::new();
        for (tenant, keypair) in self.keys {
            keys.insert(tenant, keypair);
        }
        ConnectorQueryService::new(
            self.vault,
            Arc::new(keys),
            attestation,
            settings,
            require_attestation,
        )
        .with_research(research)
    }
}

impl Default for DevResearchStack {
    fn default() -> Self {
        Self::new()
    }
}

/// What a steward's browser sends to upload one dataset
/// (`PUT /api/v1/datasets/{dataset}`, ADR 0012): the body, and the version
/// and object id it bound into the sealed manifest and object.
#[derive(Debug, Clone)]
pub struct SealedUpload {
    pub version: SnapshotVersion,
    pub object: ObjectId,
    pub body: Vec<u8>,
}

/// Seals `parquet` and a manifest listing it to `key`, as the steward's
/// browser does for `steward`'s upload of `dataset` at `version`, and frames
/// them with a header declaring `schema` and `row_cap`. The object id is
/// drawn here, as the browser draws it. Needs only the public key.
pub fn seal_upload(
    steward: TenantId,
    key: &TenantPublicKey,
    dataset: &ConnectorSlug,
    version: SnapshotVersion,
    parquet: &[u8],
    schema: DeclaredSchema,
    row_cap: u64,
) -> anyhow::Result<SealedUpload> {
    let object = ObjectId::generate();
    let sealed = hpke_seal_to_tenant(key, &object_info(&steward, dataset, &object), parquet)?;
    let manifest = serde_json::to_vec(&SnapshotManifest {
        version: version.clone(),
        objects: vec![object],
    })?;
    let manifest =
        hpke_seal_to_tenant(key, &manifest_info(&steward, dataset, &version), &manifest)?;
    let header = UploadHeader {
        version: version.clone(),
        object,
        row_cap,
        schema,
    };
    let body = encode_upload_body(&header, &manifest, &sealed)?;
    Ok(SealedUpload {
        version,
        object,
        body,
    })
}

/// Seeds the cohort [`seal_cohort_upload`] seals, so every run uploads the
/// same rows.
const UPLOAD_COHORT_SEED: u64 = 7;

/// A seeded synthetic cohort (`synth-data`'s `cohort` schema, with
/// `synth_data::cohort::min_rows(k)` rows built around the threshold `k`, so
/// groups fall on both sides of it), sealed by [`seal_upload`] as `steward`'s
/// upload of `dataset` at the current time. The header declares the
/// cohort's columns and its row count. This is the body `seal-upload` writes
/// for `scripts/test-simulated-tee.sh`.
pub fn seal_cohort_upload(
    steward: TenantId,
    key: &TenantPublicKey,
    dataset: &ConnectorSlug,
    k: usize,
) -> anyhow::Result<SealedUpload> {
    let rows = synth_data::cohort::min_rows(k);
    let spec = Spec::new(SchemaName::Cohort, UPLOAD_COHORT_SEED, rows).with_k(k);
    let parquet = Zeroizing::new(synth_data::parquet_bytes(&spec)?);
    seal_upload(
        steward,
        key,
        dataset,
        SnapshotVersion::generate(),
        &parquet,
        declared_schema(SchemaName::Cohort)?,
        u64::try_from(rows)?,
    )
}

/// The schema a steward declares for a table of `schema`: each column's name
/// and type family, in order.
fn declared_schema(schema: SchemaName) -> anyhow::Result<DeclaredSchema> {
    let columns = schema
        .arrow_schema()
        .fields()
        .iter()
        .map(|field| {
            let column_type = quackxide_engine::column_type_of(field.data_type())
                .with_context(|| format!("column {} has no declared type family", field.name()))?;
            Ok(DeclaredColumn {
                name: field.name().clone(),
                column_type,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(DeclaredSchema::new(columns)?)
}

/// Why a dev-only server refuses to start.
#[derive(Debug, PartialEq, Eq)]
pub enum DevRefusal {
    /// `DEVSTACK_ALLOW_INSECURE` is not exactly `1` in the process environment.
    NotOptedIn,
    /// `JWT_HS256_SECRET` is unset or blank.
    NoJwtSecret,
    /// `BIND_ADDR` would accept connections from other machines.
    PublicBindAddr(SocketAddr),
}

impl DevRefusal {
    /// The cause, for the `service.start` audit record: no configured values.
    pub fn audit_detail(&self) -> &'static str {
        match self {
            DevRefusal::NotOptedIn => "dev server refused: no explicit opt-in",
            DevRefusal::NoJwtSecret => "dev server refused: JWT_HS256_SECRET unset",
            DevRefusal::PublicBindAddr(_) => "dev server refused: BIND_ADDR is not loopback",
        }
    }
}

impl fmt::Display for DevRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DevRefusal::NotOptedIn => write!(
                f,
                "set {OPT_IN_VAR}=1 in this command's environment to confirm you want an \
                 insecure, development-only server (a value in .env does not count)"
            ),
            DevRefusal::NoJwtSecret => write!(
                f,
                "JWT_HS256_SECRET is not set; put one in backend/.env (README \"Development\")"
            ),
            DevRefusal::PublicBindAddr(addr) => write!(
                f,
                "BIND_ADDR {addr} is not a loopback address; dev-only servers listen only on \
                 127.0.0.1 or [::1]"
            ),
        }
    }
}

impl std::error::Error for DevRefusal {}

/// Refuses unless `process_env` sets `DEVSTACK_ALLOW_INSECURE=1`.
///
/// `process_env` looks variables up the way the source passed to
/// `PlatformConfig::from_source` does. A server passes the real process
/// environment and calls this before anything loads `.env`, so a value in
/// `.env` cannot opt in.
pub fn require_opt_in(process_env: impl Fn(&str) -> Option<String>) -> Result<(), DevRefusal> {
    match process_env(OPT_IN_VAR).as_deref() {
        Some("1") => Ok(()),
        _ => Err(DevRefusal::NotOptedIn),
    }
}

/// Refuses unless `config` has a JWT secret to sign and verify dev tokens
/// with, and a loopback `BIND_ADDR`. Returns the secret.
pub fn require_dev_config(config: &PlatformConfig) -> Result<&str, DevRefusal> {
    let Some(secret) = config
        .auth
        .hs256_secret
        .as_ref()
        .map(platform_core::SecretString::expose)
    else {
        return Err(DevRefusal::NoJwtSecret);
    };
    let bind_addr = config.server.bind_addr;
    if !bind_addr.ip().is_loopback() {
        return Err(DevRefusal::PublicBindAddr(bind_addr));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: (&str, &str) = ("JWT_HS256_SECRET", "dev-test-secret");

    /// Looks `key` up in fixed pairs, as a test source for `from_source`.
    fn lookup(vars: &[(&str, &str)], key: &str) -> Option<String> {
        vars.iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| (*value).to_owned())
    }

    fn config_with(vars: &[(&str, &str)]) -> PlatformConfig {
        PlatformConfig::from_source(|key| lookup(vars, key)).expect("config")
    }

    #[test]
    fn startup_without_the_opt_in_flag_is_refused() {
        assert_eq!(require_opt_in(|_| None), Err(DevRefusal::NotOptedIn));
        for value in ["", "0", "true", "yes"] {
            let env = [(OPT_IN_VAR, value)];
            assert_eq!(
                require_opt_in(|key| lookup(&env, key)),
                Err(DevRefusal::NotOptedIn),
                "{OPT_IN_VAR}={value:?}"
            );
        }
    }

    #[test]
    fn opt_in_flag_set_to_1_is_accepted() {
        let env = [(OPT_IN_VAR, "1")];
        assert_eq!(require_opt_in(|key| lookup(&env, key)), Ok(()));
    }

    #[test]
    fn startup_without_a_jwt_secret_is_refused() {
        let unset = config_with(&[]);
        let blank = config_with(&[("JWT_HS256_SECRET", "  ")]);
        assert_eq!(require_dev_config(&unset), Err(DevRefusal::NoJwtSecret));
        assert_eq!(require_dev_config(&blank), Err(DevRefusal::NoJwtSecret));
    }

    #[test]
    fn startup_on_a_non_loopback_address_is_refused() {
        let config = config_with(&[SECRET, ("BIND_ADDR", "0.0.0.0:8080")]);
        let addr = "0.0.0.0:8080".parse().expect("addr");
        assert_eq!(
            require_dev_config(&config),
            Err(DevRefusal::PublicBindAddr(addr))
        );
    }

    #[test]
    fn dev_config_with_a_secret_on_loopback_is_accepted() {
        for bind in ["127.0.0.1:8080", "[::1]:8080"] {
            let config = config_with(&[SECRET, ("BIND_ADDR", bind)]);
            assert_eq!(require_dev_config(&config), Ok(SECRET.1), "{bind}");
        }
    }
}
