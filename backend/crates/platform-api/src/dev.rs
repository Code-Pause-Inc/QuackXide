//! DEV ONLY (feature `dev`): the research wiring shared by the `devstack`
//! server and the API integration tests, so the two cannot drift apart, and
//! the checks a dev-only server runs before it starts.
//!
//! Nothing here is confidential. The vault is in memory, tenant keys are held
//! in process memory ([`MultiTenantDevKeyProvider`]), the grant, budget and
//! catalog registries are in memory, and by default TEE evidence is
//! fabricated ([`DevAttestation::allow_insecure_dev`]) and accepted because
//! attestation is not required. Release builds do not enable the `dev`
//! feature, so none of this is compiled into them.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use platform_config::PlatformConfig;
use platform_connectors::pipeline::PipelineError;
use platform_connectors::snapshot::SnapshotWriter;
use platform_core::{ConnectorSlug, SnapshotVersion, TenantId};
use platform_crypto::TenantKeypair;
use platform_enclave::{AttestationProvider, DevAttestation};
use platform_storage::{ObjectStoreVault, VaultStore};
use quackxide_engine::EngineSettings;

use crate::query::{ConnectorQueryService, MultiTenantDevKeyProvider};
use crate::research::ResearchStores;

/// Process-environment variable a dev-only server requires, set to `1`.
pub const OPT_IN_VAR: &str = "DEVSTACK_ALLOW_INSECURE";

/// An in-memory vault and the tenant keys that open it, held in process
/// memory. [`DevResearchStack::query_service`] turns it into the
/// research-enabled query service.
pub struct DevResearchStack {
    vault: Arc<dyn VaultStore>,
    keys: MultiTenantDevKeyProvider,
}

impl DevResearchStack {
    /// An empty in-memory vault and no tenant keys.
    pub fn new() -> Self {
        Self {
            vault: Arc::new(ObjectStoreVault::new_in_memory()),
            keys: MultiTenantDevKeyProvider::new(),
        }
    }

    /// The vault, for `AppState`.
    pub fn vault(&self) -> Arc<dyn VaultStore> {
        self.vault.clone()
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
        self.keys.insert(tenant, keypair);
        Ok(version)
    }

    /// The query service with research access on: in-memory catalog,
    /// access requests, grants and budgets, behind fabricated `Development`
    /// attestation, which passes because attestation is not required.
    pub fn query_service(
        self,
        settings: EngineSettings,
        min_cohort: u64,
        default_budget: u64,
    ) -> ConnectorQueryService {
        self.query_service_with_attestation(
            settings,
            min_cohort,
            default_budget,
            Arc::new(DevAttestation::allow_insecure_dev()),
            false,
        )
    }

    /// As [`query_service`](Self::query_service), with the attestation
    /// gate's provider and whether it requires SEV-SNP evidence.
    pub fn query_service_with_attestation(
        self,
        settings: EngineSettings,
        min_cohort: u64,
        default_budget: u64,
        attestation: Arc<dyn AttestationProvider>,
        require_attestation: bool,
    ) -> ConnectorQueryService {
        ConnectorQueryService::new(
            self.vault,
            Arc::new(self.keys),
            attestation,
            settings,
            require_attestation,
        )
        .with_research(ResearchStores::in_memory(), min_cohort, default_budget)
    }
}

impl Default for DevResearchStack {
    fn default() -> Self {
        Self::new()
    }
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
    let Some(secret) = config.auth.hs256_secret.as_deref() else {
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
