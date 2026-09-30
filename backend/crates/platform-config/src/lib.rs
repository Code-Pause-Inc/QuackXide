//! Environment-driven platform configuration.
//!
//! Every customer-facing name, domain, and endpoint is configuration; nothing
//! user-visible is hardcoded, and the engine name never appears in
//! customer-facing output.

use std::net::SocketAddr;

use platform_core::ZkMode;

/// Neutral fallback used until an operator sets `APP_PUBLIC_NAME`.
pub const DEFAULT_PUBLIC_NAME: &str = "Confidential Drive";

const DEFAULT_SYNC_INTERVAL_SECS: u64 = 900;
/// A common small-cell suppression threshold for health statistics.
pub const DEFAULT_MIN_COHORT_SIZE: u64 = 11;
const DEFAULT_QUERY_BUDGET: u64 = 100;
const DEFAULT_SIGNATURE_TOLERANCE_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct PlatformConfig {
    pub brand: BrandConfig,
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub auth: AuthConfig,
    pub connectors: ConnectorConfig,
    pub research: ResearchConfig,
    pub billing: BillingConfig,
    pub features: FeatureFlags,
}

/// Merchant-of-Record (Paddle) webhook settings. Secret redacted in Debug.
#[derive(Clone)]
pub struct BillingConfig {
    /// `MOR_WEBHOOK_SECRET` — Paddle notification-destination secret. When
    /// unset, the webhook endpoint refuses.
    pub paddle_webhook_secret: Option<String>,
    /// `MOR_SIGNATURE_TOLERANCE_SECS` — replay-guard freshness window.
    pub signature_tolerance_secs: u64,
}

impl std::fmt::Debug for BillingConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BillingConfig")
            .field(
                "paddle_webhook_secret",
                &self.paddle_webhook_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("signature_tolerance_secs", &self.signature_tolerance_secs)
            .finish()
    }
}

/// Background connector sync settings.
#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    /// `CONNECTOR_SYNC_INTERVAL_SECS` — background sync cadence.
    pub sync_interval_secs: u64,
}

/// Research-access disclosure-control settings.
#[derive(Debug, Clone)]
pub struct ResearchConfig {
    /// `RESEARCH_MIN_COHORT_SIZE` — result rows whose cohort (`COUNT(*) AS n`)
    /// is smaller are suppressed before egress.
    pub min_cohort_size: u64,
    /// `RESEARCH_DEFAULT_QUERY_BUDGET` — query units for a new grant when the
    /// steward sets none. Budgets bound adaptive (differencing) querying and
    /// are raised by top-up, never reset.
    pub default_query_budget: u64,
    /// `RESEARCH_PRICING_CURRENCY` — ISO 4217 display currency for catalog
    /// prices (stored in integer cents).
    pub pricing_currency: String,
}

/// Customer-facing identity, sourced from env so branding needs no code change.
#[derive(Debug, Clone)]
pub struct BrandConfig {
    /// `APP_PUBLIC_NAME` — product name shown in UIs and emails.
    pub public_name: String,
    /// `APP_DOMAIN_NAME` — public domain used in links and email `From:`.
    pub domain_name: String,
    /// `APP_SUPPORT_EMAIL`.
    pub support_email: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// `BIND_ADDR`, e.g. `127.0.0.1:8080`.
    pub bind_addr: SocketAddr,
}

/// GCS vault settings. Optional so the API boots in storage-less local dev;
/// routes that need the vault refuse instead.
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// `GCP_PROJECT_ID`.
    pub gcp_project_id: Option<String>,
    /// `STORAGE_BUCKET` — bucket holding `tenants/{tenant_id}/…` paths.
    pub bucket: Option<String>,
}

/// JWT verification settings. Secrets never appear in Debug output.
#[derive(Clone)]
pub struct AuthConfig {
    /// `JWT_HS256_SECRET` — shared secret for dev/self-hosted deployments.
    /// When unset, every authenticated route refuses with 503.
    pub hs256_secret: Option<String>,
    /// `JWT_ISSUER` — internal identifier expected in the `iss` claim.
    pub issuer: String,
    /// `JWT_AUDIENCE` — expected `aud` claim.
    pub audience: String,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field(
                "hs256_secret",
                &self.hs256_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct FeatureFlags {
    /// `FEATURE_ZK_ENABLED` — platform-default ZK mode. Defaults to enabled:
    /// disabling the gate must be an explicit choice.
    pub zk: ZkMode,
    /// `TEE_ATTESTATION_REQUIRED` — when true, confidential pipelines refuse
    /// to run without valid SEV-SNP attestation. Defaults to true; only local
    /// development sets it false.
    pub tee_attestation_required: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid value for {key}: {reason}")]
    Invalid { key: &'static str, reason: String },
}

impl PlatformConfig {
    /// Load from the process environment (plus `.env` if present, for dev).
    pub fn from_env() -> Result<Self, ConfigError> {
        let _ = dotenvy::dotenv(); // a missing .env is fine
        Self::from_source(|key| std::env::var(key).ok())
    }

    /// Load from any key→value source. Lets tests avoid mutating process env,
    /// which is `unsafe` in edition 2024 and racy under parallel tests.
    pub fn from_source(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let brand = BrandConfig {
            public_name: get_or(&get, "APP_PUBLIC_NAME", DEFAULT_PUBLIC_NAME),
            domain_name: get_or(&get, "APP_DOMAIN_NAME", "localhost"),
            support_email: get_or(&get, "APP_SUPPORT_EMAIL", "support@localhost"),
        };

        let bind_addr: SocketAddr = get_or(&get, "BIND_ADDR", "127.0.0.1:8080")
            .parse()
            .map_err(|e| ConfigError::Invalid {
                key: "BIND_ADDR",
                reason: format!("{e}"),
            })?;

        let storage = StorageConfig {
            gcp_project_id: get_nonempty(&get, "GCP_PROJECT_ID"),
            bucket: get_nonempty(&get, "STORAGE_BUCKET"),
        };

        let auth = AuthConfig {
            hs256_secret: get_nonempty(&get, "JWT_HS256_SECRET"),
            issuer: get_or(&get, "JWT_ISSUER", "urn:platform:auth"),
            audience: get_or(&get, "JWT_AUDIENCE", "urn:platform:drive"),
        };

        let connectors = ConnectorConfig {
            sync_interval_secs: parse_u64(
                &get,
                "CONNECTOR_SYNC_INTERVAL_SECS",
                DEFAULT_SYNC_INTERVAL_SECS,
            )?,
        };

        let research = ResearchConfig {
            min_cohort_size: parse_u64(&get, "RESEARCH_MIN_COHORT_SIZE", DEFAULT_MIN_COHORT_SIZE)?,
            default_query_budget: parse_u64(
                &get,
                "RESEARCH_DEFAULT_QUERY_BUDGET",
                DEFAULT_QUERY_BUDGET,
            )?,
            pricing_currency: get_or(&get, "RESEARCH_PRICING_CURRENCY", "USD"),
        };

        let billing = BillingConfig {
            paddle_webhook_secret: get_nonempty(&get, "MOR_WEBHOOK_SECRET"),
            signature_tolerance_secs: parse_u64(
                &get,
                "MOR_SIGNATURE_TOLERANCE_SECS",
                DEFAULT_SIGNATURE_TOLERANCE_SECS,
            )?,
        };

        let features = FeatureFlags {
            zk: ZkMode::from_flag(parse_bool(&get, "FEATURE_ZK_ENABLED", true)?),
            tee_attestation_required: parse_bool(&get, "TEE_ATTESTATION_REQUIRED", true)?,
        };

        Ok(Self {
            brand,
            server: ServerConfig { bind_addr },
            storage,
            auth,
            connectors,
            research,
            billing,
            features,
        })
    }
}

fn get_or(get: &impl Fn(&str) -> Option<String>, key: &str, default: &str) -> String {
    match get(key) {
        Some(v) if !v.trim().is_empty() => v.trim().to_owned(),
        _ => default.to_owned(),
    }
}

fn get_nonempty(get: &impl Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get(key)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

fn parse_u64(
    get: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    default: u64,
) -> Result<u64, ConfigError> {
    match get_nonempty(get, key) {
        None => Ok(default),
        Some(raw) => raw.parse().map_err(|e| ConfigError::Invalid {
            key,
            reason: format!("{e}"),
        }),
    }
}

fn parse_bool(
    get: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match get_nonempty(get, key) {
        None => Ok(default),
        Some(raw) => match raw.to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => Ok(true),
            "0" | "false" | "off" | "no" => Ok(false),
            other => Err(ConfigError::Invalid {
                key,
                reason: format!("expected a boolean, got {other:?}"),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn source(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn defaults_are_neutral_and_fail_closed() {
        let cfg = PlatformConfig::from_source(source(&[])).expect("defaults load");
        assert_eq!(cfg.brand.public_name, DEFAULT_PUBLIC_NAME);
        assert_eq!(cfg.brand.domain_name, "localhost");
        assert_eq!(cfg.server.bind_addr.port(), 8080);
        assert!(cfg.storage.bucket.is_none());
        assert!(cfg.auth.hs256_secret.is_none());
        assert_eq!(cfg.auth.issuer, "urn:platform:auth");
        assert_eq!(cfg.auth.audience, "urn:platform:drive");
        assert!(cfg.features.zk.is_enabled());
        assert!(cfg.features.tee_attestation_required);
        assert_eq!(cfg.connectors.sync_interval_secs, 900);
        assert_eq!(cfg.research.min_cohort_size, 11);
        assert_eq!(cfg.research.default_query_budget, 100);
        assert_eq!(cfg.research.pricing_currency, "USD");
        assert!(cfg.billing.paddle_webhook_secret.is_none());
        assert_eq!(cfg.billing.signature_tolerance_secs, 300);
    }

    #[test]
    fn billing_secret_is_redacted_in_debug() {
        let cfg =
            PlatformConfig::from_source(source(&[("MOR_WEBHOOK_SECRET", "pdl_secret_value")]))
                .expect("loads");
        let debugged = format!("{:?}", cfg.billing);
        assert!(!debugged.contains("pdl_secret_value"));
        assert!(debugged.contains("<redacted>"));
    }

    #[test]
    fn research_budget_parses_and_rejects_garbage() {
        let cfg = PlatformConfig::from_source(source(&[("RESEARCH_DEFAULT_QUERY_BUDGET", "25")]))
            .expect("loads");
        assert_eq!(cfg.research.default_query_budget, 25);
        assert!(
            PlatformConfig::from_source(source(&[("RESEARCH_DEFAULT_QUERY_BUDGET", "lots")]))
                .is_err()
        );
    }

    #[test]
    fn connector_interval_parses_and_rejects_garbage() {
        let cfg = PlatformConfig::from_source(source(&[("CONNECTOR_SYNC_INTERVAL_SECS", "60")]))
            .expect("loads");
        assert_eq!(cfg.connectors.sync_interval_secs, 60);
        assert!(
            PlatformConfig::from_source(source(&[("CONNECTOR_SYNC_INTERVAL_SECS", "soon")]))
                .is_err()
        );
    }

    #[test]
    fn auth_secret_never_appears_in_debug_output() {
        let cfg =
            PlatformConfig::from_source(source(&[("JWT_HS256_SECRET", "super-secret-value")]))
                .expect("loads");
        let debugged = format!("{:?}", cfg.auth);
        assert!(!debugged.contains("super-secret-value"));
        assert!(debugged.contains("<redacted>"));
    }

    #[test]
    fn brand_is_fully_configurable() {
        let cfg = PlatformConfig::from_source(source(&[
            ("APP_PUBLIC_NAME", "Acme Vault"),
            ("APP_DOMAIN_NAME", "vault.example"),
            ("APP_SUPPORT_EMAIL", "help@vault.example"),
        ]))
        .expect("loads");
        assert_eq!(cfg.brand.public_name, "Acme Vault");
        assert_eq!(cfg.brand.domain_name, "vault.example");
        assert_eq!(cfg.brand.support_email, "help@vault.example");
    }

    #[test]
    fn zk_toggle_parses_common_boolean_spellings() {
        for (raw, expected) in [("true", true), ("1", true), ("on", true), ("off", false)] {
            let cfg =
                PlatformConfig::from_source(source(&[("FEATURE_ZK_ENABLED", raw)])).expect("loads");
            assert_eq!(cfg.features.zk.is_enabled(), expected, "raw={raw}");
        }
    }

    #[test]
    fn invalid_boolean_is_a_hard_error() {
        let err = PlatformConfig::from_source(source(&[("FEATURE_ZK_ENABLED", "maybe")]))
            .expect_err("must fail");
        assert!(err.to_string().contains("FEATURE_ZK_ENABLED"));
    }

    #[test]
    fn invalid_bind_addr_is_a_hard_error() {
        let err = PlatformConfig::from_source(source(&[("BIND_ADDR", "not-an-addr")]))
            .expect_err("must fail");
        assert!(err.to_string().contains("BIND_ADDR"));
    }
}
