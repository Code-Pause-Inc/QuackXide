//! DEV ONLY — local research stack: the API with the research routes wired
//! (catalog, access requests, grants, budgets, research queries) and seeded,
//! so the steward and researcher lifecycle runs on one machine without
//! SEV-SNP hardware.
//!
//! Nothing here is confidential. Tenant keys are held in process memory, TEE
//! evidence is fabricated (`DevAttestation::allow_insecure_dev`), and the
//! vault and registries are in memory, so everything is lost on exit. The
//! binary is built only with the `dev` feature and refuses to start unless:
//!
//! * `DEVSTACK_ALLOW_INSECURE=1` is set in the command's environment (a value
//!   in `.env` does not count);
//! * `JWT_HS256_SECRET` is configured, in the environment or `backend/.env`;
//! * `BIND_ADDR` is a loopback address (default `127.0.0.1:8080`).
//!
//! At startup it creates a steward and a researcher tenant, commits a seeded
//! synthetic cohort (`synth-data`, built around `RESEARCH_MIN_COHORT_SIZE` so
//! groups fall on both sides of it) as the steward's `health` snapshot,
//! publishes a catalog listing for it, and prints an HS256 token for each
//! role. It always uses its own in-memory vault and dev providers, so it
//! ignores `STORAGE_BUCKET`, `KEY_RELEASE_URL` and `TEE_ATTESTATION_REQUIRED`;
//! it serves no metrics listener, and the admin routes answer 503.
//!
//! The startup checks, the snapshot commit and the research wiring live in
//! `platform_api::dev`, shared with the API integration tests.
//!
//! Usage, from `backend/`:
//!   DEVSTACK_ALLOW_INSECURE=1 cargo run -p platform-api --features dev --bin devstack

use std::sync::Arc;

use anyhow::{Context as _, anyhow};
use platform_api::dev::{self, DevResearchStack};
use platform_api::query::ConnectorQueryService;
use platform_api::research::PublishListingRequest;
use platform_api::{AppState, build_apps};
use platform_auth::JwtVerifier;
use platform_config::PlatformConfig;
use platform_core::{ConnectorSlug, TenantId};
use platform_crypto::TenantKeypair;
use platform_telemetry::{AuditKind, security_audit_event};
use quackxide_engine::EngineSettings;
use synth_data::{SchemaName, Spec};
use zeroize::Zeroizing;

/// Connector slug the cohort is sealed under, and so its SQL table name.
const CONNECTOR: &str = "health";
/// Fixed seed: every run serves the same synthetic rows.
const COHORT_SEED: u64 = 7;
/// Token lifetime, the same as `devtoken`'s.
const TOKEN_TTL_SECS: i64 = 8 * 3600;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Before `from_env` loads `.env`, so a stray `.env` cannot opt in.
    let opted_in = dev::require_opt_in(|key| std::env::var(key).ok());
    let config = PlatformConfig::from_env()?;
    platform_telemetry::init_from_env();

    let secret = match opted_in.and_then(|()| dev::require_dev_config(&config)) {
        Ok(secret) => secret,
        Err(refusal) => {
            security_audit_event(
                AuditKind::ServiceStart,
                None,
                "refused",
                refusal.audit_detail(),
            );
            anyhow::bail!("devstack refused to start: {refusal}");
        }
    };
    warn_insecure();

    let connector = ConnectorSlug::new(CONNECTOR)?;
    let steward = TenantId::generate();
    let researcher = TenantId::generate();
    let min_cohort = config.research.min_cohort_size;
    let (parquet, rows) = synthetic_cohort(min_cohort)?;

    // The steward's key stays in this process: dev only, not zero-trust.
    let steward_keypair = TenantKeypair::generate();
    let mut stack = DevResearchStack::new();
    stack
        .commit_snapshot(steward, steward_keypair, &connector, "cohort", &parquet)
        .await
        .context("committing the synthetic cohort")?;
    let vault = stack.vault();
    let service = stack.query_service(
        engine_settings(&config),
        min_cohort,
        config.research.default_query_budget,
    );
    let listing_id = publish_listing_for(&service, steward, &connector).await?;

    let steward_token = dev_token(secret, &config, steward, "dev-steward")?;
    let researcher_token = dev_token(secret, &config, researcher, "dev-researcher")?;
    let jwt = Arc::new(JwtVerifier::hs256(
        secret,
        &config.auth.issuer,
        &config.auth.audience,
    ));

    let bind_addr = config.server.bind_addr;
    let (app, _metrics) = build_apps(AppState {
        config: Arc::new(config),
        vault,
        jwt: Some(jwt),
        query: Some(Arc::new(service)),
        provisioning: None,
    });

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("cannot listen on {bind_addr}; is another server using it?"))?;

    let sql = example_sql();
    eprintln!();
    eprintln!("devstack listening on http://{bind_addr} (INSECURE, DEVELOPMENT ONLY)");
    eprintln!("  dataset            `{CONNECTOR}`: {rows} synthetic rows, k = {min_cohort}");
    eprintln!("  catalog listing    {listing_id}");
    eprintln!("  steward tenant     {steward}");
    eprintln!("  steward token      {steward_token}");
    eprintln!("  researcher tenant  {researcher}");
    eprintln!("  researcher token   {researcher_token}");
    eprintln!("Tokens expire in 8 h. Keys, data and grants live in memory and vanish on exit.");
    eprintln!("Once the steward approves the researcher's request, query as the researcher:");
    eprintln!(
        "  curl -s http://{bind_addr}/api/v1/research/query \\\n    \
         -H 'Authorization: Bearer {researcher_token}' \\\n    \
         -H 'Content-Type: application/json' \\\n    \
         -d '{{\"steward_tenant\":\"{steward}\",\"connector\":\"{CONNECTOR}\",\"sql\":\"{sql}\"}}'"
    );
    eprintln!();

    tracing::info!(%bind_addr, "devstack listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

/// The loud part of "insecure, development only": a stderr banner, a warning
/// log and a `service.start` audit record.
fn warn_insecure() {
    const WARNING: &str = "devstack is INSECURE and for DEVELOPMENT ONLY: tenant keys are held \
                           in process memory and TEE evidence is fabricated. Never load real \
                           data into it or expose it beyond this machine.";
    eprintln!("\n*** {WARNING} ***\n");
    tracing::warn!("{WARNING}");
    security_audit_event(
        AuditKind::ServiceStart,
        None,
        "dev_insecure",
        "devstack booting: insecure, development only",
    );
}

/// Engine settings from the configuration, as `platform-api` uses them.
fn engine_settings(config: &PlatformConfig) -> EngineSettings {
    EngineSettings {
        zk: config.features.zk,
        max_concurrent_queries: config.enclave.query_max_concurrent,
    }
}

/// A seeded synthetic cohort built around `min_cohort`, with groups on both
/// sides of it, as Parquet, and its row count.
fn synthetic_cohort(min_cohort: u64) -> anyhow::Result<(Zeroizing<Vec<u8>>, usize)> {
    let k = usize::try_from(min_cohort)?;
    let rows = synth_data::cohort::min_rows(k);
    let spec = Spec::new(SchemaName::Cohort, COHORT_SEED, rows).with_k(k);
    let parquet = synth_data::parquet_bytes(&spec).with_context(|| {
        format!("no synthetic cohort for RESEARCH_MIN_COHORT_SIZE={min_cohort}")
    })?;
    Ok((Zeroizing::new(parquet), rows))
}

/// Publishes the steward's catalog listing for the cohort and returns its id.
async fn publish_listing_for(
    service: &ConnectorQueryService,
    steward: TenantId,
    connector: &ConnectorSlug,
) -> anyhow::Result<String> {
    let request = PublishListingRequest {
        connector: connector.as_str().to_owned(),
        title: "Synthetic health cohort".to_owned(),
        description: "Seeded synthetic rows for local development; no real people.".to_owned(),
        license_fee_cents: 0,
        compute_rate_cents: 0,
        grant_budget: None,
    };
    let listing = service
        .publish_listing(steward, connector, &request)
        .await
        .map_err(|_| anyhow!("publishing the catalog listing failed"))?;
    listing["listing_id"]
        .as_str()
        .map(str::to_owned)
        .context("the published listing has no id")
}

/// An access token for `tenant`, minted as `devtoken` mints one.
fn dev_token(
    secret: &str,
    config: &PlatformConfig,
    tenant: TenantId,
    subject: &str,
) -> anyhow::Result<String> {
    platform_auth::mint_token(
        secret,
        &config.auth.issuer,
        &config.auth.audience,
        tenant,
        subject,
        TOKEN_TTL_SECS,
    )
    .context("minting a dev token")
}

/// An aggregate the disclosure gate accepts: one row per condition with its
/// cohort size `n`.
fn example_sql() -> String {
    format!(
        "SELECT condition, COUNT(*) AS n FROM {CONNECTOR} GROUP BY condition ORDER BY condition"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seeded_cohort_has_released_and_suppressed_groups() {
        let config = PlatformConfig::from_source(|_| None).expect("config");
        let min_cohort = config.research.min_cohort_size;
        let (parquet, _) = synthetic_cohort(min_cohort).expect("cohort");
        let connector = ConnectorSlug::new(CONNECTOR).expect("slug");
        let steward = TenantId::generate();
        let researcher = TenantId::generate();

        let keypair = TenantKeypair::generate();
        let mut stack = DevResearchStack::new();
        stack
            .commit_snapshot(steward, keypair, &connector, "cohort", &parquet)
            .await
            .expect("commit");
        let service = stack.query_service(
            engine_settings(&config),
            min_cohort,
            config.research.default_query_budget,
        );

        let granted = service.grant(steward, researcher, &connector, None).await;
        assert!(granted.is_ok(), "grant refused");
        let sql = example_sql();
        let Ok(result) = service
            .research_query(researcher, steward, &connector, &sql)
            .await
        else {
            panic!("research query refused");
        };
        let suppressed = result["suppressed_rows"].as_u64().unwrap_or(0);
        let released = result["rows"].as_array().map(Vec::len).unwrap_or(0);
        assert!(suppressed >= 1, "nothing suppressed: {result}");
        assert!(released >= 1, "nothing released: {result}");
    }
}
