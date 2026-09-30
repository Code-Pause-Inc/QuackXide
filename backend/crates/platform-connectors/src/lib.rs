//! Confidential connector ingestion.
//!
//! Background workers fetch SaaS data with stored OAuth2 credentials,
//! normalize and Parquet-encode it in enclave RAM, seal it to the tenant's
//! HPKE public key, and flush the ciphertext to
//! `tenants/{tenant_id}/connectors/{slug}/{object_id}.parquet`.
//!
//! `oauth` → `source` (fetch) → `mappers` (payload → `dataset`) →
//! `parquet_out` → `pipeline` (attestation gate, seal, flush) → `worker`.

use platform_core::ConnectorSlug;
use serde::Serialize;

pub mod dataset;
pub mod mappers;
pub mod ndjson;
pub mod oauth;
pub mod parquet_out;
pub mod pipeline;
pub mod source;
pub mod worker;

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error("malformed connector payload: {0}")]
    MalformedPayload(String),
    #[error("dataset shape error: {0}")]
    DatasetShape(String),
    #[error("parquet encoding error: {0}")]
    Parquet(String),
    #[error("oauth exchange failed: {0}")]
    OAuth(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("unknown connector: {0}")]
    UnknownConnector(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    Accounting,
    Erp,
    Crm,
    /// Consented research extracts produced by the data owner's systems,
    /// never an operational clinical record store.
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    /// Interactive authorization-code grant at enrollment; the stored
    /// refresh token powers background syncs.
    OAuth2AuthorizationCode,
    /// Static API key/secret provided at enrollment.
    ApiKey,
    /// Machine-to-machine client-credentials grant (RFC 6749 §4.4), used by
    /// research-extract exports (e.g. SMART Backend Services).
    OAuth2ClientCredentials,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectorDescriptor {
    /// Storage-path segment; validated.
    pub slug: ConnectorSlug,
    pub display_name: &'static str,
    pub kind: ConnectorKind,
    pub auth: AuthScheme,
}

/// Built-in connector catalog.
pub fn catalog() -> Vec<ConnectorDescriptor> {
    [
        (
            "quickbooks",
            "QuickBooks",
            ConnectorKind::Accounting,
            AuthScheme::OAuth2AuthorizationCode,
        ),
        ("odoo", "Odoo", ConnectorKind::Erp, AuthScheme::ApiKey),
        (
            "generic_crm",
            "Generic CRM",
            ConnectorKind::Crm,
            AuthScheme::OAuth2AuthorizationCode,
        ),
        // Slugs are storage-path segments: renaming one orphans stored data.
        (
            "research_extract",
            "Research Extract",
            ConnectorKind::Health,
            AuthScheme::OAuth2ClientCredentials,
        ),
    ]
    .into_iter()
    .map(|(slug, display_name, kind, auth)| ConnectorDescriptor {
        slug: ConnectorSlug::new(slug).expect("built-in slugs are valid by construction"),
        display_name,
        kind,
        auth,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalog_slugs_are_valid_and_unique() {
        let catalog = catalog();
        assert!(!catalog.is_empty());
        let slugs: HashSet<&str> = catalog.iter().map(|c| c.slug.as_str()).collect();
        assert_eq!(slugs.len(), catalog.len(), "slugs must be unique");
    }
}
