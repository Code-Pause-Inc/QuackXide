//! Dependency-light identifiers and flags shared by every other crate.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Errors for core identifier parsing/validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid tenant id (must be a UUID)")]
    InvalidTenantId,
    #[error("invalid object id (must be a UUID)")]
    InvalidObjectId,
    #[error("invalid connector slug (allowed: [a-z0-9_-], 1..=64 chars)")]
    InvalidConnectorSlug,
}

/// Opaque tenant identifier.
///
/// Always a UUID: tenant ids are embedded in object-storage paths
/// (`tenants/{tenant_id}/…`), and the UUID character set rules out separator
/// injection and path traversal by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(Uuid);

impl TenantId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl FromStr for TenantId {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::try_parse(s)
            .map(Self)
            .map_err(|_| CoreError::InvalidTenantId)
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Canonical form; used verbatim in storage paths.
        write!(f, "{}", self.0.as_hyphenated())
    }
}

/// Opaque, server-assigned object identifier.
///
/// Vault object names are UUIDs assigned at upload. User filenames are
/// encrypted client-side metadata and never appear in storage paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(Uuid);

impl ObjectId {
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl FromStr for ObjectId {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::try_parse(s)
            .map(Self)
            .map_err(|_| CoreError::InvalidObjectId)
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_hyphenated())
    }
}

/// Validated connector identifier used as a storage path segment
/// (`tenants/{t}/connectors/{slug}/…`).
///
/// Restricted to `[a-z0-9_-]`, 1..=64 chars, so a slug can never smuggle `/`,
/// `..`, or unicode into a path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ConnectorSlug(String);

const MAX_SLUG_LEN: usize = 64;

impl ConnectorSlug {
    pub fn new(raw: &str) -> Result<Self, CoreError> {
        let len_ok = (1..=MAX_SLUG_LEN).contains(&raw.len());
        let chars_ok = raw
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if len_ok && chars_ok {
            Ok(Self(raw.to_owned()))
        } else {
            Err(CoreError::InvalidConnectorSlug)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ConnectorSlug {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for ConnectorSlug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ConnectorSlug {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        ConnectorSlug::new(&raw).map_err(serde::de::Error::custom)
    }
}

/// Zero-knowledge feature mode; the platform default comes from
/// `FEATURE_ZK_ENABLED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ZkMode {
    #[default]
    Disabled,
    Enabled,
}

impl ZkMode {
    pub fn is_enabled(self) -> bool {
        matches!(self, ZkMode::Enabled)
    }

    pub fn from_flag(enabled: bool) -> Self {
        if enabled {
            Self::Enabled
        } else {
            Self::Disabled
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_id_round_trips_through_display() {
        let id = TenantId::generate();
        let parsed: TenantId = id.to_string().parse().expect("canonical form parses");
        assert_eq!(id, parsed);
    }

    #[test]
    fn tenant_id_rejects_path_traversal_and_garbage() {
        for bad in [
            "../../etc/passwd",
            "tenants/x",
            "",
            "not-a-uuid",
            "e4/../..",
        ] {
            assert_eq!(bad.parse::<TenantId>(), Err(CoreError::InvalidTenantId));
        }
    }

    #[test]
    fn connector_slug_accepts_expected_names() {
        for good in ["quickbooks", "odoo", "generic_crm", "crm-2"] {
            assert!(ConnectorSlug::new(good).is_ok(), "{good} should be valid");
        }
    }

    #[test]
    fn connector_slug_rejects_separators_and_case() {
        for bad in ["../evil", "a/b", "", "QuickBooks", "with space", "dot.dot"] {
            assert_eq!(
                ConnectorSlug::new(bad),
                Err(CoreError::InvalidConnectorSlug),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn zk_mode_flag_round_trip() {
        assert!(ZkMode::from_flag(true).is_enabled());
        assert!(!ZkMode::from_flag(false).is_enabled());
        assert_eq!(ZkMode::default(), ZkMode::Disabled);
    }
}
