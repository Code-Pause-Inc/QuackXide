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
    #[error("invalid snapshot version")]
    InvalidSnapshotVersion,
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

/// Identifies one complete snapshot of a connector's data.
///
/// `{unix_nanos:020}-{32 lowercase hex}`: fixed width, so string order is
/// time order, and the random suffix keeps concurrent writers apart. Used as
/// a storage path segment, so parsing is strict.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct SnapshotVersion(String);

const SNAPSHOT_TIME_DIGITS: usize = 20;
const SNAPSHOT_SUFFIX_HEX: usize = 32;

impl SnapshotVersion {
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        Self(format!(
            "{nanos:0width$}-{}",
            Uuid::new_v4().simple(),
            width = SNAPSHOT_TIME_DIGITS
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for SnapshotVersion {
    type Err = CoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let valid = s.split_once('-').is_some_and(|(time, suffix)| {
            time.len() == SNAPSHOT_TIME_DIGITS
                && time.bytes().all(|b| b.is_ascii_digit())
                && suffix.len() == SNAPSHOT_SUFFIX_HEX
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(CoreError::InvalidSnapshotVersion)
        }
    }
}

impl fmt::Display for SnapshotVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SnapshotVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Zero-knowledge feature mode; the platform default comes from
/// `FEATURE_ZK_ENABLED`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkMode {
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
    fn snapshot_versions_round_trip_and_order_by_time() {
        let first = SnapshotVersion::generate();
        let second = SnapshotVersion::generate();
        assert_eq!(first.as_str().parse::<SnapshotVersion>(), Ok(first.clone()));
        assert!(first < second || first.as_str()[..20] == second.as_str()[..20]);
        let earlier: SnapshotVersion = "00000000000000000001-0123456789abcdef0123456789abcdef"
            .parse()
            .expect("valid");
        assert!(earlier < first);
    }

    #[test]
    fn snapshot_versions_reject_anything_but_the_canonical_form() {
        for bad in [
            "",
            "123",
            "0000000000000000001-0123456789abcdef0123456789abcdef",
            "00000000000000000001-0123456789ABCDEF0123456789abcdef",
            "00000000000000000001-0123456789abcdef0123456789abcde",
            "00000000000000000001_0123456789abcdef0123456789abcdef",
            "00000000000000000001-0123456789abcdef0123456789abcdef/..",
            "../0000000000000000001-0123456789abcdef0123456789abcdef",
        ] {
            assert_eq!(
                bad.parse::<SnapshotVersion>(),
                Err(CoreError::InvalidSnapshotVersion),
                "{bad}"
            );
        }
    }

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
    }
}
