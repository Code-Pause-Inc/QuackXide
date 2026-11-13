//! Steward dataset uploads (ADR 0012).
//!
//! A steward's browser seals a Parquet file to the steward's key, under
//! `steward-upload-v1|{tenant}|{dataset}|{object}`, and a manifest listing
//! it, under `tenant-snapshot-manifest-v1|{tenant}|{dataset}|{version}`, and
//! sends both in one body with a plaintext header. The upload route holds no
//! key and opens neither; only a query does, inside the enclave. The route
//! checks what it can (lengths, envelope frames, the header) and
//! [`commit_upload`] stores the upload as a new snapshot of the dataset, so
//! a re-upload replaces the dataset rather than adding to it (ADR 0003).
//!
//! # Body
//!
//! Lengths are big-endian `u32`s, each checked against the bytes left
//! before anything past it is read:
//!
//! | Field | Bytes | Contents |
//! | --- | --- | --- |
//! | magic | 4 | `DSU1` |
//! | header length | 4 | 1..=[`MAX_HEADER_BYTES`] |
//! | header | header length | [`UploadHeader`], as JSON |
//! | manifest length | 4 | 1..=[`MAX_MANIFEST_BYTES`] |
//! | manifest | manifest length | the sealed manifest envelope |
//! | object | the rest | the sealed Parquet envelope |
//!
//! [`parse_upload_body`] is fuzzed (`backend/fuzz/fuzz_targets/upload_body.rs`)
//! and never echoes input: every refusal is one of [`UploadError`]'s fixed
//! reasons.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use platform_core::{
    ConnectorSlug, DatasetKind, DeclaredSchema, ObjectId, SnapshotVersion, TenantId,
};
use platform_crypto::{EnvelopeSuite, check_envelope_frame};
use platform_storage::{SnapshotRecord, StorageError, TenantPaths, VaultStore};
use platform_telemetry::{AuditKind, security_audit_event};
use serde::{Deserialize, Serialize};

use crate::snapshot::{commit_snapshot, newest_manifest};

/// Names the body format; a new layout gets a new magic.
pub const UPLOAD_MAGIC: [u8; 4] = *b"DSU1";
/// Largest header: a schema at its column and name limits fits.
pub const MAX_HEADER_BYTES: usize = 128 * 1024;
/// Largest sealed manifest. One object's manifest is a few hundred bytes.
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024;
/// Most bytes a body holds besides its object: the framing, the largest
/// header and the largest manifest.
pub const MAX_BODY_OVERHEAD: usize = 4 + 4 + MAX_HEADER_BYTES + 4 + MAX_MANIFEST_BYTES;
/// Largest row cap a header may declare: the largest integer a browser's
/// JSON numbers hold exactly (2^53 - 1).
pub const MAX_ROW_CAP: u64 = (1 << 53) - 1;
/// How far ahead of this server's clock an upload's version may be. A
/// version further ahead would keep later uploads from replacing it.
pub const MAX_VERSION_SKEW: Duration = Duration::from_secs(5 * 60);

/// What the browser declares about an upload, in plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UploadHeader {
    /// The snapshot version the browser bound into the sealed manifest. It
    /// must be newer than the dataset's current version.
    pub version: SnapshotVersion,
    /// The object id the browser bound into the sealed object.
    pub object: ObjectId,
    /// The most rows the upload holds; the enclave refuses more.
    pub row_cap: u64,
    /// The upload's columns; the enclave refuses Parquet that differs.
    pub schema: DeclaredSchema,
}

/// The header as it arrives. The object id is a string first, so a
/// non-canonical spelling (which the browser would have sealed under) is
/// refused instead of silently respelled.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHeader {
    version: SnapshotVersion,
    object: String,
    row_cap: u64,
    schema: DeclaredSchema,
}

impl TryFrom<WireHeader> for UploadHeader {
    type Error = UploadError;

    fn try_from(wire: WireHeader) -> Result<Self, Self::Error> {
        let object: ObjectId = wire.object.parse().map_err(|_| UploadError::BadHeader)?;
        if object.to_string() != wire.object || !(1..=MAX_ROW_CAP).contains(&wire.row_cap) {
            return Err(UploadError::BadHeader);
        }
        Ok(Self {
            version: wire.version,
            object,
            row_cap: wire.row_cap,
            schema: wire.schema,
        })
    }
}

/// A parsed upload: the header and the two envelopes, which share a suite.
#[derive(Debug, Clone)]
pub struct UploadBody {
    pub header: UploadHeader,
    pub suite: EnvelopeSuite,
    pub manifest: Bytes,
    pub object: Bytes,
}

/// Why an upload body was refused. Each is a fixed reason; none carries
/// input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadError {
    BadMagic,
    Truncated,
    BadHeader,
    BadManifest,
    BadObject,
    TooLarge,
}

impl std::fmt::Display for UploadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for UploadError {}

impl UploadError {
    /// The refusal as a client sees it.
    pub fn message(self) -> &'static str {
        match self {
            UploadError::BadMagic => "not a dataset upload body",
            UploadError::Truncated => "upload body is truncated",
            UploadError::BadHeader => "upload header is malformed or out of bounds",
            UploadError::BadManifest => "upload manifest is not a supported envelope frame",
            UploadError::BadObject => "upload object is not a supported envelope frame",
            UploadError::TooLarge => "upload exceeds the dataset size limit",
        }
    }

    /// Stable label for audit records.
    pub fn reason(self) -> &'static str {
        match self {
            UploadError::BadMagic => "bad_magic",
            UploadError::Truncated => "truncated",
            UploadError::BadHeader => "bad_header",
            UploadError::BadManifest => "bad_manifest",
            UploadError::BadObject => "bad_object",
            UploadError::TooLarge => "too_large",
        }
    }
}

/// Split the first `n` bytes off `rest`.
fn take(rest: &mut Bytes, n: usize) -> Result<Bytes, UploadError> {
    if rest.len() < n {
        return Err(UploadError::Truncated);
    }
    Ok(rest.split_to(n))
}

/// Split a big-endian `u32` length off `rest`.
fn take_len(rest: &mut Bytes) -> Result<usize, UploadError> {
    let raw = take(rest, 4)?;
    let len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    usize::try_from(len).map_err(|_| UploadError::Truncated)
}

/// Parse an upload body, refusing an object over `max_object_bytes`
/// ([`UploadError::TooLarge`]) and anything malformed. Both envelopes must
/// be complete frames of one suite this build reads. Nothing is copied: the
/// envelopes are slices of `body`.
pub fn parse_upload_body(body: Bytes, max_object_bytes: u64) -> Result<UploadBody, UploadError> {
    let mut rest = body;
    if take(&mut rest, UPLOAD_MAGIC.len())? != UPLOAD_MAGIC[..] {
        return Err(UploadError::BadMagic);
    }
    let header_len = take_len(&mut rest)?;
    if !(1..=MAX_HEADER_BYTES).contains(&header_len) {
        return Err(UploadError::BadHeader);
    }
    let header = take(&mut rest, header_len)?;
    let header: UploadHeader = serde_json::from_slice::<WireHeader>(&header)
        .map_err(|_| UploadError::BadHeader)?
        .try_into()?;
    let manifest_len = take_len(&mut rest)?;
    if !(1..=MAX_MANIFEST_BYTES).contains(&manifest_len) {
        return Err(UploadError::BadManifest);
    }
    let manifest = take(&mut rest, manifest_len)?;
    let object = rest;
    if u64::try_from(object.len()).unwrap_or(u64::MAX) > max_object_bytes {
        return Err(UploadError::TooLarge);
    }
    let suite = check_envelope_frame(&manifest).map_err(|_| UploadError::BadManifest)?;
    if check_envelope_frame(&object).map_err(|_| UploadError::BadObject)? != suite {
        return Err(UploadError::BadObject);
    }
    Ok(UploadBody {
        header,
        suite,
        manifest,
        object,
    })
}

/// Build an upload body, as the browser does. Refuses a header or manifest
/// over its limit.
pub fn encode_upload_body(
    header: &UploadHeader,
    manifest: &[u8],
    object: &[u8],
) -> Result<Vec<u8>, UploadError> {
    let header = serde_json::to_vec(header).map_err(|_| UploadError::BadHeader)?;
    let header_len = u32::try_from(header.len())
        .ok()
        .filter(|&len| (1..=MAX_HEADER_BYTES).contains(&(len as usize)))
        .ok_or(UploadError::BadHeader)?;
    let manifest_len = u32::try_from(manifest.len())
        .ok()
        .filter(|&len| (1..=MAX_MANIFEST_BYTES).contains(&(len as usize)))
        .ok_or(UploadError::BadManifest)?;
    let mut body = Vec::with_capacity(12 + header.len() + manifest.len() + object.len());
    body.extend_from_slice(&UPLOAD_MAGIC);
    body.extend_from_slice(&header_len.to_be_bytes());
    body.extend_from_slice(&header);
    body.extend_from_slice(&manifest_len.to_be_bytes());
    body.extend_from_slice(manifest);
    body.extend_from_slice(object);
    Ok(body)
}

/// Why [`commit_upload`] refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum UploadCommitError {
    /// The dataset is not in the upload namespace; only connectors write it.
    #[error("dataset is not in the upload namespace")]
    NotUploadDataset,
    /// The version is more than [`MAX_VERSION_SKEW`] ahead of the clock.
    #[error("snapshot version is ahead of the server clock")]
    VersionAhead,
    /// The dataset's current snapshot is this version or newer.
    #[error("a snapshot at or after this version is already committed")]
    StaleVersion,
    /// The declared schema differs from the current snapshot's.
    #[error("declared schema does not match the dataset's recorded schema")]
    SchemaMismatch,
    /// The current snapshot's record is missing or malformed, so the
    /// recorded schema is unknown (fail closed).
    #[error("the current snapshot's record is missing or malformed")]
    RecordUnreadable,
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl UploadCommitError {
    /// Stable label for audit records.
    pub fn reason(&self) -> &'static str {
        match self {
            UploadCommitError::NotUploadDataset => "not_upload_dataset",
            UploadCommitError::VersionAhead => "version_ahead",
            UploadCommitError::StaleVersion => "stale_version",
            UploadCommitError::SchemaMismatch => "schema_mismatch",
            UploadCommitError::RecordUnreadable => "record_unreadable",
            UploadCommitError::Storage(_) => "storage",
        }
    }
}

/// What [`commit_upload`] stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadReport {
    pub version: SnapshotVersion,
    pub object: ObjectId,
    pub suite: EnvelopeSuite,
    pub ciphertext_bytes: usize,
}

/// Store `upload` as the new current snapshot of `tenant`'s `dataset`: the
/// object, then the plaintext record (suite, declared row cap and schema),
/// then the browser-sealed manifest, which commits it; then superseded
/// snapshots are pruned. The first upload creates the dataset. A later one
/// must carry a newer version and the schema already recorded. A failure
/// before the manifest is written leaves the current snapshot as it was.
pub async fn commit_upload(
    vault: &dyn VaultStore,
    tenant: TenantId,
    dataset: &ConnectorSlug,
    upload: UploadBody,
    now: SystemTime,
) -> Result<UploadReport, UploadCommitError> {
    if dataset.kind() != DatasetKind::Upload {
        return Err(UploadCommitError::NotUploadDataset);
    }
    let UploadBody {
        header,
        suite,
        manifest,
        object,
    } = upload;
    let now = now
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    if header.version.unix_nanos() > now.saturating_add(MAX_VERSION_SKEW.as_nanos()) {
        return Err(UploadCommitError::VersionAhead);
    }
    if let Some((current, _)) = newest_manifest(vault, tenant, dataset).await? {
        if header.version <= current {
            return Err(UploadCommitError::StaleVersion);
        }
        let record_path = TenantPaths::connector_record(tenant, dataset, &current);
        let recorded = match vault.get(&record_path).await {
            Ok(bytes) => SnapshotRecord::parse(&bytes, &current)
                .ok()
                .and_then(|record| record.schema),
            Err(StorageError::NotFound) => None,
            Err(err) => return Err(err.into()),
        };
        match recorded {
            None => return Err(UploadCommitError::RecordUnreadable),
            Some(recorded) if recorded != header.schema => {
                return Err(UploadCommitError::SchemaMismatch);
            }
            Some(_) => {}
        }
    }

    let UploadHeader {
        version,
        object: object_id,
        row_cap,
        schema,
    } = header;
    let ciphertext_bytes = object.len();
    vault
        .put(
            &TenantPaths::connector_snapshot_object(tenant, dataset, &version, object_id),
            object,
        )
        .await?;
    security_audit_event(
        AuditKind::DataAccess,
        Some(tenant),
        "ok",
        &format!(
            "upload object dataset={dataset} snapshot={version} object={object_id} \
             ciphertext_bytes={ciphertext_bytes}"
        ),
    );
    let record = SnapshotRecord {
        version: version.clone(),
        suite: suite.id().to_owned(),
        row_cap: Some(row_cap),
        schema: Some(schema),
    };
    commit_snapshot(vault, tenant, dataset, &record, manifest, 1).await?;
    Ok(UploadReport {
        version,
        object: object_id,
        suite,
        ciphertext_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{SnapshotManifest, manifest_info, object_info};
    use platform_core::{ColumnType, DeclaredColumn};
    use platform_crypto::{TenantKeypair, hpke_seal_to_tenant};
    use platform_storage::ObjectStoreVault;

    const MAX: u64 = 1024 * 1024;

    fn schema(columns: &[(&str, ColumnType)]) -> DeclaredSchema {
        DeclaredSchema::new(
            columns
                .iter()
                .map(|(name, column_type)| DeclaredColumn {
                    name: (*name).to_owned(),
                    column_type: *column_type,
                })
                .collect(),
        )
        .expect("schema")
    }

    fn cohort_schema() -> DeclaredSchema {
        schema(&[
            ("condition", ColumnType::String),
            ("age", ColumnType::Int64),
        ])
    }

    /// A version `offset` nanoseconds after now.
    fn version_at(offset: i128) -> SnapshotVersion {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos() as i128;
        version_from((now + offset) as u128)
    }

    fn version_from(unix_nanos: u128) -> SnapshotVersion {
        format!("{unix_nanos:020}-{}", uuid_hex())
            .parse()
            .expect("version")
    }

    fn uuid_hex() -> String {
        ObjectId::generate().to_string().replace('-', "")
    }

    struct Fixture {
        tenant: TenantId,
        keypair: TenantKeypair,
        dataset: ConnectorSlug,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                tenant: TenantId::generate(),
                keypair: TenantKeypair::generate(),
                dataset: ConnectorSlug::new("upload_cohorts").expect("slug"),
            }
        }

        /// A body the browser would send for `parquet`.
        fn body(
            &self,
            version: &SnapshotVersion,
            schema: DeclaredSchema,
            parquet: &[u8],
        ) -> Vec<u8> {
            let key = self.keypair.public_key();
            let object = ObjectId::generate();
            let sealed = hpke_seal_to_tenant(
                &key,
                &object_info(&self.tenant, &self.dataset, &object),
                parquet,
            )
            .expect("seal object");
            let manifest = serde_json::to_vec(&SnapshotManifest {
                version: version.clone(),
                objects: vec![object],
            })
            .expect("manifest");
            let manifest = hpke_seal_to_tenant(
                &key,
                &manifest_info(&self.tenant, &self.dataset, version),
                &manifest,
            )
            .expect("seal manifest");
            let header = UploadHeader {
                version: version.clone(),
                object,
                row_cap: 7,
                schema,
            };
            encode_upload_body(&header, &manifest, &sealed).expect("encode")
        }

        async fn commit(
            &self,
            vault: &dyn VaultStore,
            body: Vec<u8>,
        ) -> Result<UploadReport, UploadCommitError> {
            let parsed = parse_upload_body(body.into(), MAX).expect("parse");
            commit_upload(vault, self.tenant, &self.dataset, parsed, SystemTime::now()).await
        }
    }

    /// The parts of a valid body, to rebuild with one part changed.
    fn parts(body: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let header_len = u32::from_be_bytes(body[4..8].try_into().unwrap()) as usize;
        let header = body[8..8 + header_len].to_vec();
        let at = 8 + header_len;
        let manifest_len = u32::from_be_bytes(body[at..at + 4].try_into().unwrap()) as usize;
        let manifest = body[at + 4..at + 4 + manifest_len].to_vec();
        let object = body[at + 4 + manifest_len..].to_vec();
        (header, manifest, object)
    }

    fn frame(magic: &[u8], header: &[u8], manifest: &[u8], object: &[u8]) -> Vec<u8> {
        let mut body = magic.to_vec();
        body.extend_from_slice(&(header.len() as u32).to_be_bytes());
        body.extend_from_slice(header);
        body.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
        body.extend_from_slice(manifest);
        body.extend_from_slice(object);
        body
    }

    #[test]
    fn a_browser_built_body_parses_back() {
        let fixture = Fixture::new();
        let version = version_at(0);
        let body = fixture.body(&version, cohort_schema(), b"parquet bytes");
        let (_, manifest, object) = parts(&body);
        let parsed = parse_upload_body(body.into(), MAX).expect("parse");
        assert_eq!(parsed.header.version, version);
        assert_eq!(parsed.header.row_cap, 7);
        assert_eq!(parsed.header.schema, cohort_schema());
        assert_eq!(parsed.suite, EnvelopeSuite::Hpk1);
        assert_eq!(parsed.manifest[..], manifest[..]);
        assert_eq!(parsed.object[..], object[..]);
    }

    #[test]
    fn malformed_bodies_are_refused_with_a_fixed_reason() {
        let fixture = Fixture::new();
        let body = fixture.body(&version_at(0), cohort_schema(), b"parquet bytes");
        let (header, manifest, object) = parts(&body);
        let header_json: serde_json::Value = serde_json::from_slice(&header).expect("json");
        let with = |field: &str, value: serde_json::Value| {
            let mut changed = header_json.clone();
            changed[field] = value;
            serde_json::to_vec(&changed).expect("json")
        };
        let relabel = |envelope: &[u8]| {
            let mut out = envelope.to_vec();
            out[..4].copy_from_slice(b"HPK2");
            out
        };
        let object_id = header_json["object"].as_str().expect("id").to_owned();

        let cases: Vec<(&str, Vec<u8>, UploadError)> = vec![
            ("empty", Vec::new(), UploadError::Truncated),
            (
                "wrong magic",
                frame(b"DSU2", &header, &manifest, &object),
                UploadError::BadMagic,
            ),
            ("magic only", b"DSU1".to_vec(), UploadError::Truncated),
            (
                "header longer than the body",
                body[..body.len().min(8 + header.len() - 1)].to_vec(),
                UploadError::Truncated,
            ),
            (
                "no manifest length",
                body[..8 + header.len() + 2].to_vec(),
                UploadError::Truncated,
            ),
            (
                "manifest longer than the body",
                body[..8 + header.len() + 4 + manifest.len() - 1].to_vec(),
                UploadError::Truncated,
            ),
            (
                "empty header",
                frame(b"DSU1", b"", &manifest, &object),
                UploadError::BadHeader,
            ),
            (
                "header over its limit",
                frame(
                    b"DSU1",
                    &vec![b' '; MAX_HEADER_BYTES + 1],
                    &manifest,
                    &object,
                ),
                UploadError::BadHeader,
            ),
            (
                "header not json",
                frame(b"DSU1", b"not json", &manifest, &object),
                UploadError::BadHeader,
            ),
            (
                "unknown header field",
                frame(
                    b"DSU1",
                    &with("nullable", serde_json::json!(true)),
                    &manifest,
                    &object,
                ),
                UploadError::BadHeader,
            ),
            (
                "row cap zero",
                frame(b"DSU1", &with("row_cap", 0.into()), &manifest, &object),
                UploadError::BadHeader,
            ),
            (
                "row cap past 2^53 - 1",
                frame(
                    b"DSU1",
                    &with("row_cap", (MAX_ROW_CAP + 1).into()),
                    &manifest,
                    &object,
                ),
                UploadError::BadHeader,
            ),
            (
                "object id not canonical",
                frame(
                    b"DSU1",
                    &with("object", object_id.to_uppercase().into()),
                    &manifest,
                    &object,
                ),
                UploadError::BadHeader,
            ),
            (
                "object id not a uuid",
                frame(b"DSU1", &with("object", "../x".into()), &manifest, &object),
                UploadError::BadHeader,
            ),
            (
                "version not canonical",
                frame(b"DSU1", &with("version", "1".into()), &manifest, &object),
                UploadError::BadHeader,
            ),
            (
                "empty schema",
                frame(
                    b"DSU1",
                    &with("schema", serde_json::json!([])),
                    &manifest,
                    &object,
                ),
                UploadError::BadHeader,
            ),
            (
                "empty manifest",
                frame(b"DSU1", &header, b"", &object),
                UploadError::BadManifest,
            ),
            (
                "manifest over its limit",
                frame(b"DSU1", &header, &vec![0; MAX_MANIFEST_BYTES + 1], &object),
                UploadError::BadManifest,
            ),
            (
                "manifest of an unknown suite",
                frame(b"DSU1", &header, &relabel(&manifest), &object),
                UploadError::BadManifest,
            ),
            (
                "manifest truncated to its magic",
                frame(b"DSU1", &header, &manifest[..20], &object),
                UploadError::BadManifest,
            ),
            (
                "no object",
                frame(b"DSU1", &header, &manifest, b""),
                UploadError::BadObject,
            ),
            (
                "object of an unknown suite",
                frame(b"DSU1", &header, &manifest, &relabel(&object)),
                UploadError::BadObject,
            ),
            (
                "object truncated",
                frame(b"DSU1", &header, &manifest, &object[..20]),
                UploadError::BadObject,
            ),
        ];
        for (name, body, expected) in cases {
            let err = parse_upload_body(body.into(), MAX).expect_err(name);
            assert_eq!(err, expected, "{name}");
        }
    }

    #[test]
    fn an_object_over_the_size_limit_is_too_large() {
        let fixture = Fixture::new();
        let body = fixture.body(&version_at(0), cohort_schema(), b"parquet bytes");
        let (_, _, object) = parts(&body);
        let exact = object.len() as u64;
        assert!(parse_upload_body(body.clone().into(), exact).is_ok());
        assert_eq!(
            parse_upload_body(body.into(), exact - 1).expect_err("over"),
            UploadError::TooLarge
        );
    }

    #[test]
    fn the_encoder_refuses_parts_over_their_limits() {
        let fixture = Fixture::new();
        let body = fixture.body(&version_at(0), cohort_schema(), b"x");
        let parsed = parse_upload_body(body.into(), MAX).expect("parse");
        assert_eq!(
            encode_upload_body(&parsed.header, &[], &parsed.object),
            Err(UploadError::BadManifest)
        );
        assert_eq!(
            encode_upload_body(
                &parsed.header,
                &vec![0; MAX_MANIFEST_BYTES + 1],
                &parsed.object
            ),
            Err(UploadError::BadManifest)
        );
    }

    async fn stored(vault: &dyn VaultStore, tenant: TenantId) -> Vec<String> {
        let mut paths: Vec<String> = vault
            .list(&TenantPaths::tenant_root(tenant))
            .await
            .expect("list")
            .into_iter()
            .map(|path| path.as_str().to_owned())
            .collect();
        paths.sort();
        paths
    }

    #[tokio::test]
    async fn an_upload_is_stored_as_a_snapshot_that_opens() {
        let vault = ObjectStoreVault::new_in_memory();
        let fixture = Fixture::new();
        let version = version_at(0);
        let report = fixture
            .commit(
                &vault,
                fixture.body(&version, cohort_schema(), b"parquet bytes"),
            )
            .await
            .expect("commit");
        assert_eq!(report.version, version);
        assert_eq!(report.suite, EnvelopeSuite::Hpk1);

        let (tenant, dataset) = (fixture.tenant, &fixture.dataset);
        let mut expected = vec![
            TenantPaths::connector_snapshot_object(tenant, dataset, &version, report.object),
            TenantPaths::connector_record(tenant, dataset, &version),
            TenantPaths::connector_manifest(tenant, dataset, &version),
        ]
        .into_iter()
        .map(|path| path.as_str().to_owned())
        .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(stored(&vault, tenant).await, expected);

        let record = vault
            .get(&TenantPaths::connector_record(tenant, dataset, &version))
            .await
            .expect("record");
        let record = SnapshotRecord::parse(&record, &version).expect("parse");
        assert_eq!(record.suite, "HPK1");
        assert_eq!(record.row_cap, Some(7));
        assert_eq!(record.schema, Some(cohort_schema()));

        // The steward's key opens both envelopes under the bindings the
        // query path uses.
        let object = vault
            .get(&TenantPaths::connector_snapshot_object(
                tenant,
                dataset,
                &version,
                report.object,
            ))
            .await
            .expect("object");
        let opened = fixture
            .keypair
            .open_envelope(&object_info(&tenant, dataset, &report.object), &object)
            .expect("open object");
        assert_eq!(opened.expose(), b"parquet bytes");
        let manifest = vault
            .get(&TenantPaths::connector_manifest(tenant, dataset, &version))
            .await
            .expect("manifest");
        fixture
            .keypair
            .open_envelope(&manifest_info(&tenant, dataset, &version), &manifest)
            .expect("open manifest");
    }

    #[tokio::test]
    async fn a_re_upload_replaces_the_snapshot() {
        let vault = ObjectStoreVault::new_in_memory();
        let fixture = Fixture::new();
        let first = version_at(-2_000);
        let second = version_at(-1_000);
        fixture
            .commit(&vault, fixture.body(&first, cohort_schema(), b"first"))
            .await
            .expect("first");
        let report = fixture
            .commit(&vault, fixture.body(&second, cohort_schema(), b"second"))
            .await
            .expect("second");
        let (tenant, dataset) = (fixture.tenant, &fixture.dataset);
        let mut expected = vec![
            TenantPaths::connector_snapshot_object(tenant, dataset, &second, report.object),
            TenantPaths::connector_record(tenant, dataset, &second),
            TenantPaths::connector_manifest(tenant, dataset, &second),
        ]
        .into_iter()
        .map(|path| path.as_str().to_owned())
        .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(stored(&vault, tenant).await, expected);
    }

    #[tokio::test]
    async fn uploads_that_cannot_become_current_are_refused() {
        let vault = ObjectStoreVault::new_in_memory();
        let fixture = Fixture::new();
        let current = version_at(-1_000);
        fixture
            .commit(&vault, fixture.body(&current, cohort_schema(), b"rows"))
            .await
            .expect("first");
        let before = stored(&vault, fixture.tenant).await;

        // Not newer than the current snapshot.
        for version in [current.clone(), version_from(current.unix_nanos() - 1)] {
            let err = fixture
                .commit(&vault, fixture.body(&version, cohort_schema(), b"rows"))
                .await
                .expect_err("stale");
            assert!(matches!(err, UploadCommitError::StaleVersion), "{err:?}");
        }
        // Too far ahead of the clock.
        let ahead = version_at(MAX_VERSION_SKEW.as_nanos() as i128 + 60_000_000_000);
        let err = fixture
            .commit(&vault, fixture.body(&ahead, cohort_schema(), b"rows"))
            .await
            .expect_err("ahead");
        assert!(matches!(err, UploadCommitError::VersionAhead), "{err:?}");
        // Another schema than the recorded one.
        let other = schema(&[("condition", ColumnType::String)]);
        let err = fixture
            .commit(&vault, fixture.body(&version_at(0), other, b"rows"))
            .await
            .expect_err("schema");
        assert!(matches!(err, UploadCommitError::SchemaMismatch), "{err:?}");
        assert_eq!(
            stored(&vault, fixture.tenant).await,
            before,
            "nothing written"
        );
    }

    #[tokio::test]
    async fn an_unreadable_record_fails_closed() {
        let vault = ObjectStoreVault::new_in_memory();
        let fixture = Fixture::new();
        let current = version_at(-1_000);
        fixture
            .commit(&vault, fixture.body(&current, cohort_schema(), b"rows"))
            .await
            .expect("first");
        let record = TenantPaths::connector_record(fixture.tenant, &fixture.dataset, &current);
        for replacement in [Some(&b"not json"[..]), None] {
            match replacement {
                Some(bytes) => vault
                    .put(&record, Bytes::copy_from_slice(bytes))
                    .await
                    .expect("put"),
                None => vault.delete(&record).await.expect("delete"),
            }
            let err = fixture
                .commit(
                    &vault,
                    fixture.body(&version_at(0), cohort_schema(), b"rows"),
                )
                .await
                .expect_err("unreadable");
            assert!(
                matches!(err, UploadCommitError::RecordUnreadable),
                "{err:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_the_upload_namespace_accepts_uploads() {
        let vault = ObjectStoreVault::new_in_memory();
        let fixture = Fixture::new();
        let body = fixture.body(&version_at(0), cohort_schema(), b"rows");
        let parsed = parse_upload_body(body.into(), MAX).expect("parse");
        let connector = ConnectorSlug::new("research_extract").expect("slug");
        let err = commit_upload(
            &vault,
            fixture.tenant,
            &connector,
            parsed,
            SystemTime::now(),
        )
        .await
        .expect_err("connector slug");
        assert!(
            matches!(err, UploadCommitError::NotUploadDataset),
            "{err:?}"
        );
        assert!(stored(&vault, fixture.tenant).await.is_empty());
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn arbitrary_bodies_never_panic(body in prop::collection::vec(any::<u8>(), 0..512)) {
                let _ = parse_upload_body(body.into(), MAX);
            }

            #[test]
            fn arbitrary_tails_after_a_valid_magic_never_panic(
                tail in prop::collection::vec(any::<u8>(), 0..512),
                max in 0u64..1024,
            ) {
                let mut body = UPLOAD_MAGIC.to_vec();
                body.extend_from_slice(&tail);
                if let Ok(parsed) = parse_upload_body(body.into(), max) {
                    prop_assert!(parsed.object.len() as u64 <= max);
                }
            }
        }
    }
}
