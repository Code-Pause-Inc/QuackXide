//! Attestation-gated key release (`P50`) and enclave runtime identity (`P85`).
//!
//! Trust model:
//! 1. At startup, the enclave generates an ephemeral in-RAM HPKE keypair
//!    ([`EnclaveIdentity`]) whose private key never leaves process memory.
//! 2. Per query, [`AttestedKeyProvider`] requests a single-use 32-byte
//!    challenge nonce from the key-release relying party, binds
//!    `(nonce, enclave_hpke_pk, result_signing_pk, tls_cert_sha256, config_digest)`
//!    into the 64-byte `REPORT_DATA` field, and obtains a signed 1184-byte
//!    SEV-SNP report from [`AttestationProvider`].
//! 3. [`KeyReleaseRelyingParty`] consumes the single-use nonce, recomputes the
//!    expected 64-byte `REPORT_DATA`, verifies the binary report and
//!    `ARK -> ASK -> VCEK` chain via [`AttestationVerifier`], and HPKE-seals
//!    the tenant's key material to the verified `enclave_hpke_pk`.
//! 4. The enclave unwraps the key in RAM into a per-query zeroize-on-drop
//!    session ([`QueryKeySession`]), opens the snapshot manifest and objects,
//!    and drops the key as soon as decryption completes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use platform_core::TenantId;
use platform_crypto::{
    SecretBytes, TenantKeypair, TenantPublicKey, X25519_PUBLIC_KEY_BYTES, hpke_seal_to_tenant,
};
use platform_enclave::{
    AttestationProvider, AttestationVerifier, ReportDataBinding, SnpCertChain, TeePlatform,
    fresh_nonce,
};
use platform_telemetry::{AuditKind, security_audit_event};
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;

use crate::ApiError;
use crate::query::{EnclaveKeyProvider, QueryKeySession};

const CHALLENGE_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING_CHALLENGES: usize = 4096;

/// Canonical HPKE `info` binding for a key-release envelope.
pub fn key_release_info(tenant: TenantId, nonce: &[u8; 32]) -> Vec<u8> {
    format!("quackxide-key-release-v1|{tenant}|{}", B64.encode(nonce)).into_bytes()
}

/// Ephemeral enclave identity generated in RAM at process boot.
///
/// The private HPKE scalar lives only inside `ephemeral_hpke` (which zeroizes
/// on drop) and is never serialized, logged, or exported.
pub struct EnclaveIdentity {
    ephemeral_hpke: TenantKeypair,
    ephemeral_hpke_public_raw: [u8; X25519_PUBLIC_KEY_BYTES],
    result_signing_public_key: [u8; 32],
    tls_cert_sha256: [u8; 32],
    config_digest: [u8; 32],
}

impl EnclaveIdentity {
    /// Generate a fresh in-RAM enclave identity with default zeroed TLS/config
    /// digests (for local dev and tests).
    pub fn generate() -> Self {
        Self::with_metadata([0u8; 32], [0u8; 32])
    }

    /// Generate a fresh in-RAM enclave identity bound to `tls_cert_sha256` and
    /// `config_digest`.
    pub fn with_metadata(tls_cert_sha256: [u8; 32], config_digest: [u8; 32]) -> Self {
        let ephemeral_hpke = TenantKeypair::generate();
        let mut ephemeral_hpke_public_raw = [0u8; X25519_PUBLIC_KEY_BYTES];
        ephemeral_hpke_public_raw.copy_from_slice(&ephemeral_hpke.public_key().to_raw());
        let result_signing_public_key = fresh_nonce();
        Self {
            ephemeral_hpke,
            ephemeral_hpke_public_raw,
            result_signing_public_key,
            tls_cert_sha256,
            config_digest,
        }
    }

    pub fn enclave_hpke_public_key(&self) -> &[u8; X25519_PUBLIC_KEY_BYTES] {
        &self.ephemeral_hpke_public_raw
    }

    pub fn result_signing_public_key(&self) -> &[u8; 32] {
        &self.result_signing_public_key
    }

    pub fn tls_cert_sha256(&self) -> &[u8; 32] {
        &self.tls_cert_sha256
    }

    pub fn config_digest(&self) -> &[u8; 32] {
        &self.config_digest
    }

    /// Build the canonical 64-byte [`ReportDataBinding`] for `nonce`.
    pub fn binding_for_nonce(&self, nonce: [u8; 32]) -> ReportDataBinding {
        ReportDataBinding {
            nonce,
            enclave_hpke_public_key: self.ephemeral_hpke_public_raw,
            result_signing_public_key: self.result_signing_public_key,
            tls_cert_sha256: self.tls_cert_sha256,
            config_digest: self.config_digest,
        }
    }

    /// Open a key-release HPKE envelope inside enclave RAM and reconstruct a
    /// transient zeroize-on-drop [`TenantKeypair`].
    pub fn unwrap_released_key(
        &self,
        info: &[u8],
        wrapped_key: &[u8],
    ) -> Result<TenantKeypair, ApiError> {
        let raw_sk = self
            .ephemeral_hpke
            .open_envelope(info, wrapped_key)
            .map_err(|_| ApiError::AttestationUnavailable)?;
        TenantKeypair::from_private_key_bytes(raw_sk.expose())
            .map_err(|_| ApiError::AttestationUnavailable)
    }
}

impl Default for EnclaveIdentity {
    fn default() -> Self {
        Self::generate()
    }
}

// ── Wire types for the key-release and attestation protocols ─────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub nonce_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyReleaseRequest {
    pub tenant_id: String,
    pub nonce_b64: String,
    pub report_b64: String,
    pub cert_chain_b64: String,
    pub enclave_hpke_public_key_b64: String,
    pub result_signing_public_key_b64: String,
    pub tls_cert_sha256_b64: String,
    pub config_digest_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyReleaseResponse {
    pub wrapped_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollTenantKeyRequest {
    pub tenant_id: String,
    pub private_key_b64: String,
}

/// Public evidence bundle returned by `GET /api/v1/attestation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationBundle {
    pub platform: String,
    pub nonce_b64: String,
    pub report_b64: String,
    pub cert_chain_b64: String,
    pub enclave_hpke_public_key_b64: String,
    pub result_signing_public_key_b64: String,
    pub tls_cert_sha256_b64: String,
    pub config_digest_b64: String,
}

// ── Relying Party (Key-Release Service) ──────────────────────────────────────

/// Attestation-verifying key-release relying party (`P50`).
///
/// Issues single-use nonces, verifies 1184-byte SEV-SNP reports and
/// `ARK -> ASK -> VCEK` certificate chains using [`AttestationVerifier`], and
/// releases tenant keys wrapped under HPKE to the attested enclave's ephemeral
/// public key.
pub struct KeyReleaseRelyingParty {
    verifier: AttestationVerifier,
    require_hardware_sev_snp: bool,
    expected_config_digest: Option<[u8; 32]>,
    challenge_ttl: Duration,
    challenges: Mutex<HashMap<[u8; 32], Instant>>,
    keys: RwLock<HashMap<TenantId, SecretBytes>>,
    release_count: AtomicUsize,
}

impl KeyReleaseRelyingParty {
    pub fn new(verifier: AttestationVerifier, require_hardware_sev_snp: bool) -> Self {
        Self {
            verifier,
            require_hardware_sev_snp,
            expected_config_digest: None,
            challenge_ttl: CHALLENGE_TTL,
            challenges: Mutex::new(HashMap::new()),
            keys: RwLock::new(HashMap::new()),
            release_count: AtomicUsize::new(0),
        }
    }

    pub fn with_expected_config_digest(mut self, digest: [u8; 32]) -> Self {
        self.expected_config_digest = Some(digest);
        self
    }

    pub fn with_challenge_ttl(mut self, ttl: Duration) -> Self {
        self.challenge_ttl = ttl;
        self
    }

    pub fn release_count(&self) -> usize {
        self.release_count.load(Ordering::SeqCst)
    }

    /// Register a tenant's key material with the relying party.
    pub fn insert_tenant_key(&self, tenant: TenantId, keypair: &TenantKeypair) {
        self.insert_raw_tenant_key(tenant, keypair.to_private_key_bytes());
    }

    pub fn insert_raw_tenant_key(&self, tenant: TenantId, private_key_bytes: SecretBytes) {
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        keys.insert(tenant, private_key_bytes);
    }

    /// Mint a fresh 32-byte single-use challenge nonce.
    pub fn issue_challenge(&self) -> ChallengeResponse {
        let nonce = fresh_nonce();
        let now = Instant::now();
        let ttl = self.challenge_ttl;
        let mut challenges = self
            .challenges
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        challenges.retain(|_, issued_at| now.duration_since(*issued_at) <= ttl);
        if challenges.len() >= MAX_PENDING_CHALLENGES
            && let Some(oldest_key) = challenges.iter().min_by_key(|(_, ts)| *ts).map(|(k, _)| *k)
        {
            challenges.remove(&oldest_key);
        }
        challenges.insert(nonce, now);
        ChallengeResponse {
            nonce_b64: B64.encode(nonce),
        }
    }

    /// Verify the enclave's attestation report and release the tenant's key
    /// wrapped via HPKE to the enclave's ephemeral public key.
    pub fn release_key(&self, req: &KeyReleaseRequest) -> Result<KeyReleaseResponse, ApiError> {
        let tenant: TenantId = req.tenant_id.parse().map_err(|_| {
            security_audit_event(
                AuditKind::KeyRelease,
                None,
                "denied",
                "invalid tenant_id in key-release request",
            );
            ApiError::AttestationUnavailable
        })?;

        let nonce = decode_32(&req.nonce_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed challenge nonce");
            ApiError::AttestationUnavailable
        })?;

        // Consume single-use challenge nonce and enforce TTL.
        let issued_at = {
            let mut challenges = self
                .challenges
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            challenges.remove(&nonce)
        };
        let Some(issued_at) = issued_at else {
            self.audit_denial(tenant, "unknown or replayed challenge nonce");
            return Err(ApiError::AttestationUnavailable);
        };
        if issued_at.elapsed() > self.challenge_ttl {
            self.audit_denial(tenant, "expired challenge nonce");
            return Err(ApiError::AttestationUnavailable);
        }

        let enclave_hpke_pk_raw = decode_32(&req.enclave_hpke_public_key_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed enclave HPKE public key");
            ApiError::AttestationUnavailable
        })?;
        let enclave_hpke_pk = TenantPublicKey::from_raw(&enclave_hpke_pk_raw).map_err(|_| {
            self.audit_denial(tenant, "invalid X25519 enclave HPKE public key");
            ApiError::AttestationUnavailable
        })?;

        let result_signing_pk = decode_32(&req.result_signing_public_key_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed result-signing public key");
            ApiError::AttestationUnavailable
        })?;
        let tls_cert_sha256 = decode_32(&req.tls_cert_sha256_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed TLS certificate digest");
            ApiError::AttestationUnavailable
        })?;
        let config_digest = decode_32(&req.config_digest_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed config digest");
            ApiError::AttestationUnavailable
        })?;

        if let Some(expected_cfg) = &self.expected_config_digest
            && !bool::from(expected_cfg.ct_eq(&config_digest))
        {
            self.audit_denial(tenant, "deployment config digest mismatch");
            return Err(ApiError::AttestationUnavailable);
        }

        let report_bytes = B64.decode(&req.report_b64).map_err(|_| {
            self.audit_denial(tenant, "malformed base64 SEV-SNP report");
            ApiError::AttestationUnavailable
        })?;
        let cert_chain_bytes = B64.decode(&req.cert_chain_b64).map_err(|_| {
            self.audit_denial(tenant, "malformed base64 certificate chain");
            ApiError::AttestationUnavailable
        })?;
        let cert_chain = SnpCertChain::from_bytes(&cert_chain_bytes).map_err(|_| {
            self.audit_denial(tenant, "invalid SEV-SNP certificate chain");
            ApiError::AttestationUnavailable
        })?;

        // Recompute the exact 64-byte REPORT_DATA binding expected in the signed report.
        let expected_binding = ReportDataBinding {
            nonce,
            enclave_hpke_public_key: enclave_hpke_pk_raw,
            result_signing_public_key: result_signing_pk,
            tls_cert_sha256,
            config_digest,
        };
        let verified = self
            .verifier
            .verify(
                &report_bytes,
                &cert_chain,
                &expected_binding.to_report_data(),
            )
            .map_err(|_| {
                self.audit_denial(tenant, "SEV-SNP report verification failed");
                ApiError::AttestationUnavailable
            })?;

        if self.require_hardware_sev_snp && verified.platform() != TeePlatform::SevSnp {
            self.audit_denial(
                tenant,
                "simulated SEV-SNP platform rejected by hardware-required relying party",
            );
            return Err(ApiError::AttestationUnavailable);
        }

        let keys = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(tenant_secret) = keys.get(&tenant) else {
            self.audit_denial(tenant, "no key enrolled for tenant");
            return Err(ApiError::AttestationUnavailable);
        };

        let info = key_release_info(tenant, &nonce);
        let wrapped = hpke_seal_to_tenant(&enclave_hpke_pk, &info, tenant_secret.expose())
            .map_err(|_| {
                security_audit_event(
                    AuditKind::KeyRelease,
                    Some(tenant),
                    "failed",
                    "HPKE key wrapping failed",
                );
                ApiError::AttestationUnavailable
            })?;

        security_audit_event(
            AuditKind::KeyRelease,
            Some(tenant),
            "ok",
            match verified.platform() {
                TeePlatform::SevSnp => "key released to hardware-attested SEV-SNP enclave",
                TeePlatform::Simulated => "key released to simulated SEV-SNP enclave (dev only)",
                TeePlatform::Development => "key released (dev)",
            },
        );
        self.release_count.fetch_add(1, Ordering::SeqCst);

        Ok(KeyReleaseResponse {
            wrapped_key_b64: B64.encode(wrapped),
        })
    }

    fn audit_denial(&self, tenant: TenantId, reason: &str) {
        security_audit_event(AuditKind::KeyRelease, Some(tenant), "denied", reason);
    }

    /// Axum router exposing the key-release HTTP service (`/v1/challenge`,
    /// `/v1/release`, `/v1/keys`, and `/healthz`).
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/healthz", get(|| async { Json(json!({ "status": "ok" })) }))
            .route(
                "/v1/challenge",
                post(|State(rp): State<Arc<Self>>| async move { Json(rp.issue_challenge()) }),
            )
            .route(
                "/v1/release",
                post(
                    |State(rp): State<Arc<Self>>, Json(req): Json<KeyReleaseRequest>| async move {
                        rp.release_key(&req).map(Json)
                    },
                ),
            )
            .route(
                "/v1/keys",
                put(
                    |State(rp): State<Arc<Self>>,
                     Json(req): Json<EnrollTenantKeyRequest>| async move {
                        let tenant: TenantId = req
                            .tenant_id
                            .parse()
                            .map_err(|_| ApiError::BadRequest("invalid tenant id"))?;
                        let raw = B64
                            .decode(req.private_key_b64.trim())
                            .map_err(|_| ApiError::BadRequest("invalid base64 private key"))?;
                        let kp = TenantKeypair::from_private_key_bytes(&raw)
                            .map_err(|_| ApiError::BadRequest("invalid X25519 private key"))?;
                        rp.insert_tenant_key(tenant, &kp);
                        Ok::<StatusCode, ApiError>(StatusCode::NO_CONTENT)
                    },
                ),
            )
            .with_state(self)
    }
}

// ── KeyReleaseClient (In-Process + HTTP) & AttestedKeyProvider ──────────────

#[async_trait]
pub trait KeyReleaseClient: Send + Sync {
    async fn issue_challenge(&self) -> Result<ChallengeResponse, ApiError>;
    async fn release_key(&self, req: &KeyReleaseRequest) -> Result<KeyReleaseResponse, ApiError>;
}

/// In-process client wrapping [`KeyReleaseRelyingParty`] for tests and
/// single-process simulated runs.
pub struct InProcessKeyReleaseClient(pub Arc<KeyReleaseRelyingParty>);

#[async_trait]
impl KeyReleaseClient for InProcessKeyReleaseClient {
    async fn issue_challenge(&self) -> Result<ChallengeResponse, ApiError> {
        Ok(self.0.issue_challenge())
    }

    async fn release_key(&self, req: &KeyReleaseRequest) -> Result<KeyReleaseResponse, ApiError> {
        self.0.release_key(req)
    }
}

/// HTTP client talking to a remote or containerized `key-release` service.
pub struct HttpKeyReleaseClient {
    base_url: String,
    http: reqwest::Client,
}

impl HttpKeyReleaseClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self { base_url, http }
    }
}

#[async_trait]
impl KeyReleaseClient for HttpKeyReleaseClient {
    async fn issue_challenge(&self) -> Result<ChallengeResponse, ApiError> {
        let url = format!("{}/v1/challenge", self.base_url);
        let resp = self
            .http
            .post(&url)
            .send()
            .await
            .map_err(|_| ApiError::AttestationUnavailable)?;
        if !resp.status().is_success() {
            return Err(ApiError::AttestationUnavailable);
        }
        resp.json::<ChallengeResponse>()
            .await
            .map_err(|_| ApiError::AttestationUnavailable)
    }

    async fn release_key(&self, req: &KeyReleaseRequest) -> Result<KeyReleaseResponse, ApiError> {
        let url = format!("{}/v1/release", self.base_url);
        let resp = self
            .http
            .post(&url)
            .json(req)
            .send()
            .await
            .map_err(|_| ApiError::AttestationUnavailable)?;
        if !resp.status().is_success() {
            return Err(ApiError::AttestationUnavailable);
        }
        resp.json::<KeyReleaseResponse>()
            .await
            .map_err(|_| ApiError::AttestationUnavailable)
    }
}

/// Production and simulated-TEE [`EnclaveKeyProvider`] (`P50`).
///
/// Acquires the tenant's key once per query via the challenge-attestation
/// protocol, unwraps it inside enclave RAM into a zeroize-on-drop
/// [`ReleasedKeySession`], and drops the key when the query finishes.
pub struct AttestedKeyProvider {
    identity: Arc<EnclaveIdentity>,
    attestation: Arc<dyn AttestationProvider>,
    client: Arc<dyn KeyReleaseClient>,
    release_count: AtomicUsize,
}

impl AttestedKeyProvider {
    pub fn new(
        identity: Arc<EnclaveIdentity>,
        attestation: Arc<dyn AttestationProvider>,
        client: Arc<dyn KeyReleaseClient>,
    ) -> Self {
        Self {
            identity,
            attestation,
            client,
            release_count: AtomicUsize::new(0),
        }
    }

    pub fn release_count(&self) -> usize {
        self.release_count.load(Ordering::SeqCst)
    }

    async fn acquire_keypair(&self, tenant: TenantId) -> Result<TenantKeypair, ApiError> {
        let challenge = self.client.issue_challenge().await.map_err(|_| {
            security_audit_event(
                AuditKind::KeyRelease,
                Some(tenant),
                "failed",
                "key-release challenge endpoint unreachable",
            );
            ApiError::AttestationUnavailable
        })?;
        let nonce = decode_32(&challenge.nonce_b64).ok_or_else(|| {
            security_audit_event(
                AuditKind::KeyRelease,
                Some(tenant),
                "failed",
                "key-release service returned invalid nonce",
            );
            ApiError::AttestationUnavailable
        })?;

        let binding = self.identity.binding_for_nonce(nonce);
        let evidence = self
            .attestation
            .produce_evidence(&binding.to_report_data())
            .await
            .map_err(|_| {
                security_audit_event(
                    AuditKind::KeyRelease,
                    Some(tenant),
                    "denied",
                    "failed to produce enclave attestation evidence for key release",
                );
                ApiError::AttestationUnavailable
            })?;

        let req = KeyReleaseRequest {
            tenant_id: tenant.to_string(),
            nonce_b64: challenge.nonce_b64,
            report_b64: B64.encode(&evidence.report),
            cert_chain_b64: B64.encode(&evidence.cert_chain),
            enclave_hpke_public_key_b64: B64.encode(self.identity.enclave_hpke_public_key()),
            result_signing_public_key_b64: B64.encode(self.identity.result_signing_public_key()),
            tls_cert_sha256_b64: B64.encode(self.identity.tls_cert_sha256()),
            config_digest_b64: B64.encode(self.identity.config_digest()),
        };

        let resp = self.client.release_key(&req).await?;
        let wrapped_bytes = B64
            .decode(&resp.wrapped_key_b64)
            .map_err(|_| ApiError::AttestationUnavailable)?;
        let info = key_release_info(tenant, &nonce);
        let kp = self.identity.unwrap_released_key(&info, &wrapped_bytes)?;
        self.release_count.fetch_add(1, Ordering::SeqCst);
        Ok(kp)
    }
}

struct ReleasedKeySession {
    keypair: TenantKeypair,
}

#[async_trait]
impl QueryKeySession for ReleasedKeySession {
    async fn open_envelope(&self, info: &[u8], envelope: &[u8]) -> Result<SecretBytes, ApiError> {
        self.keypair
            .open_envelope(info, envelope)
            .map_err(|_| ApiError::Backend)
    }
}

#[async_trait]
impl EnclaveKeyProvider for AttestedKeyProvider {
    async fn open_envelope(
        &self,
        tenant: TenantId,
        info: &[u8],
        envelope: &[u8],
    ) -> Result<SecretBytes, ApiError> {
        let keypair = self.acquire_keypair(tenant).await?;
        keypair
            .open_envelope(info, envelope)
            .map_err(|_| ApiError::Backend)
    }

    async fn begin_query_session<'a>(
        &'a self,
        tenant: TenantId,
    ) -> Result<Box<dyn QueryKeySession + 'a>, ApiError> {
        let keypair = self.acquire_keypair(tenant).await?;
        Ok(Box::new(ReleasedKeySession { keypair }))
    }
}

fn decode_32(b64: &str) -> Option<[u8; 32]> {
    let raw = B64.decode(b64.trim()).ok()?;
    raw.try_into().ok()
}
