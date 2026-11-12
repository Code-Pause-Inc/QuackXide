//! The simulated TEE's attestation-gated key release: a development and
//! simulation stand-in for Cloud KMS (ADR 0004), compiled only with the
//! `dev` feature.
//!
//! Protocol:
//! 1. At startup, the enclave generates an ephemeral in-RAM HPKE keypair
//!    ([`EnclaveIdentity`]) whose private key never leaves process memory.
//! 2. Per query, [`AttestedKeyProvider`] requests a single-use 32-byte
//!    challenge nonce from the key-release relying party, binds
//!    `(nonce, enclave_hpke_pk, result_signing_pk, tls_cert_sha256, config_digest)`
//!    into 64 bytes, and obtains a simulated Confidential Space token carrying
//!    them as its two nonces from [`AttestationProvider`].
//! 3. [`KeyReleaseRelyingParty`] consumes the single-use nonce, recomputes the
//!    binding, verifies the token with the production [`TokenVerifier`]
//!    against the simulator's key set ([`KeySource`]), and HPKE-seals the
//!    tenant's key material to the verified `enclave_hpke_pk`.
//!
//! [`sim_attestation_router`] is the `sim-attestation` service that plays
//! Google's part: it signs those tokens and publishes their key set.
//! 4. The enclave unwraps the key in RAM into a per-query zeroize-on-drop
//!    session ([`QueryKeySession`]), opens the snapshot manifest and objects,
//!    and drops the key as soon as decryption completes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::extract::State;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use platform_core::TenantId;
use platform_crypto::{SecretBytes, TenantKeypair, TenantPublicKey, hpke_seal_to_tenant};
use platform_enclave::simulated_token::TokenSigner;
use platform_enclave::token::{
    JwkSet, ReleasePolicy, SIMULATED_AUDIENCE, TokenError, TokenVerifier, nonces_from_bytes,
};
use platform_enclave::{AttestationProvider, ReportDataBinding, fresh_nonce};
use platform_telemetry::{AuditKind, security_audit_event};
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;

use super::EnclaveIdentity;
use crate::ApiError;
use crate::query::{EnclaveKeyProvider, QueryKeySession};

const CHALLENGE_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING_CHALLENGES: usize = 4096;
/// At most one key-set refetch per interval, so tokens naming random key ids
/// cannot make the stand-in fetch on every request.
const KEY_REFETCH_INTERVAL: Duration = Duration::from_secs(5);

/// Canonical HPKE `info` binding for a key-release envelope.
pub fn key_release_info(tenant: TenantId, nonce: &[u8; 32]) -> Vec<u8> {
    format!("quackxide-key-release-v1|{tenant}|{}", B64.encode(nonce)).into_bytes()
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
    pub token: String,
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

// ── Relying Party (Key-Release Service) ──────────────────────────────────────

/// Where the relying party gets the simulator's token-signing keys.
#[async_trait]
pub trait KeySource: Send + Sync {
    async fn fetch(&self) -> Result<JwkSet, TokenError>;
}

/// A fixed key set (tests and single-process demos).
pub struct StaticKeySource(pub JwkSet);

#[async_trait]
impl KeySource for StaticKeySource {
    async fn fetch(&self) -> Result<JwkSet, TokenError> {
        Ok(self.0.clone())
    }
}

/// The `sim-attestation` service's `GET /jwks`.
pub struct HttpKeySource {
    url: String,
    http: reqwest::Client,
}

impl HttpKeySource {
    pub fn new(base_url: &str) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        Self {
            url: format!("{}/jwks", base_url.trim_end_matches('/')),
            http,
        }
    }
}

#[async_trait]
impl KeySource for HttpKeySource {
    async fn fetch(&self) -> Result<JwkSet, TokenError> {
        self.http
            .get(&self.url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| TokenError::KeySetUnavailable)?
            .json()
            .await
            .map_err(|_| TokenError::KeySetUnavailable)
    }
}

/// Token-verifying key-release relying party: the simulated TEE's stand-in
/// for Cloud KMS (ADR 0004).
///
/// Issues single-use nonces, verifies simulated Confidential Space tokens
/// with [`TokenVerifier`] and `policy`, and releases tenant keys wrapped
/// under HPKE to the attested enclave's ephemeral public key.
pub struct KeyReleaseRelyingParty {
    source: Arc<dyn KeySource>,
    issuer: String,
    policy: ReleasePolicy,
    verifier: RwLock<Option<Arc<TokenVerifier>>>,
    last_fetch: Mutex<Option<Instant>>,
    refetch_interval: Duration,
    expected_config_digest: Option<[u8; 32]>,
    challenge_ttl: Duration,
    challenges: Mutex<HashMap<[u8; 32], Instant>>,
    keys: RwLock<HashMap<TenantId, SecretBytes>>,
    release_count: AtomicUsize,
}

impl KeyReleaseRelyingParty {
    pub fn new(
        source: Arc<dyn KeySource>,
        issuer: impl Into<String>,
        policy: ReleasePolicy,
    ) -> Self {
        Self {
            source,
            issuer: issuer.into(),
            policy,
            verifier: RwLock::new(None),
            last_fetch: Mutex::new(None),
            refetch_interval: KEY_REFETCH_INTERVAL,
            expected_config_digest: None,
            challenge_ttl: CHALLENGE_TTL,
            challenges: Mutex::new(HashMap::new()),
            keys: RwLock::new(HashMap::new()),
            release_count: AtomicUsize::new(0),
        }
    }

    pub fn with_refetch_interval(mut self, interval: Duration) -> Self {
        self.refetch_interval = interval;
        self
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

    /// The current verifier, refetching the key set (at most once per
    /// interval) when it has none or `token` names a key it does not know.
    async fn verifier_for(&self, token: &str) -> Result<Arc<TokenVerifier>, TokenError> {
        let current = self
            .verifier
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(v) = &current
            && v.knows_kid(token)
        {
            return Ok(v.clone());
        }
        let may_fetch = {
            let mut last = self
                .last_fetch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let due =
                current.is_none() || last.is_none_or(|at| at.elapsed() >= self.refetch_interval);
            if due {
                *last = Some(Instant::now());
            }
            due
        };
        if !may_fetch {
            return current.ok_or(TokenError::KeySetUnavailable);
        }
        let jwks = self.source.fetch().await?;
        let verifier = Arc::new(TokenVerifier::new(
            &jwks,
            &self.issuer,
            SIMULATED_AUDIENCE,
            self.policy.clone(),
        )?);
        *self
            .verifier
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(verifier.clone());
        Ok(verifier)
    }

    /// Verify the enclave's attestation token and release the tenant's key
    /// wrapped via HPKE to the enclave's ephemeral public key.
    pub async fn release_key(
        &self,
        req: &KeyReleaseRequest,
    ) -> Result<KeyReleaseResponse, ApiError> {
        let tenant: TenantId = req.tenant_id.parse().map_err(|_| {
            security_audit_event(
                AuditKind::KeyRelease,
                None,
                "denied",
                "invalid tenant_id in key-release request",
            );
            ApiError::Forbidden
        })?;

        let nonce = decode_32(&req.nonce_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed challenge nonce");
            ApiError::Forbidden
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
            return Err(ApiError::Forbidden);
        };
        if issued_at.elapsed() > self.challenge_ttl {
            self.audit_denial(tenant, "expired challenge nonce");
            return Err(ApiError::Forbidden);
        }

        let enclave_hpke_pk_raw = decode_32(&req.enclave_hpke_public_key_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed enclave HPKE public key");
            ApiError::Forbidden
        })?;
        let enclave_hpke_pk = TenantPublicKey::from_raw(&enclave_hpke_pk_raw).map_err(|_| {
            self.audit_denial(tenant, "invalid X25519 enclave HPKE public key");
            ApiError::Forbidden
        })?;

        let result_signing_pk = decode_32(&req.result_signing_public_key_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed result-signing public key");
            ApiError::Forbidden
        })?;
        let tls_cert_sha256 = decode_32(&req.tls_cert_sha256_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed TLS certificate digest");
            ApiError::Forbidden
        })?;
        let config_digest = decode_32(&req.config_digest_b64).ok_or_else(|| {
            self.audit_denial(tenant, "malformed config digest");
            ApiError::Forbidden
        })?;

        if let Some(expected_cfg) = &self.expected_config_digest
            && !bool::from(expected_cfg.ct_eq(&config_digest))
        {
            self.audit_denial(tenant, "deployment config digest mismatch");
            return Err(ApiError::Forbidden);
        }

        // Recompute the 64-byte binding the token's nonces must carry.
        let expected_binding = ReportDataBinding {
            nonce,
            enclave_hpke_public_key: enclave_hpke_pk_raw,
            result_signing_public_key: result_signing_pk,
            tls_cert_sha256,
            config_digest,
        };
        let expected_nonces = nonces_from_bytes(&expected_binding.to_report_data())
            .map_err(|_| ApiError::AttestationUnavailable)?;
        let verifier = self.verifier_for(&req.token).await.map_err(|err| {
            // An unreachable key set is an outage (503); anything else is a refusal (403).
            let (outcome, status) = match err {
                TokenError::KeySetUnavailable => ("failed", ApiError::AttestationUnavailable),
                _ => ("denied", ApiError::Forbidden),
            };
            security_audit_event(
                AuditKind::KeyRelease,
                Some(tenant),
                outcome,
                &err.to_string(),
            );
            status
        })?;
        verifier
            .verify(&req.token, &expected_nonces)
            .map_err(|err| {
                self.audit_denial(tenant, &err.to_string());
                ApiError::Forbidden
            })?;

        let keys = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(tenant_secret) = keys.get(&tenant) else {
            self.audit_denial(tenant, "no key enrolled for tenant");
            return Err(ApiError::Forbidden);
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
            "key released to simulated Confidential Space enclave (dev only)",
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
                        rp.release_key(&req).await.map(Json)
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
                        let public_key_b64 = B64.encode(kp.public_key().to_raw());
                        Ok::<_, ApiError>(Json(json!({ "public_key_b64": public_key_b64 })))
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
        self.0.release_key(req).await
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
            token: evidence.token,
            enclave_hpke_public_key_b64: B64.encode(self.identity.enclave_hpke_public_key()),
            result_signing_public_key_b64: B64.encode(self.identity.result_signing_public_key()),
            tls_cert_sha256_b64: B64.encode(self.identity.tls_cert_sha256()),
            config_digest_b64: B64.encode(self.identity.config_digest()),
        };

        // A refusal (403) or outage (503) at the stand-in is "attestation
        // unavailable" to the enclave's caller.
        let resp = self
            .client
            .release_key(&req)
            .await
            .map_err(|_| ApiError::AttestationUnavailable)?;
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

#[derive(Deserialize)]
struct TokenRequest {
    audience: String,
    nonces: Vec<String>,
}

/// The `sim-attestation` service: `POST /v1/token` signs a token for the
/// requested audience and nonces (the Confidential Space launcher's request
/// shape), and `GET /jwks` publishes the signer's key set.
pub fn sim_attestation_router(signer: Arc<TokenSigner>) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async { Json(json!({ "status": "ok" })) }),
        )
        .route(
            "/v1/token",
            post(
                |State(signer): State<Arc<TokenSigner>>, Json(req): Json<TokenRequest>| async move {
                    let token = signer.sign(&req.audience, &req.nonces, Duration::from_secs(3600));
                    Json(json!({ "token": token }))
                },
            ),
        )
        .route(
            "/jwks",
            get(|State(signer): State<Arc<TokenSigner>>| async move { Json(signer.jwks()) }),
        )
        .with_state(signer)
}
