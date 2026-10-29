# Simulated TEE to Google Cloud Confidential Computing — Developer Guide

This document maps each component of the local simulated TEE (`platform-enclave` and `platform-api::key_release`) to its production counterpart. Production is a Confidential Space workload on Intel TDX with Cloud KMS (ADR 0004). The simulation speaks AMD SEV-SNP reports and runs a key-release stand-in; both are development-only and are built only with the `dev` feature. Production evidence is Google's attestation token instead, so the SEV-SNP structures below have no production counterpart of their own.

---

## 1. Component-by-Component Mapping: Simulation vs. Production

| QuackXide Component | What It Does in Local Simulation (`TeePlatform::Simulated`) | Production Counterpart (ADR 0004) |
| --- | --- | --- |
| **`AttestationProvider` (`SimulatedSnp`)** | Constructs a 1184-byte binary `SnpReport` in process memory and signs bytes `0x000..0x2A0` with an ephemeral in-memory P-384 `vcek_signing_key`. | A Confidential Space provider (P48) asks the launcher (`/run/container_launcher/teeserver.sock`) for an attestation token. Google's attestation service verifies the TDX quote and signs the token; QuackXide never parses a raw TDX quote. |
| **`SnpReport` (1184 bytes, ABI v1.55 Table 22)** | 1184-byte wire format: `version=2`, `vmpl=0`, `signature_algo=1` (ECDSA P-384 with SHA-384), 64-byte `report_data` at `0x050`, 48-byte `measurement` at `0x090`, `reported_tcb` at `0x180`, 64-byte `chip_id` at `0x1A0`, and 72-byte little-endian padded `R`/`S` scalars at `0x2A0..0x330`. | Google's signed attestation token, with claims including `hwmodel`, `swname`, `dbgstat`, the support attributes, the container image digest and the nonces ([token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)). |
| **`ARK -> ASK -> VCEK` Chain (`SnpCertChain`)** | Ephemeral P-384 root (`ArkCertificate`), intermediate (`AskCertificate`), and leaf (`VcekCertificate`) generated at startup by `SimulatedSnp::with_config`. Never persisted or committed to git. | Google's token-signing keys. How the verifier and the browser trust them is ADR 0004 open question 3. |
| **`TrustRoot` (`TrustRoot::Simulated`)** | Pins the ephemeral ARK public key for the current dev/CI session and stamps `VerifiedReport::platform()` as `TeePlatform::Simulated`. | P47's token verifier pins Google's keys. `TrustRoot::ProductionAmd` has no production use. |
| **`MEASUREMENT` (48-byte SHA-384 at `0x090..0x0C0`)** | `DEFAULT_SIMULATED_MEASUREMENT` (or container binary digest injected into `SimulatedSnpConfig::measurement`). Checked in constant time against `VerificationPolicy::expected_measurements`. | The container image digest in the token. The release policy and P47's verifier allow only the digests P49 publishes. |
| **`REPORT_DATA` (64 bytes at `0x050..0x090` / `ReportDataBinding`)** | `bytes[0..32]` = relying-party freshness `nonce`. `bytes[32..64]` = `SHA-256("quackxide-snp-report-data-v1" \|\| enclave_hpke_pk \|\| result_signing_pk \|\| tls_cert_sha256 \|\| config_digest)`. | The same digest, passed as a token nonce together with the browser's nonce (ADR 0004, "Freshness and binding"). |
| **`GuestPolicy` (`0x008..0x010`)** | Enforces `DEBUG == 0` (bit 19) and `MIGRATE_MA == 0` (bit 18). `SimulatedSnpConfig` allows toggling both bits to test refusal paths. | `dbgstat == disabled-since-boot` and the `STABLE` support attribute: a debug Confidential Space image never passes the release policy. |
| **`TcbVersion` (`reported_tcb` at `0x180..0x188`)** | Enforces component-wise `boot_loader >= min.boot_loader`, `tee >= min.tee`, `snp >= min.snp`, `microcode >= min.microcode`, and matches `VcekCertificate::tcb`. | Checked by Google's attestation service, which `docs/THREAT_MODEL.md` A2 trusts for hardware verification. |
| **`EnclaveIdentity` (`platform-api::key_release`)** | Generates an ephemeral in-RAM X25519 HPKE keypair and identity key at enclave process boot (`main.rs`). Private keys never leave process memory and are overwritten on drop. | The same in-RAM key generation inside the TDX guest, whose memory TDX encrypts. A build without `dev` keeps no private half until P85 gives it a production use. |
| **`GET /api/v1/attestation?nonce_b64=...`** | Accepts a 32-byte relying-party or browser nonce, constructs `ReportDataBinding`, calls `SimulatedSnp::attest`, and returns the base64 1184-byte `SnpReport`, `SnpCertChain`, and public keys. | The same endpoint returns Google's token and the public keys, so browsers (P85) and auditors can verify the enclave before querying. |
| **`KeyReleaseRelyingParty` (`bin/key-release.rs`, dev only)** | Standalone HTTP relying party (`POST /v1/challenge`, `POST /v1/release`, `PUT /v1/keys`) holding tenant keys outside `platform-api`. Verifies single-use 60s challenge nonces + `AttestationVerifier` before HPKE-sealing the tenant private key (`key-release-v1\|{tenant_id}\|{nonce_b64}`) to the enclave's attested HPKE public key. | Cloud KMS in the maintainer's key project. Each dataset's data key is wrapped to a KMS X-Wing key, and KMS decapsulates only for a workload identity federation principal whose token meets the release policy (P50). |
| **`AttestedKeyProvider` & `ReleasedKeySession` (dev only)** | Implements `EnclaveKeyProvider::begin_query_session`. Executes the challenge + attestation + HPKE unwrap handshake **once per query** (not once per Parquet object), holds the unwrapped `TenantKeypair` in enclave RAM for the query's lifetime, and zeroizes the private scalar on `Drop`. | A production `EnclaveKeyProvider` that asks KMS to decapsulate the data keys a query needs, once per query, with nothing cached (P50). |

---

## 2. How Workload Identity Works on Google Cloud

On Google Cloud, a Confidential VM's launch measurement covers Google's firmware, not the container that runs on it, so a raw hardware report cannot prove which `platform-api` image is running. Confidential Space closes that gap, and it is why ADR 0004 chose it:

* **Host VM image:** `projects/confidential-space-images/global/images/family/confidential-space` on an Intel TDX machine type that P12 confirms (`confidential-space-debug` only for development; its tokens report debug and never pass the release policy).
* **How the image is measured:** the Confidential Space launcher pulls the workload image by digest, applies its launch policy (`tee.launch_policy.*` labels on the production image from P49), and records the image digest and policy in the evidence it presents to Google's attestation service.
* **How `platform-api` uses it:** it requests a token with its own audience and nonces from `/run/container_launcher/teeserver.sock` (P48). The token, not a raw report, is what the gates, KMS and the browser verify.

---

## 3. Attestation-Gated Key Release: Simulation vs. Cloud KMS

In the simulation, `platform-api` holds no tenant decryption keys at rest or in environment variables. Instead, `AttestedKeyProvider` acquires a per-query `ReleasedKeySession` over a 4-step protocol with the `KeyReleaseRelyingParty` stand-in:

```
platform-api (Enclave)                                    key-release (stand-in for Cloud KMS)
──────────────────────                                    ────────────────────────────────────
1. POST /v1/challenge ──────────────────────────────────▶ mints single-use 32B nonce (60s TTL)
                      ◀────────────────────────────────── { nonce_b64, expires_at_unix }
2. ReportDataBinding { nonce, enclave_hpke_pk, ... }
   AttestationProvider::attest(report_data) -> 1184B SnpReport
3. POST /v1/release { tenant_id, nonce_b64, report_b64,
   cert_chain_b64, enclave_hpke_pk, config_digest } ────▶ consumes nonce (single-use)
                                                          recomputes ReportDataBinding from request keys
                                                          AttestationVerifier::verify(report, chain, binding)
                                                          seals tenant key via HPKE to enclave_hpke_pk
                                                          (info = "key-release-v1|{tenant_id}|{nonce_b64}")
                      ◀────────────────────────────────── { wrapped_tenant_private_key_b64 }
4. hpke::open with in-RAM EnclaveIdentity::hpke_keypair
   unwraps TenantKeypair into ReleasedKeySession
   decrypts snapshot manifest + Parquet objects in RAM
   Drop overwrites TenantKeypair scalar bytes
```

The stand-in accepts tenant private keys over plain HTTP (`PUT /v1/keys`). That is acceptable only because it handles synthetic data in local Docker and CI, and it is why it is built only with the `dev` feature: a `platform-api` built without `dev` refuses to start when `KEY_RELEASE_URL` is set.

### Production: Confidential Space + Workload Identity Federation + Cloud KMS

ADR 0004 requires an off-the-shelf release mechanism, so production uses no QuackXide release service. In the key project, which only the maintainer administers (P12, P50):

1. Create a **Workload Identity Pool** and an OIDC provider trusting `https://confidentialcomputing.googleapis.com`.
2. Attach an **Attribute Condition** on the provider that enforces Intel TDX, a production Confidential Space image with debug disabled, and an allowed `platform-api` image digest:
   ```cel
   assertion.swname == 'CONFIDENTIAL_SPACE' &&
   assertion.hwmodel == 'GCP_INTEL_TDX' &&
   assertion.dbgstat == 'disabled-since-boot' &&
   'STABLE' in assertion.submods.confidential_space.support_attributes &&
   assertion.submods.container.image_digest == 'sha256:<APPROVED_PLATFORM_API_DIGEST>'
   ```
3. Grant that federated principal decapsulation on the KMS key, and nothing else. No deployment identity has IAM on the key project.

---

## 4. Containerized Simulated TEE Topology

`Dockerfile` and `docker-compose.simulated-tee.yml` package the simulation into an isolated local Docker topology verified by `scripts/test-simulated-tee.sh`. Both images are built with the `dev` feature and are never deployed; the production image is P49's, in `deploy/`.

```
                  Host / Browser Client
                            │
                            │ HTTP :8080 (public_net)
                            ▼
┌───────────────────────────────────────────────────────┐
│  enclave-api (simulated enclave workload)             │
│  - Target: Dockerfile -> enclave-api (uid 65532)      │
│  - Rootfs: read_only: true + /tmp tmpfs (64 MiB)      │
│  - Capabilities: cap_drop: [ALL], no-new-privileges   │
│  - Attestation: SimulatedSnp::from_env()              │
└─────────────┬───────────────────────────┬─────────────┘
              │                           │
              │ enclave_internal_net      │ enclave_internal_net
              │ (internal: true)          │ (internal: true)
              ▼                           ▼
┌───────────────────────────┐ ┌─────────────────────────┐
│ key-release-service       │ │ fake-gcs                │
│ (stand-in for Cloud KMS)  │ │ (Encrypted Object Vault)│
│ - bin/key-release         │ │ - fake-gcs-server:4443  │
│ - Verifies 1184B report   │ │ - Stores HPKE-sealed    │
│   before HPKE-wrapping    │ │   manifests & Parquet   │
│   tenant private key      │ │   snapshots only        │
└───────────────────────────┘ └─────────────────────────┘
```

### Container & Network Component Mapping

| Simulated TEE Component (`docker-compose.simulated-tee.yml`) | Production Equivalent | How the Simulation Relates to Production |
| :--- | :--- | :--- |
| **`enclave-api` container (`Dockerfile` target `enclave-api`)** | **Confidential Space workload** on an Intel TDX Confidential VM, from the production image (P49) | Runs `platform-api` built with the `dev` feature as non-root (`65532:65532`) with `read_only: true`, `cap_drop: ["ALL"]`, and `no-new-privileges:true`. The production image is built without `dev`. |
| **`SIMULATED_SNP_SEED` cross-container PKI** | **Google's token-signing keys** | Allows `enclave-api` and `key-release-service` (running in separate containers with isolated memory) to deterministically derive the same synthetic `ARK -> ASK -> VCEK` root of trust without sharing private keys over the network. |
| **`SIMULATED_SNP_MEASUREMENT_HEX` & `SIMULATED_SNP_DEBUG`** | **Image digest claim** & **debug vs. production Confidential Space image** (`dbgstat`) | Allows `scripts/test-simulated-tee.sh` to inject a mismatched launch measurement or `DEBUG=1` policy into `enclave-api` and prove that `key-release-service` refuses key release (`HTTP 403` -> `/api/v1/query` fails closed with `HTTP 503`). |
| **`key-release-service` (`Dockerfile` target `key-release`)** | **Cloud KMS + Workload Identity Federation** in the maintainer's key project | The stand-in holds tenant private keys outside the enclave and evaluates the `SnpReport`, P-384 chain, `MEASUREMENT`, `GuestPolicy`, `TcbVersion`, and `ReportDataBinding` before sealing the tenant key to the enclave. In production, KMS holds a non-exportable key, and per-dataset data keys are wrapped to it. |
| **`fake-gcs` (`fsouza/fake-gcs-server`) + `STORAGE_EMULATOR_HOST`** | **Google Cloud Storage (GCS)** bucket in the Ciphertext Vault Project | `ObjectStoreVault::new_gcs` uses the same `object_store::gcp::GoogleCloudStorageBuilder` code path in both environments. In local Docker, `STORAGE_EMULATOR_HOST=http://fake-gcs:4443` routes HTTP calls to `fake-gcs`; in GCP, omitting `STORAGE_EMULATOR_HOST` routes HTTPS calls to `https://storage.googleapis.com` using Workload Identity credentials. |
| **`enclave_internal_net` (`internal: true`)** | **VPC Service Controls (VPC-SC) perimeter + Private Google Access** | Isolates the enclave-to-KMS and enclave-to-GCS control/storage traffic from the public ingress network (`public_net`). |

### Running the Local Simulated TEE Verification Suite

Run the automated end-to-end Docker verification script from the repository root:

```bash
./scripts/test-simulated-tee.sh
```

`scripts/test-simulated-tee.sh` executes five automated stages:
1. Builds and starts `fake-gcs` and `key-release-service` with a shared `SIMULATED_SNP_SEED`.
2. Creates the `quackxide-vault` GCS bucket in `fake-gcs` and enrolls a tenant keypair on `key-release-service`.
3. Starts `enclave-api`, which seals the synthetic QuickBooks fixture into `fake-gcs` under the tenant's HPKE public key (`HPK1` envelope + AES-256-GCM chunks).
4. Verifies `GET /api/v1/attestation` (signed 1184-byte `SnpReport` + P-384 chain) and `POST /api/v1/query` (attested key release over `enclave_internal_net`, in-RAM DuckDB execution, and P-384 `enclave_signature` over the query result).
5. Forces two tamper scenarios on `enclave-api` — a corrupted 48-byte `SIMULATED_SNP_MEASUREMENT_HEX` and `SIMULATED_SNP_DEBUG=true` — and verifies that `key-release-service` rejects both reports and `enclave-api` fails closed with `HTTP 503`.

---

## 5. From the Simulation to Production

The production path is built by its own plan items, not by pointing the simulation at hardware:

1. **Token verification (P47):** a portable verifier for Google's attestation token, also built for the browser (P85).
2. **Token acquisition and verified gates (P48):** a Confidential Space provider; `gate_execution` (`platform-enclave`) and `EnclavePipeline::attestation_gate` (`platform-connectors`) act on the verified token.
3. **Key release (P50):** Cloud KMS behind workload identity federation, as in Section 3.
4. **Production gate enforcement (`TEE_ATTESTATION_REQUIRED=true`):** both gates reject `TeePlatform::Simulated` and `TeePlatform::Development` whenever `require_attestation == true`, and `TrustRoot::ProductionAmd` rejects any chain signed by `SimulatedSnp`.

---

## 6. What `SimulatedSnp` + `KeyReleaseRelyingParty` Prove — and What They Do Not

* **What they prove in local Docker and CI:**
  * The 1184-byte binary report serializer/parser (`SnpReport`), ECDSA P-384 SHA-384 signature check (`0x000..0x2A0` with little-endian 72-byte `R`/`S` scalars), `ARK -> ASK -> VCEK` chain validation, CRL serial revocation, certificate expiration, `GuestPolicy` checks (`DEBUG=0`, `MIGRATE_MA=0`), component-wise `TcbVersion` minimum check, constant-time `MEASUREMENT` allowlist check, 64-byte `ReportDataBinding` verification, single-use challenge nonce freshness, HPKE key wrapping (`key-release-v1`), and GCS vault storage (`ObjectStoreVault::new_gcs`) all execute end-to-end across isolated containers on every query.
* **What they do NOT provide:**
  * Host memory encryption. In local Docker, the host OS kernel can inspect container memory. Plaintext protection against a compromised host operator exists only on Intel TDX hardware under Confidential Space.
  * The production evidence and release path. Production verifies Google's attestation token and releases data keys through Cloud KMS; the simulation exercises SEV-SNP reports and the stand-in instead.
