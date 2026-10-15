# Simulated TEE to Google Cloud Confidential Computing — Developer Guide

This document maps each component of the local simulated TEE (`platform-enclave` and `platform-api::key_release`) to its hardware and control-plane counterpart in Google Cloud Platform (GCP), and specifies the implementation path from local Docker simulation to GCP AMD SEV-SNP Confidential VMs.

---

## 1. Component-by-Component Mapping: Simulation vs. Google Cloud

| QuackXide Component | What It Does in Local Simulation (`TeePlatform::Simulated`) | Real-World Counterpart in Google Cloud (`TeePlatform::SevSnp`) |
| --- | --- | --- |
| **`AttestationProvider` (`SimulatedSnp` vs. `SnpAttestation`)** | Constructs a 1184-byte binary `SnpReport` in process memory and signs bytes `0x000..0x2A0` with an ephemeral in-memory P-384 `vcek_signing_key`. | Issues the `SNP_GET_REPORT` `ioctl` to `/dev/sev-guest` (or reads `/sys/kernel/config/tsm/report` via Linux `configfs-tsm` on kernel 6.7+) inside a GCP `c3d` or `n2d` Confidential VM running with `--confidential-compute-type=SEV_SNP`. The physical AMD EPYC Secure Processor (ASP/PSP) signs the report using the chip-unique hardware VCEK. |
| **`SnpReport` (1184 bytes, ABI v1.55 Table 22)** | Identical 1184-byte wire format: `version=2`, `vmpl=0`, `signature_algo=1` (ECDSA P-384 with SHA-384), 64-byte `report_data` at `0x050`, 48-byte `measurement` at `0x090`, `reported_tcb` at `0x180`, 64-byte `chip_id` at `0x1A0`, and 72-byte little-endian padded `R`/`S` scalars at `0x2A0..0x330`. | Identical 1184-byte wire format returned by the AMD Secure Processor inside the `SNP_REPORT_RSP` structure. |
| **`ARK -> ASK -> VCEK` Chain (`SnpCertChain`)** | Ephemeral P-384 root (`ArkCertificate`), intermediate (`AskCertificate`), and leaf (`VcekCertificate`) generated at startup by `SimulatedSnp::with_config`. Never persisted or committed to git. | Fetched from AMD's Key Distribution Service (KDS) (`https://kdsintf.amd.com/vcek/v1/{Milan\|Genoa}/{chip_id}?blSPL=..&teeSPL=..&snpSPL=..&ucodeSPL=..`) or cached via the host hypervisor's `SNP_GET_EXT_REPORT` certificate table and provisioned into the enclave. |
| **`TrustRoot` (`TrustRoot::Simulated` vs. `TrustRoot::ProductionAmd`)** | `TrustRoot::Simulated` pins the ephemeral ARK public key for the current dev/CI session and stamps `VerifiedReport::platform()` as `TeePlatform::Simulated`. | `TrustRoot::ProductionAmd` pins AMD's hardware ARK public keys (Milan/Genoa/Turin root certificates) compiled into the verifier binary. Rejects any `SimulatedSnp` chain. |
| **`MEASUREMENT` (48-byte SHA-384 at `0x090..0x0C0`)** | `DEFAULT_SIMULATED_MEASUREMENT` (or container binary digest injected into `SimulatedSnpConfig::measurement`). Checked in constant time against `VerificationPolicy::expected_measurements`. | Measures the initial guest UEFI firmware image (`OVMF.fd`) loaded by GCE at VM launch. **Important GCP nuance:** on GCP Confidential VMs, the AMD hardware `MEASUREMENT` covers Google's signed OVMF UEFI firmware, *not* the container image. Workload identity (`platform-api` container image digest) is bound via measured boot (see Section 2). |
| **`REPORT_DATA` (64 bytes at `0x050..0x090` / `ReportDataBinding`)** | `bytes[0..32]` = relying-party freshness `nonce`. `bytes[32..64]` = `SHA-256("quackxide-snp-report-data-v1" \|\| enclave_hpke_pk \|\| result_signing_pk \|\| tls_cert_sha256 \|\| config_digest)`. | Identical 64-byte input passed in `snp_report_req.user_data` to `/dev/sev-guest`. Cryptographically binds the enclave's in-RAM ephemeral X25519 HPKE key and Ed25519 signing key to the hardware signature. |
| **`GuestPolicy` (`0x008..0x010`)** | Enforces `DEBUG == 0` (bit 19) and `MIGRATE_MA == 0` (bit 18). `SimulatedSnpConfig` allows toggling both bits to test refusal paths. | Enforced by the AMD Secure Processor at VM launch (`SEV_LAUNCH_START` / `SNP_LAUNCH_START`) and attested in the report. A debug-enabled VM can have its memory read by the hypervisor and is unconditionally rejected by `AttestationVerifier`. |
| **`TcbVersion` (`reported_tcb` at `0x180..0x188`)** | Enforces component-wise `boot_loader >= min.boot_loader`, `tee >= min.tee`, `snp >= min.snp`, `microcode >= min.microcode`, and matches `VcekCertificate::tcb`. | Reflects the physical host's AMD Secure Processor firmware and microcode patch levels (`SPL`), preventing rollback to vulnerable CPU microcode or SNP firmware versions. |
| **`EnclaveIdentity` (`platform-api::key_release`)** | Generates an ephemeral in-RAM X25519 HPKE keypair (`hpke_keypair`) and identity key at enclave process boot (`main.rs`). Private keys never leave process memory and are overwritten on drop. | Identical in-RAM key generation inside the GCP Confidential VM guest memory (encrypted by the AMD EPYC memory controller with a VM-specific AES-128-XTS hardware key). |
| **`GET /api/v1/attestation?nonce_b64=...`** | Accepts a 32-byte relying-party or browser nonce, constructs `ReportDataBinding`, calls `SimulatedSnp::attest`, and returns the base64 1184-byte `SnpReport`, `SnpCertChain`, and public keys. | Identical HTTP endpoint served by `platform-api`, backed by `SnpAttestation` (`/dev/sev-guest`). Allows browsers (`P85`) and external auditors to verify enclave hardware identity before uploading or querying data. |
| **`KeyReleaseRelyingParty` (`bin/key-release.rs`)** | Standalone HTTP relying party (`POST /v1/challenge`, `POST /v1/release`, `PUT /v1/keys`) holding tenant keys outside `platform-api`. Verifies single-use 60s challenge nonces + `AttestationVerifier` before HPKE-sealing the tenant private key (`key-release-v1\|{tenant_id}\|{nonce_b64}`) to the enclave's attested HPKE public key. | Maps either to the standalone `key-release` service deployed in an isolated GCP project backed by Cloud KMS HSM keys, or to GCP Confidential Space + IAM Workload Identity Pool + Cloud KMS key release (see Section 3). |
| **`AttestedKeyProvider` & `ReleasedKeySession`** | Implements `EnclaveKeyProvider::begin_query_session`. Executes the challenge + attestation + HPKE unwrap handshake **once per query** (not once per Parquet object), holds the unwrapped `TenantKeypair` in enclave RAM for the query's lifetime, and zeroizes the private scalar on `Drop`. | Identical runtime provider inside `platform-api` configured via `KEY_RELEASE_URL`. |

---

## 2. How Workload Identity Works on Google Cloud (Closing the Firmware Measurement Gap)

On bare-metal KVM, you control the guest firmware/initramfs image, so `SnpReport.measurement` (48 bytes) can directly hash a Unified Kernel Image (UKI) containing `platform-api`.

On **Google Cloud Compute Engine (GCE)**, Google controls and boots the guest UEFI firmware (`OVMF`). Consequently:
1. `SnpReport.measurement` proves the VM booted **Google's genuine Confidential VM UEFI firmware** on genuine AMD SEV-SNP hardware with `DEBUG=0`.
2. To prove **which container image** (`platform-api` SHA-256 digest) is running inside that VM, GCP provides two deployment models:

### Option A: GCP Confidential Space (Managed Container Runtime)
* **Host VM Image:** `projects/confidential-space-images/global/images/family/confidential-space-hardened` (use `confidential-space-debug` only for non-production troubleshooting).
* **How container measurement works:**
  1. At VM boot, Google's UEFI firmware measures the bootloader and Container-Optimized OS kernel into the virtual TPM (`/dev/tpm0`).
  2. The Confidential Space launcher pulls your `platform-api` container image from Artifact Registry by digest (`tee.image-reference=...@sha256:...`), measures the image digest and environment policy (`tee.launch_policy.*` labels) into vTPM PCRs, and exposes a Unix domain socket at `/run/container_launcher/teeserver.sock`.
* **How `platform-api` uses it:**
  * Alongside the raw `/dev/sev-guest` report (exposed into the container via `--device /dev/sev-guest`), `platform-api` binds its ephemeral `ReportDataBinding` hash as the nonce/eat_nonce to `/run/container_launcher/teeserver.sock` so the verifier validates **both** the raw AMD SEV-SNP hardware report (`AttestationVerifier`) **and** the container image SHA-256 digest.

### Option B: Direct GCP Confidential VM (`SEV_SNP`) with Measured UKI / COS
* **Provisioning command:**
  ```sh
  gcloud compute instances create quackxide-enclave-01 \
    --machine-type=n2d-standard-4 \
    --zone=us-central1-a \
    --confidential-compute-type=SEV_SNP \
    --maintenance-policy=TERMINATE \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring \
    --image-family=ubuntu-2404-lts-amd64 \
    --image-project=ubuntu-os-cloud
  ```
* **Passing the hardware device into Docker:**
  When running the `platform-api` Docker container on a direct GCP Confidential VM, map the kernel guest device into the container:
  ```sh
  docker run --rm \
    --read-only \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --device=/dev/sev-guest:/dev/sev-guest \
    -e TEE_ATTESTATION_REQUIRED=true \
    -e KEY_RELEASE_URL=https://key-release.internal.example \
    -p 8080:8080 \
    us-docker.pkg.dev/<PROJECT_ID>/quackxide/platform-api@sha256:<DIGEST>
  ```

---

## 3. Attestation-Gated Key Release: Simulation vs. Google Cloud KMS

In Step 2, `platform-api` never holds static tenant decryption keys at rest or in environment variables. Instead, `AttestedKeyProvider` acquires a per-query `ReleasedKeySession` over a 4-step protocol with `KeyReleaseRelyingParty`:

```
platform-api (Enclave)                                    key-release (Relying Party / KMS)
──────────────────────                                    ─────────────────────────────────
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

### Mapping to Google Cloud Production

There are two production deployment architectures on GCP for this protocol:

#### Architecture 1: QuackXide `key-release` Service Backed by Cloud KMS (Direct 1:1 Mapping)
Run the `key-release` binary (`backend/crates/platform-api/src/bin/key-release.rs`) in a separate, locked-down GCP project (the Key Custody Project) with:
* `TrustRoot::ProductionAmd` (pinned AMD Milan/Genoa ARK public keys) and `VerificationPolicy::production_default()` (`require_hardware_sev_snp: true`, `allow_debug_policy: false`, `allow_migratable: false`).
* Tenant private key scalars stored encrypted at rest under a **Cloud HSM** key (`projects/<KMS_PROJECT>/locations/us-central1/keyRings/quackxide-tenant-keks/cryptoKeys/<TENANT_ID>`).
* Only when `KeyReleaseRelyingParty::release_key` verifies the 1184-byte `SnpReport` and `ReportDataBinding` does it call `kms.projects.locations.keyRings.cryptoKeys.decrypt` to unwrap the tenant's X25519 scalar and immediately re-seal it via HPKE to the enclave's attested ephemeral `enclave_hpke_public_key`.
* **Advantage:** Zero changes to `platform-api`, `AttestedKeyProvider`, or `HttpKeyReleaseClient`; only `KEY_RELEASE_URL` changes. Furthermore, Cloud KMS never needs to understand raw 1184-byte SEV-SNP reports directly because `KeyReleaseRelyingParty` acts as the cryptographic relying party.

#### Architecture 2: GCP Confidential Space + Workload Identity Federation + Cloud KMS
If using GCP's managed Confidential Space attestation verifier (`https://confidentialcomputing.googleapis.com`):
1. Create a **Workload Identity Pool** and an OIDC provider trusting `https://confidentialcomputing.googleapis.com`.
2. Attach an **Attribute Condition** on the provider that enforces hardware SEV-SNP, production Confidential Space image, and the exact `platform-api` container SHA-256 digest:
   ```cel
   assertion.swname == 'CONFIDENTIAL_SPACE' &&
   'STABLE' in assertion.submods.confidential_space.support_attributes &&
   assertion.submods.container.image_digest == 'sha256:<APPROVED_PLATFORM_API_DIGEST>' &&
   assertion.submods.gce.sev_snp != null
   ```
3. Grant that federated principal `roles/cloudkms.cryptoKeyDecrypter` on the tenant KMS key ring.

---

## 4. Containerized Simulated TEE Topology & Google Cloud Mapping (Step 3)

`Dockerfile` and `docker-compose.simulated-tee.yml` package the full 3-plane Confidential Computing architecture into an isolated local Docker topology verified by `scripts/test-simulated-tee.sh`.

```
                  Host / Browser Client
                            │
                            │ HTTP :8080 (public_net)
                            ▼
┌───────────────────────────────────────────────────────┐
│  enclave-api (Confidential Workload Container)        │
│  - Target: Dockerfile -> enclave-api (uid 65532)      │
│  - Rootfs: read_only: true + /tmp tmpfs (64 MiB)      │
│  - Capabilities: cap_drop: [ALL], no-new-privileges   │
│  - Labels: tee.launch_policy.*                        │
│  - Attestation: SimulatedSnp::from_env()              │
└─────────────┬───────────────────────────┬─────────────┘
              │                           │
              │ enclave_internal_net      │ enclave_internal_net
              │ (internal: true)          │ (internal: true)
              ▼                           ▼
┌───────────────────────────┐ ┌─────────────────────────┐
│ key-release-service       │ │ fake-gcs                │
│ (Attestation Relying      │ │ (Encrypted Object Vault)│
│  Party & Key Custody)     │ │                         │
│ - bin/key-release         │ │ - fake-gcs-server:4443  │
│ - Verifies 1184B report   │ │ - Stores HPKE-sealed    │
│   before HPKE-wrapping    │ │   manifests & Parquet   │
│   tenant private key      │ │   snapshots only        │
└───────────────────────────┘ └─────────────────────────┘
```

### Container & Network Component Mapping

| Simulated TEE Component (`docker-compose.simulated-tee.yml`) | Real-World Google Cloud Production Equivalent | How the Simulation Matches Production |
| :--- | :--- | :--- |
| **`enclave-api` container (`Dockerfile` target `enclave-api`)** | **Google Cloud Confidential Space workload** running on an AMD SEV-SNP Confidential VM (`n2d` / `c3d` with `sev_snp` confidential instance type) | Runs the identical compiled `/usr/local/bin/platform-api` binary as non-root (`65532:65532`) with `read_only: true`, `cap_drop: ["ALL"]`, and `no-new-privileges:true`. |
| **`LABEL "tee.launch_policy.*"` (`Dockerfile`)** | **Confidential Space Launch Policy** enforced by the Confidential Space hardened Container-Optimized OS (COS) launcher | `allow_cmd_override="false"` prevents the host operator from overriding the container entrypoint; `allow_env_override` allowlists only non-secret configuration variables; `log_redirect="never"` prevents stdout/stderr exfiltration to untrusted host logging agents. |
| **`SIMULATED_SNP_SEED` cross-container PKI** | **AMD Key Distribution Service (KDS)** + hardware VCEK fused into the AMD SP | Allows `enclave-api` and `key-release-service` (running in separate containers with isolated memory) to deterministically derive the same synthetic `ARK -> ASK -> VCEK` root of trust without sharing private keys over the network. |
| **`SIMULATED_SNP_MEASUREMENT_HEX` & `SIMULATED_SNP_DEBUG`** | **OVMF + kernel + container image digest measurement** (`0x090..0x0C0`) & **Confidential Space debug vs. production image** (`POLICY.DEBUG` bit 19) | Allows `scripts/test-simulated-tee.sh` to inject a mismatched launch measurement or `DEBUG=1` policy into `enclave-api` and prove that `key-release-service` refuses key release (`HTTP 403` -> `/api/v1/query` fails closed with `HTTP 503`). |
| **`key-release-service` (`Dockerfile` target `key-release`)** | **Cloud KMS (HSM) + Workload Identity Pool / Relying Party Key-Release Service** in a dedicated Key Custody GCP Project | Holds tenant private keys outside the enclave VM. Evaluates the 1184-byte `SnpReport`, P-384 chain, `MEASUREMENT`, `GuestPolicy`, `TcbVersion`, and 64-byte `ReportDataBinding` before sealing the tenant key via HPKE (`key-release-v1`) to the enclave's ephemeral X25519 key. |
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

### Deploying the Same Container Image to Google Cloud Confidential Space

1. **Build and push the `enclave-api` image to Artifact Registry** and record its immutable `@sha256:...` digest:
   ```bash
   docker build --target enclave-api \
     -t us-central1-docker.pkg.dev/<WORKLOAD_PROJECT>/enclave/platform-api:latest .
   docker push us-central1-docker.pkg.dev/<WORKLOAD_PROJECT>/enclave/platform-api:latest
   ```
2. **Deploy `key-release` (or configure Cloud KMS + WIF) in the Key Custody Project** with `TEE_ATTESTATION_REQUIRED=true` and `KEY_RELEASE_ARK_PUBKEY_B64` set to AMD's Milan/Genoa ARK public key.
3. **Launch the Confidential Space VM** on an AMD SEV-SNP machine series (`n2d-standard-4` or `c3d-standard-4`) pointing at the pinned `@sha256:...` image digest:
   ```bash
   gcloud compute instances create quackxide-enclave-01 \
     --project=<WORKLOAD_PROJECT> \
     --zone=us-central1-a \
     --machine-type=n2d-standard-4 \
     --confidential-compute-type=SEV_SNP \
     --maintenance-policy=TERMINATE \
     --shielded-secure-boot \
     --image-project=confidential-space-images \
     --image-family=confidential-space \
     --metadata="^~^tee-image-reference=us-central1-docker.pkg.dev/<WORKLOAD_PROJECT>/enclave/platform-api@sha256:<DIGEST>~tee-env-BIND_ADDR=0.0.0.0:8080~tee-env-STORAGE_BUCKET=<VAULT_BUCKET>~tee-env-KEY_RELEASE_URL=https://<KEY_RELEASE_HOST>~tee-env-TEE_ATTESTATION_REQUIRED=true~tee-env-FEATURE_ZK_ENABLED=true"
   ```

---

## 5. Transitioning Code from `SimulatedSnp` to `SnpAttestation` on GCP

Because `SimulatedSnp`, `AttestationVerifier`, and `KeyReleaseRelyingParty` already speak the binary 1184-byte AMD SEV-SNP protocol, transitioning to GCP hardware requires **zero changes to `AttestationVerifier`, `ReportDataBinding`, `AttestedKeyProvider`, or the key-release wire protocol**:

1. **Report Acquisition (`SnpAttestation::produce_evidence` in `backend/crates/platform-enclave/src/lib.rs`):**
   * Open `/dev/sev-guest` (`O_RDWR`) and issue the `SNP_GET_EXT_REPORT` ioctl (`_IOWR('S', 0x1, struct snp_guest_request_ioctl)`) with the 64-byte `ReportDataBinding::to_report_data()` buffer.
   * Alternatively, on Linux 6.7+ kernels with `configfs-tsm`, write the 64-byte `report_data` to `/sys/kernel/config/tsm/report/quackxide/inblob` and read the 1184-byte binary report from `outblob`.
2. **Trust Root Configuration (`TrustRoot::ProductionAmd`):**
   * Configure `AttestationVerifier::new(TrustRoot::ProductionAmd { ark_public_keys_sec1 }, policy)` on the key-release service (`P50`) and browser verifier (`P85`) with AMD's pinned Milan/Genoa ARK public keys.
3. **Production Gate Enforcement (`TEE_ATTESTATION_REQUIRED=true`):**
   * Both `gate_execution` (`platform-enclave`) and `EnclavePipeline::attestation_gate` (`platform-connectors`) unconditionally reject `TeePlatform::Simulated` and `TeePlatform::Development` whenever `require_attestation == true`.
   * Conversely, a `KeyReleaseRelyingParty` constructed with `TrustRoot::ProductionAmd` or `require_hardware_sev_snp = true` unconditionally rejects any certificate chain signed by `SimulatedSnp`.

---

## 6. What `SimulatedSnp` + `KeyReleaseRelyingParty` Prove — and What They Do Not

* **What they prove in local Docker and CI:**
  * The 1184-byte binary report serializer/parser (`SnpReport`), ECDSA P-384 SHA-384 signature check (`0x000..0x2A0` with little-endian 72-byte `R`/`S` scalars), `ARK -> ASK -> VCEK` chain validation, CRL serial revocation, certificate expiration, `GuestPolicy` checks (`DEBUG=0`, `MIGRATE_MA=0`), component-wise `TcbVersion` minimum check, constant-time `MEASUREMENT` allowlist check, 64-byte `ReportDataBinding` verification, single-use challenge nonce freshness, HPKE key wrapping (`key-release-v1`), and GCS vault storage (`ObjectStoreVault::new_gcs`) all execute end-to-end across isolated containers on every query.
* **What they do NOT provide:**
  * Host memory encryption. In local Docker, the host OS kernel can inspect container memory. Plaintext protection against a compromised host operator exists only when running on physical AMD SEV-SNP hardware (`TeePlatform::SevSnp`).
