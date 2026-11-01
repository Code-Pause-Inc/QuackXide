# Simulated TEE to Google Cloud Confidential Computing — Developer Guide

This document maps each component of the local simulated TEE to its production counterpart. Production is a Confidential Space workload on Intel TDX with Cloud KMS (ADR 0004). The simulation issues Confidential Space-shaped attestation tokens and checks them with the production verifier and release policy, so dev and CI exercise the evidence path production runs. Everything simulated is development-only and built only with the `dev` feature (`platform-enclave`'s `simulated`).

---

## 1. Component-by-Component Mapping: Simulation vs. Production

| QuackXide Component | What It Does in Local Simulation (`TeePlatform::Simulated`) | Production Counterpart (ADR 0004) |
| --- | --- | --- |
| **`sim-attestation` (`TokenSigner`, `bin/sim-attestation.rs`)** | Signs RS256 tokens with a throwaway RSA-2048 key generated at start, with Google's claim layout: `iss`, `aud`, `exp`, `nbf`, `eat_nonce`, `hwmodel`, `swname`, `dbgstat`, `submods.confidential_space.support_attributes`, `submods.container.image_digest`. `GET /jwks` publishes the key set. | Google's attestation service, which verifies the TDX quote and signs the token ([token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)). |
| **`SimulatedTokenProvider` (`AttestationProvider`)** | Requests a token from `sim-attestation` with `POST /v1/token {audience, nonces, token_type: "OIDC"}`, and verifies its own tokens with `TokenVerifier` (dev gates). | A Confidential Space provider (P48) requesting the token from the launcher (`/run/container_launcher/teeserver.sock`) with the same request shape. |
| **`TokenVerifier` (`platform_enclave::token`)** | The production verifier: RS256 only; issuer, audience, `exp`/`nbf` (60 s leeway), nonces; `hwmodel == GCP_INTEL_TDX`, `swname == CONFIDENTIAL_SPACE`, `dbgstat == disabled-since-boot`, `STABLE`, allowed image digest. | The same code, given Google's key set (ADR 0004 open question 3) and the image digests P49 publishes. |
| **Nonces (`ReportDataBinding`)** | Two 32-byte nonces, base64url: the freshness nonce, and `SHA-256(tag ‖ enclave_hpke_pk ‖ result_signing_pk ‖ tls_cert_sha256 ‖ config_digest)`. | The same binding (ADR 0004, "Freshness and binding"). |
| **`SIM_TOKEN_DBGSTAT`, `SIM_TOKEN_IMAGE_DIGEST`, `SIM_TOKEN_HWMODEL`** | Change the claims `sim-attestation` signs, to prove refusals. | A debug Confidential Space image, a different image, or other hardware. |
| **`EnclaveIdentity` (`platform-api::key_release`)** | Ephemeral in-RAM HPKE keypair generated at process start; the private key never leaves process memory. | The same key generation inside the TDX guest, whose memory TDX encrypts. |
| **`GET /api/v1/attestation?nonce_b64=...`** | Returns the token bound to the caller's nonce and the enclave's keys, plus the public keys. | The same endpoint, returning Google's token for the browser (P85). |
| **`KeyReleaseRelyingParty` (`bin/key-release.rs`, dev only)** | Issues single-use 60 s challenge nonces, verifies the token with `TokenVerifier` against the `sim-attestation` key set (refetched at most every 5 s on an unknown key id), and HPKE-seals the tenant private key (`key-release-v1\|{tenant_id}\|{nonce_b64}`) to the enclave's HPKE key. Tenant keys are enrolled over plain HTTP (`PUT /v1/keys`). | Cloud KMS in the maintainer's key project. Each dataset's data key is wrapped to a KMS X-Wing key, and KMS decapsulates only for a workload identity federation principal whose token meets the release policy (P50). |
| **`AttestedKeyProvider` & `ReleasedKeySession` (dev only)** | Challenge, token and HPKE unwrap **once per query**, holding the tenant key in RAM for the query and zeroizing it on `Drop`. | A production `EnclaveKeyProvider` asking KMS to decapsulate the data keys a query needs, once per query, with nothing cached (P50). |

---

## 2. How Workload Identity Works on Google Cloud

A Confidential VM's launch measurement covers Google's firmware, not the container on it, so a raw hardware report cannot prove which `platform-api` image runs. Confidential Space closes that gap, which is why ADR 0004 chose it:

* **Host VM image:** `projects/confidential-space-images/global/images/family/confidential-space` on an Intel TDX machine type that P12 confirms (`confidential-space-debug` only for development; its tokens report debug and never pass the release policy).
* **How the image is measured:** the launcher pulls the workload image by digest, applies its launch policy (`tee.launch_policy.*` labels on the production image from P49), and Google's attestation service puts the image digest and policy in the token.
* **How `platform-api` uses it:** it requests a token with its own audience and nonces from the launcher (P48). The token is what the gates, KMS and the browser verify.

---

## 3. Key Release: Simulation vs. Cloud KMS

```
enclave-api                      sim-attestation              key-release-service
───────────                      ───────────────              ───────────────────
1. POST /v1/challenge ───────────────────────────────────────▶ single-use 32-byte nonce (60 s)
2. binding = nonce ‖ SHA-256(tag ‖ keys ‖ config)
3. POST /v1/token ─────────────▶ signs RS256 token with
   {audience, nonces}              the binding as eat_nonce
                 ◀────────────────
4. POST /v1/release {tenant, token, public keys} ────────────▶ consumes the nonce, recomputes the binding,
                                                               TokenVerifier + release policy,
                                                               seals the tenant key to the enclave HPKE key
5. unwraps in RAM → decrypts the snapshot → query → zeroizes
```

The stand-in releases the whole tenant key; production releases per-dataset data keys through KMS (P50), so data-key handling is not exercised until then.

### Production: Confidential Space + Workload Identity Federation + Cloud KMS

ADR 0004 requires an off-the-shelf release mechanism, so production uses no QuackXide release service. In the key project, which only the maintainer administers (P12, P50):

1. Create a **Workload Identity Pool** and an OIDC provider trusting `https://confidentialcomputing.googleapis.com`.
2. Attach an **Attribute Condition** that enforces Intel TDX, a production Confidential Space image with debug disabled, and an allowed `platform-api` image digest:
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

`Dockerfile` and `docker-compose.simulated-tee.yml` package the simulation into a local Docker topology verified by `scripts/test-simulated-tee.sh`. All images are built with the `dev` feature and are never deployed; the production image is P49's, in `deploy/`.

```
                  Host / Browser Client
                            │ HTTP :8080 (public_net)
                            ▼
┌───────────────────────────────────────────────────────┐
│  enclave-api (simulated workload, uid 65532)          │
│  - read_only rootfs, cap_drop: [ALL]                  │
│  - SimulatedTokenProvider → sim-attestation           │
└──────────┬──────────────────┬─────────────────────────┘
           │ enclave_internal_net (internal: true)
           ▼                  ▼
┌──────────────────┐ ┌──────────────────┐
│ sim-attestation  │ │ key-release-     │
│ (Google's part)  │ │ service (KMS     │
│ /v1/token, /jwks │ │ stand-in)        │
└──────────────────┘ └──────────────────┘
```

`enclave-api` keeps sealed snapshots in the in-memory vault. `fake-gcs-server` 1.49.3 routes `object_store` 0.13's simple uploads (`PUT /{bucket}/{object}`) to its JSON upload handler and refuses them, so the stack has no storage emulator; the GCS client is covered by `platform-storage`'s tests against local fake servers.

`setup_net` (not internal) connects `key-release-service` and `sim-attestation` to `127.0.0.1` ports, only so the test script can enroll a tenant key and wait for the simulator: Docker publishes no ports for containers that are only on an internal network.

| Simulated TEE Component | Production Equivalent | How the Simulation Relates to Production |
| :--- | :--- | :--- |
| **`enclave-api` (`Dockerfile` target `enclave-api`)** | **Confidential Space workload** on an Intel TDX Confidential VM, from the production image (P49) | Runs `platform-api` built with the `dev` feature as non-root with `read_only: true`, `cap_drop: ["ALL"]` and `no-new-privileges:true`. The production image is built without `dev`. |
| **`sim-attestation` (target `sim-attestation`)** | **Google's attestation service** | Issues the token format and claims production verifies; its key is throwaway, so a verifier holding Google's keys refuses its tokens. |
| **`key-release-service` (target `key-release`)** | **Cloud KMS + Workload Identity Federation** in the maintainer's key project | Checks the same claims as the attribute condition above before release. Holds tenant private keys itself; production KMS holds a non-exportable key and per-dataset data keys are wrapped to it. |
| **`enclave_internal_net` (`internal: true`)** | **VPC Service Controls perimeter + Private Google Access** | Keeps enclave-to-KMS and enclave-to-storage traffic off the public ingress network (`public_net`). |

### Running the Local Simulated TEE Verification Suite

```bash
./scripts/test-simulated-tee.sh
```

It runs five stages:
1. Builds every image and starts `sim-attestation` and `key-release-service`.
2. Enrolls a tenant key (`PUT /v1/keys`, which returns the public key).
3. Starts `enclave-api`, which seals the synthetic QuickBooks fixture into its in-memory vault under the tenant's public key.
4. Checks that `GET /api/v1/attestation` returns a token and that `POST /api/v1/query` returns rows after token-gated key release.
5. Restarts `sim-attestation` with a debug image, an unlisted image digest and non-TDX hardware in turn, and requires `HTTP 503` each time; then restores the default claims and requires `HTTP 200`.

---

## 5. From the Simulation to Production

The production path is built by its own plan items, not by pointing the simulation at hardware:

1. **Token acquisition and verified gates (P48):** a Confidential Space provider requesting tokens from the launcher; the gates act on the verified token. The verifier (P47) is already shared with the simulation.
2. **Key release (P50):** Cloud KMS behind workload identity federation, as in Section 3.
3. **Production gate enforcement (`TEE_ATTESTATION_REQUIRED=true`):** both gates reject `TeePlatform::Simulated` and `TeePlatform::Development`. A build without `dev` has no simulator, and when attestation is not required it refuses every attestation.

---

## 6. What the Simulation Proves — and What It Does Not

* **What it proves in local Docker and CI:** the token format and claims, the RS256 verifier with its algorithm allowlist, issuer, audience, validity and nonce checks, the release policy (TDX, Confidential Space, debug disabled, `STABLE`, image digest), the key-set refetch after a simulator restart, single-use challenge nonces, HPKE key wrapping (`key-release-v1`) and once-per-query key sessions, end to end across isolated containers.
* **What it does not provide:**
  * Host memory encryption. In local Docker the host can read container memory. Protection from a compromised host exists only on Intel TDX hardware under Confidential Space.
  * Real hardware evidence: the TDX quote and its verification by Google are outside the simulation, and Google's own key set is not used.
  * Per-dataset data keys: the stand-in releases whole tenant keys (P50).
