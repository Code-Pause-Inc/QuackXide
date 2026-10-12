# 0004. Key custody and attested key release

* Status: Proposed
* Date: 2026-10-12

## Context

A research query runs on the researcher's request while the steward is
offline, so something other than the steward's browser must be able to
open the steward's dataset, and the operator must not.

Today nothing can. The steward's HPKE private key is generated
non-extractable in the browser and only its public half is exported
(`frontend/src/lib/crypto/core.ts:171-180`); every server-side
`TenantKeypair` is test or development only
(`backend/crates/platform-crypto/src/lib.rs:203-204`). Connector data is
sealed to that public key. `docs/THREAT_MODEL.md` and
`docs/ARCHITECTURE.md` say the steward's key is released into the enclave
for each query, but a non-extractable key cannot be released anywhere,
and no key broker or KMS exists, so a production `EnclaveKeyProvider`
(`backend/crates/platform-api/src/query.rs:37-47`) has nothing to release.
Drive files are wrapped under a browser-only key-encryption key and stay
out of research access; this record does not change Drive.

The operator controls the host, the network, DNS, the object store, the
cloud project's IAM and every value passed to the VM (ADR 0005). Two facts
about GCP bound what attestation can prove there:

* The SEV-SNP launch measurement covers only Google's firmware, and the
  guest chooses REPORT_DATA itself. A report with a valid AMD chain, a
  fresh nonce and a bound key can come from any guest on that firmware,
  including a modified `platform-api`.
* The Google-managed vTPM is software-based
  ([Confidential VM attestation](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/attestation)),
  so a measured-boot quote from it makes Google part of the trusted base.

The key-release mechanism must be off the shelf; this record designs no
key-release protocol.

## Options considered

**How a dataset key reaches an attested workload.**

* (a) A per-dataset data key wrapped both to the steward and to an
  attestation-gated release service: a managed KMS whose policy checks
  attestation, or a key broker in its own Confidential VM.
* (b) Steward-online release: when the steward grants access, their
  browser unwraps the dataset key and re-seals it to an attested enclave
  key. The enclave key is gone after a restart, so stewards must come back
  online, and the browser must handle dataset keys outside the custody
  rules in `core.ts:5-9`. Rejected as the primary path.

**How evidence proves which binary runs.**

1. A vTPM measured-boot quote beside the SNP report. On GCP the vTPM is
   Google's software, and its binding to the SNP report is not documented.
2. A token from the provider's attestation service for a hardened
   workload runtime. On GCP that is Confidential Space: Google's service
   issues a signed token whose claims include the container image digest,
   the image's support status and debug state
   ([token claims](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)).
   Google is trusted for the result. Confidential Space is documented for
   AMD SEV and Intel TDX, not SEV-SNP.
3. A launch-measurement policy over firmware and an image the project
   builds. GCP does not put the guest image in the measurement, so this
   needs another cloud. Rejected for v1.

**The combinations that remain.**

| | A. Confidential Space on TDX + Cloud KMS | C. SEV-SNP + key broker (Trustee) |
| --- | --- | --- |
| Which binary runs | Image digest in Google's token | Not solved on GCP; best is Google's software vTPM (option 1) |
| Who verifies before release | Google's attestation service and Cloud KMS IAM | A broker we run in its own Confidential VM ([Trustee](https://github.com/confidential-containers/trustee), Apache-2.0) |
| Where keys live | KMS; private key never exportable | The broker, which must persist them (wrapped by KMS, so operator IAM again) |
| Trusted | Google (hardware verification, workload identity, key custody); whoever controls the key project's IAM | AMD; Google's vTPM; whoever runs the broker |
| Steward online? | No | No |
| What the team runs | Nothing new | A second Confidential VM, its policy, backups and availability |
| Effect on the plan | Platform moves from SNP to TDX; P47/P48 verify Google's token; P49 publishes an image digest | Smallest |

Who can decrypt when something fails, in both:

* Release service down (KMS or Google's attestation service for A, the
  broker for C): research queries fail closed; stewards still open their
  own data in the browser.
* Steward's device lost: queries keep working; the steward loses direct
  access until a recovery path exists.
* Key policy changed by whoever administers it: that party can authorize
  another image, which then decrypts. Under C this is whoever runs the
  broker, which is the operator.
* Image not on the allowed list, or a debug image: nothing decrypts.

A third combination, Confidential Space on plain AMD SEV, is rejected:
SEV lacks SNP's memory-integrity protection. Google's attestation token
lists no SEV-SNP hardware model for plain Confidential VMs either, so we
found no documented way to gate KMS on attestation while staying on SNP.

## Decision

Option A is recommended. Moving from SEV-SNP to TDX is the maintainer's
decision (open question 1); if SNP stays, option C applies and the
sections below keep their shape with the broker in place of KMS.

**Each dataset has its own data key, wrapped twice.** The dataset is
encrypted under a random data key. The data key is stored beside the
ciphertext, wrapped to the steward's enrolled browser key (so the steward
keeps direct access) and to a Cloud KMS key-encapsulation key of type
X-Wing, the hybrid suite of ADR 0001
([KMS key encapsulation](https://docs.cloud.google.com/kms/docs/key-encapsulation-mechanisms)).
Whoever seals the dataset encapsulates to the KMS key's public half:
the steward's browser for uploads (P38), `connector-worker` for connector
data if P19 keeps it. Encapsulating needs only the public key, never
attestation. The enclave never holds the steward's private key.

**Only an attested workload can decapsulate.** KMS decapsulation is
granted only to a workload identity federation principal whose attestation
token has `swname == CONFIDENTIAL_SPACE`, the `STABLE` support attribute,
the TDX hardware model and an image digest on the allowed list
([granting access](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources)).
The KMS key, the identity pool and that policy live in a key project that
only the maintainer administers, separate from the deployment project;
no deployment identity has IAM on it. This keeps deployers and the
workload's own service account out of the release decision. It does not
keep the maintainer out: `docs/THREAT_MODEL.md` A2 records that the key
project's administrator can authorize another image.

**Release is per query, with nothing cached.** The enclave decapsulates
the data keys a query needs, opens the dataset in memory and drops the
keys when the query ends. Revoking a grant or removing an image digest
takes effect on the next query. The cost is one KMS call per query.

**Freshness and binding.** Key release relies on the freshness of
Google's short-lived token; the project issues no nonce for it. For the
browser (P85), the browser supplies a nonce, and the workload requests a
custom token with its own audience and two nonces: the browser's, and the
SHA-256 digest of the request-decryption public key, the result-signing
public key, the TLS public key hash (P67) and the deployment configuration
digest (ADR 0005). That digest is the binding P14 calls the REPORT_DATA
layout; under option C the same 32 bytes go into REPORT_DATA. The
browser verifies Google's signature, issuer, audience, nonce and claims
before it sends a query. P47's raw-report verifier is not on the release
path under option A.

**The researcher's result key** is generated non-extractable in the
researcher's browser and enrolled (P33). The enclave takes the recipient
public key from the researcher's sealed request, sent after the browser
verified the enclave, and accepts it only if it matches the enrolled
key's fingerprint, so the operator-controlled enrollment record is never
the only source.

**Platform secrets** reach the workload through the same gate: Secret
Manager access is granted only to the attested principal, never to the
VM's service account (ADR 0005).

**`connector-worker`**, if kept, holds only the KMS public key. It can
seal data and cannot open any.

**Settled briefly.**

| Topic | Decision |
| --- | --- |
| Enrollment (P33) | One key per tenant, created once; replacing it is an explicit, audited rotation. |
| Steward loses their device | Queries keep working through the KMS copy; the steward loses direct access. Recovery is out of v1 and documented as a limit; re-wrapping data keys to a new enrolled key inside the enclave is the later path. |
| Revoked grant, changed image | Effective on the next query; no released key outlives a query. |
| Rotation (P77) | New KMS key versions for new datasets; existing data keys re-wrapped inside the enclave. |
| Backup (P76) | Ciphertext and wrapped data keys are backed up from the bucket. The KMS private key cannot be exported; KMS's scheduled-destruction delay and the steward's copy are the fallbacks. |
| Forged grants, budgets or identities | The registries are operator-controlled: A2 residual for v1; signed grants proposed outside v1. |
| Forged or rolled-back snapshots (ADR 0003) | Optional, not scheduled: a KMS signing key behind the same gate lets attested workloads sign manifests, which closes that residual. |
| Served JavaScript | Remains the residual ADR 0005 records; the bundle is inside the image, so the image digest covers it. |

## Consequences

* Google is trusted for hardware verification, workload identity and key
  custody, and the platform is tied to GCP. A2 names this.
* The maintainer, as key-project administrator, can authorize any image.
  A2 records it; break-glass and policy changes are audited (P77).
* P12 picks a TDX machine type; P47 and P48 become verification of
  Google's token; P49 publishes the image digest the policy allows; P50
  wires KMS and workload identity federation; P85 verifies Google's token
  in the browser. P5 records the re-plan.
* Every query makes KMS calls: latency, quota and cost scale with queries.
* Destroying the KMS key leaves only the stewards' copies.
* The storage format changes: each dataset object carries its wrapped
  data keys, under a new frame version beside `HPK1`. Nothing is deployed,
  so no migration is provided.
* On acceptance, `docs/THREAT_MODEL.md` (Assets, A2), `docs/ARCHITECTURE.md`
  (key-release trust boundary, research flow) and `docs/PROJECT_SCOPE.md`
  change to "the data key is released", not "the steward's key".

## Open questions

1. TDX (option A) or SEV-SNP (option C)? Needs P12 phase A: a TDX machine
   type and region available to the project, and its cost.
2. Is Cloud KMS X-Wing generally available? The release notes list X-Wing
   KEM keys and an HPKE option built on X-Wing without a launch stage.
3. Whether KMS opens standard HPKE envelopes itself, or returns a shared
   secret the enclave turns into a wrapping key. ADR 0007 (P17) decides
   the construction; this record only requires X-Wing.
4. How the browser trusts Google's token-signing keys: a key set pinned in
   the release bundle (and refreshed with releases) or fetched from Google
   at run time.
5. The documented nonce size limits disagree (8 to 88 or 10 to 74 bytes);
   a 32-byte digest fits both.
