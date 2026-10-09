# 0005. Query and deployment topology

* Status: Proposed
* Date: 2026-10-07

## Context

Data, SQL text and results may be plaintext only in the user's browser and
inside the attested Confidential VM. Queries run inside the `platform-api`
process today: `ConnectorQueryService` sits on the same Axum router
(`platform-api/src/lib.rs:266-268`) and gates on that process's own SEV-SNP
probe. `platform-api` serves plain TCP (`main.rs:72-76`), the API has no
CORS layer, and configuration is read from the process environment and an
always-loaded `.env` (`platform-config/src/lib.rs:148`). `docs/PROJECT_SCOPE.md`
speaks of "the API and enclave workers" without saying where the process
boundary is, what terminates TLS, or how far the operator's settings are
trusted inside the VM.

The operator controls the host, the network, DNS, the object store, the
cloud project's IAM, and every value passed to the VM: environment
variables, `.env`, instance metadata and startup scripts. An attestation
report proves which image runs, not which settings it was given.

## Decision

**One process.** `platform-api`, with the query engine in-process, runs
inside an AMD SEV-SNP Confidential VM. The attested boundary is the VM.

**A planned edge/worker split, not built in v1.** A split into an HTTP edge
and a query worker isolates anything only if the worker itself verifies the
token, checks the grant, charges the budget, runs the attestation and
disclosure gates, holds every released and enclave key, and receives queries
sealed by the browser and returns results sealed to the researcher. The edge
then holds only bearer tokens and ciphertext. To keep that step mechanical,
the keys and sealing built for sealed queries and results stay behind
`ConnectorQueryService`, and nothing outside it holds them.

**TLS terminates inside the VM, in `platform-api`.** The stack is `rustls`
0.23 (Apache-2.0 OR ISC OR MIT) with `tokio-rustls` 0.26 (MIT OR
Apache-2.0), both already in `backend/Cargo.lock`. The certificate is obtained by
ACME from inside the VM with `instant-acme` 0.8 (Apache-2.0), built with
`default-features = false` and the `ring` and `hyper-rustls` features so
the backend keeps one crypto provider. `platform-api` generates the TLS
private key itself; it never leaves the process, and its public-key hash is
bound into the attestation evidence. A load balancer in front of the VM, if
any, passes TCP through and holds no certificate. No proxy runs in the
image.

**Same origin.** The frontend bundle is served by `platform-api` from
inside the measured image, on the API's origin. The API has no CORS
allowlist.

**`connector-worker` follows the scope decision on connector ingestion.**
If live ingestion is deferred from v1, `connector-worker` is not deployed
and is not part of this topology. If it is kept, it runs in its own
Confidential VM under the same attestation policy and passes the
attestation gate before it seals anything. This record keeps only the
chosen branch when it is accepted.

**The operator's settings are untrusted.** Everything the operator can set
is untrusted input. Configuration may tighten a security control, never
loosen it. Each security-relevant setting is one of:

* a constant in code;
* bounded in code, so configuration can only tighten it (as the minimum
  cohort size has a floor that configuration cannot lower); or
* part of a deployment configuration whose digest is bound into the
  attestation evidence, so a verifier sees exactly what the VM was given.

This covers the attestation requirement, the ZK gate, the minimum cohort
size, the default query budget, the token issuer, audience and
verification-key source, the attestation policy values, and the key-release
endpoint. One image serves every deployment; deployments differ only in
that bound configuration.

The environment may carry only values that point at things the operator
already controls: the bind address, the domain, the cloud project, the
storage bucket, the log filter, and the brand strings. A wrong value can
cause an outage but cannot weaken a control.

Secrets reach the VM only by release to the attested workload, through the
same attested path that releases data keys. A secret store that the VM's
service account reads under ordinary IAM does not qualify, because the
operator controls that IAM. A release build cannot enter development mode,
and `.env` is never loaded in production.

## Consequences

* "The API" and "the enclave" are the same process in v1. Wherever the docs
  say a result or query is plaintext only inside the enclave, they mean the
  `platform-api` process inside the attested VM.
* A memory-safety or logic bug in the HTTP edge or its dependencies runs in
  the process that holds plaintext and keys. The VM boundary contains the
  operator, not our own bugs. The edge/worker split is the upgrade path.
* `platform-api` owns ACME issuance and renewal and a TLS accept loop in
  place of `axum::serve`. A renewed key changes the attested TLS key hash.
* The operator controls DNS and can obtain another publicly trusted
  certificate for the domain. The controls are Certificate Transparency
  monitoring and the browser's check of the attested TLS key, and
  `docs/THREAT_MODEL.md` records the residual when the TLS edge is built.
* The image carries the frontend bundle and no TLS proxy.
* The production-mode mechanism must make development mode unreachable in
  a release build, for example by compiling the development paths out. A
  switch read from the environment alone does not satisfy this record.
* The attestation evidence must carry the digest of the deployment
  configuration, and the browser and the key-release check must know what
  digest to expect for a deployment. The evidence layout and that check
  are decided with key custody (ADR 0004).
* Configuration keys that today loosen a control from the environment
  (`TEE_ATTESTATION_REQUIRED`, `FEATURE_ZK_ENABLED`,
  `RESEARCH_DEFAULT_QUERY_BUDGET`, `JWT_ISSUER`, `JWT_AUDIENCE`) move into
  the bound configuration or are refused in production.
* The deployment procedure takes verification keys, attestation policy
  values and secrets only in the forms above, never from the host
  environment or a plainly IAM-readable secret store.
