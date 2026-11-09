# 0005. Query and deployment topology

* Status: Proposed
* Date: 2026-10-07

## Context

Data, SQL text and results may be plaintext only in the user's browser and
inside the attested Confidential VM. Queries run inside the `platform-api`
process today: `ConnectorQueryService` sits on the same Axum router
(`platform-api/src/lib.rs:413-416`) and gates on that process's own
attestation evidence (`gate_execution`, `platform-enclave/src/lib.rs:180`).
No hardware provider passes that gate yet; only the development-only
simulated TEE does (P84), and acquiring Google's token on TDX is P48.
`platform-api` serves plain TCP (`main.rs:145-147`), the API has no
CORS layer, and configuration is read from the process environment and an
always-loaded `.env` (`platform-config/src/lib.rs:200`). `docs/PROJECT_SCOPE.md`
speaks of "the API and enclave workers" without saying where the process
boundary is, what terminates TLS, or how far the operator's settings are
trusted inside the VM.

The operator controls the host, the network, DNS, the object store, the
cloud project's IAM, and every value passed to the VM: environment
variables, `.env`, instance metadata and startup scripts. On GCP the
launch measurement covers only Google's firmware, so ADR 0004 proves which
image runs through the image digest in Google's Confidential Space token.
That digest does not show which settings the image was given.

## Decision

**One process.** `platform-api`, with the query engine in-process, runs
as a Confidential Space workload on an Intel TDX Confidential VM
(ADR 0004). The attested boundary is the VM; which binary runs in it is
proven by the image digest in Google's attestation token. ADR 0006's
identity service runs in its own Confidential VM under the same
attestation policy; this record covers only `platform-api`.

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
inside the image, on the API's origin. The API has no CORS allowlist.

**`connector-worker` follows the scope decision on connector ingestion.**
If live ingestion is deferred from v1, `connector-worker` is not deployed
and is not part of this topology. If it is kept, it runs in its own
Confidential VM under the same attestation policy and passes the
attestation gate before it seals anything. It holds no tenant private key
and never reads object contents: its service account may only list,
create and delete objects under `tenants/{t}/connectors/`, which is what
ADR 0003's snapshots, manifests and pruning need. It seals to the KMS
public key only, taken from the attested deployment configuration
(ADR 0004), never to a tenant key or from the environment: a steward copy
would need the steward's key from the operator-controlled enrollment
record, and a substituted key would let the operator open the data. Source
credentials are secrets and reach it only by attested release, like every
other secret. This record keeps only the chosen branch when it is
accepted.

**The operator's settings are untrusted.** Everything the operator can set
is untrusted input. Configuration may tighten a security control, never
loosen it. Each security-relevant setting is one of:

* a constant in code;
* bounded in code, so configuration can only tighten it (as the minimum
  cohort size has a floor that configuration cannot lower); or
* part of the deployment configuration, which reaches the workload as
  container environment variables. Google's token lists those
  (`submods.container.env`), and key release and the browser both check
  them, so a verifier sees exactly what the VM was given.

This covers the attestation requirement, the ZK gate, the minimum cohort
size, the default query budget, the token issuer, audience and
verification-key source, the attestation policy values, and the key-release
endpoint. One image serves every deployment; deployments differ only in
that deployment configuration.

Outside the deployment configuration, the environment may carry only
values that point at things the operator already controls (the bind
address, the domain, the cloud project, the storage bucket, the registry
store's address, the log filter, and the brand strings) and values bounded
in code, which it can only tighten. A wrong value can cause an outage but
cannot weaken a control.

**The image fixes what the operator may override.** Its Confidential Space
launch policy labels, covered by the image digest, are:

* `tee.launch_policy.allow_env_override` lists exactly the names this
  record lets the environment carry (the deployment configuration and the
  values above that point at things the operator controls);
* `tee.launch_policy.allow_cmd_override` is `false`, so the operator cannot
  replace the command; and
* `tee.launch_policy.log_redirect` and
  `tee.launch_policy.monitoring_memory_allow` stay `debugonly`, so the
  production image refuses log redirection and memory monitoring.
  Capability, cgroup and mount overrides stay off.

Without this policy, "a verifier sees exactly what the VM was given" would
not hold: the operator could set names outside the list, or run another
command in the same image.

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
  certificate for the domain, then terminate TLS outside the VM. Checking
  the attested application keys and checking the TLS connection are
  separate:
  * The browser verifies the attestation evidence, seals each query to the
    application keys it binds, and accepts results only under them (P85).
    These checks run in JavaScript the server delivers, and browser
    JavaScript cannot inspect its own TLS connection. They do not show
    that the browser reached the attested VM, and an operator who
    intercepts TLS can serve JavaScript that skips them.
  * A client that sees the TLS handshake checks the endpoint's key against
    the attested TLS key hash: P85's independent command-line checker,
    which also checks the digest of the served frontend bundle.
    Certificate Transparency monitoring detects the second certificate.

  Against that operator, bearer tokens, SQL text, results and the frontend
  bundle depend on TLS reaching the VM, and the served JavaScript remains
  trusted. The checker and Certificate Transparency monitoring detect the
  interception; nothing here prevents it. `docs/THREAT_MODEL.md` records
  this residual when the TLS edge is built.
* The image carries the frontend bundle and no TLS proxy.
* The production-mode mechanism must make development mode unreachable in
  a release build, for example by compiling the development paths out. A
  switch read from the environment alone does not satisfy this record.
* Key release checks the deployment configuration as well as the image.
  The key project's release condition (ADR 0004) also requires the
  deployment's expected configuration values in `submods.container.env`,
  so an allowed image given another configuration gets no keys. This adds
  to ADR 0004's condition and removes nothing from it. How the condition
  expresses the configuration (each value, or one canonical value) is
  settled in P50.
* The browser checks the same configuration by policy. It reads the named
  configuration keys from the token's `submods.container.env`, the same
  names the KMS release condition pins (P50), and refuses a value outside
  what the frontend accepts (for example, the attestation requirement or
  the ZK gate turned off, or a minimum cohort size below its floor). There is
  no per-deployment digest to compare against: one frontend image serves
  every deployment, so there is no trusted place to publish one.
* Configuration keys that today loosen a control from the environment
  (`TEE_ATTESTATION_REQUIRED`, `FEATURE_ZK_ENABLED`,
  `RESEARCH_DEFAULT_QUERY_BUDGET`, `JWT_ISSUER`, `JWT_AUDIENCE`) move into
  the deployment configuration or are refused in production.
* The deployment procedure takes verification keys, attestation policy
  values and secrets only in the forms above, never from the host
  environment or a plainly IAM-readable secret store.
