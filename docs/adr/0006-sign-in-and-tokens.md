# 0006. Sign-in, identity and token signatures

* Status: Accepted
* Date: 2026-10-22

## Context

* ADR 0001 moves signatures to Ed25519 + ML-DSA-65 and keeps the RS256
  verifier "only as long as migration requires". `backend/deny.toml`
  ignores RUSTSEC-2023-0071 because "RS256 is retired by ADR 0001" and no
  network-facing service does RSA private-key operations.
* A managed identity provider issues classical tokens (RS256 or ES256 JWTs),
  and `jsonwebtoken` 10.x has no ML-DSA. No standard JOSE algorithm exists
  for the hybrid.
* The code already describes a platform token service between the provider
  and the API. `TokenType` has `Preauth` ("issued after IdP sign-in, before
  the TOTP challenge"), `Access` and a rotating `Refresh`
  (`backend/crates/platform-auth/src/lib.rs`), minted by `TokenSigner`,
  which "runs on the identity-service signer" (`sign.rs`). That service
  does not exist.
* Nothing models users. Tenants are created only by the Paddle webhook
  (`backend/crates/platform-api/src/admin.rs`), and `TenantRecord`
  (`backend/crates/platform-tenancy/src/lib.rs`) has no members.
  `require_tenant` accepts any validly signed `tid` without checking
  `TenantStatus`, so a suspended tenant keeps access.
* Since Code-Pause-Inc/QuackXide#23 the verifier requires `typ`, and
  `authenticate` (`backend/crates/platform-api/src/lib.rs`) accepts only
  `access` tokens. Any design must keep a pre-MFA token from counting as
  fully authenticated.
* Steward and researcher are grant relationships between tenants
  (`backend/crates/platform-tenancy/src/grants.rs`), not roles.
* `platform-crypto` has a TOTP module, "the platform's mandatory second
  factor" (`totp.rs`). `THREAT_MODEL.md` A3 lists account takeover of a
  steward or researcher as **To build** and does not name administrators.
* ADR 0007 says v1 has no cryptographic migration mode, because nothing
  has been sealed under the classical suites outside development.
* Nothing is deployed and only synthetic data exists.

## Decision

### 1. Provider and topology

* **Provider: Auth0 (Okta).** P13 creates its tenants. The requirements
  were standard OIDC with authorization code + PKCE, a published JWKS,
  exact-match redirect URIs, white-label hosted pages and emails (P29), and
  synthetic test identities on a non-production tenant. Auth0 meets them
  with its documented flow, so the browser sign-in (section 6) uses the
  standard confidential-client design with no provider-specific
  workarounds.
* **Sign-in holds no health data.** Auth0's HIPAA BAA is available only on
  its Enterprise plan. The provider holds only steward, researcher and
  administrator accounts; datasets never reach it. If the sponsor decides
  that sign-in data needs a BAA, this record is revisited.

**Why Auth0.** Keeping the standard sign-in flow outweighs staying in
GCP. Google Cloud Identity Platform (GCIP), the alternative considered,
would keep sign-in inside GCP, but its browser SDK hands the provider's ID
token to the browser. It would need custom replacements for `state`,
`nonce` and the confidential client (a sign-in transaction, `Origin`
checks, an `auth_time` limit and a used-token store): more
security-critical code to build, test and review. GCIP's main advantage,
a BAA on any plan, matters only if health data reaches sign-in, which it
does not.

* **Token exchange, not direct trust.** A platform identity service sits
  between the provider and the API:
  1. The identity service verifies the provider's ID token. Only it fetches
     and refreshes the provider's JWKS, and it does only public-key
     operations on provider material.
  2. It resolves the person to a tenant (section 3) and mints a platform
     `preauth` token.
  3. After the second factor (section 4) it mints `access` and `refresh`.
  4. The API verifies **only platform tokens** (`tid`, `adm`, `typ`) and
     never sees provider tokens.
* Why not direct trust: provider tokens carry no `tid` or `typ`, their MFA
  state differs between providers, and the API would need a second
  verifier plus provider JWKS on every replica. The exchange keeps one
  token format at the API and keeps the token-signature choice (section 2)
  ours rather than the provider's.
* **The identity service is a separate binary in its own Confidential
  VM**, under the same attestation policy as `platform-api`. ADR 0005's
  one-process topology covers only `platform-api` and the query engine, so
  this record places the identity service.
* **Its signing key gets the same protection as data keys.** The key can
  mint a token for any `tid`, with or without `adm`, so it is held in
  Cloud KMS and released only to the attested identity-service workload,
  following option A of ADR 0004 (key custody and attested key release).
  It never resides in an API process or replica, and no operator path
  exports it.
* The API learns the identity service's issuer, audience and verification
  key from the configuration bound into the attestation evidence
  (ADR 0005).

### 2. Token signatures

**Option (a).** The identity service mints platform tokens
signed with hybrid Ed25519 + ML-DSA-65, as ADR 0001 requires.

* The format is not a JWT, since no JOSE algorithm covers the hybrid. The
  format and libraries (RustCrypto `ed25519-dalek` and `ml-dsa`, under
  ADR 0007's definition of established implementations) are fixed in P37.
  A token is valid only if **both** signatures verify.
* Claims are unchanged: `sub`, `tid`, `iss`, `aud`, `exp`, `adm`, `typ`,
  plus `iat` and `jti` (needed for refresh families, section 5).
* ML-DSA-65 signatures are about 3.3 KB, so a token is about 4.5 KB
  encoded. P37 tests a maximum-size token through the router.
* **No classical migration mode.** Following ADR 0007, nothing to migrate
  has been issued outside development, so the API refuses classical-only
  tokens in production. HS256 stays for development and CI only.
* **P37** is the one issue that builds the signer and verifier.
* When P37 lands: RS256 is removed from production, `THREAT_MODEL.md` A4
  ("Forge signatures") and the suite table in `ARCHITECTURE.md` are
  updated, and the `backend/deny.toml` reason is reviewed. No
  network-facing service will do RSA private-key operations, so the
  RUSTSEC-2023-0071 exception stands; the reason text changes only if the
  `rsa` crate stays for development key generation.

**Option (b), not chosen.** A superseding ADR limits hybrid signatures to
long-lived material (keys only an attested workload holds) and keeps
short-lived tokens classical (Ed25519 or RS256). It is simpler and smaller,
justified because a token expiring in minutes gains little from
post-quantum protection. It conflicts with ADR 0001 as written and would
mean A4's "Forge signatures" row is closed by argument rather than code.

### 3. Identity and tenancy

* **One identity, one tenant** in v1. An `IdentityRegistry` maps the
  provider's `(iss, sub)` to one `tid`. Lookup is by `(iss, sub)` only;
  email is never used as a key, since it can change or be reassigned.
* Steward and researcher **stay grant relationships**. No role claims are
  added to tokens.
* **Tenants without Paddle.** An administrator provisions a researcher or
  non-paying tenant through the admin API, which creates the
  `TenantRecord` (with no subscription) and the identity mapping, and
  emits an audit event. Paddle-created tenants get their identity mapping
  the same way, linked by the subscription's customer. Self-service
  sign-up without a Paddle subscription or admin invitation is refused:
  an unknown identity gets no `preauth` token.
* **`adm`** comes only from a server-side allowlist in the identity
  registry, keyed by `(iss, sub)`. Never from a provider attribute, group
  or claim the user or a provider tenant admin can edit.
* **Suspended or unknown tenants are refused**, at the exchange and at
  `require_tenant` / `require_admin` (403 with an `auth.decision` event,
  fail closed if no registry is configured; built in P29). Reactivation is
  an audited admin action.
* Multi-member tenants and invitations are out of scope for v1.

### 4. Second factor

* **The platform's TOTP**, enforced by the identity service
  between `preauth` and `access`. It is provider-independent, the code
  exists, and it gives one place to audit the factor. Provider MFA would
  also need the identity service to require and check an MFA claim
  (`amr`/`acr`), whose meaning varies by provider, so Auth0's MFA is not
  used.
* **Everyone needs it:** stewards, researchers and administrators. An
  `adm` access token is never issued without it. `THREAT_MODEL.md` A3 is
  updated to say so. Passkeys (WebAuthn) for administrators may follow in
  v1.1.
* **Storage** (the `IdentityRegistry` trait, in-memory in P29 and P30,
  durable in P63): TOTP secrets, AEAD-encrypted at rest under a key from
  configuration; the last accepted step per user (replay protection);
  failed-attempt counters; refresh-token families.
* **Recovery** is an audited administrator reset only in v1; one-time
  recovery codes are not issued. The reset requires an out-of-band check
  of the person's identity, and no administrator can reset their own
  account, so at least two administrators must exist at all times. The
  procedure is documented in the runbook.

### 5. Session

| Token | Lifetime | Notes |
| --- | --- | --- |
| `preauth` | 5 minutes | Single use; good only for the second-factor step |
| `access` | 10 minutes | Bearer token for API calls |
| `refresh` | Rotates on every use; 30-minute idle limit, 12-hour absolute limit | Reuse of a rotated token revokes the whole family |

* Sign-out and administrator disable revoke the refresh family
  immediately. An access token stays valid until its short expiry; no
  per-request revocation check in v1.
* Every refusal emits `auth.decision`.
* **In the browser** the access token is held in memory only and passed to
  the crypto worker (P31). Never `localStorage`, `sessionStorage` or
  IndexedDB.
* **The refresh token** is held by the browser in an `HttpOnly`, `Secure`,
  `SameSite=Strict` cookie scoped to the identity service's refresh path,
  so a page reload does not force a new sign-in and script cannot read it.
  Because that endpoint is cookie-authenticated, it also checks `Origin`
  against an exact allowlist and requires a custom request header (CSRF
  defence). API calls themselves stay bearer-only, so they need no CSRF
  defence.
* The identity service and the app are served from the same site, so the
  `SameSite=Strict` refresh cookie is sent on refresh requests.

### 6. Browser sign-in flow

* OAuth 2.0 / OIDC **authorization code with PKCE (S256)**, using Auth0's
  hosted Universal Login page. The implicit and hybrid flows are not used.
* **The identity service is a confidential client** and runs the code
  exchange, with a maintained OIDC library or Auth0's server SDK. The
  browser only follows redirects. No provider token ever reaches the
  browser, and no hand-written OAuth runs in the frontend.
* The identity service generates the single-use `state`, the OIDC `nonce`
  and the PKCE verifier. It keeps them server-side for the sign-in
  transaction (at most 10 minutes), keyed by a random transaction id in an
  `HttpOnly`, `Secure`, `SameSite=Lax` cookie bound to that one sign-in.
  On callback it checks `state` (the login-CSRF defence), consumes it, and
  checks `nonce` in the ID token. Replayed or unknown values are refused.
* Redirect URIs are exact-match, registered per environment in Auth0
  (P13).
* No access, ID or refresh token is ever placed in a URL, fragment or
  browser history. After the callback, the browser makes a `fetch` that
  returns the `preauth` token in the response body, and the refresh token
  is set as the cookie described in section 5.
* If Auth0's server SDK hides `state`, `nonce` or PKCE, the PR adopting it
  shows how it gives equivalent login-CSRF, replay and audience binding.

## Consequences

* Auth0 is a second vendor outside GCP. Separate development, staging
  and production tenants need at least the Essentials plan (the Free plan
  has one tenant). Auth0's hosted pages and emails are configured with the
  public brand (P29).
* A new identity-service binary exists (P29) in its own attested
  Confidential VM, and holds the only token signing key, released by
  Cloud KMS only to that workload. Its key custody is documented for
  deployment (P68, P77).
* The API keeps one verifier and one token format. Provider changes stay
  inside the identity service.
* Tokens grow to about 4.5 KB. Headers, proxies and the
  router must accept them (tested in P37).
* `JwtVerifier`/`RawClaims` cannot verify provider tokens unchanged; the
  exchange gets its own provider verifier (P29).
* The identity registry becomes security-critical state that must be
  durable (P63) and is backed up with the tenant registry.
* A refresh cookie means one cookie-authenticated endpoint, which needs
  the CSRF checks above and tests for them.
* Issues that implement this record: P13 (provider tenants and
  identities), P28 (production verification from configuration), P29
  (exchange, membership, `adm` allowlist, refusing suspended tenants),
  P30 (second factor and session lifecycle), P31 (token in the crypto
  worker), P32 (frontend sign-in, sign-out, refresh), P37 (hybrid
  signatures), P63 (durable identity and session stores).
* `docs/ARCHITECTURE.md` documents the resulting authorization model,
  and `docs/THREAT_MODEL.md` A3 and A4 are updated to match.
