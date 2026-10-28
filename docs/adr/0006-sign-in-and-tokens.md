# 0006. Sign-in, identity and token signatures

* Status: Proposed
* Date: 2026-10-22

> **Draft.** Items marked **[Maintainer decision]** are open and need
> @AxolDad. The text around them gives the recommended answer so the
> record can be accepted once they are filled in.

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

* **Provider: [Maintainer decision]** — the managed OIDC provider (P13
  creates its tenants). Requirements for the choice: standards OIDC with
  authorization code + PKCE, a published JWKS, exact-match redirect URIs,
  white-label hosted pages and emails (P29), and synthetic test identities
  on a non-production tenant. The two candidates are compared below.

#### Provider options

Prices and plan terms were checked on 2026-10-27 and may change.

| | Google Cloud Identity Platform (GCIP) | Auth0 (Okta) |
| --- | --- | --- |
| Hosting | Google Cloud, same project and billing as the SEV-SNP environment (P12) | Separate vendor (Okta) outside GCP |
| HIPAA BAA | Listed as a covered service under the Google Cloud BAA | Add-on to the Enterprise plan only |
| Free allowance | First 50,000 monthly active users free for email, phone and social sign-in; OIDC/SAML federation free for the first 50 per project, then $0.015 each | Free plan up to 25,000 monthly active users, 1 tenant |
| Paid plans | Pay per user above the free tier; SMS for MFA billed per message (US $0.01) | Essentials $35/month, Professional $240/month, Enterprise custom |
| Test environments | A separate GCP project per environment | 1 tenant on Free, 3 on Essentials, separate dev and prod environments from Essentials |
| Sign-in pages | Built with Google's Firebase/Identity Platform SDK and UI library rather than a provider-hosted login page | Provider-hosted Universal Login page, customizable, with a custom domain |
| Fit with section 6 | Section 6b: the browser SDK signs in and posts the GCIP ID token once to the identity service, with a sign-in transaction, `Origin` checks and replay limits in place of `state` and `nonce`. P13 confirms whether a standard authorization-code endpoint exists (then 6a applies) | Section 6a: standard authorization code + PKCE, with the identity service as the confidential client |
| Main trade-off | Stays in GCP with the BAA available at no plan upgrade, but may require changing the browser flow | Least setup and standard OIDC, but the BAA needs the Enterprise plan |

Both issue classical JWTs with a published JWKS, so the exchange design
and section 2 are unaffected by the choice. Either way, the platform's own
TOTP (section 4) is the second factor, so provider MFA features are not
required.

Questions that decide between them:

1. Will real protected health information ever reach sign-in, so a BAA is
   required? If yes, GCIP, or Auth0 Enterprise.
2. Must every service run inside GCP?
3. What monthly budget is available for identity?
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
* Deployment of the identity service (separate binary or module in the
  API process) follows ADR 0005. **[Maintainer decision]** if ADR 0005 does
  not already settle it. Its signing key never resides on an API replica.

### 2. Token signatures

**Recommended: option (a).** The identity service mints platform tokens
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

**Alternative: option (b).** A superseding ADR limits hybrid signatures to
long-lived material (keys only an attested workload holds) and keeps
short-lived tokens classical (Ed25519 or RS256). It is simpler and smaller,
justified because a token expiring in minutes gains little from
post-quantum protection. It conflicts with ADR 0001 as written and would
mean A4's "Forge signatures" row is closed by argument rather than code.

**[Maintainer decision]** — confirm (a), or choose (b).

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

* **Recommended: the platform's TOTP**, enforced by the identity service
  between `preauth` and `access`. It is provider-independent, the code
  exists, and it gives one place to audit the factor. Provider MFA would
  also need the identity service to require and check an MFA claim
  (`amr`/`acr`), whose meaning varies by provider.
  **[Maintainer decision]** — confirm, or choose provider MFA checked
  through a required claim at the exchange.
* **Everyone needs it:** stewards, researchers and administrators. An
  `adm` access token is never issued without it. `THREAT_MODEL.md` A3 is
  updated to say so.
* **Storage** (the `IdentityRegistry` trait, in-memory in P29 and P30,
  durable in P63): TOTP secrets, AEAD-encrypted at rest under a key from
  configuration; the last accepted step per user (replay protection);
  failed-attempt counters; refresh-token families.
* Recovery: one-time recovery codes stored hashed, or an audited
  administrator reset. **[Maintainer decision]**; recommended: audited
  administrator reset only for v1, documented in the runbook.

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
  defence. **[Maintainer decision]** if a reload should instead force a
  fresh sign-in (refresh token in memory only).

### 6. Browser sign-in flow

The flow depends on the provider chosen in section 1: 6a applies to Auth0
and 6b to Google Cloud Identity Platform (GCIP). These rules hold for both:

* No hand-written OAuth or OIDC code in the frontend or the identity
  service; only the provider's maintained SDK or a maintained OIDC library.
* The implicit and hybrid flows are not used.
* Redirect URIs and authorized domains are exact-match, registered per
  environment (P13).
* No access, ID or refresh token is ever placed in a URL, fragment or
  browser history.
* The platform `preauth` token is returned in a response body, and the
  refresh token is set as the cookie described in section 5.

#### 6a. Auth0: the identity service is a confidential client

* OAuth 2.0 / OIDC **authorization code with PKCE (S256)**, using Auth0's
  hosted Universal Login page.
* **The identity service runs the code exchange.** The browser only
  follows redirects. No provider token ever reaches the browser.
* The identity service generates the single-use `state`, the OIDC `nonce`
  and the PKCE verifier. It keeps them server-side for the sign-in
  transaction (at most 10 minutes), keyed by a random transaction id in an
  `HttpOnly`, `Secure`, `SameSite=Lax` cookie bound to that one sign-in.
  On callback it checks `state` (the login-CSRF defence), consumes it, and
  checks `nonce` in the ID token. Replayed or unknown values are refused.
* After the callback, the browser makes a `fetch` that returns the
  `preauth` token in the response body.

#### 6b. GCIP: the browser SDK signs in, the identity service exchanges

GCIP sign-in runs through Google's Identity Platform (Firebase Auth) web
SDK, which handles the provider redirect, `state` and PKCE itself and
gives the browser a GCIP ID token. P13 confirms whether GCIP also offers a
standard authorization-code endpoint the identity service could call as in
6a; if so, 6a is used instead. Otherwise:

* **SDK set-up.** The SDK uses in-memory persistence
  (`inMemoryPersistence`), so the GCIP session is not written to
  IndexedDB or `localStorage`. For redirect-based sign-in, the SDK's
  `/__/auth/` handler is served from the app's own domain (a transparent
  proxy to the project's auth domain, per Google's guidance for browsers
  that block third-party storage), so it works without third-party
  cookies and the redirect URI is on our domain.
* **Start of sign-in.** Before calling the SDK, the page asks the identity
  service for a single-use sign-in transaction. The service sets its id in
  an `HttpOnly`, `Secure`, `SameSite=Strict` cookie, valid for at most 10
  minutes.
* **Exchange.** The page sends the GCIP ID token once, in a `POST` body,
  to the identity service's exchange endpoint, then signs out of the SDK
  and drops the token. The endpoint requires the transaction cookie, an
  `Origin` exactly matching the app's origin, and a custom request header,
  and it consumes the transaction. This stands in for `state` and `nonce`:
  another site cannot make the victim's browser exchange the attacker's
  token (login CSRF), and a token can be exchanged only inside a sign-in
  the page itself started.
* **Verification at the exchange** (P29), as Google documents for ID
  tokens: `alg` is RS256 and `kid` matches one of Google's published
  securetoken public keys (fetched and refreshed only here); `iss` is
  exactly `https://securetoken.google.com/<project-id>`; `aud` is exactly
  the project id; `exp` is in the future and `iat` in the past, with a
  bounded clock skew; `sub` is non-empty and is the user id used as the
  registry key. In addition, `auth_time` must be within the last 5
  minutes, so an older GCIP token cannot start a platform session, and
  each `(sub, iat)` pair is accepted once, so a replayed token is refused.
* **What differs from 6a.** The GCIP ID token is briefly held by the
  browser, in memory only. The controls above give the login-CSRF, replay
  and audience binding that `state`, `nonce` and a confidential client
  give in 6a. The ID token is never sent to `platform-api`.
* GCIP's own MFA is not used; the platform's TOTP (section 4) still runs
  after the exchange.

## Consequences

* A new identity-service component exists (P29) and holds the only token
  signing key. Its key custody is documented for deployment (P68, P77).
* The API keeps one verifier and one token format. Provider changes stay
  inside the identity service.
* Tokens grow to about 4.5 KB under option (a). Headers, proxies and the
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
