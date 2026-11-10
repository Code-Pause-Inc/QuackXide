# 0009. Production mode: one runtime switch, refused development paths

* Status: Proposed
* Date: 2026-11-09

## Context

The definition of done and several plan items say "production build", but
nothing defined one. Development paths reached the shipped binaries,
selected by environment variables with at most a warning: the in-memory
vault when `STORAGE_BUCKET` is unset, HS256 shared-secret tokens,
`TEE_ATTESTATION_REQUIRED=false` (which `backend/.env.example` sets), the
simulated attestation provider, the key-release stand-in, and
`connector-worker`'s demo tenant and embedded fixture sources. `.env` was
always loaded, so a stray file could switch any of them on. The released
frontend was the development build, defaulting to the local IndexedDB
vault.

The `dev` Cargo feature already keeps the simulator, the key-release
stand-in and the dev binaries out of release builds, but a build-time
switch cannot stop an operator setting from selecting a path that every
build contains, such as the in-memory vault or HS256.

## Decision

* One runtime switch, `APP_ENV`. Only `development` selects development;
  unset, blank and unknown values mean production.
* `APP_ENV` is read from the process environment before `.env`, and `.env`
  is loaded only in development. Dev-only binaries (built only with the
  `dev` feature) load `.env` and run as development.
* `PlatformConfig::check_production(service)` is the single gate. Each
  service calls it at the start of its startup function
  (`platform_api::startup::build`, `platform_connectors::startup::build`)
  before building anything. It is not part of `from_source`, so tests can
  build any configuration. In production it refuses `JWT_HS256_SECRET`, an
  unset `STORAGE_BUCKET`, `TEE_ATTESTATION_REQUIRED=false`,
  `SIM_ATTESTATION_URL`, `KEY_RELEASE_URL`, and, for `connector-worker`,
  the demo tenant and fixture sources. A refusal lists every reason, by key
  name only, and emits a `service.start` "denied" audit event.
* Later plan items add their own refusals to this function (P28, P51, P62,
  P63, P67).
* The `dev` Cargo feature stays as the compile-time layer and now also
  gates `devtoken`. `scripts/check.sh` lints the release binaries without
  it.
* The frontend has a release build mode (`vite build --mode release`, run
  by `release.yml`) that fails unless `VITE_VAULT_MODE` is `http` and fails
  if `VITE_DEV_JWT` or `VITE_ADMIN_JWT` is set.
* `FEATURE_ZK_ENABLED=false` is not refused yet; whether production mode
  refuses it is left to the maintainer (research mode already forces ZK on).

## Consequences

* Production is what you get by omission; development must be asked for in
  the process environment.
* Until the production key provider, verification keys, durable registries
  and identity stores land, production mode cannot boot. Local runs, CI and
  the simulated TEE set `APP_ENV=development`.
* `cargo run -p platform-api` and `connector-worker` need
  `APP_ENV=development` locally; `devtoken` needs `--features dev`.
