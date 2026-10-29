<p align="center"><img src="assets/logo.png" alt="QuackXide" width="320"></p>

# QuackXide

**A secure database and data-processing system for sensitive and protected
data.**

> Data goes in. Analysis comes out. The dataset doesn't.

## Purpose

QuackXide stores, queries, and analyzes sensitive and protected data without
exposing it in the clear:

* **Encrypted in** — data is encrypted on the owner's device, or inside an
  attested enclave, before it is stored.
* **Encrypted at rest** — storage holds ciphertext under keys the operator
  does not hold.
* **Encrypted out** — results leave encrypted to the recipient, after
  disclosure controls. Rows never leave.
* **Minimal plaintext surface** — plaintext exists only in attested enclave
  memory, for one query, and is zeroized afterwards.

The governing rule is the **no-naked-data invariant**: no normal application
path lets an analytics user retrieve an unrestricted plaintext dataset.
There is no CSV export, table dump, or `SELECT *` path.

QuackXide is built for security, efficiency, speed, and reliability in
production — fail-closed behavior, tested failure paths, durable state,
measured performance, and reproducible deployment.

## Why

Trusted research environments (TREs) keep sensitive data in a locked-down
workspace, admit vetted people on approved projects, and review every
export by hand. What they enforce is largely policy:

* **They trust the researcher.** Researchers see record-level data inside
  the workspace; downloading it is forbidden by contract, not prevented. In
  April 2026, data on UK Biobank's 500,000 participants was listed for sale
  after researchers with approved access downloaded it
  ([The Register](https://www.theregister.com/2026/04/23/500k_biobank_volunteers_data_listed/),
  [Health Research Authority](https://www.hra.nhs.uk/about-us/news-updates/our-response-to-concerns-over-uk-biobank-data/)).
  An HHS OIG audit of the NIH All of Us Researcher Workbench found users
  could download prohibited participant data by ticking a certification box
  ([A-18-24-06111](https://oig.hhs.gov/documents/audit/11266/A-18-24-06111.pdf)).
* **They trust the reviewer.** Manual output checking is slow and misses
  record-level data hidden in outputs.
* **They trust the operator.** Plaintext on the operator's disks is readable
  by staff, a stolen credential, a misconfigured log, or a subpoena.

QuackXide replaces each with a mechanism: researchers never receive rows,
disclosure control runs in the query engine, and the operator never holds a
key that opens the data.

## How it works

1. **Ingress.** Drive files are encrypted in the browser (Web Crypto,
   non-extractable keys, AES-256-GCM). Connector pipelines sync external
   sources into attested enclave memory, shape them into Parquet, and seal
   them to the tenant's HPKE key before anything persists.
2. **Storage.** Ciphertext only, in HPKE envelopes with versioned framing
   and context binding. Storage paths are built only from typed tenant ids,
   so cross-tenant access cannot be expressed.
3. **Query.** Apache DataFusion runs inside the enclave over transiently
   decrypted Parquet. A logical-plan allowlist admits only simple aggregate
   queries; each must carry a genuine `COUNT(*) AS n`, and cohorts below
   `RESEARCH_MIN_COHORT_SIZE` are suppressed. Blind indexes support
   equality search without decryption.
4. **Research access.** A steward grants a researcher a finite query
   budget, spent before execution and never refunded. Research queries
   pass the same gate.

Every security decision, including denials, is written to a
`SECURITY_AUDIT_EVENT` stream with identifiers and outcomes only.

| Document | Contents |
| --- | --- |
| `docs/ARCHITECTURE.md` | Trust model, dataflows, crate boundaries, cryptography, audit stream |
| `docs/THREAT_MODEL.md` | Assets, adversaries, controls, residual risk |
| `docs/PROJECT_SCOPE.md` | Release scope and definition of done |
| `docs/V1_PLAN.md` | v1.0 plan: work items, order, and the issues they map to |
| `docs/DATA_POLICY.md` | Synthetic and public data only |
| `docs/SIMULATED_TEE_GCP_GUIDE.md` | The simulated SEV-SNP TEE and its production counterparts (Confidential Space on TDX, Cloud KMS) |
| `docs/adr/` | Architecture decision records |

## Layout

```
backend/crates/
  platform-core/          Typed tenant/object ids, connector slugs, ZK mode
  platform-config/        Env-driven config (brand, features, research)
  platform-telemetry/     JSON tracing + SECURITY_AUDIT_EVENT stream
  platform-crypto/        AEAD, HPKE envelopes, blind indexes, TOTP
  platform-auth/          JWT verification (dev HS256, RS256/JWKS) + keygen
  platform-storage/       Tenant-isolated ciphertext vault (GCS / emulator / in-memory)
  platform-enclave/       1184B SEV-SNP report parser, P-384 chain verifier, SimulatedSnp
  platform-connectors/    Connector catalog, OAuth2, NDJSON, Parquet-out
  platform-tenancy/       Tenants, grants, budgets, dataset catalog
  platform-billing/       Merchant-of-Record webhook verification
  quackxide-engine/       QueryScope, plan gate, disclosure policies
  platform-api/           HTTP edge, enclave identity, tests
                          dev-only, feature "dev": research stack (bin/devstack, src/dev.rs),
                          key-release stand-in (bin/key-release, src/key_release/stand_in.rs), bin/query-demo
  synth-data/             Seeded synthetic test and benchmark data (dev-only)
frontend/src/
  lib/crypto/             Web Crypto worker (keys never touch the UI thread)
  lib/vault/              Ciphertext-only vault clients (local / http)
  components/             Drive, researcher portal, steward console, admin
Dockerfile                Dev-only simulated TEE images (enclave-api, key-release), built with feature "dev"
docker-compose.simulated-tee.yml  3-plane local Simulated SEV-SNP TEE stack
scripts/test-simulated-tee.sh     End-to-end Docker smoke + tamper-refusal verification
scripts/check.sh          Validation gate — run before every push
scripts/hooks/            Git hooks
```

## Development

Backend (Rust, pinned in `rust-toolchain.toml`), from `backend/`:

```sh
cp .env.example .env
cargo run -p platform-api        # /healthz, /readyz, /api/v1/meta; metrics on 127.0.0.1:9464/metrics
```

Frontend (Node, pinned in `.nvmrc`), from `frontend/`:

```sh
cp .env.example .env
npm install && npm run dev       # http://localhost:5173
```

The dev server proxies `/api`, `/admin` and `/healthz` to the backend
(`API_PROXY_TARGET`, default `http://127.0.0.1:8080`), so the browser calls
its own origin and needs no CORS. Leave `VITE_API_BASE_URL` empty.

End-to-end locally, from `backend/`. The secret goes in `backend/.env`
(gitignored) so both terminals read the same value:

```sh
sed -i.bak "s/^JWT_HS256_SECRET=.*/JWT_HS256_SECRET=\"$(openssl rand -hex 32)\"/" .env && rm .env.bak
cargo run -p platform-api                    # terminal 1
cargo run -p platform-api --bin devtoken     # terminal 2: prints a token
# frontend/.env: VITE_VAULT_MODE="http", VITE_DEV_JWT="<token>"
cargo run -p platform-api --features dev --bin query-demo   # sealed-query round trip over SimulatedSnp + KeyReleaseRelyingParty
```

### Local research stack (dev only)

`devstack` runs the API with the research routes wired and seeded, so the
steward and researcher lifecycle runs on one machine without TEE
hardware. It is insecure by design: tenant keys live in process memory, TEE
evidence is fabricated, and all state is in memory and lost when it stops.
It is built only with the `dev` feature, listens only on a loopback
`BIND_ADDR`, and refuses to start unless the command sets
`DEVSTACK_ALLOW_INSECURE=1` (a value in `.env` does not count) and
`JWT_HS256_SECRET` is set in `backend/.env`, as above.

Terminal 1, from `backend/`. Leave it running:

```sh
DEVSTACK_ALLOW_INSECURE=1 cargo run -p platform-api --features dev --bin devstack
```

At startup it seals a synthetic cohort (`synth-data`, with groups on both
sides of `RESEARCH_MIN_COHORT_SIZE`) as a steward's `health` dataset,
publishes its catalog listing, and prints a token for the steward and one
for a researcher.

Terminal 2: put the two tokens in variables, then run the researcher's
access request, the steward's approval and the researcher's query:

```sh
S_TOKEN='<steward token>'
R_TOKEN='<researcher token>'
API=http://127.0.0.1:8080
CATALOG=$(curl -s "$API/api/v1/catalog" -H "Authorization: Bearer $R_TOKEN")
LISTING=$(echo "$CATALOG" | sed -E 's/.*"listing_id":"([^"]+)".*/\1/')
STEWARD=$(echo "$CATALOG" | sed -E 's/.*"steward_tenant":"([^"]+)".*/\1/')
REQ=$(curl -s -X POST "$API/api/v1/catalog/$LISTING/request" -H "Authorization: Bearer $R_TOKEN" -H 'Content-Type: application/json' -d '{"note":"local test"}' | sed -E 's/.*"request_id":"([^"]+)".*/\1/')
curl -s -X POST "$API/api/v1/research/requests/$REQ/approve" -H "Authorization: Bearer $S_TOKEN" -H 'Content-Type: application/json' -d '{}'
curl -s "$API/api/v1/research/query" -H "Authorization: Bearer $R_TOKEN" -H 'Content-Type: application/json' -d "{\"steward_tenant\":\"$STEWARD\",\"connector\":\"health\",\"sql\":\"SELECT condition, COUNT(*) AS n FROM health GROUP BY condition ORDER BY condition\"}"
```

The query releases only conditions with at least `RESEARCH_MIN_COHORT_SIZE`
rows and counts the rest in `suppressed_rows`: with the default of 11, seven
are released and two suppressed. The frontend has no research-query form yet,
so these steps use `curl`.

### Simulated AMD SEV-SNP TEE (Local Docker)

`docker-compose.simulated-tee.yml` runs the 3-plane Confidential Computing
topology locally across isolated networks (`public_net` and `internal: true`
`enclave_internal_net`) with `read_only: true` and `cap_drop: ["ALL"]`:

* **`enclave-api`** — Confidential workload container (`platform-api`) using
  `SimulatedSnp` to sign 1184-byte binary SEV-SNP reports binding its
  ephemeral X25519 HPKE key and P-384 result-signing key into `REPORT_DATA`.
* **`key-release-service`** — The stand-in for Cloud KMS (`bin/key-release`,
  ADR 0004): a relying party that verifies the `ARK -> ASK -> VCEK` P-384 chain, `MEASUREMENT`,
  `GuestPolicy` (`DEBUG=0`, `MIGRATE_MA=0`), `TcbVersion`, and single-use
  challenge nonce before wrapping a tenant's private key via HPKE
  (`key-release-v1`) for a single query.
* **`fake-gcs`** — Local Cloud Storage vault (`fsouza/fake-gcs-server` via
  `STORAGE_EMULATOR_HOST`) holding only HPKE-sealed manifests and Parquet
  snapshots.

The simulation runs its protocol (report format, verifier, key release
through the stand-in, sealed queries) on any machine. It does not protect
anything: the host can read the simulated enclave's memory, and the
stand-in accepts tenant private keys over plain HTTP, so it is for
development and CI only. Both images are built with the `dev` feature, and
`key-release` and `query-demo` exist only in such builds; a build without
`dev` refuses to start when `KEY_RELEASE_URL` is set.
`TEE_ATTESTATION_REQUIRED=true` refuses simulated evidence, the production
trust root rejects simulated chains, and query and research responses report
`"tee_platform": "simulated"`.

Run the full Docker stack or execute the automated happy-path and
tamper-refusal (`MEASUREMENT` mismatch + `GuestPolicy::DEBUG=1`) suite:

```sh
docker compose -f docker-compose.simulated-tee.yml up --build
./scripts/test-simulated-tee.sh
```

See `docs/SIMULATED_TEE_GCP_GUIDE.md` for how each simulated component maps to
Confidential Space on Intel TDX, Cloud KMS, and VPC Service Controls.

Synthetic data (dev-only), from `backend/`:

```sh
cargo run -p synth-data -- --schema cohort --seed 7 --rows 1000
cargo run -p synth-data -- --schema cohort --seed 7 --rows 200 --k 5
cargo run --release -p synth-data -- --schema wide --seed 1 --rows 1000000
cargo run -p synth-data -- --help
```

Without `--out`, files go to `backend/target/synth-data/`, which is
gitignored. Each run prints the file's path and the command that writes it
again.

Before every push, run `scripts/check.sh` and enable the hooks once with
`git config core.hooksPath scripts/hooks`.

**White-label.** Customer-facing names, domains, and endpoints are
configuration (`APP_PUBLIC_NAME`, `APP_DOMAIN_NAME`, `VITE_APP_*`).
`scripts/check.sh` fails if the engine name reaches the frontend bundle.

## Status

The architecture is implemented and tested end-to-end against synthetic
data; it is not yet deployed to production. Remaining for the first
production release (details in `docs/PROJECT_SCOPE.md`):

* **Sign-in** — RS256/JWKS verification and TOTP exist; the managed
  sign-in service does not. Development uses HS256 tokens.
* **Attestation** — production runs as a Confidential Space workload on
  Intel TDX (ADR 0004). Verifying Google's attestation token, in the
  enclave and in the browser, remains. For the simulated TEE, 1184-byte
  SEV-SNP report parsing, `ARK -> ASK -> VCEK` P-384 chain verification
  (`AttestationVerifier`) and `SimulatedSnp` are implemented.
* **Key release** — in production, Cloud KMS unwraps each dataset's data
  key only for the attested workload (ADR 0004); this remains. The
  simulated TEE's stand-in (`KeyReleaseRelyingParty`, `AttestedKeyProvider`,
  `bin/key-release`), with once-per-query key sessions and zeroize-on-drop,
  is implemented and built only with the `dev` feature.
* **Durability** — registries are in-memory behind traits.
* **Encrypted results** — query responses carry an attested P-384
  `enclave_signature` over JSON/TLS; client-key HPKE result encryption remains.
* **Post-quantum cryptography** — target is X25519 + ML-KEM-768 and
  Ed25519 + ML-DSA-65; current suites are X25519 and RS256.

## Contributing

Read `CONTRIBUTING.md` and `CODE_OF_CONDUCT.md`. Report vulnerabilities
privately per `SECURITY.md`. Changes are recorded in `CHANGELOG.md`.

**Contributors:** AxolDad — Jeremy L.D. Ryan (founder and maintainer); the
USF core contribution team — Jake Abendroth, William Shenker, Angelina Tam,
and Gabriel Zubovsky. Full list in `CONTRIBUTORS.md`.

## License

Copyright 2026 Code Pause, Inc., Jeremy L.D. Ryan (@AxolDad) <Jeremy.Ryan@codepause.com>.

Licensed under either of Apache License, Version 2.0 (`LICENSE-APACHE`) or
MIT license (`LICENSE-MIT`), at your option. Unless you explicitly state
otherwise, any contribution intentionally submitted for inclusion in
QuackXide by you, as defined in the Apache-2.0 license, shall be
dual-licensed as above, without any additional terms or conditions.
