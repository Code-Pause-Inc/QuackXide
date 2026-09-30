# AGENTS.md

Guidance for automated coding tools working in this repository. It adds
nothing to `CONTRIBUTING.md`, which every change must follow.

* Read `README.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`, and
  `docs/PROJECT_SCOPE.md` before changing anything. The core rule is the
  no-naked-data invariant.
* Backend: Rust (pinned in `rust-toolchain.toml`), edition 2024, `unsafe`
  denied, from `backend/`. Frontend: Node (pinned in `.nvmrc`), Vite +
  React 19 + TypeScript + Tailwind v4, from `frontend/`.
* `scripts/check.sh` must pass before every push. Record significant
  design decisions in `docs/adr/`.
* Fail closed. Use RustCrypto, `hpke`, and Web Crypto; never implement
  cryptographic primitives.
* Synthetic or public data only (`docs/DATA_POLICY.md`).
* Conventional, short commit messages. Docs describe the current system,
  not its history.
* The human who submits a change is its author. Tools are never credited:
  no tool names, trailers, co-author lines, or "generated" footers in
  files, commits, or pull requests. `scripts/attribution-guard.sh` enforces
  this.
