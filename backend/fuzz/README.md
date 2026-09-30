Fuzz targets for the backend's untrusted-input parsers: `paddle_signature`, `ndjson`, `hpke_envelope`, `jwt_verify`.
Requires a nightly toolchain and `cargo install cargo-fuzz`; this crate is outside the backend workspace and the stable build.
Run from `backend/fuzz` with `cargo +nightly fuzz run <target>`.
