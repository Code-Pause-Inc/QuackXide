//! Generates an RS256 signing keypair for production auth.
//!
//! The private PEM (`JWT_RS256_PRIVATE_KEY_PEM`) is a secret for the signer
//! process only; the JWKS (`JWT_JWKS_JSON`) is public and goes to every
//! verifying replica.
//!
//! Rotation: publish a JWKS with both old and new public keys, switch the
//! signer to the new key, and drop the old key once its tokens have expired.
//!
//! Usage:
//!   cargo run -p platform-auth --bin keygen [--bits 2048]

fn main() -> anyhow::Result<()> {
    let bits = std::env::args()
        .position(|a| a == "--bits")
        .and_then(|i| std::env::args().nth(i + 1))
        .map(|raw| raw.parse::<usize>())
        .transpose()
        .map_err(|e| anyhow::anyhow!("invalid --bits value: {e}"))?
        .unwrap_or(platform_auth::keygen::MIN_RSA_BITS);

    eprintln!("generating a {bits}-bit RSA keypair (this takes a few seconds)...");
    let keypair = platform_auth::generate_rs256_keypair(bits)
        .map_err(|e| anyhow::anyhow!("keygen failed: {e}"))?;

    println!("# kid: {}", keypair.kid);
    println!();
    println!("# ── JWT_RS256_PRIVATE_KEY_PEM ─────────────────────────────────");
    println!("# SECRET. Signer process only. Never commit; prefer Secret Manager.");
    println!("{}", keypair.private_pem);
    println!("# ── JWT_JWKS_JSON ─────────────────────────────────────────────");
    println!("# PUBLIC. Every verifying API replica's config.");
    println!("{}", keypair.jwks_json);

    Ok(())
}
