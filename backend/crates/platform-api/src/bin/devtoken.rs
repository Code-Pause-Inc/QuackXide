//! DEV ONLY — mints an HS256 bearer token for local testing of the drive and
//! admin APIs. Production tokens come from the managed IdP; this binary
//! refuses to run without an explicitly configured `JWT_HS256_SECRET` and is
//! never part of any deployed image.
//!
//! Usage:
//!   cargo run -p platform-api --bin devtoken             # fresh tenant
//!   cargo run -p platform-api --bin devtoken <tenant-uuid>
//!   cargo run -p platform-api --bin devtoken --admin     # admin-claim token

use platform_config::PlatformConfig;
use platform_core::TenantId;

const TOKEN_TTL_SECS: i64 = 8 * 3600;

fn main() -> anyhow::Result<()> {
    let config = PlatformConfig::from_env()?;
    let Some(secret) = config.auth.hs256_secret else {
        anyhow::bail!("JWT_HS256_SECRET is not set — refusing to mint a token");
    };

    let arg = std::env::args().nth(1);
    let admin = arg.as_deref() == Some("--admin");

    let tenant: TenantId = match arg {
        Some(raw) if !admin => raw
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid tenant uuid: {e}"))?,
        _ => TenantId::generate(),
    };

    let mint = if admin {
        platform_auth::mint_admin_token
    } else {
        platform_auth::mint_token
    };
    let token = mint(
        &secret,
        &config.auth.issuer,
        &config.auth.audience,
        tenant,
        if admin { "dev-admin" } else { "dev-user" },
        TOKEN_TTL_SECS,
    )?;

    eprintln!("tenant: {tenant}");
    eprintln!("admin: {admin} — expires 8h — dev use only");
    println!("{token}");
    Ok(())
}
