//! TOTP (RFC 6238) over HOTP (RFC 4226), the platform's mandatory second
//! factor.
//!
//! SHA-1 only: mainstream authenticator apps ignore the `algorithm`
//! parameter and hardcode HMAC-SHA1. HMAC's security does not rest on SHA-1
//! collision resistance.
//!
//! [`TotpSecret::verify`] is stateless and returns the matched step. Replay
//! protection (refusing a step at or below the last accepted one) is the
//! caller's job, since only the caller holds durable per-user state.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RFC 6238's default step length.
pub const TOTP_STEP_SECS: u64 = 30;
/// RFC 6238's default code length, which authenticator apps assume.
pub const TOTP_DIGITS: u32 = 6;
/// Secret length in bytes (160 bits), the RFC 6238 reference size.
pub const TOTP_SECRET_BYTES: usize = 20;

/// A TOTP secret shared with the user's authenticator app. Zeroized on drop;
/// `Debug` never prints it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret(Vec<u8>);

impl TotpSecret {
    pub fn generate() -> Self {
        let mut bytes = vec![0u8; TOTP_SECRET_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Restore a secret persisted via [`TotpSecret::expose`]. The caller must
    /// protect those bytes at rest like any other secret.
    pub fn from_raw(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Unpadded RFC 4648 base32, as `otpauth://` URIs and manual entry expect.
    pub fn to_base32(&self) -> String {
        base32_encode(&self.0)
    }

    /// The `otpauth://` provisioning URI. `issuer` must be the configured
    /// brand name, never the engine name; `account` is the user's label
    /// (typically their email).
    pub fn otpauth_uri(&self, issuer: &str, account: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            percent_encode(issuer),
            percent_encode(account),
            self.to_base32(),
            percent_encode(issuer),
            TOTP_DIGITS,
            TOTP_STEP_SECS,
        )
    }

    /// Verify `code` at `now` (Unix seconds), allowing `drift` steps of skew
    /// either way (1 is the recommended default). Returns the matched step;
    /// callers must record it and refuse any later match `<=` it, or the
    /// code stays replayable for its whole window.
    pub fn verify(&self, code: &str, now: u64, drift: u64) -> Option<u64> {
        let code = code.trim();
        if code.len() != TOTP_DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let submitted: u32 = code.parse().ok()?;
        let current_step = now / TOTP_STEP_SECS;
        // Saturate absurd drift values rather than panic.
        let drift = i64::try_from(drift).unwrap_or(i64::MAX);
        for delta in -drift..=drift {
            let Some(step) = current_step.checked_add_signed(delta) else {
                continue; // no negative steps near the epoch
            };
            if ct_eq_u32(hotp(&self.0, step, TOTP_DIGITS), submitted) {
                return Some(step);
            }
        }
        None
    }
}

impl std::fmt::Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TotpSecret(<{} bytes redacted>)", self.0.len())
    }
}

/// RFC 4226 §5.3 dynamic truncation. `digits` is a parameter so the RFC 6238
/// 8-digit test vectors can exercise this function directly.
fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let hs = mac.finalize().into_bytes();
    let offset = (hs[19] & 0x0f) as usize;
    let p = ((u32::from(hs[offset]) & 0x7f) << 24)
        | (u32::from(hs[offset + 1]) << 16)
        | (u32::from(hs[offset + 2]) << 8)
        | u32::from(hs[offset + 3]);
    p % 10u32.pow(digits)
}

/// A single word compare has no data-dependent early exit, unlike a
/// byte-slice comparison, so it does not leak timing.
fn ct_eq_u32(a: u32, b: u32) -> bool {
    a == b
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, no padding.
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits_in_buffer = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits_in_buffer += 8;
        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let idx = ((buffer >> bits_in_buffer) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits_in_buffer > 0 {
        let idx = ((buffer << (5 - bits_in_buffer)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

/// Minimal RFC 3986 percent-encoding for `otpauth://` labels and query
/// values: unreserved bytes pass through, every other byte becomes `%XX`.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B vectors (SHA-1, 8 digits, 30s step, T0=0).
    const RFC_SEED_SHA1: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc6238_sha1_vectors() {
        let vectors: [(u64, &str); 6] = [
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ];
        for (time, expected) in vectors {
            let step = time / TOTP_STEP_SECS;
            let got = hotp(RFC_SEED_SHA1, step, 8);
            assert_eq!(format!("{got:08}"), expected, "T={time} step={step}");
        }
    }

    // RFC 4648 §10 vectors, unpadded.
    #[test]
    fn rfc4648_base32_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (input, expected) in vectors {
            assert_eq!(base32_encode(input), expected, "input={input:?}");
        }
    }

    #[test]
    fn generate_produces_distinct_secrets_of_the_right_length() {
        let a = TotpSecret::generate();
        let b = TotpSecret::generate();
        assert_eq!(a.expose().len(), TOTP_SECRET_BYTES);
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn debug_is_redacted() {
        let secret = TotpSecret::from_raw(vec![0xAB; TOTP_SECRET_BYTES]);
        let debugged = format!("{secret:?}");
        assert!(!debugged.contains("AB"));
        assert!(debugged.contains("redacted"));
        assert!(!format!("{secret:?}").contains(&secret.to_base32()));
    }

    #[test]
    fn otpauth_uri_encodes_issuer_and_account() {
        let secret = TotpSecret::from_raw(vec![1u8; TOTP_SECRET_BYTES]);
        let uri = secret.otpauth_uri("Acme Vault", "researcher+lab@example.com");
        assert!(uri.starts_with("otpauth://totp/Acme%20Vault:researcher%2Blab%40example.com?"));
        assert!(uri.contains(&format!("secret={}", secret.to_base32())));
        assert!(uri.contains("issuer=Acme%20Vault"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn verify_accepts_the_current_step_code() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000u64;
        let code = format!(
            "{:06}",
            hotp(secret.expose(), now / TOTP_STEP_SECS, TOTP_DIGITS)
        );
        assert_eq!(secret.verify(&code, now, 1), Some(now / TOTP_STEP_SECS));
    }

    #[test]
    fn verify_respects_the_drift_window_boundary() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000u64;
        let current_step = now / TOTP_STEP_SECS;

        let prev_code = format!(
            "{:06}",
            hotp(secret.expose(), current_step - 1, TOTP_DIGITS)
        );
        let next_code = format!(
            "{:06}",
            hotp(secret.expose(), current_step + 1, TOTP_DIGITS)
        );
        let too_old_code = format!(
            "{:06}",
            hotp(secret.expose(), current_step - 2, TOTP_DIGITS)
        );

        assert_eq!(secret.verify(&prev_code, now, 1), Some(current_step - 1));
        assert_eq!(secret.verify(&next_code, now, 1), Some(current_step + 1));
        assert_eq!(
            secret.verify(&too_old_code, now, 1),
            None,
            "two steps back must be outside a ±1 drift window"
        );
        // With drift=0, even the adjacent-step codes fall outside.
        assert_eq!(secret.verify(&prev_code, now, 0), None);
    }

    #[test]
    fn verify_rejects_malformed_input() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000u64;
        for bad in ["", "12345", "1234567", "12345a", "  123456extra"] {
            assert_eq!(secret.verify(bad, now, 1), None, "input={bad:?}");
        }
    }

    #[test]
    fn verify_rejects_a_code_from_the_wrong_secret() {
        let mine = TotpSecret::generate();
        let theirs = TotpSecret::generate();
        let now = 1_700_000_000u64;
        let their_code = format!(
            "{:06}",
            hotp(theirs.expose(), now / TOTP_STEP_SECS, TOTP_DIGITS)
        );
        assert_eq!(mine.verify(&their_code, now, 1), None);
    }

    /// `verify` is stateless, so the caller tracks `last_used_step` and
    /// refuses any match that is not newer.
    #[test]
    fn caller_is_responsible_for_replay_rejection() {
        let secret = TotpSecret::generate();
        let now = 1_700_000_000u64;
        let code = format!(
            "{:06}",
            hotp(secret.expose(), now / TOTP_STEP_SECS, TOTP_DIGITS)
        );

        let mut last_used_step: Option<u64> = None;

        let first = secret.verify(&code, now, 1).expect("first use matches");
        assert!(last_used_step.is_none_or(|last| first > last));
        last_used_step = Some(first);

        let second = secret.verify(&code, now, 1).expect("verify is stateless");
        assert!(
            second <= last_used_step.unwrap(),
            "a real caller rejects here: matched step did not advance"
        );
    }
}
