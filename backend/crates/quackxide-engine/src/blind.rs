//! Blind-index equality: the ciphertext-scan path.
//!
//! The client, which holds the per-tenant, per-field index key, computes the
//! blind index (`platform_crypto::blind_index`, HMAC-SHA256/128) of its search
//! term; the engine matches it against a stored blind-index column and never
//! sees plaintext. Only equality is supported.

/// Hex-encoded blind index of `value` under `index_key`. Stored in a Parquet
/// column and matched with plain SQL equality (`WHERE bidx = '<hex>'`).
pub fn blind_index_hex(index_key: &[u8], value: &[u8]) -> String {
    let raw = platform_crypto::blind_index(index_key, value);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blind_index_hex_is_deterministic_and_key_separated() {
        let a1 = blind_index_hex(b"tenant-field-key", b"acme corp");
        let a2 = blind_index_hex(b"tenant-field-key", b"acme corp");
        let other_value = blind_index_hex(b"tenant-field-key", b"other corp");
        let other_key = blind_index_hex(b"different-key", b"acme corp");
        assert_eq!(a1, a2);
        assert_eq!(a1.len(), 32, "128-bit index as hex");
        assert_ne!(a1, other_value);
        assert_ne!(a1, other_key);
    }
}
