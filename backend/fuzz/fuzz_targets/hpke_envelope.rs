#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use platform_crypto::{TenantKeypair, TenantPublicKey, X25519_PUBLIC_KEY_BYTES};

static KEYPAIR: LazyLock<TenantKeypair> = LazyLock::new(TenantKeypair::generate);

fuzz_target!(|input: (&[u8], &[u8])| {
    let (info, envelope) = input;
    assert!(KEYPAIR.open_envelope(info, envelope).is_err());
    assert_eq!(
        TenantPublicKey::from_raw(envelope).is_ok(),
        envelope.len() == X25519_PUBLIC_KEY_BYTES
    );
});
