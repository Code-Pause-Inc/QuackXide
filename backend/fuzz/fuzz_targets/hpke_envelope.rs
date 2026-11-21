#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use platform_crypto::{EnvelopeSuite, SuitePolicy, TenantKeypair, TenantPublicKey};

static KEYPAIRS: LazyLock<[TenantKeypair; 2]> = LazyLock::new(|| {
    [
        TenantKeypair::generate(EnvelopeSuite::Hpk1),
        TenantKeypair::generate(EnvelopeSuite::Hpk2),
    ]
});

fuzz_target!(|input: (&[u8], &[u8])| {
    let (info, envelope) = input;
    for keypair in KEYPAIRS.iter() {
        assert!(keypair.open_envelope(info, envelope).is_err());
    }
    // Only the two suites' lengths can parse; an X-Wing key of the right
    // length may still be refused if its ML-KEM half is not canonical.
    let parsed = TenantPublicKey::from_raw(envelope, SuitePolicy::DEVELOPMENT);
    assert!(parsed.is_err() || envelope.len() == 32 || envelope.len() == 1216);
    if envelope.len() == 32 {
        assert!(parsed.is_ok());
    }
    let _ = TenantKeypair::from_private_key_bytes(envelope, SuitePolicy::DEVELOPMENT);
});
