#![no_main]

use libfuzzer_sys::fuzz_target;
use platform_billing::verify_paddle_signature;

fuzz_target!(|input: (&str, &str, &[u8], u64, u64)| {
    let (secret, header, body, now, tolerance) = input;
    assert!(verify_paddle_signature(secret, header, body, now, tolerance).is_err());
});
