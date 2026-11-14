#![no_main]

use libfuzzer_sys::fuzz_target;
use platform_connectors::upload::{MAX_BODY_OVERHEAD, encode_upload_body, parse_upload_body};
use platform_crypto::check_envelope_frame;

fuzz_target!(|input: (u32, &[u8])| {
    let (max_object_bytes, body) = input;
    let max_object_bytes = u64::from(max_object_bytes);
    let Ok(parsed) = parse_upload_body(body.to_vec().into(), max_object_bytes) else {
        return;
    };
    // An accepted body is an object within the limit, framed envelopes of
    // one suite, and no more than the fixed overhead besides.
    assert!(parsed.object.len() as u64 <= max_object_bytes);
    assert_eq!(
        check_envelope_frame(&parsed.manifest).ok(),
        Some(parsed.suite)
    );
    assert_eq!(
        check_envelope_frame(&parsed.object).ok(),
        Some(parsed.suite)
    );
    assert!(body.len() <= parsed.object.len() + MAX_BODY_OVERHEAD);
    // Encoding what was parsed gives a body that parses to the same upload.
    let again = encode_upload_body(&parsed.header, &parsed.manifest, &parsed.object)
        .expect("parsed parts are within their limits");
    let reparsed =
        parse_upload_body(again.into(), max_object_bytes).expect("an encoded upload parses");
    assert_eq!(reparsed.header, parsed.header);
    assert_eq!(reparsed.manifest, parsed.manifest);
    assert_eq!(reparsed.object, parsed.object);
});
