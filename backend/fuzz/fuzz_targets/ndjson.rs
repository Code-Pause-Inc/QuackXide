#![no_main]

use libfuzzer_sys::fuzz_target;
use platform_connectors::ndjson::{NdjsonLimits, parse_ndjson};

fuzz_target!(|input: (u8, u16, u16, &[u8])| {
    let (max_lines, max_line_bytes, max_total_bytes, bytes) = input;
    let limits = NdjsonLimits {
        max_lines: max_lines.into(),
        max_line_bytes: max_line_bytes.into(),
        max_total_bytes: max_total_bytes.into(),
    };
    let Ok(values) = parse_ndjson(bytes, &limits) else {
        return;
    };
    assert!(bytes.len() <= limits.max_total_bytes);
    assert!(values.len() <= limits.max_lines);
    let mut lines = std::str::from_utf8(bytes)
        .expect("accepted input is UTF-8")
        .split('\n')
        .map(str::trim)
        .filter(|line| !line.is_empty());
    assert_eq!(lines.clone().count(), values.len());
    assert!(lines.all(|line| line.len() <= limits.max_line_bytes));
});
