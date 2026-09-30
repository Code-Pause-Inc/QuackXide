//! Bounded NDJSON / JSONL framing. Semantics belong to `mappers`.
//!
//! * **Bounded.** The upstream is untrusted and parsing happens in enclave
//!   RAM, so every limit is checked before allocation.
//! * **Fail-closed.** An unparseable line fails the batch; silently dropped
//!   rows would corrupt the cohort counts disclosure control relies on.
//!
//! Errors carry line numbers, never line content: lines may hold clinical
//! data, and error strings reach logs.

use serde_json::Value;

use crate::ConnectorError;

/// Parse limits. Defaults are conservative; larger exports raise them
/// explicitly.
#[derive(Debug, Clone, Copy)]
pub struct NdjsonLimits {
    pub max_lines: usize,
    pub max_line_bytes: usize,
    pub max_total_bytes: usize,
}

impl Default for NdjsonLimits {
    fn default() -> Self {
        Self {
            max_lines: 1_000_000,
            max_line_bytes: 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Parse NDJSON into one `Value` per non-blank line. Blank lines are
/// skipped; any unparseable line fails the whole batch.
pub fn parse_ndjson(bytes: &[u8], limits: &NdjsonLimits) -> Result<Vec<Value>, ConnectorError> {
    if bytes.len() > limits.max_total_bytes {
        return Err(ConnectorError::MalformedPayload(format!(
            "ndjson payload is {} bytes, limit {}",
            bytes.len(),
            limits.max_total_bytes
        )));
    }

    let text = std::str::from_utf8(bytes).map_err(|_| {
        ConnectorError::MalformedPayload("ndjson payload is not valid UTF-8".into())
    })?;

    let mut out = Vec::new();
    for (index, raw_line) in text.split('\n').enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > limits.max_line_bytes {
            return Err(ConnectorError::MalformedPayload(format!(
                "ndjson line {line_number} is {} bytes, limit {}",
                line.len(),
                limits.max_line_bytes
            )));
        }
        if out.len() >= limits.max_lines {
            return Err(ConnectorError::MalformedPayload(format!(
                "ndjson exceeds {} records",
                limits.max_lines
            )));
        }
        let value: Value = serde_json::from_str(line).map_err(|_| {
            ConnectorError::MalformedPayload(format!("ndjson line {line_number} is not valid JSON"))
        })?;
        out.push(value);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_value_per_line() {
        let values = parse_ndjson(b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}", &NdjsonLimits::default())
            .expect("parse");
        assert_eq!(values.len(), 3);
        assert_eq!(values[2]["a"], 3);
    }

    #[test]
    fn blank_lines_crlf_and_trailing_newline_are_tolerated() {
        let values = parse_ndjson(
            b"{\"a\":1}\r\n\r\n   \n{\"a\":2}\n\n",
            &NdjsonLimits::default(),
        )
        .expect("parse");
        assert_eq!(values.len(), 2, "blank lines are skipped, not counted");
        assert_eq!(values[1]["a"], 2);
    }

    #[test]
    fn empty_input_is_an_empty_batch_not_an_error() {
        assert!(
            parse_ndjson(b"", &NdjsonLimits::default())
                .expect("parse")
                .is_empty()
        );
        assert!(
            parse_ndjson(b"\n\n  \n", &NdjsonLimits::default())
                .expect("parse")
                .is_empty()
        );
    }

    #[test]
    fn a_malformed_line_fails_the_batch_rather_than_being_skipped() {
        let err = parse_ndjson(b"{\"a\":1}\nnot json\n{\"a\":3}", &NdjsonLimits::default())
            .expect_err("must reject");
        assert!(matches!(err, ConnectorError::MalformedPayload(_)));
        assert!(err.to_string().contains("line 2"), "got: {err}");
    }

    #[test]
    fn errors_never_echo_line_content() {
        let secret = "{\"patient_name\":\"Jane Q Public\",";
        let payload = format!("{secret}\n");
        let err =
            parse_ndjson(payload.as_bytes(), &NdjsonLimits::default()).expect_err("must reject");
        let rendered = err.to_string();
        assert!(!rendered.contains("Jane Q Public"), "leaked: {rendered}");
        assert!(!rendered.contains("patient_name"), "leaked: {rendered}");
    }

    #[test]
    fn limits_are_enforced() {
        let tight = NdjsonLimits {
            max_lines: 2,
            max_line_bytes: 32,
            max_total_bytes: 1024,
        };

        assert!(
            parse_ndjson(b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}", &tight)
                .expect_err("line count")
                .to_string()
                .contains("exceeds 2 records")
        );

        let long_line = format!("{{\"a\":\"{}\"}}\n", "x".repeat(64));
        assert!(
            parse_ndjson(long_line.as_bytes(), &tight)
                .expect_err("line bytes")
                .to_string()
                .contains("limit 32")
        );

        let huge = vec![b'x'; 2048];
        assert!(
            parse_ndjson(&huge, &tight)
                .expect_err("total bytes")
                .to_string()
                .contains("limit 1024")
        );
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        let err =
            parse_ndjson(&[0xff, 0xfe, b'\n'], &NdjsonLimits::default()).expect_err("must reject");
        assert!(err.to_string().contains("UTF-8"));
    }

    #[test]
    fn non_object_json_values_are_accepted_at_this_layer() {
        let values = parse_ndjson(b"[1,2]\n\"str\"\n42", &NdjsonLimits::default()).expect("parse");
        assert_eq!(values.len(), 3);
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        fn limits() -> impl Strategy<Value = NdjsonLimits> {
            (0usize..16, 0usize..128, 0usize..2048).prop_map(
                |(max_lines, max_line_bytes, max_total_bytes)| NdjsonLimits {
                    max_lines,
                    max_line_bytes,
                    max_total_bytes,
                },
            )
        }

        fn json() -> impl Strategy<Value = Value> {
            let leaf = prop_oneof![
                Just(Value::Null),
                any::<bool>().prop_map(Value::from),
                any::<i64>().prop_map(Value::from),
                any::<u64>().prop_map(Value::from),
                any::<String>().prop_map(Value::from),
            ];
            leaf.prop_recursive(3, 24, 4, |inner| {
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
                    prop::collection::btree_map(any::<String>(), inner, 0..4)
                        .prop_map(|m| Value::Object(m.into_iter().collect())),
                ]
            })
        }

        fn lines(bytes: &[u8]) -> impl Iterator<Item = &str> {
            std::str::from_utf8(bytes)
                .unwrap()
                .split('\n')
                .map(str::trim)
                .filter(|line| !line.is_empty())
        }

        proptest! {
            #[test]
            fn arbitrary_bytes_never_panic_or_exceed_limits(
                bytes in prop::collection::vec(any::<u8>(), 0..4096),
                limits in limits(),
            ) {
                if let Ok(values) = parse_ndjson(&bytes, &limits) {
                    prop_assert!(bytes.len() <= limits.max_total_bytes);
                    prop_assert!(values.len() <= limits.max_lines);
                    prop_assert_eq!(values.len(), lines(&bytes).count());
                    prop_assert!(lines(&bytes).all(|line| line.len() <= limits.max_line_bytes));
                }
            }

            #[test]
            fn line_shaped_text_never_panics_or_exceeds_limits(
                text in r#"([ \r\t]*(\{"a":[0-9]{1,4}\}|[0-9]{1,6}|"[a-z]{0,8}"|null|\[|x)?[ \r\t]*\n){0,24}"#,
                limits in limits(),
            ) {
                if let Ok(values) = parse_ndjson(text.as_bytes(), &limits) {
                    prop_assert!(text.len() <= limits.max_total_bytes);
                    prop_assert!(values.len() <= limits.max_lines);
                    prop_assert!(
                        lines(text.as_bytes()).all(|line| line.len() <= limits.max_line_bytes)
                    );
                }
            }

            #[test]
            fn well_formed_input_round_trips(
                values in prop::collection::vec(json(), 0..32),
                crlf: bool,
                blank_every in 1usize..5,
            ) {
                let eol = if crlf { "\r\n" } else { "\n" };
                let mut text = String::new();
                for (i, value) in values.iter().enumerate() {
                    if i % blank_every == 0 {
                        text.push_str(eol);
                    }
                    text.push_str(&value.to_string());
                    text.push_str(eol);
                }
                let parsed = parse_ndjson(text.as_bytes(), &NdjsonLimits::default()).unwrap();
                prop_assert_eq!(parsed, values);
            }

            #[test]
            fn line_count_limit_is_exact(
                values in prop::collection::vec(json(), 0..16),
                max_lines in 0usize..16,
            ) {
                let text = values.iter().map(Value::to_string).collect::<Vec<_>>().join("\n");
                let limits = NdjsonLimits { max_lines, ..NdjsonLimits::default() };
                let accepted = parse_ndjson(text.as_bytes(), &limits).is_ok();
                prop_assert_eq!(accepted, values.len() <= max_lines);
            }
        }
    }
}
