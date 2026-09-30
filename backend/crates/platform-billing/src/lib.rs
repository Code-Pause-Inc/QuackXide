//! Paddle (Merchant-of-Record) webhook verification and event mapping.
//!
//! Paddle signs each webhook with `Paddle-Signature: ts=<unix>;h1=<hex>`,
//! where `h1` is HMAC-SHA256 over `"<ts>:<raw_body>"`. The raw body must be
//! hashed byte-for-byte; re-serialized JSON will not match. `ts` outside the
//! tolerance window is rejected as a replay.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Default freshness window for the `ts` replay guard.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BillingError {
    #[error("malformed signature header")]
    MalformedSignature,
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("timestamp outside tolerance")]
    StaleTimestamp,
    #[error("malformed event payload")]
    MalformedPayload,
}

/// Parse a `ts=…;h1=…` header into `(ts, raw_ts, h1_hex)`. Tolerant of
/// ordering and surrounding whitespace; ignores unknown `key=value` parts.
/// `raw_ts` is the exact header text the MAC covers; it must be ASCII digits
/// only, so signs and other forms `u64::from_str` would accept are refused.
fn parse_signature_header(header: &str) -> Option<(u64, &str, &str)> {
    let mut ts = None;
    let mut h1 = None;
    for part in header.split(';') {
        let (key, value) = part.split_once('=')?;
        match key.trim() {
            "ts" => ts = Some(value.trim()),
            "h1" => h1 = Some(value.trim()),
            _ => {}
        }
    }
    let raw_ts = ts?;
    if raw_ts.is_empty() || !raw_ts.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((raw_ts.parse::<u64>().ok()?, raw_ts, h1?))
}

/// Decode an even-length string of ASCII hex digits; anything else is refused.
fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let bytes = hex.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

/// Verify a Paddle webhook signature over the raw body. `now_unix` is
/// injected so the freshness check is testable.
pub fn verify_paddle_signature(
    secret: &str,
    signature_header: &str,
    raw_body: &[u8],
    now_unix: u64,
    tolerance_secs: u64,
) -> Result<(), BillingError> {
    let (ts, raw_ts, h1_hex) =
        parse_signature_header(signature_header).ok_or(BillingError::MalformedSignature)?;

    if now_unix.abs_diff(ts) > tolerance_secs {
        return Err(BillingError::StaleTimestamp);
    }
    let expected = decode_hex(h1_hex).ok_or(BillingError::MalformedSignature)?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| BillingError::MalformedSignature)?;
    mac.update(raw_ts.as_bytes());
    mac.update(b":");
    mac.update(raw_body);
    // Constant-time comparison.
    mac.verify_slice(&expected)
        .map_err(|_| BillingError::SignatureMismatch)
}

/// A parsed Paddle event (the fields provisioning needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddleEvent {
    pub event_id: String,
    pub event_type: String,
    pub occurred_at: String,
    pub subscription_id: Option<String>,
    pub customer_id: Option<String>,
    pub status: Option<String>,
    pub plan: Option<String>,
}

#[derive(Deserialize)]
struct RawEvent {
    #[serde(default)]
    event_id: String,
    event_type: String,
    #[serde(default)]
    occurred_at: String,
    #[serde(default)]
    data: serde_json::Value,
}

/// Parse a Paddle event body. `event_type` is required; the rest are
/// best-effort so schema additions don't break parsing.
pub fn parse_event(raw_body: &[u8]) -> Result<PaddleEvent, BillingError> {
    let raw: RawEvent =
        serde_json::from_slice(raw_body).map_err(|_| BillingError::MalformedPayload)?;
    let data = &raw.data;
    let string_at = |ptr: &str| {
        data.pointer(ptr)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    Ok(PaddleEvent {
        event_id: raw.event_id,
        event_type: raw.event_type,
        occurred_at: raw.occurred_at,
        subscription_id: string_at("/id"),
        customer_id: string_at("/customer_id"),
        status: string_at("/status"),
        plan: string_at("/items/0/price/id").or_else(|| string_at("/items/0/price_id")),
    })
}

/// What a parsed event asks the platform to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningAction {
    Provision {
        subscription_id: String,
        customer_id: String,
        plan: String,
    },
    Suspend {
        subscription_id: String,
    },
    Ignore {
        reason: String,
    },
}

/// Map a Paddle event to a provisioning action.
pub fn action_for(event: &PaddleEvent) -> ProvisioningAction {
    match event.event_type.as_str() {
        "subscription.created" | "subscription.activated" => {
            match (&event.subscription_id, &event.customer_id) {
                (Some(sub), Some(cus)) => ProvisioningAction::Provision {
                    subscription_id: sub.clone(),
                    customer_id: cus.clone(),
                    plan: event.plan.clone().unwrap_or_else(|| "unknown".to_owned()),
                },
                _ => ProvisioningAction::Ignore {
                    reason: "subscription event missing id/customer".to_owned(),
                },
            }
        }
        "subscription.canceled" | "subscription.paused" => match &event.subscription_id {
            Some(sub) => ProvisioningAction::Suspend {
                subscription_id: sub.clone(),
            },
            None => ProvisioningAction::Ignore {
                reason: "cancellation missing subscription id".to_owned(),
            },
        },
        other => ProvisioningAction::Ignore {
            reason: format!("unhandled event type: {other}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "pdl_ntfset_test_secret";

    /// Produce a valid `ts=…;h1=…` header for `body` at time `ts`.
    fn sign(secret: &str, ts: u64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(ts.to_string().as_bytes());
        mac.update(b":");
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        format!("ts={ts};h1={hex}")
    }

    #[test]
    fn valid_signature_passes() {
        let body = br#"{"event_type":"subscription.created"}"#;
        let header = sign(SECRET, 1_700_000_000, body);
        assert!(
            verify_paddle_signature(SECRET, &header, body, 1_700_000_010, DEFAULT_TOLERANCE_SECS)
                .is_ok()
        );
    }

    #[test]
    fn tampered_body_is_rejected() {
        let body = br#"{"event_type":"subscription.created"}"#;
        let header = sign(SECRET, 1_700_000_000, body);
        let tampered = br#"{"event_type":"subscription.canceled"}"#;
        assert_eq!(
            verify_paddle_signature(
                SECRET,
                &header,
                tampered,
                1_700_000_010,
                DEFAULT_TOLERANCE_SECS
            ),
            Err(BillingError::SignatureMismatch)
        );
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let body = br#"{"a":1}"#;
        let header = sign(SECRET, 1_700_000_000, body);
        assert_eq!(
            verify_paddle_signature(
                "other",
                &header,
                body,
                1_700_000_005,
                DEFAULT_TOLERANCE_SECS
            ),
            Err(BillingError::SignatureMismatch)
        );
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let body = br#"{"a":1}"#;
        let header = sign(SECRET, 1_700_000_000, body);
        assert_eq!(
            verify_paddle_signature(SECRET, &header, body, 1_700_001_000, DEFAULT_TOLERANCE_SECS),
            Err(BillingError::StaleTimestamp)
        );
    }

    #[test]
    fn malformed_headers_are_rejected() {
        let body = br#"{}"#;
        for header in [
            "",
            "garbage",
            "ts=abc;h1=00",
            "h1=deadbeef",
            "ts=1700000000",
        ] {
            let result = verify_paddle_signature(
                SECRET,
                header,
                body,
                1_700_000_000,
                DEFAULT_TOLERANCE_SECS,
            );
            assert!(result.is_err(), "header should be rejected: {header:?}");
        }
    }

    #[test]
    fn odd_length_hex_is_rejected() {
        let body = br#"{}"#;
        let header = "ts=1700000000;h1=abc";
        assert_eq!(
            verify_paddle_signature(SECRET, header, body, 1_700_000_000, DEFAULT_TOLERANCE_SECS),
            Err(BillingError::MalformedSignature)
        );
    }

    #[test]
    fn decode_hex_rejects_non_hex_input() {
        assert_eq!(decode_hex("aéb"), None);
        assert_eq!(decode_hex("+f"), None);
        assert_eq!(decode_hex("-1"), None);
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("0g"), None);
        assert_eq!(decode_hex("00Ff7a"), Some(vec![0x00, 0xff, 0x7a]));
        assert_eq!(decode_hex(""), Some(vec![]));
    }

    #[test]
    fn non_ascii_signature_is_malformed_not_panic() {
        let body = br#"{}"#;
        for h1 in ["aéb", "+f", "é"] {
            let header = format!("ts=1700000000;h1={h1}");
            assert_eq!(
                verify_paddle_signature(
                    SECRET,
                    &header,
                    body,
                    1_700_000_000,
                    DEFAULT_TOLERANCE_SECS
                ),
                Err(BillingError::MalformedSignature),
                "h1 should be rejected: {h1:?}"
            );
        }
    }

    /// Sign over the exact `raw_ts` text, as the sender does.
    fn sign_raw(secret: &str, raw_ts: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(raw_ts.as_bytes());
        mac.update(b":");
        mac.update(body);
        let tag = mac.finalize().into_bytes();
        let hex: String = tag.iter().map(|b| format!("{b:02x}")).collect();
        format!("ts={raw_ts};h1={hex}")
    }

    #[test]
    fn mac_covers_raw_timestamp_text() {
        let body = br#"{"event_type":"subscription.created"}"#;
        let header = sign_raw(SECRET, "01700000000", body);
        assert_eq!(
            verify_paddle_signature(SECRET, &header, body, 1_700_000_010, DEFAULT_TOLERANCE_SECS),
            Ok(())
        );
        // A canonical ts must not verify a MAC made over a different spelling.
        let canonical = sign_raw(SECRET, "1700000000", body);
        let h1 = canonical.split_once(";h1=").unwrap().1;
        let respelled = format!("ts=01700000000;h1={h1}");
        assert_eq!(
            verify_paddle_signature(
                SECRET,
                &respelled,
                body,
                1_700_000_010,
                DEFAULT_TOLERANCE_SECS
            ),
            Err(BillingError::SignatureMismatch)
        );
    }

    #[test]
    fn signed_timestamp_forms_are_malformed() {
        let body = br#"{}"#;
        for raw_ts in ["+1700000000", "-1", " ", "17e8"] {
            let header = sign_raw(SECRET, raw_ts, body);
            assert_eq!(
                verify_paddle_signature(
                    SECRET,
                    &header,
                    body,
                    1_700_000_000,
                    DEFAULT_TOLERANCE_SECS
                ),
                Err(BillingError::MalformedSignature),
                "ts should be rejected: {raw_ts:?}"
            );
        }
    }

    #[test]
    fn parse_subscription_created_event() {
        let body = br#"{
            "event_id": "evt_123",
            "event_type": "subscription.created",
            "occurred_at": "2026-07-30T12:00:00Z",
            "data": {
                "id": "sub_abc",
                "customer_id": "cus_xyz",
                "status": "active",
                "items": [{ "price": { "id": "pri_pro" } }]
            }
        }"#;
        let event = parse_event(body).expect("parse");
        assert_eq!(event.event_type, "subscription.created");
        assert_eq!(event.subscription_id.as_deref(), Some("sub_abc"));
        assert_eq!(event.customer_id.as_deref(), Some("cus_xyz"));
        assert_eq!(event.plan.as_deref(), Some("pri_pro"));

        match action_for(&event) {
            ProvisioningAction::Provision {
                subscription_id,
                customer_id,
                plan,
            } => {
                assert_eq!(subscription_id, "sub_abc");
                assert_eq!(customer_id, "cus_xyz");
                assert_eq!(plan, "pri_pro");
            }
            other => panic!("expected Provision, got {other:?}"),
        }
    }

    #[test]
    fn cancellation_maps_to_suspend() {
        let body = br#"{"event_type":"subscription.canceled","data":{"id":"sub_abc"}}"#;
        let event = parse_event(body).expect("parse");
        assert_eq!(
            action_for(&event),
            ProvisioningAction::Suspend {
                subscription_id: "sub_abc".into()
            }
        );
    }

    #[test]
    fn unrelated_event_is_ignored() {
        let body = br#"{"event_type":"transaction.completed","data":{"id":"txn_1"}}"#;
        let event = parse_event(body).expect("parse");
        assert!(matches!(
            action_for(&event),
            ProvisioningAction::Ignore { .. }
        ));
    }

    #[test]
    fn non_json_body_is_malformed() {
        assert_eq!(
            parse_event(b"not json"),
            Err(BillingError::MalformedPayload)
        );
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        const TS: u64 = 1_700_000_000;

        fn verify(header: &str, body: &[u8]) -> Result<(), BillingError> {
            verify_paddle_signature(SECRET, header, body, TS, DEFAULT_TOLERANCE_SECS)
        }

        /// `header` with byte `at` replaced; `None` if unchanged or not UTF-8
        /// (such a header never reaches the verifier as `&str`).
        fn mutate(header: &str, at: usize, byte: u8) -> Option<String> {
            let mut bytes = header.as_bytes().to_vec();
            if bytes[at] == byte {
                return None;
            }
            bytes[at] = byte;
            String::from_utf8(bytes).ok()
        }

        proptest! {
            #[test]
            fn arbitrary_headers_never_panic_or_verify(
                header in any::<String>(),
                body in any::<Vec<u8>>(),
                now in any::<u64>(),
                tolerance in any::<u64>(),
            ) {
                let _ = parse_signature_header(&header);
                prop_assert!(verify_paddle_signature(SECRET, &header, &body, now, tolerance).is_err());
            }

            #[test]
            fn structured_headers_never_verify(
                ts in "[0-9]{0,21}",
                h1 in "[0-9a-fA-F]{0,80}",
                junk in "[ ;=a-z0-9]{0,16}",
                body in any::<Vec<u8>>(),
            ) {
                let header = format!("{junk};ts={ts};h1={h1}");
                prop_assert!(verify_paddle_signature(SECRET, &header, &body, TS, u64::MAX).is_err());
            }

            #[test]
            fn decode_hex_matches_reference(hex in any::<String>()) {
                let reference = (hex.len() % 2 == 0 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                    .then(|| {
                        (0..hex.len())
                            .step_by(2)
                            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                            .collect::<Vec<_>>()
                    });
                prop_assert_eq!(decode_hex(&hex), reference);
            }

            #[test]
            fn signed_input_round_trips(ts in 0..u64::MAX / 2, body in any::<Vec<u8>>()) {
                let header = sign(SECRET, ts, &body);
                prop_assert_eq!(
                    verify_paddle_signature(SECRET, &header, &body, ts, DEFAULT_TOLERANCE_SECS),
                    Ok(())
                );
                let h1 = header.split_once(";h1=").unwrap().1;
                let reordered = format!(" h1 = {h1} ; ts = {ts} ");
                prop_assert_eq!(
                    verify_paddle_signature(SECRET, &reordered, &body, ts, DEFAULT_TOLERANCE_SECS),
                    Ok(())
                );
            }

            #[test]
            fn body_mutation_fails(
                body in prop::collection::vec(any::<u8>(), 1..512),
                pick: usize,
                flip in 1..=u8::MAX,
            ) {
                let header = sign(SECRET, TS, &body);
                let mut tampered = body.clone();
                tampered[pick % body.len()] ^= flip;
                prop_assert_eq!(verify(&header, &tampered), Err(BillingError::SignatureMismatch));
            }

            #[test]
            fn ts_mutation_fails(body in any::<Vec<u8>>(), pick: usize, byte: u8) {
                let header = sign(SECRET, TS, &body);
                let at = "ts=".len() + pick % TS.to_string().len();
                if let Some(tampered) = mutate(&header, at, byte) {
                    prop_assert!(
                        verify_paddle_signature(SECRET, &tampered, &body, TS, u64::MAX).is_err(),
                        "accepted {tampered:?}"
                    );
                }
            }

            #[test]
            fn h1_mutation_fails(body in any::<Vec<u8>>(), pick: usize, byte: u8) {
                let header = sign(SECRET, TS, &body);
                let start = header.find(";h1=").unwrap() + ";h1=".len();
                let at = start + pick % (header.len() - start);
                // Hex is case-insensitive: an upper-cased digit is the same MAC.
                prop_assume!(header.as_bytes()[at].to_ascii_uppercase() != byte);
                if let Some(tampered) = mutate(&header, at, byte) {
                    prop_assert!(verify(&tampered, &body).is_err(), "accepted {tampered:?}");
                }
            }

            #[test]
            fn truncated_h1_fails(body in any::<Vec<u8>>(), keep in 0usize..32) {
                let header = sign(SECRET, TS, &body);
                let truncated = &header[..header.find(";h1=").unwrap() + ";h1=".len() + keep * 2];
                prop_assert_eq!(verify(truncated, &body), Err(BillingError::SignatureMismatch));
            }
        }
    }
}
