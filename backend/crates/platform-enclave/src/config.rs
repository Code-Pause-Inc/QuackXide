//! The deployment configuration bound into attestation (ADR 0010 "Binding
//! v2", ADR 0005): the names a workload reports in its token, their digest,
//! and the policy a verifier holds them to. No environment access here: the
//! browser module computes the same from a verified token.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

/// The configuration names bound into attestation, in digest order.
pub const BOUND_CONFIG_NAMES: [&str; 4] = [
    "TEE_ATTESTATION_REQUIRED",
    "FEATURE_ZK_ENABLED",
    "RESEARCH_MIN_COHORT_SIZE",
    "RESEARCH_DOMINANCE_PERCENT",
];

/// The lowest p% rule `p` any build accepts: the default, below which a
/// dominated total is released (ADR 0015).
pub const DOMINANCE_PERCENT_FLOOR: u64 = 10;

/// `name`'s value as the platform reads it: trimmed, and unset when empty
/// (`platform-config`'s rule).
fn bound_value(lookup: &impl Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    lookup(name)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// The bound names that are set, with their values as the platform reads
/// them: what a workload reports in its token.
pub fn bound_env(lookup: impl Fn(&str) -> Option<String>) -> BTreeMap<String, String> {
    BOUND_CONFIG_NAMES
        .iter()
        .filter_map(|name| bound_value(&lookup, name).map(|v| ((*name).to_owned(), v)))
        .collect()
}

/// ADR 0010's `config-digest`: SHA-256 over each set bound name, in order, as
/// `u16 len(name) ‖ name ‖ u32 len(value) ‖ value` (big-endian). Unset names
/// are left out.
pub fn config_digest(lookup: impl Fn(&str) -> Option<String>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for name in BOUND_CONFIG_NAMES {
        if let Some(value) = bound_value(&lookup, name) {
            let name_len = u16::try_from(name.len()).expect("bound names are short");
            // Values come from the environment or from a token capped at
            // `MAX_TOKEN_BYTES`, never near 4 GiB.
            let value_len = u32::try_from(value.len()).expect("bound values are short");
            hasher.update(name_len.to_be_bytes());
            hasher.update(name.as_bytes());
            hasher.update(value_len.to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hasher.finalize().into()
}

/// What a verifier accepts in a deployment's bound configuration: the
/// attestation requirement and the ZK gate on (unset means on), and a
/// minimum cohort size and p% rule `p` of at least their floors (unset
/// means the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigPolicy {
    pub allow_attestation_off: bool,
    pub min_cohort_floor: u64,
}

/// A bound value the policy refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigRefused {
    #[error("{0} loosens a control")]
    Loosens(&'static str),
    #[error("{0} is not a value the platform reads")]
    Unreadable(&'static str),
}

impl ConfigPolicy {
    /// Release builds.
    pub const RELEASE: Self = Self {
        allow_attestation_off: false,
        min_cohort_floor: 11,
    };
    /// Development builds, which run on the simulated TEE: simulated tokens
    /// never satisfy required attestation, and its cohorts are built for k = 2.
    pub const SIMULATOR: Self = Self {
        allow_attestation_off: true,
        min_cohort_floor: 2,
    };

    pub fn check(&self, lookup: impl Fn(&str) -> Option<String>) -> Result<(), ConfigRefused> {
        let [attestation, zk, min_cohort, dominance] = BOUND_CONFIG_NAMES;
        if !flag(&lookup, attestation)? && !self.allow_attestation_off {
            return Err(ConfigRefused::Loosens(attestation));
        }
        if !flag(&lookup, zk)? {
            return Err(ConfigRefused::Loosens(zk));
        }
        at_least(&lookup, min_cohort, self.min_cohort_floor)?;
        at_least(&lookup, dominance, DOMINANCE_PERCENT_FLOOR)
    }
}

/// An integer as `platform-config` reads it; unset is its default, which
/// meets the floor.
fn at_least(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    floor: u64,
) -> Result<(), ConfigRefused> {
    let Some(raw) = bound_value(lookup, name) else {
        return Ok(());
    };
    let value: u64 = raw.parse().map_err(|_| ConfigRefused::Unreadable(name))?;
    if value < floor {
        return Err(ConfigRefused::Loosens(name));
    }
    Ok(())
}

/// A boolean as `platform-config` reads it; unset is true (both bound flags
/// default to on).
fn flag(
    lookup: &impl Fn(&str) -> Option<String>,
    name: &'static str,
) -> Result<bool, ConfigRefused> {
    match bound_value(lookup, name)
        .map(|v| v.to_ascii_lowercase())
        .as_deref()
    {
        None | Some("1" | "true" | "on" | "yes") => Ok(true),
        Some("0" | "false" | "off" | "no") => Ok(false),
        Some(_) => Err(ConfigRefused::Unreadable(name)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    fn hex(bytes: [u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn digest_layout_is_pinned() {
        // python3: sha256(b"".join(pack(">H",len(n))+n+pack(">I",len(v))+v
        //   for n, v in the three names set to "true", "true", "11"))
        let digest = config_digest(env(&[
            ("TEE_ATTESTATION_REQUIRED", "true"),
            ("FEATURE_ZK_ENABLED", "true"),
            ("RESEARCH_MIN_COHORT_SIZE", "11"),
        ]));
        assert_eq!(
            hex(digest),
            "c49e446ca65465262054e95c10b6ada0acee968e1b64e356ef460582e2d8b97b"
        );
    }

    #[test]
    fn unset_empty_and_whitespace_names_are_left_out() {
        let empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex(config_digest(|_| None)), empty_sha256);
        let blank = env(&[
            ("TEE_ATTESTATION_REQUIRED", ""),
            ("FEATURE_ZK_ENABLED", "  "),
        ]);
        assert_eq!(hex(config_digest(blank)), empty_sha256);
    }

    #[test]
    fn digest_covers_the_trimmed_value() {
        assert_eq!(
            config_digest(env(&[("RESEARCH_MIN_COHORT_SIZE", " 11 ")])),
            config_digest(env(&[("RESEARCH_MIN_COHORT_SIZE", "11")])),
        );
    }

    #[test]
    fn bound_env_keeps_only_set_bound_names() {
        let reported = bound_env(env(&[
            ("RESEARCH_MIN_COHORT_SIZE", " 2 "),
            ("FEATURE_ZK_ENABLED", ""),
            ("PATH", "/bin"),
        ]));
        assert_eq!(
            reported.into_iter().collect::<Vec<_>>(),
            [("RESEARCH_MIN_COHORT_SIZE".to_owned(), "2".to_owned())]
        );
    }

    #[test]
    fn digest_changes_when_a_name_appears() {
        assert_ne!(
            config_digest(|_| None),
            config_digest(env(&[("FEATURE_ZK_ENABLED", "true")])),
        );
    }

    #[test]
    fn release_policy() {
        let check = |pairs: &[(&str, &str)]| ConfigPolicy::RELEASE.check(env(pairs));
        assert_eq!(check(&[]), Ok(()));
        assert_eq!(
            check(&[("TEE_ATTESTATION_REQUIRED", "false")]),
            Err(ConfigRefused::Loosens("TEE_ATTESTATION_REQUIRED"))
        );
        for on in ["ON", "yes", "1", "True"] {
            assert_eq!(check(&[("FEATURE_ZK_ENABLED", on)]), Ok(()), "{on}");
        }
        assert_eq!(
            check(&[("RESEARCH_MIN_COHORT_SIZE", "10")]),
            Err(ConfigRefused::Loosens("RESEARCH_MIN_COHORT_SIZE"))
        );
        assert_eq!(check(&[("RESEARCH_MIN_COHORT_SIZE", "11")]), Ok(()));
        assert_eq!(check(&[("RESEARCH_MIN_COHORT_SIZE", "+11")]), Ok(()));
    }

    #[test]
    fn simulator_policy() {
        let check = |pairs: &[(&str, &str)]| ConfigPolicy::SIMULATOR.check(env(pairs));
        assert_eq!(check(&[("TEE_ATTESTATION_REQUIRED", "false")]), Ok(()));
        assert_eq!(
            check(&[("FEATURE_ZK_ENABLED", "off")]),
            Err(ConfigRefused::Loosens("FEATURE_ZK_ENABLED"))
        );
        assert_eq!(check(&[("RESEARCH_MIN_COHORT_SIZE", "2")]), Ok(()));
        assert_eq!(
            check(&[("RESEARCH_MIN_COHORT_SIZE", "1")]),
            Err(ConfigRefused::Loosens("RESEARCH_MIN_COHORT_SIZE"))
        );
    }

    #[test]
    fn dominance_percent_is_bound_and_held_to_its_floor() {
        let p = |raw: &'static str| {
            move |name: &str| (name == "RESEARCH_DOMINANCE_PERCENT").then(|| raw.to_owned())
        };
        assert_eq!(bound_env(p("10")).len(), 1);
        assert_ne!(config_digest(p("10")), config_digest(|_| None));
        for policy in [ConfigPolicy::RELEASE, ConfigPolicy::SIMULATOR] {
            assert_eq!(
                policy.check(p("9")),
                Err(ConfigRefused::Loosens("RESEARCH_DOMINANCE_PERCENT"))
            );
            assert_eq!(policy.check(p("10")), Ok(()));
            assert_eq!(policy.check(p("25")), Ok(()));
            assert_eq!(
                policy.check(p("ten")),
                Err(ConfigRefused::Unreadable("RESEARCH_DOMINANCE_PERCENT"))
            );
        }
    }

    #[test]
    fn unparseable_values_fail() {
        for raw in ["11.0", "0x0b", "eleven"] {
            assert_eq!(
                ConfigPolicy::RELEASE.check(env(&[("RESEARCH_MIN_COHORT_SIZE", raw)])),
                Err(ConfigRefused::Unreadable("RESEARCH_MIN_COHORT_SIZE")),
                "{raw}"
            );
        }
        assert_eq!(
            ConfigPolicy::RELEASE.check(env(&[("FEATURE_ZK_ENABLED", "maybe")])),
            Err(ConfigRefused::Unreadable("FEATURE_ZK_ENABLED"))
        );
    }

    #[test]
    fn whitespace_is_unset() {
        assert_eq!(
            ConfigPolicy::RELEASE.check(env(&[("TEE_ATTESTATION_REQUIRED", "  ")])),
            Ok(())
        );
    }
}
