//! `enclave-check`: checks a deployment's enclave as the researcher's browser
//! does (ADR 0010 "Browser verification") and seals research queries to it.
//! It fetches the attestation key set itself, never from the API, and seals
//! nothing unless every check passes.
//!
//! A release build compiles in no trust anchors: no production issuer,
//! key-set URL or image digest exists until P49 and P50, so whoever checks a
//! deployment supplies them, over `https`. A `dev` build defaults to the
//! simulator's.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use platform_core::TenantId;
use platform_crypto::{EnvelopeSuite, SuitePolicy};
use platform_enclave::config::ConfigPolicy;
use platform_enclave::evidence::{BoundKeys, VerifiedEnclave, verify_evidence};
use platform_enclave::fresh_nonce;
use platform_enclave::token::{BROWSER_ATTESTATION_AUDIENCE, JwkSet, ReleasePolicy, TokenVerifier};
use zeroize::Zeroizing;

use crate::key_release::{AttestationBundle, KeyWire, compiled_config_policy, decode_b64url_32};
use crate::sealed::{SealedQueryPlaintext, seal_query};

const USAGE: &str = "usage:
  enclave-check verify --api <url> [trust]
  enclave-check seal-query --api <url> --researcher <uuid> --grant <id> --steward <uuid>
      --connector <slug> --recipient-key <base64url raw HPK2> --nonce <base64url 32 bytes>
      --sql <text> [trust]
  enclave-check keygen                      (dev builds only)
trust: --issuer <iss> --jwks-url <url> --image-digest <sha256:...> (repeatable);
       required, over https, in a release build";

/// Who signs attestation tokens and which images are allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trust {
    pub issuer: String,
    pub jwks_url: String,
    pub image_digests: Vec<String>,
}

/// The simulator's trust anchors, a `dev` build's defaults.
#[cfg(feature = "dev")]
fn dev_trust() -> Trust {
    use platform_enclave::simulated_token::{DEFAULT_SIM_ISSUER, SIMULATED_IMAGE_DIGEST};
    Trust {
        issuer: DEFAULT_SIM_ISSUER.to_owned(),
        jwks_url: format!("{DEFAULT_SIM_ISSUER}/jwks"),
        image_digests: vec![SIMULATED_IMAGE_DIGEST.to_owned()],
    }
}

/// Parsed flags: each flag once, except `--image-digest`.
struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut pairs = Vec::new();
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let value = it
                .next()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
            if !flag.starts_with("--") {
                return Err(format!("unexpected {flag}\n{USAGE}"));
            }
            if flag != "--image-digest" && pairs.iter().any(|(f, _)| f == flag) {
                return Err(format!("{flag} given twice"));
            }
            pairs.push((flag.clone(), value.clone()));
        }
        Ok(Self(pairs))
    }

    fn get(&self, flag: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(f, _)| f == flag)
            .map(|(_, v)| v.as_str())
    }

    fn require(&self, flag: &str) -> Result<&str, String> {
        self.get(flag)
            .ok_or_else(|| format!("{flag} is required\n{USAGE}"))
    }

    fn all(&self, flag: &str) -> Vec<String> {
        self.0
            .iter()
            .filter(|(f, _)| f == flag)
            .map(|(_, v)| v.clone())
            .collect()
    }
}

/// The trust anchors from `flags` over `defaults` (`None` in a release
/// build, where all three are required and URLs must be `https`). `api` is
/// held to the same rule.
fn trust_from(flags: &Flags, api: &str, defaults: Option<Trust>) -> Result<Trust, String> {
    let digests = flags.all("--image-digest");
    let trust = match defaults {
        Some(d) => Trust {
            issuer: flags.get("--issuer").map_or(d.issuer, str::to_owned),
            jwks_url: flags.get("--jwks-url").map_or(d.jwks_url, str::to_owned),
            image_digests: if digests.is_empty() {
                d.image_digests
            } else {
                digests
            },
        },
        None => {
            if digests.is_empty() {
                return Err(format!("--image-digest is required\n{USAGE}"));
            }
            for url in [api, flags.require("--jwks-url")?] {
                if !url.starts_with("https://") {
                    return Err(format!("{url} is not https"));
                }
            }
            Trust {
                issuer: flags.require("--issuer")?.to_owned(),
                jwks_url: flags.require("--jwks-url")?.to_owned(),
                image_digests: digests,
            }
        }
    };
    Ok(trust)
}

/// Decode `bundle`'s keys and run [`verify_evidence`] against `challenge`.
pub fn verify_bundle(
    bundle: &AttestationBundle,
    challenge: &[u8; 32],
    verifier: &TokenVerifier,
    policy: ConfigPolicy,
) -> Result<VerifiedEnclave, String> {
    if bundle.version != 1 {
        return Err(format!("unsupported bundle version {}", bundle.version));
    }
    // Either suite parses here; `verify_evidence` refuses all but HPK2.
    let request_key = bundle
        .request_key
        .to_public_key(SuitePolicy::DEVELOPMENT)
        .map_err(|_| "malformed request key in the bundle".to_owned())?;
    let signing = bundle
        .signing_keys
        .to_verifying_keys()
        .map_err(|_| "malformed signing keys in the bundle".to_owned())?;
    let kms_public_key = match &bundle.kms_public_key {
        None => Vec::new(),
        Some(b64) => URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| "malformed KMS public key in the bundle".to_owned())?,
    };
    let tls_spki_sha256 = match &bundle.tls_spki_sha256 {
        None => None,
        Some(b64) => {
            Some(decode_b64url_32(b64).ok_or("malformed TLS key digest in the bundle".to_owned())?)
        }
    };
    let keys = BoundKeys {
        request_key: request_key.to_framed(),
        signing_ed25519: signing.ed25519_bytes(),
        signing_ml_dsa_65: signing.ml_dsa_65_bytes(),
        kms_public_key,
        tls_spki_sha256,
    };
    verify_evidence(
        verifier,
        &bundle.token,
        challenge,
        &keys,
        &bundle.key_id,
        policy,
    )
    .map_err(|e| e.to_string())
}

/// Fetch the bundle for a fresh challenge and the key set, and verify.
async fn attest(
    http: &reqwest::Client,
    api: &str,
    trust: &Trust,
) -> Result<(AttestationBundle, VerifiedEnclave), String> {
    let challenge = fresh_nonce();
    let url = format!(
        "{}/api/v1/attestation?nonce={}",
        api.trim_end_matches('/'),
        URL_SAFE_NO_PAD.encode(challenge)
    );
    let bundle: AttestationBundle = fetch_json(http, &url)
        .await
        .map_err(|e| format!("attestation bundle: {e}"))?;
    let jwks: JwkSet = fetch_json(http, &trust.jwks_url)
        .await
        .map_err(|e| format!("attestation key set: {e}"))?;
    let verifier = TokenVerifier::new(
        &jwks,
        &trust.issuer,
        BROWSER_ATTESTATION_AUDIENCE,
        ReleasePolicy {
            allowed_image_digests: trust.image_digests.clone(),
        },
    )
    .map_err(|e| format!("attestation key set: {e}"))?;
    let verified = verify_bundle(&bundle, &challenge, &verifier, compiled_config_policy())?;
    Ok((bundle, verified))
}

async fn fetch_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let response = http
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| format!("{url} is unreachable or refused"))?;
    response
        .json()
        .await
        .map_err(|_| format!("{url} did not return the expected JSON"))
}

/// Run `enclave-check` with `args` (without the program name). `Ok` is what
/// to print; `Err` names what failed.
pub async fn run(args: &[String], http: &reqwest::Client) -> Result<String, String> {
    #[cfg(feature = "dev")]
    let defaults = Some(dev_trust());
    #[cfg(not(feature = "dev"))]
    let defaults = None;
    run_with(args, http, defaults).await
}

async fn run_with(
    args: &[String],
    http: &reqwest::Client,
    defaults: Option<Trust>,
) -> Result<String, String> {
    let (command, rest) = args.split_first().ok_or_else(|| USAGE.to_owned())?;
    let flags = Flags::parse(rest)?;
    match command.as_str() {
        "verify" => {
            let api = flags.require("--api")?;
            let trust = trust_from(&flags, api, defaults)?;
            let (_, verified) = attest(http, api, &trust).await?;
            Ok(format!(
                "ok key_id={}\n\
                 checks 1-5 passed: signature, platform, image {}, challenge, binding and configuration\n\
                 not checked: TLS key binding (needs P67)\n\
                 not checked: served frontend digest (needs P49)",
                verified.key_id,
                verified.token.image_digest(),
            ))
        }
        "seal-query" => {
            let api = flags.require("--api")?;
            let trust = trust_from(&flags, api, defaults)?;
            let researcher: TenantId = flags
                .require("--researcher")?
                .parse()
                .map_err(|_| "--researcher is not a tenant id".to_owned())?;
            let recipient = KeyWire {
                suite: EnvelopeSuite::Hpk2.id().to_owned(),
                public_key: flags.require("--recipient-key")?.to_owned(),
            };
            recipient
                .to_public_key(SuitePolicy::only(EnvelopeSuite::Hpk2))
                .map_err(|_| "--recipient-key is not a raw HPK2 public key".to_owned())?;
            decode_b64url_32(flags.require("--nonce")?)
                .ok_or("--nonce must be 32 bytes of base64url".to_owned())?;
            let plaintext = SealedQueryPlaintext {
                steward_tenant: flags.require("--steward")?.to_owned(),
                connector: flags.require("--connector")?.to_owned(),
                sql: Zeroizing::new(flags.require("--sql")?.to_owned()),
                request_nonce: flags.require("--nonce")?.to_owned(),
                recipient_key: recipient,
            };
            let grant = flags.require("--grant")?;
            let (bundle, verified) = attest(http, api, &trust).await?;
            let request_key = bundle
                .request_key
                .to_public_key(SuitePolicy::only(EnvelopeSuite::Hpk2))
                .map_err(|_| "the bundle's request key is not HPK2".to_owned())?;
            let request = seal_query(
                &request_key,
                &verified.key_id,
                researcher,
                grant,
                &plaintext,
            )
            .map_err(|e| format!("sealing failed: {e}"))?;
            serde_json::to_string(&request).map_err(|e| e.to_string())
        }
        #[cfg(feature = "dev")]
        "keygen" => {
            let keypair = platform_crypto::TenantKeypair::generate(EnvelopeSuite::Hpk2);
            let private = keypair.to_private_key_bytes();
            Ok(serde_json::json!({
                "private_key": URL_SAFE_NO_PAD.encode(private.expose()),
                "public_key": URL_SAFE_NO_PAD.encode(keypair.public_key().to_raw()),
            })
            .to_string())
        }
        _ => Err(USAGE.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_release::EnclaveIdentity;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn release_trust(list: &[&str]) -> Result<Trust, String> {
        let flags = Flags::parse(&args(list)).unwrap();
        let api = flags
            .get("--api")
            .unwrap_or("https://api.example")
            .to_owned();
        trust_from(&flags, &api, None)
    }

    #[test]
    fn a_release_build_requires_every_trust_anchor() {
        let full = [
            "--issuer",
            "https://iss.example",
            "--jwks-url",
            "https://keys.example/jwks",
            "--image-digest",
            "sha256:aa",
        ];
        assert!(release_trust(&full).is_ok());
        for drop in ["--issuer", "--jwks-url", "--image-digest"] {
            let i = full.iter().position(|f| *f == drop).unwrap();
            let without: Vec<&str> = full
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i && *j != i + 1)
                .map(|(_, f)| *f)
                .collect();
            assert!(release_trust(&without).is_err(), "{drop}");
        }
    }

    #[test]
    fn a_release_build_requires_https() {
        let http_keys = [
            "--issuer",
            "https://iss.example",
            "--jwks-url",
            "http://keys.example/jwks",
            "--image-digest",
            "sha256:aa",
        ];
        assert!(release_trust(&http_keys).unwrap_err().contains("not https"));
        let http_api = [
            "--api",
            "http://api.example",
            "--issuer",
            "https://iss.example",
            "--jwks-url",
            "https://keys.example/jwks",
            "--image-digest",
            "sha256:aa",
        ];
        assert!(release_trust(&http_api).unwrap_err().contains("not https"));
    }

    #[test]
    fn dev_defaults_apply_and_can_be_overridden() {
        let defaults = Trust {
            issuer: "urn:sim".to_owned(),
            jwks_url: "http://sim/jwks".to_owned(),
            image_digests: vec!["sha256:sim".to_owned()],
        };
        let flags = Flags::parse(&args(&["--jwks-url", "http://other/jwks"])).unwrap();
        let trust = trust_from(&flags, "http://api", Some(defaults)).unwrap();
        assert_eq!(trust.issuer, "urn:sim");
        assert_eq!(trust.jwks_url, "http://other/jwks");
        assert_eq!(trust.image_digests, ["sha256:sim"]);
    }

    #[test]
    fn a_flag_given_twice_is_refused() {
        assert!(Flags::parse(&args(&["--api", "a", "--api", "b"])).is_err());
    }

    /// An `HPK1` request key is refused even when the bundle is otherwise
    /// well formed (ADR 0010 "No downgrade").
    #[test]
    fn an_hpk1_request_key_is_refused() {
        let identity = EnclaveIdentity::generate();
        let mut bundle = AttestationBundle::new(&identity, "token".to_owned());
        let hpk1 = platform_crypto::TenantKeypair::generate(EnvelopeSuite::Hpk1).public_key();
        bundle.request_key = KeyWire::from_public_key(&hpk1);
        let verifier = test_verifier();
        let err = verify_bundle(&bundle, &[0; 32], &verifier, ConfigPolicy::SIMULATOR).unwrap_err();
        assert!(err.contains("not HPK2"), "{err}");
    }

    #[test]
    fn a_malformed_bundle_field_is_refused() {
        let identity = EnclaveIdentity::generate();
        let verifier = test_verifier();
        let mut bad_signing = AttestationBundle::new(&identity, "token".to_owned());
        bad_signing.signing_keys.ed25519 = "!!".to_owned();
        assert!(
            verify_bundle(&bad_signing, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
                .unwrap_err()
                .contains("signing keys")
        );
        let mut bad_tls = AttestationBundle::new(&identity, "token".to_owned());
        bad_tls.tls_spki_sha256 = Some("AAAA".to_owned());
        assert!(
            verify_bundle(&bad_tls, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
                .unwrap_err()
                .contains("TLS")
        );
    }

    fn test_verifier() -> TokenVerifier {
        let signer = platform_enclave::simulated_token::TokenSigner::generate(
            "urn:test",
            platform_enclave::simulated_token::SimulatedClaims::default(),
        );
        TokenVerifier::new(
            &signer.jwks(),
            "urn:test",
            BROWSER_ATTESTATION_AUDIENCE,
            ReleasePolicy {
                allowed_image_digests: Vec::new(),
            },
        )
        .unwrap()
    }
}
