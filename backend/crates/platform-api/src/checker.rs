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
use platform_enclave::bundle::{VerifiedBundle, verify_bundle};
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

/// The flags each command takes; any other is refused, so a misspelt trust
/// flag cannot fall back to the defaults unnoticed.
const VERIFY_FLAGS: &[&str] = &["--api", "--issuer", "--jwks-url", "--image-digest"];
const SEAL_QUERY_FLAGS: &[&str] = &[
    "--api",
    "--issuer",
    "--jwks-url",
    "--image-digest",
    "--researcher",
    "--grant",
    "--steward",
    "--connector",
    "--recipient-key",
    "--nonce",
    "--sql",
];

/// The largest response body the checker reads: a bundle or a key set is a
/// few tens of KiB (`MAX_TOKEN_BYTES` caps the token at 16 KiB).
const MAX_FETCH_BYTES: usize = 256 * 1024;

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
    fn parse(args: &[String], allowed: &[&str]) -> Result<Self, String> {
        let mut pairs = Vec::new();
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            if !allowed.contains(&flag.as_str()) {
                return Err(format!("unexpected {flag}\n{USAGE}"));
            }
            let value = it
                .next()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
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

/// Fetch the bundle for a fresh challenge and the key set, and verify.
async fn attest(
    http: &reqwest::Client,
    api: &str,
    trust: &Trust,
) -> Result<(AttestationBundle, VerifiedBundle), String> {
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
    let verified = verify_bundle(&bundle, &challenge, &verifier, compiled_config_policy())
        .map_err(|e| e.to_string())?;
    Ok((bundle, verified))
}

/// The HTTP client the binary uses: `https` only in a release build, on
/// redirects too, so "over `https`" holds past the first hop.
pub fn client() -> Result<reqwest::Client, String> {
    client_for(!cfg!(feature = "dev"))
}

/// [`client`] with the `https`-only rule passed in: tests build with `dev`.
fn client_for(https_only: bool) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(https_only)
        .build()
        .map_err(|e| format!("HTTP client: {e}"))
}

/// GET `url` as JSON, reading at most [`MAX_FETCH_BYTES`] of it.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    http: &reqwest::Client,
    url: &str,
) -> Result<T, String> {
    let too_large = || {
        format!(
            "{url} returned more than {MAX_FETCH_BYTES} bytes, larger than any bundle or key set"
        )
    };
    let mut response = http
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| format!("{url} is unreachable or refused"))?;
    if response
        .content_length()
        .is_some_and(|len| len > MAX_FETCH_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| format!("{url} broke off its response"))?
    {
        if body.len() + chunk.len() > MAX_FETCH_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| format!("{url} did not return the expected JSON"))
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
    let allowed: &[&str] = match command.as_str() {
        "verify" => VERIFY_FLAGS,
        "seal-query" => SEAL_QUERY_FLAGS,
        _ => &[],
    };
    let flags = Flags::parse(rest, allowed)?;
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
                verified.key_id, verified.image_digest,
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
    use platform_enclave::config::ConfigPolicy;

    use super::*;
    use crate::key_release::{EnclaveIdentity, attestation_bundle};

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn release_trust(list: &[&str]) -> Result<Trust, String> {
        let flags = Flags::parse(&args(list), VERIFY_FLAGS).unwrap();
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
        let flags =
            Flags::parse(&args(&["--jwks-url", "http://other/jwks"]), VERIFY_FLAGS).unwrap();
        let trust = trust_from(&flags, "http://api", Some(defaults)).unwrap();
        assert_eq!(trust.issuer, "urn:sim");
        assert_eq!(trust.jwks_url, "http://other/jwks");
        assert_eq!(trust.image_digests, ["sha256:sim"]);
    }

    #[test]
    fn a_flag_given_twice_is_refused() {
        assert!(Flags::parse(&args(&["--api", "a", "--api", "b"]), VERIFY_FLAGS).is_err());
    }

    /// A misspelt trust flag must not fall back to the defaults unnoticed.
    #[test]
    fn an_unknown_flag_is_refused() {
        let err = Flags::parse(&args(&["--api", "a", "--imagedigest", "x"]), VERIFY_FLAGS)
            .err()
            .expect("refused");
        assert!(err.contains("--imagedigest"), "{err}");
        assert!(Flags::parse(&args(&["--sql", "q"]), VERIFY_FLAGS).is_err());
        assert!(Flags::parse(&args(&["--sql", "q"]), SEAL_QUERY_FLAGS).is_ok());
    }

    /// A hostile endpoint cannot make the checker buffer an unbounded body.
    #[tokio::test]
    async fn an_oversized_response_is_refused() {
        let body = "x".repeat(MAX_FETCH_BYTES + 1);
        let router = axum::Router::new().route(
            "/big",
            axum::routing::get(move || {
                let body = body.clone();
                async move { body }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/big", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let err = fetch_json::<serde_json::Value>(&reqwest::Client::new(), &url)
            .await
            .unwrap_err();
        assert!(err.contains("larger"), "{err}");
    }

    /// An `HPK1` request key is refused even when the bundle is otherwise
    /// well formed (ADR 0010 "No downgrade").
    #[test]
    fn an_hpk1_request_key_is_refused() {
        let identity = EnclaveIdentity::generate();
        let mut bundle = attestation_bundle(&identity, "token".to_owned());
        let hpk1 = platform_crypto::TenantKeypair::generate(EnvelopeSuite::Hpk1).public_key();
        bundle.request_key = KeyWire::from_public_key(&hpk1);
        let verifier = test_verifier();
        let err = verify_bundle(&bundle, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not HPK2"), "{err}");
    }

    #[test]
    fn a_malformed_bundle_field_is_refused() {
        let identity = EnclaveIdentity::generate();
        let verifier = test_verifier();
        let mut bad_signing = attestation_bundle(&identity, "token".to_owned());
        bad_signing.signing_keys.ed25519 = "!!".to_owned();
        assert!(
            verify_bundle(&bad_signing, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
                .unwrap_err()
                .to_string()
                .contains("signing keys")
        );
        let mut bad_tls = attestation_bundle(&identity, "token".to_owned());
        bad_tls.tls_spki_sha256 = Some("AAAA".to_owned());
        assert!(
            verify_bundle(&bad_tls, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
                .unwrap_err()
                .to_string()
                .contains("TLS")
        );
        let mut bad_version = attestation_bundle(&identity, "token".to_owned());
        bad_version.version = 2;
        assert!(
            verify_bundle(&bad_version, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
                .unwrap_err()
                .to_string()
                .contains("unsupported bundle version 2")
        );
        let mut bad_request = attestation_bundle(&identity, "token".to_owned());
        bad_request.request_key.public_key = "!!".to_owned();
        assert!(
            verify_bundle(&bad_request, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
                .unwrap_err()
                .to_string()
                .contains("malformed request key")
        );
        let mut bad_kms = attestation_bundle(&identity, "token".to_owned());
        bad_kms.kms_public_key = Some("!!".to_owned());
        assert!(
            verify_bundle(&bad_kms, &[0; 32], &verifier, ConfigPolicy::SIMULATOR)
                .unwrap_err()
                .to_string()
                .contains("malformed KMS public key")
        );
    }

    /// `seal-query` refuses a bad researcher, recipient key or nonce before
    /// it contacts the deployment.
    #[tokio::test]
    async fn seal_query_refuses_bad_arguments_before_attesting() {
        let key = |suite| {
            URL_SAFE_NO_PAD.encode(
                platform_crypto::TenantKeypair::generate(suite)
                    .public_key()
                    .to_raw(),
            )
        };
        let (hpk2, hpk1) = (key(EnvelopeSuite::Hpk2), key(EnvelopeSuite::Hpk1));
        let nonce = URL_SAFE_NO_PAD.encode(fresh_nonce());
        let short_nonce = URL_SAFE_NO_PAD.encode(&fresh_nonce()[..16]);
        let researcher = "6f2c8a2e-1111-4222-8333-444455556666";
        let seal = |researcher: &str, key: &str, nonce: &str| {
            let list = args(&[
                "seal-query",
                "--api",
                "http://127.0.0.1:1",
                "--researcher",
                researcher,
                "--grant",
                "g",
                "--steward",
                researcher,
                "--connector",
                "c",
                "--recipient-key",
                key,
                "--nonce",
                nonce,
                "--sql",
                "SELECT 1",
            ]);
            let defaults = Trust {
                issuer: "urn:sim".to_owned(),
                jwks_url: "http://127.0.0.1:1/jwks".to_owned(),
                image_digests: vec!["sha256:sim".to_owned()],
            };
            async move {
                run_with(&list, &reqwest::Client::new(), Some(defaults))
                    .await
                    .unwrap_err()
            }
        };
        for (r, k, n, want) in [
            (
                "not-a-uuid",
                &*hpk2,
                &*nonce,
                "--researcher is not a tenant id",
            ),
            (
                researcher,
                "!!",
                &nonce,
                "--recipient-key is not a raw HPK2",
            ),
            (
                researcher,
                &hpk1,
                &nonce,
                "--recipient-key is not a raw HPK2",
            ),
            (researcher, &hpk2, "!!", "--nonce must be 32 bytes"),
            (researcher, &hpk2, &short_nonce, "--nonce must be 32 bytes"),
            // Valid arguments get as far as fetching the bundle.
            (researcher, &hpk2, &nonce, "attestation bundle"),
        ] {
            let err = seal(r, k, n).await;
            assert!(err.contains(want), "{want}: {err}");
        }
    }

    /// A release build's client refuses plain `http`.
    #[tokio::test]
    async fn the_release_client_refuses_http() {
        let router = axum::Router::new().route("/k", axum::routing::get(|| async { "{}" }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/k", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let fetch = |https_only| {
            let url = url.clone();
            async move { fetch_json::<serde_json::Value>(&client_for(https_only).unwrap(), &url).await }
        };
        assert!(fetch(true).await.is_err());
        assert!(
            fetch(false).await.is_ok(),
            "the same server answers over http"
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
