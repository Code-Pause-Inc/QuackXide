//! OAuth2 (RFC 6749) token exchange for background syncs.
//!
//! Interactive consent happens once at enrollment; workers then exchange the
//! stored refresh token for short-lived access tokens. Client secrets and
//! refresh tokens are held in zeroizing, redacted containers.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::ConnectorError;

/// A secret string: zeroized on drop, redacted in Debug.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[derive(Debug)]
pub struct OAuth2Config {
    pub token_url: String,
    pub client_id: String,
    pub client_secret: SecretString,
}

/// RFC 6749 §5.1 token response (unknown fields ignored). Tokens are
/// zeroized on drop and redacted in Debug.
#[derive(Deserialize)]
pub struct TokenResponse {
    pub access_token: SecretString,
    #[serde(default)]
    pub refresh_token: Option<SecretString>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub token_type: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// Form body for the refresh-token grant.
pub fn refresh_grant_form<'a>(
    config: &'a OAuth2Config,
    refresh_token: &'a str,
) -> Vec<(&'static str, &'a str)> {
    vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &config.client_id),
        ("client_secret", config.client_secret.expose()),
    ]
}

/// Form body for the client-credentials grant (RFC 6749 §4.4). `scope` is
/// optional per the RFC; SMART Backend Services requires it.
pub fn client_credentials_form<'a>(
    config: &'a OAuth2Config,
    scope: Option<&'a str>,
) -> Vec<(&'static str, &'a str)> {
    let mut form = vec![
        ("grant_type", "client_credentials"),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.expose()),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }
    form
}

/// Exchange a refresh token for a fresh access token.
pub async fn refresh_access_token(
    client: &reqwest::Client,
    config: &OAuth2Config,
    refresh_token: &SecretString,
) -> Result<TokenResponse, ConnectorError> {
    post_token_form(
        client,
        config,
        refresh_grant_form(config, refresh_token.expose()),
    )
    .await
}

/// Obtain an access token via the client-credentials grant.
pub async fn client_credentials_token(
    client: &reqwest::Client,
    config: &OAuth2Config,
    scope: Option<&str>,
) -> Result<TokenResponse, ConnectorError> {
    post_token_form(client, config, client_credentials_form(config, scope)).await
}

/// Shared token-endpoint exchange for every grant type.
async fn post_token_form(
    client: &reqwest::Client,
    config: &OAuth2Config,
    form: Vec<(&'static str, &str)>,
) -> Result<TokenResponse, ConnectorError> {
    let response = client
        .post(token_endpoint(&config.token_url)?)
        .form(&form)
        .send()
        .await
        .map_err(|e| ConnectorError::Http(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        // Never include the response body: error pages can echo credentials.
        return Err(ConnectorError::OAuth(format!(
            "token endpoint returned {status}"
        )));
    }

    parse_token_response(
        &response
            .bytes()
            .await
            .map_err(|e| ConnectorError::Http(e.to_string()))?,
    )
}

/// Credentials are only ever sent over TLS; plain HTTP is accepted for
/// loopback endpoints (local test servers) and nothing else.
fn token_endpoint(raw: &str) -> Result<reqwest::Url, ConnectorError> {
    let url = reqwest::Url::parse(raw)
        .map_err(|_| ConnectorError::OAuth("invalid token endpoint URL".into()))?;
    let loopback = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback => Ok(url),
        _ => Err(ConnectorError::OAuth(
            "token endpoint must use https".into(),
        )),
    }
}

pub fn parse_token_response(bytes: &[u8]) -> Result<TokenResponse, ConnectorError> {
    serde_json::from_slice(bytes)
        .map_err(|_| ConnectorError::OAuth("malformed token response".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuth2Config {
        OAuth2Config {
            token_url: "https://idp.example/token".into(),
            client_id: "client-1".into(),
            client_secret: SecretString::new("s3cret".into()),
        }
    }

    #[test]
    fn token_endpoint_requires_tls_off_loopback() {
        assert!(token_endpoint("https://idp.example/token").is_ok());
        assert!(token_endpoint("http://127.0.0.1:8080/token").is_ok());
        assert!(token_endpoint("http://[::1]:8080/token").is_ok());
        assert!(token_endpoint("http://localhost/token").is_ok());
        for bad in [
            "http://idp.example/token",
            "http://10.0.0.5/token",
            "ftp://idp.example/token",
            "not a url",
            "",
        ] {
            assert!(token_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn refresh_form_is_a_correct_rfc6749_grant() {
        let cfg = config();
        let form = refresh_grant_form(&cfg, "rt-123");
        assert!(form.contains(&("grant_type", "refresh_token")));
        assert!(form.contains(&("refresh_token", "rt-123")));
        assert!(form.contains(&("client_id", "client-1")));
    }

    #[test]
    fn client_credentials_form_is_a_correct_rfc6749_grant() {
        let cfg = config();
        let form = client_credentials_form(&cfg, Some("system/Observation.rs"));
        assert!(form.contains(&("grant_type", "client_credentials")));
        assert!(form.contains(&("client_id", "client-1")));
        assert!(form.contains(&("scope", "system/Observation.rs")));
        assert!(!form.iter().any(|(k, _)| *k == "refresh_token"));
    }

    #[test]
    fn client_credentials_scope_is_optional() {
        let cfg = config();
        let form = client_credentials_form(&cfg, None);
        assert!(!form.iter().any(|(k, _)| *k == "scope"));
        assert!(form.contains(&("grant_type", "client_credentials")));
    }

    #[test]
    fn token_response_parses_with_and_without_optional_fields() {
        let full = parse_token_response(
            br#"{"access_token":"at","refresh_token":"rt","expires_in":3600,"token_type":"bearer","x_extra":1}"#,
        )
        .expect("parse");
        assert_eq!(full.access_token.expose(), "at");
        assert_eq!(
            full.refresh_token.as_ref().map(SecretString::expose),
            Some("rt")
        );
        assert_eq!(full.expires_in, Some(3600));

        let minimal = parse_token_response(br#"{"access_token":"only"}"#).expect("parse");
        assert_eq!(minimal.access_token.expose(), "only");
        assert!(minimal.refresh_token.is_none());

        assert!(parse_token_response(b"not json").is_err());
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let cfg = config();
        let debugged = format!("{cfg:?}");
        assert!(!debugged.contains("s3cret"));
        assert!(debugged.contains("<redacted>"));
    }

    #[test]
    fn token_response_is_redacted_in_debug() {
        let tokens = parse_token_response(
            br#"{"access_token":"at-SECRET-1","refresh_token":"rt-SECRET-2","expires_in":60}"#,
        )
        .expect("parse");
        let debugged = format!("{tokens:?}");
        assert!(!debugged.contains("SECRET"), "{debugged}");
        assert!(debugged.contains("<redacted>"));
        assert!(debugged.contains("60"));
    }
}
