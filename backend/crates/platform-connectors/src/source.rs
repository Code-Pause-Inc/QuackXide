//! Connector sources: where raw data enters the enclave.

use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use platform_core::TenantId;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::dataset::Dataset;
use crate::oauth::{
    OAuth2Config, SecretString, TokenResponse, read_capped, refresh_access_token, tls_url,
};
use crate::{ConnectorDescriptor, ConnectorError, mappers};

#[derive(Debug, Clone)]
pub struct SyncContext {
    pub tenant: TenantId,
    /// Incremental-sync watermark (full sync when None).
    pub since: Option<DateTime<Utc>>,
}

/// A source of connector data. `fetch` runs INSIDE the enclave; whatever it
/// returns exists only in enclave RAM until sealed to the tenant key.
#[async_trait]
pub trait ConnectorSource: Send + Sync {
    fn descriptor(&self) -> &ConnectorDescriptor;
    async fn fetch(&self, ctx: &SyncContext) -> Result<Vec<Dataset>, ConnectorError>;
}

/// Source backed by embedded sample payloads, for dev, demos, and tests.
pub struct FixtureSource {
    descriptor: ConnectorDescriptor,
    datasets: Vec<Dataset>,
}

fn descriptor_for(slug: &str) -> Result<ConnectorDescriptor, ConnectorError> {
    crate::catalog()
        .into_iter()
        .find(|c| c.slug.as_str() == slug)
        .ok_or_else(|| ConnectorError::UnknownConnector(slug.to_owned()))
}

impl FixtureSource {
    pub fn quickbooks_demo() -> Result<Self, ConnectorError> {
        Ok(Self {
            descriptor: descriptor_for("quickbooks")?,
            datasets: vec![mappers::quickbooks_invoices(
                &mappers::fixtures::quickbooks(),
            )?],
        })
    }

    pub fn odoo_demo() -> Result<Self, ConnectorError> {
        Ok(Self {
            descriptor: descriptor_for("odoo")?,
            datasets: vec![mappers::odoo_partners(&mappers::fixtures::odoo())?],
        })
    }

    pub fn crm_demo() -> Result<Self, ConnectorError> {
        Ok(Self {
            descriptor: descriptor_for("generic_crm")?,
            datasets: vec![mappers::crm_contacts(&mappers::fixtures::crm())?],
        })
    }
}

#[async_trait]
impl ConnectorSource for FixtureSource {
    fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    async fn fetch(&self, _ctx: &SyncContext) -> Result<Vec<Dataset>, ConnectorError> {
        Ok(self.datasets.clone())
    }
}

/// Largest connector payload read into enclave RAM.
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Redirects are refused, not followed: a hop could downgrade to cleartext
/// or carry the request to a host the endpoint check never saw.
fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
}

/// Production HTTP source: OAuth2 refresh → authenticated GET → mapper.
pub struct HttpJsonSource {
    descriptor: ConnectorDescriptor,
    endpoint: reqwest::Url,
    oauth: OAuth2Config,
    /// Held across the exchange so concurrent syncs never replay a token the
    /// provider has already rotated. In memory only; not persisted.
    refresh_token: Mutex<SecretString>,
    mapper: fn(&Value) -> Result<Dataset, ConnectorError>,
    client: reqwest::Client,
}

impl HttpJsonSource {
    pub fn new(
        slug: &str,
        endpoint: String,
        oauth: OAuth2Config,
        refresh_token: SecretString,
        mapper: fn(&Value) -> Result<Dataset, ConnectorError>,
    ) -> Result<Self, ConnectorError> {
        Ok(Self {
            descriptor: descriptor_for(slug)?,
            endpoint: tls_url(&endpoint)
                .map_err(|reason| ConnectorError::Http(format!("connector endpoint {reason}")))?,
            oauth,
            refresh_token: Mutex::new(refresh_token),
            mapper,
            client: client_builder()
                .build()
                .map_err(|e| ConnectorError::Http(e.to_string()))?,
        })
    }

    /// Exchange the stored refresh token, keeping a rotated one if issued.
    async fn refresh(&self) -> Result<TokenResponse, ConnectorError> {
        let mut stored = self.refresh_token.lock().await;
        let mut tokens = refresh_access_token(&self.client, &self.oauth, &stored).await?;
        if let Some(rotated) = tokens.refresh_token.take() {
            *stored = rotated;
        }
        Ok(tokens)
    }
}

#[async_trait]
impl ConnectorSource for HttpJsonSource {
    fn descriptor(&self) -> &ConnectorDescriptor {
        &self.descriptor
    }

    async fn fetch(&self, _ctx: &SyncContext) -> Result<Vec<Dataset>, ConnectorError> {
        let tokens = self.refresh().await?;
        let response = self
            .client
            .get(self.endpoint.clone())
            .bearer_auth(tokens.access_token.expose())
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ConnectorError::Http(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ConnectorError::Http(format!(
                "connector endpoint returned {status}"
            )));
        }
        let body = read_capped(response, MAX_PAYLOAD_BYTES).await?;
        let payload: Value = serde_json::from_slice(body.expose())
            .map_err(|e| ConnectorError::Http(e.to_string()))?;
        Ok(vec![(self.mapper)(&payload)?])
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex as StdMutex};

    use super::*;

    fn oauth(token_url: String) -> OAuth2Config {
        OAuth2Config {
            token_url,
            client_id: "client-1".into(),
            client_secret: SecretString::new("s3cret".into()),
        }
    }

    #[test]
    fn unknown_slug_is_refused() {
        let result = HttpJsonSource::new(
            "no_such_connector",
            "http://127.0.0.1:1/data".into(),
            oauth("http://127.0.0.1:1/token".into()),
            SecretString::new("rt-0".into()),
            mappers::crm_contacts,
        );
        assert!(matches!(
            result,
            Err(ConnectorError::UnknownConnector(slug)) if slug == "no_such_connector"
        ));
    }

    type Seen = Arc<StdMutex<Vec<(String, String)>>>;

    /// Minimal HTTP/1.1 stub: records each request line and body, and writes
    /// back whatever `respond` returns for them.
    fn spawn_server(respond: fn(&str, &str) -> String) -> (String, Seen) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let seen = Arc::new(StdMutex::new(Vec::new()));
        let recorded = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                reader.read_line(&mut request_line).expect("request line");
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).expect("header");
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().expect("length");
                    }
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).expect("body");
                let body = String::from_utf8(body).expect("utf8");

                let response = respond(&request_line, &body);
                recorded.lock().expect("lock").push((request_line, body));
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (base, seen)
    }

    fn ok(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    /// `/token` rotates `rt-0` to `rt-1` once; `/data` serves the CRM fixture.
    fn crm_provider(request_line: &str, body: &str) -> String {
        if request_line.contains("/token") {
            if body.contains("refresh_token=rt-0") {
                ok(r#"{"access_token":"at","refresh_token":"rt-1"}"#)
            } else {
                ok(r#"{"access_token":"at"}"#)
            }
        } else {
            ok(&mappers::fixtures::crm().to_string())
        }
    }

    fn source_for(base: &str) -> HttpJsonSource {
        let mut source = HttpJsonSource::new(
            "generic_crm",
            format!("{base}/data"),
            oauth(format!("{base}/token")),
            SecretString::new("rt-0".into()),
            mappers::crm_contacts,
        )
        .expect("known slug");
        // The production client, minus any proxy in the test environment.
        source.client = client_builder().no_proxy().build().expect("client");
        source
    }

    fn ctx() -> SyncContext {
        SyncContext {
            tenant: TenantId::generate(),
            since: None,
        }
    }

    fn requested(seen: &Seen, path: &str) -> bool {
        seen.lock()
            .expect("lock")
            .iter()
            .any(|(line, _)| line.contains(path))
    }

    #[tokio::test]
    async fn rotated_refresh_token_is_used_for_later_syncs() {
        let (base, seen) = spawn_server(crm_provider);
        let source = source_for(&base);

        for _ in 0..3 {
            let datasets = source.fetch(&ctx()).await.expect("sync");
            assert_eq!(datasets.len(), 1);
        }

        let sent: Vec<String> = seen
            .lock()
            .expect("lock")
            .iter()
            .filter(|(line, _)| line.contains("/token"))
            .map(|(_, body)| {
                body.split('&')
                    .find_map(|kv| kv.strip_prefix("refresh_token="))
                    .expect("refresh_token field")
                    .to_owned()
            })
            .collect();
        // Rotated once, then the rotated token is kept when none is reissued.
        assert_eq!(sent, ["rt-0", "rt-1", "rt-1"]);
    }

    #[test]
    fn cleartext_endpoints_are_refused() {
        let build = |endpoint: &str| {
            HttpJsonSource::new(
                "generic_crm",
                endpoint.into(),
                oauth("https://idp.example/token".into()),
                SecretString::new("rt-0".into()),
                mappers::crm_contacts,
            )
        };
        assert!(build("https://api.example/data").is_ok());
        assert!(build("http://127.0.0.1:8080/data").is_ok());
        for bad in [
            "http://api.example/data",
            "http://10.0.0.5/data",
            "ftp://api.example/data",
            "not a url",
            "",
        ] {
            assert!(matches!(build(bad), Err(ConnectorError::Http(_))), "{bad}");
        }
    }

    #[tokio::test]
    async fn redirects_are_refused_without_being_followed() {
        fn redirecting(request_line: &str, body: &str) -> String {
            if request_line.contains("/data") {
                "HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
            } else {
                crm_provider(request_line, body)
            }
        }
        let (base, seen) = spawn_server(redirecting);

        let result = source_for(&base).fetch(&ctx()).await;

        assert!(matches!(result, Err(ConnectorError::Http(_))), "{result:?}");
        assert!(!requested(&seen, "/elsewhere"), "redirect was followed");
    }

    #[tokio::test]
    async fn oversized_payloads_are_refused() {
        fn oversized(request_line: &str, body: &str) -> String {
            if request_line.contains("/data") {
                // Declared length alone must refuse it; no body is sent.
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    MAX_PAYLOAD_BYTES + 1
                )
            } else {
                crm_provider(request_line, body)
            }
        }
        let (base, _) = spawn_server(oversized);

        let result = source_for(&base).fetch(&ctx()).await;

        assert!(
            matches!(&result, Err(ConnectorError::Http(msg)) if msg.contains("exceeds")),
            "{result:?}"
        );
    }

    fn padded_token() -> String {
        let pad = "x".repeat(crate::oauth::MAX_TOKEN_RESPONSE_BYTES);
        format!(r#"{{"access_token":"at","pad":"{pad}"}}"#)
    }

    #[tokio::test]
    async fn oversized_token_responses_are_refused() {
        fn oversized(request_line: &str, body: &str) -> String {
            if request_line.contains("/token") {
                ok(&padded_token())
            } else {
                crm_provider(request_line, body)
            }
        }
        let (base, seen) = spawn_server(oversized);

        let result = source_for(&base).fetch(&ctx()).await;

        assert!(
            matches!(&result, Err(ConnectorError::Http(msg)) if msg.contains("exceeds")),
            "{result:?}"
        );
        assert!(!requested(&seen, "/data"));
    }

    #[tokio::test]
    async fn oversized_chunked_token_responses_are_refused() {
        fn chunked(request_line: &str, body: &str) -> String {
            if request_line.contains("/token") {
                // No Content-Length: the cap must hold while streaming.
                let token = padded_token();
                let half = token.len() / 2;
                format!(
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                    half,
                    &token[..half],
                    token.len() - half,
                    &token[half..]
                )
            } else {
                crm_provider(request_line, body)
            }
        }
        let (base, seen) = spawn_server(chunked);

        let result = source_for(&base).fetch(&ctx()).await;

        assert!(
            matches!(&result, Err(ConnectorError::Http(msg)) if msg.contains("exceeds")),
            "{result:?}"
        );
        assert!(!requested(&seen, "/data"));
    }
}
