//! Connector sources: where raw data enters the enclave.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use platform_core::TenantId;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::dataset::Dataset;
use crate::oauth::{OAuth2Config, SecretString, TokenResponse, refresh_access_token};
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

/// Production HTTP source: OAuth2 refresh → authenticated GET → mapper.
pub struct HttpJsonSource {
    descriptor: ConnectorDescriptor,
    endpoint: String,
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
            endpoint,
            oauth,
            refresh_token: Mutex::new(refresh_token),
            mapper,
            client: reqwest::Client::new(),
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
        let payload: Value = self
            .client
            .get(&self.endpoint)
            .bearer_auth(tokens.access_token.expose())
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ConnectorError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| ConnectorError::Http(e.to_string()))?
            .json()
            .await
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

    /// Minimal HTTP/1.1 stub: `/token` records each form body and rotates
    /// `rt-0` to `rt-1` once; any other path serves the CRM fixture.
    fn spawn_stub() -> (String, Arc<StdMutex<Vec<String>>>) {
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
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().expect("length");
                        }
                    }
                }
                let mut body = vec![0u8; content_length];
                reader.read_exact(&mut body).expect("body");
                let body = String::from_utf8(body).expect("utf8");

                let response = if request_line.contains("/token") {
                    let rotate = body.contains("refresh_token=rt-0");
                    recorded.lock().expect("lock").push(body);
                    if rotate {
                        r#"{"access_token":"at","refresh_token":"rt-1"}"#.to_owned()
                    } else {
                        r#"{"access_token":"at"}"#.to_owned()
                    }
                } else {
                    mappers::fixtures::crm().to_string()
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
            }
        });
        (base, seen)
    }

    #[tokio::test]
    async fn rotated_refresh_token_is_used_for_later_syncs() {
        let (base, seen) = spawn_stub();
        let mut source = HttpJsonSource::new(
            "generic_crm",
            format!("{base}/data"),
            oauth(format!("{base}/token")),
            SecretString::new("rt-0".into()),
            mappers::crm_contacts,
        )
        .expect("known slug");
        source.client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("client");
        let ctx = SyncContext {
            tenant: TenantId::generate(),
            since: None,
        };

        for _ in 0..3 {
            let datasets = source.fetch(&ctx).await.expect("sync");
            assert_eq!(datasets.len(), 1);
        }

        let sent: Vec<String> = seen
            .lock()
            .expect("lock")
            .iter()
            .map(|body| {
                body.split('&')
                    .find_map(|kv| kv.strip_prefix("refresh_token="))
                    .expect("refresh_token field")
                    .to_owned()
            })
            .collect();
        // Rotated once, then the rotated token is kept when none is reissued.
        assert_eq!(sent, ["rt-0", "rt-1", "rt-1"]);
    }
}
