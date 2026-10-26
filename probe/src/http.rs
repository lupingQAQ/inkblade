//! Native HTTP(S) client used by the template runtime and the Kubernetes API.
//!
//! TLS is provided by rustls through ureq, linked statically into the probe;
//! the deployed binary has no runtime library dependency.  Redirects are
//! bounded and can be disabled by the template.  A caller can supply a
//! private CA bundle (the in-pod service-account CA) for the Kubernetes API.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use crate::base64;
use crate::json::{self, Value};

pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u64,
    pub max_redirects: u32,
    pub max_body: usize,
    pub ca_pem: Option<Vec<u8>>,
}

pub fn request(request: HttpRequest) -> Result<Value, String> {
    let timeout = Duration::from_millis(request.timeout_ms.clamp(50, 120_000));
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(timeout)
        .timeout_read(timeout)
        .timeout_write(timeout)
        .redirects(request.max_redirects.min(10));
    if let Some(ca_pem) = &request.ca_pem {
        builder = builder.tls_config(Arc::new(tls_config(ca_pem)?));
    }
    let agent = builder.build();
    let mut req = agent.request(request.method, request.url);
    for (name, value) in &request.headers {
        req = req.set(name, value);
    }
    let response = match request.body {
        Some(body) => req.send_bytes(&body),
        None => req.call(),
    };
    match response {
        Ok(response) => read_response(response, request.max_body),
        Err(ureq::Error::Status(code, response)) => {
            let mut value = read_response(response, request.max_body)?;
            if let Value::Obj(items) = &mut value {
                items.push(("status".to_string(), json::number(code)));
                items.push(("ok".to_string(), json::bool_value(false)));
            }
            Ok(value)
        }
        Err(ureq::Error::Transport(error)) => Err(format!("http transport: {error}")),
    }
}

fn tls_config(ca_pem: &[u8]) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cursor = std::io::Cursor::new(ca_pem);
    for certificate in rustls_pemfile::certs(&mut cursor) {
        let certificate = certificate.map_err(|error| format!("ca pem: {error}"))?;
        roots
            .add(certificate)
            .map_err(|error| format!("ca cert: {error}"))?;
    }
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn read_response(response: ureq::Response, max_body: usize) -> Result<Value, String> {
    let status = response.status();
    let mut headers = Vec::new();
    for name in response.headers_names() {
        if let Some(value) = response.header(&name) {
            headers.push((name, value.to_string()));
        }
    }
    let mut body = Vec::new();
    let limit = max_body.clamp(1, 16 * 1024 * 1024);
    let mut reader = response.into_reader();
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if body.len() < limit {
                    let take = (limit - body.len()).min(count);
                    body.extend_from_slice(&buffer[..take]);
                    if take < count {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(error) => return Err(format!("http body: {error}")),
        }
    }
    let text = String::from_utf8_lossy(&body).to_string();
    let parsed = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .map(|value| Value::from_serde(&value))
        .unwrap_or(Value::Null);
    let digest = base64::hex(&crate::sha256::sha256(&body));
    Ok(json::object(vec![
        ("status", json::number(status as u64)),
        ("ok", json::bool_value((200..300).contains(&status))),
        (
            "headers",
            Value::Obj(
                headers
                    .into_iter()
                    .map(|(name, value)| (name, json::string(value)))
                    .collect(),
            ),
        ),
        ("body", json::string(text.clone())),
        ("text", json::string(text)),
        ("json", parsed),
        ("bytes", json::number(body.len() as u64)),
        ("sha256", json::string(digest)),
        ("truncated", json::bool_value(truncated)),
    ]))
}
