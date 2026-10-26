//! Kubernetes access from inside the pod.
//!
//! Read operations use the mounted service-account token directly against the
//! API server over HTTPS.  Streaming `exec`/`copy` need SPDY/WebSocket support
//! that would pull a large client stack into the probe, so those operations use
//! `kubectl` when it is present, with a temporary kubeconfig built from the
//! same in-pod token and CA.  The token is never printed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::base64;
use crate::http::{self, HttpRequest};
use crate::json::{self, Value};
use crate::util;

pub const DEFAULT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
pub const DEFAULT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
pub const DEFAULT_NAMESPACE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

#[derive(Clone, Debug)]
pub struct K8sConfig {
    pub server: String,
    pub token_path: String,
    pub ca_path: String,
    pub namespace: String,
    pub kubeconfig: Option<String>,
}

impl K8sConfig {
    pub fn from_env() -> Result<Self, String> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .map_err(|_| "KUBERNETES_SERVICE_HOST is not set".to_string())?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
        let server = if host.contains(':') {
            format!("https://[{host}]:{port}")
        } else {
            format!("https://{host}:{port}")
        };
        let namespace = util::read_text(DEFAULT_NAMESPACE, 4096)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "default".to_string());
        Ok(Self {
            server,
            token_path: DEFAULT_TOKEN.to_string(),
            ca_path: DEFAULT_CA.to_string(),
            namespace,
            kubeconfig: None,
        })
    }

    pub fn token(&self) -> Result<String, String> {
        let token = util::read_text(&self.token_path, 16 * 1024)
            .ok_or_else(|| format!("service-account token not found: {}", self.token_path))?;
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err("service-account token is empty".to_string());
        }
        Ok(token)
    }

    pub fn ca(&self) -> Option<Vec<u8>> {
        util::read_bytes(&self.ca_path, 1024 * 1024)
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
        timeout_ms: u64,
        max_body: usize,
    ) -> Result<Value, String> {
        let token = self.token()?;
        let url = format!("{}{}", self.server.trim_end_matches('/'), path);
        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {token}")),
            ("Accept".to_string(), "application/json".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        http::request(HttpRequest {
            method,
            url: &url,
            headers,
            body,
            timeout_ms,
            max_redirects: 0,
            max_body,
            ca_pem: self.ca(),
        })
    }

    pub fn list(&self, resource: &str, namespace: Option<&str>, timeout_ms: u64) -> Result<Value, String> {
        let path = match resource {
            "nodes" | "namespaces" => format!("/api/v1/{resource}"),
            "pods" | "services" | "secrets" | "serviceaccounts" | "events" => {
                match namespace {
                    Some("") => format!("/api/v1/{resource}"),
                    Some(namespace) => format!(
                        "/api/v1/namespaces/{}/{resource}",
                        url_encode(namespace)
                    ),
                    None => format!(
                        "/api/v1/namespaces/{}/{resource}",
                        url_encode(&self.namespace)
                    ),
                }
            }
            other => return Err(format!("unsupported k8s resource {other}")),
        };
        let response = self.request("GET", &path, None, timeout_ms, 8 * 1024 * 1024)?;
        Ok(pass_through(response))
    }

    pub fn get(&self, resource: &str, namespace: Option<&str>, name: &str, timeout_ms: u64) -> Result<Value, String> {
        let namespace = namespace.unwrap_or(&self.namespace);
        let path = match resource {
            "nodes" | "namespaces" => format!("/api/v1/{resource}/{}", url_encode(name)),
            other => format!(
                "/api/v1/namespaces/{}/{other}/{}",
                url_encode(namespace),
                url_encode(name)
            ),
        };
        let response = self.request("GET", &path, None, timeout_ms, 4 * 1024 * 1024)?;
        Ok(pass_through(response))
    }

    fn kubectl(&self, args: &[String], timeout_ms: u64) -> Result<Value, String> {
        let kubeconfig = self.materialize_kubeconfig()?;
        let started = std::time::Instant::now();
        let mut command = Command::new(std::env::var("KUBECTL").unwrap_or_else(|_| "kubectl".to_string()));
        command
            .env("KUBECONFIG", &kubeconfig)
            .args(args)
            .stdin(std::process::Stdio::null());
        let output = command
            .output()
            .map_err(|error| format!("kubectl unavailable for exec/copy: {error}"))?;
        let _ = fs::remove_file(&kubeconfig);
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        if !output.status.success() {
            return Err(format!(
                "kubectl failed ({}): {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }
        Ok(json::object(vec![
            ("ok", json::bool_value(true)),
            ("stdout", json::string(stdout)),
            ("stderr", json::string(stderr)),
            ("duration_ms", json::number(started.elapsed().as_millis() as u64)),
            ("timeout_ms", json::number(timeout_ms)),
        ]))
    }

    fn materialize_kubeconfig(&self) -> Result<PathBuf, String> {
        if let Some(path) = &self.kubeconfig {
            return Ok(PathBuf::from(path));
        }
        let token = self.token()?;
        let ca_b64 = base64::encode(&self.ca().unwrap_or_default());
        let document = json::object(vec![
            ("apiVersion", json::string("v1")),
            ("kind", json::string("Config")),
            (
                "clusters",
                Value::Arr(vec![json::object(vec![
                    ("name", json::string("inkblade-probe")),
                    (
                        "cluster",
                        json::object(vec![
                            ("server", json::string(self.server.clone())),
                            ("certificate-authority-data", json::string(ca_b64)),
                        ]),
                    ),
                ])]),
            ),
            (
                "users",
                Value::Arr(vec![json::object(vec![
                    ("name", json::string("inkblade-probe")),
                    ("user", json::object(vec![("token", json::string(token))])),
                ])]),
            ),
            (
                "contexts",
                Value::Arr(vec![json::object(vec![
                    ("name", json::string("inkblade-probe")),
                    (
                        "context",
                        json::object(vec![
                            ("cluster", json::string("inkblade-probe")),
                            ("user", json::string("inkblade-probe")),
                            ("namespace", json::string(self.namespace.clone())),
                        ]),
                    ),
                ])]),
            ),
            ("current-context", json::string("inkblade-probe")),
        ]);
        let path = util::home_or_tmp().join(format!(
            ".inkblade-probe-kubeconfig-{}",
            util::random_hex(6)
        ));
        fs::write(&path, document.to_json()).map_err(|error| format!("kubeconfig write: {error}"))?;
        set_private(&path)?;
        Ok(path)
    }

    pub fn exec(
        &self,
        namespace: &str,
        pod: &str,
        container: Option<&str>,
        argv: &[String],
        timeout_ms: u64,
    ) -> Result<Value, String> {
        let mut args = vec![
            "exec".to_string(),
            "-n".to_string(),
            namespace.to_string(),
            pod.to_string(),
        ];
        if let Some(container) = container {
            args.push("-c".to_string());
            args.push(container.to_string());
        }
        args.push("--".to_string());
        args.extend(argv.iter().cloned());
        self.kubectl(&args, timeout_ms)
    }

    pub fn copy(
        &self,
        namespace: &str,
        pod: &str,
        container: Option<&str>,
        source: &str,
        destination: &str,
        timeout_ms: u64,
    ) -> Result<Value, String> {
        let mut args = vec![
            "cp".to_string(),
            "-n".to_string(),
            namespace.to_string(),
        ];
        if let Some(container) = container {
            args.push("-c".to_string());
            args.push(container.to_string());
        }
        args.push(source.to_string());
        args.push(destination.to_string());
        self.kubectl(&args, timeout_ms)
    }
}

fn pass_through(response: Value) -> Value {
    if response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
        response.get("json").cloned().unwrap_or(response)
    } else {
        response
    }
}

fn set_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("kubeconfig chmod: {error}"))?;
    }
    Ok(())
}

pub fn url_encode(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoding() {
        assert_eq!(url_encode("a b/c"), "a%20b%2Fc");
    }
}
