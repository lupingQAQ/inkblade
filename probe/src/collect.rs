//! Read-only environment collection inside the pod.

use std::fs;

use crate::base64;
use crate::config::Options;
use crate::json::{self, Value};
use crate::sha256;
use crate::util;

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

pub fn snapshot(opts: &Options) -> Value {
    let (uid, gid) = util::uid_gid();
    let mut files_read = Vec::new();
    let mounts = read_lines("/proc/mounts", 2 * 1024 * 1024, &mut files_read)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                Some(json::object(vec![
                    ("device", json::string(parts[0])),
                    ("mount", json::string(parts[1])),
                    ("fstype", json::string(parts[2])),
                    ("options", json::string(parts[3])),
                ]))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let cgroup = read_lines("/proc/self/cgroup", 256 * 1024, &mut files_read).unwrap_or_default();
    let interfaces = interfaces(&mut files_read);
    let route = read_lines("/proc/net/route", 256 * 1024, &mut files_read).unwrap_or_default();
    let arp = read_lines("/proc/net/arp", 256 * 1024, &mut files_read).unwrap_or_default();
    let hosts = read_lines("/etc/hosts", 256 * 1024, &mut files_read).unwrap_or_default();
    let resolv = read_lines("/etc/resolv.conf", 64 * 1024, &mut files_read).unwrap_or_default();
    let devices = list_dir("/dev", 512);
    let sa = service_account(&mut files_read);
    let env = std::env::vars()
        .map(|(key, value)| {
            json::object(vec![
                ("key", json::string(key.clone())),
                ("value", json::string(util::mask_value(&key, &value))),
            ])
        })
        .collect::<Vec<_>>();
    json::object(vec![
        ("probe_id", json::string(opts.probe_id.clone())),
        ("parent_id", opts.parent_id.clone().map(json::string).unwrap_or(Value::Null)),
        ("ts", json::number(util::now())),
        ("read_only", json::bool_value(opts.read_only)),
        (
            "host",
            json::object(vec![
                ("hostname", json::string(util::hostname())),
                ("pid", json::number(std::process::id() as u64)),
                ("uid", json::string(uid)),
                ("gid", json::string(gid)),
                ("caps", Value::Arr(util::effective_caps().into_iter().map(json::string).collect())),
            ]),
        ),
        ("env", Value::Arr(env)),
        ("mounts", Value::Arr(mounts)),
        ("cgroup", Value::Arr(cgroup.into_iter().map(json::string).collect())),
        ("service_account", sa),
        (
            "network",
            json::object(vec![
                ("interfaces", Value::Arr(interfaces)),
                ("routes", Value::Arr(route.into_iter().map(json::string).collect())),
                ("arp", Value::Arr(arp.into_iter().map(json::string).collect())),
                ("hosts", Value::Arr(hosts.into_iter().map(json::string).collect())),
                ("resolv_conf", Value::Arr(resolv.into_iter().map(json::string).collect())),
            ]),
        ),
        ("devices", Value::Arr(devices)),
        ("files_read", Value::Arr(files_read.into_iter().map(json::string).collect())),
        ("limits", json::object(vec![
            ("max_output", json::number(opts.max_output_bytes() as u64)),
            ("max_timeout_ms", json::number(opts.max_timeout_ms)),
        ])),
    ])
}

fn service_account(files_read: &mut Vec<String>) -> Value {
    let token_path = format!("{SA_DIR}/token");
    let token = util::read_text(&token_path, 32 * 1024);
    let namespace = util::read_text(&format!("{SA_DIR}/namespace"), 4096)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let ca = util::read_bytes(&format!("{SA_DIR}/ca.crt"), 2 * 1024 * 1024);
    let mut claims = Value::Null;
    let mut token_sha = String::new();
    if let Some(token) = &token {
        files_read.push(token_path.clone());
        token_sha = base64::hex(&sha256::sha256(token.as_bytes()));
        if let Some(payload) = token.split('.').nth(1) {
            if let Ok(bytes) = base64::decode_url(payload) {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    if let Ok(parsed) = json::parse(text) {
                        claims = parsed;
                    }
                }
            }
        }
    }
    let mut hints = Vec::new();
    if token.is_some() {
        hints.push(json::string("token_mounted"));
    }
    if namespace.is_some() {
        hints.push(json::string("namespace_mounted"));
    }
    if ca.is_some() {
        hints.push(json::string("ca_mounted"));
    }
    json::object(vec![
        ("token_present", json::bool_value(token.is_some())),
        ("token_sha256", json::string(token_sha)),
        ("namespace", namespace.clone().map(json::string).unwrap_or(Value::Null)),
        ("ca_present", json::bool_value(ca.is_some())),
        ("claims", claims),
        ("rbac_hints", Value::Arr(hints)),
        ("paths", Value::Arr(vec![json::string(token_path)])),
    ])
}

fn interfaces(files_read: &mut Vec<String>) -> Vec<Value> {
    let mut out = Vec::new();
    let directory = match fs::read_dir("/sys/class/net") {
        Ok(directory) => directory,
        Err(_) => return out,
    };
    for entry in directory.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let mac_path = format!("/sys/class/net/{name}/address");
        let mac = util::read_text(&mac_path, 4096).map(|value| value.trim().to_string());
        if mac.is_some() {
            files_read.push(mac_path);
        }
        let state = util::read_text(&format!("/sys/class/net/{name}/operstate"), 4096)
            .map(|value| value.trim().to_string());
        out.push(json::object(vec![
            ("name", json::string(name)),
            ("mac", mac.map(json::string).unwrap_or(Value::Null)),
            ("state", state.map(json::string).unwrap_or(Value::Null)),
        ]));
    }
    out
}

fn list_dir(path: &str, limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(directory) = fs::read_dir(path) {
        for entry in directory.flatten() {
            let metadata = entry.metadata().ok();
            out.push(json::object(vec![
                ("name", json::string(entry.file_name().to_string_lossy().to_string())),
                ("dir", json::bool_value(metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false))),
                ("size", json::number(metadata.as_ref().map(|m| m.len()).unwrap_or(0))),
            ]));
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

fn read_lines(path: &str, limit: usize, files_read: &mut Vec<String>) -> Option<Vec<String>> {
    let text = util::read_text(path, limit)?;
    files_read.push(path.to_string());
    Some(text.lines().map(|line| line.to_string()).collect())
}
