//! Read-only security posture discovery (`probe collect`).
//!
//! The section is deliberately observation-only: process table, kernel modules,
//! well-known agent directories, admission policy objects and runtime-sensor
//! artefacts.  No file is written and no command is executed.  Every claim
//! carries the source path/proc entry that produced it so the Python policy
//! engine can turn the observation into `defense:<product>` facts.

use std::fs;

use crate::base64;
use crate::json::{self, Value};
use crate::k8s::K8sConfig;
use crate::sha256;
use crate::util;

const SA_NAMESPACE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const SA_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const MAX_PROCESSES: usize = 8192;

/// (product key used by core/defenseprobe.py, process-name tokens)
const PROCESS_MATCHERS: &[(&str, &[&str])] = &[
    ("falco", &["falco"]),
    ("kyverno", &["kyverno"]),
    ("elkeid", &["elkeid", "olehid"]),
    ("agentsmith", &["agentsmith", "smith-agent", "smithd"]),
    ("kubearmor", &["kubearmor"]),
    ("tetragon", &["tetragon"]),
    ("hostagent", &["wazuh", "ossec", "osquery"]),
    ("imagescan", &["trivy", "grype", "syft"]),
    ("waf-inference", &["modsecurity", "coraza", "safeline"]),
    ("netobserv", &["hubble", "typha"]),
];

/// (product key, kernel-module name)
const MODULE_MATCHERS: &[(&str, &[&str])] = &[
    ("falco", &["falco"]),
    ("elkeid", &["elkeid", "olehid"]),
    ("agentsmith", &["smith"]),
    ("kubearmor", &["kubearmor"]),
    ("tetragon", &["tetragon"]),
];

/// (path, product key) — presence only; the probe never reads agent data.
const AGENT_DIRS: &[(&str, &str)] = &[
    ("/etc/falco", "falco"),
    ("/var/run/falco", "falco"),
    ("/usr/share/falco", "falco"),
    ("/etc/kyverno", "admission"),
    ("/opt/kyverno", "admission"),
    ("/opt/elkeid", "elkeid"),
    ("/etc/elkeid", "elkeid"),
    ("/var/run/elkeid", "elkeid"),
    ("/opt/kubearmor", "kubearmor"),
    ("/etc/kubearmor", "kubearmor"),
    ("/opt/tetragon", "tetragon"),
    ("/var/run/tetragon", "tetragon"),
    ("/var/ossec", "hostagent"),
    ("/etc/osquery", "hostagent"),
    ("/var/osquery", "hostagent"),
    ("/root/.cache/trivy", "imagescan"),
    ("/var/lib/trivy", "imagescan"),
    ("/etc/modsecurity", "waf-inference"),
    ("/etc/coraza", "waf-inference"),
];

/// (product key, rules-file path inside the sensor's mount namespace)
const RULESET_PATHS: &[(&str, &str)] = &[("falco", "/etc/falco/falco_rules.yaml")];

/// Rule names that matter to the bypass policy: if the sensor does not carry a
/// rule for a technique family, that technique is a coverage gap, not a bypass.
const INTERESTING_RULES: &[(&str, &str)] = &[
    ("executing-binary", "Executing binary not part of base image"),
    ("terminal-shell", "Terminal shell in container"),
    ("privileged-container", "Privileged container started"),
    ("write-below-etc", "Write below etc"),
    ("write-below-binary", "Write below binary dir"),
    ("k8s-api-contact", "Contact K8S API Server From Container"),
    ("drop-execute", "Drop and execute new binary in container"),
];

pub fn snapshot(files_read: &mut Vec<String>) -> Value {
    let processes = processes(files_read);
    let modules = kernel_modules(files_read);
    let dirs = agent_dirs();
    let config = K8sConfig::from_env().ok();
    let pods = config
        .as_ref()
        .map(|cfg| pods(cfg, files_read))
        .unwrap_or(Value::Null);
    let admission = config
        .as_ref()
        .map(|cfg| admission(cfg, files_read))
        .unwrap_or_else(|| {
            json::object(vec![
                ("available", json::bool_value(false)),
                ("error", json::string("KUBERNETES_SERVICE_HOST is not set")),
            ])
        });
    let scope = config
        .as_ref()
        .map(|cfg| scope(cfg, &admission, files_read))
        .unwrap_or_else(|| {
            json::object(vec![
                ("namespace", json::string(namespace_from_sa().unwrap_or_default())),
                ("labels", Value::Obj(Vec::new())),
                ("policies_in_scope", Value::Arr(Vec::new())),
            ])
        });
    let rulesets = rulesets(&processes, files_read);
    let sensor = sensor(&processes, &modules, &pods, &rulesets);
    let products = product_index(&processes, &modules, &dirs, &pods, &admission, &rulesets, &sensor);

    json::object(vec![
        ("schema", json::string("inkblade-security-posture/1")),
        ("collected", json::bool_value(true)),
        ("namespace", json::string(namespace_from_sa().unwrap_or_default())),
        ("service_account", sa_summary(files_read)),
        ("processes", Value::Arr(processes.into_iter().map(|p| p.0).collect())),
        ("kernel_modules", Value::Arr(modules.iter().map(|m| json::string(m.clone())).collect())),
        ("agent_dirs", Value::Arr(dirs)),
        ("admission", admission),
        ("scope", scope),
        ("pods", pods),
        ("rulesets", rulesets),
        ("runtime_sensor", sensor),
        ("products", Value::Arr(products)),
        ("no_exec", json::bool_value(true)),
        ("no_write", json::bool_value(true)),
    ])
}

/// (json row, command line) — the command line is used for matching only.
fn processes(files_read: &mut Vec<String>) -> Vec<(Value, String)> {
    let mut out = Vec::new();
    let mut scanned = 0usize;
    let mut truncated = false;
    let directory = match fs::read_dir("/proc") {
        Ok(directory) => directory,
        Err(_) => return out,
    };
    for entry in directory.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        scanned += 1;
        if scanned > MAX_PROCESSES {
            truncated = true;
            break;
        }
        let base = format!("/proc/{name}");
        let comm = util::read_text(&format!("{base}/comm"), 512)
            .map(|v| v.trim().to_string())
            .unwrap_or_default();
        let cmdline_raw = util::read_text(&format!("{base}/cmdline"), 8192).unwrap_or_default();
        let cmdline = cmdline_raw
            .split('\0')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let haystack = format!("{comm} {cmdline}").to_lowercase();
        let mut matched: Vec<&str> = Vec::new();
        for &(product, tokens) in PROCESS_MATCHERS {
            if tokens.iter().any(|token| token_hit(&haystack, token)) {
                matched.push(product);
            }
        }
        if matched.is_empty() {
            continue;
        }
        if out.len() < 256 {
            files_read.push(format!("{base}/comm"));
            out.push((
                json::object(vec![
                    ("pid", json::number(name.parse::<u64>().unwrap_or(0))),
                    ("comm", json::string(comm)),
                    ("cmdline", json::string(util::truncate_text(&cmdline, 512).0)),
                    ("matched", Value::Arr(matched.into_iter().map(json::string).collect())),
                ]),
                cmdline,
            ));
        }
    }
    if truncated {
        files_read.push("truncated:/proc".to_string());
    }
    out
}

fn token_hit(haystack: &str, token: &str) -> bool {
    if haystack.contains(token) {
        // Avoid matching "falco" inside an unrelated word: require a boundary
        // that is not an ASCII letter/digit on both sides.
        let needle = token.as_bytes();
        let bytes = haystack.as_bytes();
        let mut start = 0usize;
        while let Some(pos) = haystack[start..].find(token) {
            let abs = start + pos;
            let before_ok = abs == 0 || !bytes[abs - 1].is_ascii_alphanumeric();
            let after = abs + needle.len();
            let after_ok = after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
            start = abs + 1;
        }
        return false;
    }
    false
}

fn kernel_modules(files_read: &mut Vec<String>) -> Vec<String> {
    let text = match util::read_text("/proc/modules", 4 * 1024 * 1024) {
        Some(text) => text,
        None => return Vec::new(),
    };
    files_read.push("/proc/modules".to_string());
    text.lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .collect()
}

fn agent_dirs() -> Vec<Value> {
    AGENT_DIRS
        .iter()
        .map(|(path, product)| {
            let present = fs::metadata(path).is_ok();
            json::object(vec![
                ("path", json::string(*path)),
                ("product", json::string(*product)),
                ("present", json::bool_value(present)),
            ])
        })
        .collect()
}

fn namespace_from_sa() -> Option<String> {
    util::read_text(SA_NAMESPACE, 4096)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn sa_summary(files_read: &mut Vec<String>) -> Value {
    let token = util::read_text(SA_TOKEN, 32 * 1024);
    let mut sub = String::new();
    let mut claims = Value::Null;
    if let Some(token) = token.as_ref() {
        files_read.push(SA_TOKEN.to_string());
        if let Some(payload) = token.split('.').nth(1) {
            if let Ok(bytes) = base64::decode_url(payload) {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    if let Ok(parsed) = json::parse(text) {
                        sub = parsed
                            .get("sub")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        claims = parsed;
                    }
                }
            }
        }
    }
    json::object(vec![
        ("present", json::bool_value(token.is_some())),
        ("subject", json::string(sub)),
        ("claims", claims),
    ])
}

fn pods(config: &K8sConfig, files_read: &mut Vec<String>) -> Value {
    match config.list("pods", Some(""), 5_000) {
        Ok(response) => {
            files_read.push("GET /api/v1/pods".to_string());
            let items = response
                .get("items")
                .and_then(Value::as_array)
                .map(|items| items.to_vec())
                .unwrap_or_default();
            let mut out = Vec::new();
            for item in items.into_iter().take(200) {
                let name = item
                    .path("metadata.name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let namespace = item
                    .path("metadata.namespace")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let phase = item
                    .path("status.phase")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let mut images = Vec::new();
                if let Some(containers) = item.path("spec.containers").and_then(Value::as_array) {
                    for container in containers {
                        if let Some(image) = container.get("image").and_then(Value::as_str) {
                            images.push(json::string(image.to_string()));
                        }
                    }
                }
                out.push(json::object(vec![
                    ("name", json::string(name)),
                    ("namespace", json::string(namespace)),
                    ("phase", json::string(phase)),
                    ("images", Value::Arr(images)),
                ]));
            }
            json::object(vec![
                ("available", json::bool_value(true)),
                ("items", Value::Arr(out)),
            ])
        }
        Err(error) => json::object(vec![
            ("available", json::bool_value(false)),
            ("error", json::string(error)),
        ]),
    }
}

fn admission(config: &K8sConfig, files_read: &mut Vec<String>) -> Value {
    let modern = policy_group(
        config,
        "/apis/policies.kyverno.io/v1/validatingpolicies",
        "validatingpolicies.policies.kyverno.io",
        files_read,
    );
    let legacy = policy_group(
        config,
        "/apis/kyverno.io/v1/clusterpolicies",
        "clusterpolicies.kyverno.io",
        files_read,
    );
    let modern_ok = modern.get("available").and_then(Value::as_bool) == Some(true);
    let legacy_ok = legacy.get("available").and_then(Value::as_bool) == Some(true);
    let mut merged: Vec<Value> = Vec::new();
    for group in [&modern, &legacy] {
        if let Some(items) = group.get("items").and_then(Value::as_array) {
            merged.extend(items.iter().cloned());
        }
    }
    let errors = json::object(vec![
        ("modern", modern.get("error").cloned().unwrap_or(Value::Null)),
        ("legacy", legacy.get("error").cloned().unwrap_or(Value::Null)),
    ]);
    let kyverno = json::object(vec![
        ("available", json::bool_value(modern_ok || legacy_ok)),
        ("api", json::string("policies.kyverno.io/v1 + kyverno.io/v1")),
        ("count", json::number(merged.len() as u64)),
        ("items", Value::Arr(merged)),
        ("errors", errors),
    ]);
    let gatekeeper = policy_group(
        config,
        "/apis/constraints.gatekeeper.sh/v1beta1/constraints",
        "constraints.gatekeeper.sh",
        files_read,
    );
    json::object(vec![
        ("available", json::bool_value(
            kyverno.get("available").and_then(Value::as_bool).unwrap_or(false)
                || gatekeeper.get("available").and_then(Value::as_bool).unwrap_or(false),
        )),
        ("kyverno", kyverno),
        ("gatekeeper", gatekeeper),
    ])
}

/// Unwrap the probe HTTP envelope (`{"ok":true,"json":{...}}`) into the API body.
fn api_body(response: Value) -> Value {
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        response.get("json").cloned().unwrap_or(response)
    } else {
        response
    }
}

fn policy_group(config: &K8sConfig, path: &str, api: &str, files_read: &mut Vec<String>) -> Value {
    match config.request("GET", path, None, 5_000, 4 * 1024 * 1024) {
        Ok(response) => {
            files_read.push(format!("GET {path}"));
            let response = api_body(response);
            let items = response
                .get("items")
                .and_then(Value::as_array)
                .map(|items| items.to_vec())
                .unwrap_or_default();
            let mut policies = Vec::new();
            for item in items.into_iter().take(200) {
                let name = item
                    .path("metadata.name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                let mut scope_text = String::new();
                for key in ["matchConditions", "matchConstraints", "match", "rules"] {
                    if let Some(value) = item.path(&format!("spec.{key}")) {
                        scope_text.push_str(&value.to_json());
                        scope_text.push(' ');
                    }
                }
                let (scope, truncated) = util::truncate_text(&scope_text, 4096);
                policies.push(json::object(vec![
                    ("name", json::string(name)),
                    ("scope", json::string(scope)),
                    ("scope_truncated", json::bool_value(truncated)),
                ]));
            }
            json::object(vec![
                ("available", json::bool_value(true)),
                ("api", json::string(api)),
                ("count", json::number(policies.len() as u64)),
                ("items", Value::Arr(policies)),
            ])
        }
        Err(error) => json::object(vec![
            ("available", json::bool_value(false)),
            ("api", json::string(api)),
            ("error", json::string(util::truncate_text(&error, 512).0)),
        ]),
    }
}

fn scope(config: &K8sConfig, admission: &Value, files_read: &mut Vec<String>) -> Value {
    let ns = namespace_from_sa().unwrap_or_else(|| config.namespace.clone());
    let mut labels = Value::Obj(Vec::new());
    let mut error = Value::Null;
    let path = format!("/api/v1/namespaces/{ns}");
    match config.request("GET", &path, None, 5_000, 1024 * 1024) {
        Ok(response) => {
            files_read.push(format!("GET {path}"));
            let response = api_body(response);
            if let Some(value) = response.path("metadata.labels") {
                labels = value.clone();
            }
        }
        Err(err) => error = json::string(util::truncate_text(&err, 256).0),
    }
    let mut in_scope = Vec::new();
    for group in ["kyverno", "gatekeeper"] {
        if let Some(policies) = admission
            .get(group)
            .and_then(|value| value.get("items"))
            .and_then(Value::as_array)
        {
            for policy in policies {
                let name = policy.get("name").and_then(Value::as_str).unwrap_or_default();
                let scope_text = policy.get("scope").and_then(Value::as_str).unwrap_or_default();
                let quoted = format!("'{}'", ns);
                let dquoted = format!("\"{}\"", ns);
                if scope_text.contains(&quoted) || scope_text.contains(&dquoted) {
                    in_scope.push(json::string(format!("{group}:{name}")));
                }
            }
        }
    }
    json::object(vec![
        ("namespace", json::string(ns)),
        ("labels", labels),
        ("policies_in_scope", Value::Arr(in_scope)),
        ("error", error),
    ])
}

fn rulesets(processes: &[(Value, String)], files_read: &mut Vec<String>) -> Value {
    let mut out = Vec::new();
    for &(product, relative) in RULESET_PATHS {
        // Try the probe's own mount and each sensor process root.
        let mut candidates: Vec<String> = vec![relative.to_string()];
        for (row, _) in processes {
            let matched = row
                .get("matched")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).any(|name| name == product))
                .unwrap_or(false);
            if !matched {
                continue;
            }
            if let Some(pid) = row.get("pid").and_then(Value::as_u64) {
                candidates.push(format!("/proc/{pid}/root{relative}"));
            }
        }
        for path in candidates {
            let text = match util::read_text(&path, 32 * 1024 * 1024) {
                Some(text) => text,
                None => continue,
            };
            files_read.push(path.clone());
            let mut rule_names: Vec<String> = Vec::new();
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("- rule:") {
                    let name = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                    if !name.is_empty() && rule_names.len() < 400 {
                        rule_names.push(name);
                    }
                }
            }
            let mut present = Vec::new();
            for (key, needle) in INTERESTING_RULES {
                if rule_names
                    .iter()
                    .any(|name| name.to_lowercase().contains(&needle.to_lowercase()))
                {
                    present.push(json::string(*key));
                }
            }
            out.push(json::object(vec![
                ("product", json::string(product)),
                ("path", json::string(path)),
                ("sha256", json::string(base64::hex(&sha256::sha256(text.as_bytes())))),
                ("rule_count", json::number(rule_names.len() as u64)),
                ("rules", Value::Arr(rule_names.into_iter().map(json::string).collect())),
                ("interesting_rules", Value::Arr(present)),
                ("parse", json::string("rule: prefix lines")),
            ]));
            break;
        }
    }
    Value::Arr(out)
}

fn sensor(
    processes: &[(Value, String)],
    modules: &[String],
    pods: &Value,
    rulesets: &Value,
) -> Value {
    let btf = fs::metadata("/sys/kernel/btf/vmlinux").is_ok();
    let falco = processes.iter().find(|(row, _)| {
        row.get("matched")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).any(|name| name == "falco"))
            .unwrap_or(false)
    });
    let mut falco_detail = json::object(vec![("running", json::bool_value(falco.is_some()))]);
    if let Some((row, _)) = falco {
        let pid = row.get("pid").and_then(Value::as_u64).unwrap_or(0);
        let module_loaded = modules.iter().any(|name| name == "falco");
        let driver = if module_loaded {
            "kernel_module"
        } else if btf {
            "modern_ebpf_inferred"
        } else {
            "unknown"
        };
        falco_detail = json::object(vec![
            ("running", json::bool_value(true)),
            ("pid", json::number(pid)),
            ("comm", row.get("comm").cloned().unwrap_or(Value::Null)),
            ("btf", json::bool_value(btf)),
            ("kernel_module", json::bool_value(module_loaded)),
            ("driver", json::string(driver)),
            ("rulesets", json::number(
                rulesets
                    .as_array()
                    .map(|items| items.len() as u64)
                    .unwrap_or(0),
            )),
        ]);
    }
    let kyverno_pods = pods
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|pod| {
                    pod.get("namespace").and_then(Value::as_str) == Some("kyverno")
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json::object(vec![
        ("falco", falco_detail),
        ("kyverno", json::object(vec![
            ("pods", Value::Arr(kyverno_pods)),
        ])),
        ("btf", json::bool_value(btf)),
        ("modern_ebpf_possible", json::bool_value(btf)),
    ])
}

fn product_index(
    processes: &[(Value, String)],
    modules: &[String],
    dirs: &[Value],
    pods: &Value,
    admission_section: &Value,
    rulesets: &Value,
    sensor: &Value,
) -> Vec<Value> {
    let mut products: Vec<String> = Vec::new();
    let add = |products: &mut Vec<String>, key: &str| {
        if !products.iter().any(|existing| existing == key) {
            products.push(key.to_string());
        }
    };
    for (row, _) in processes {
        if let Some(matched) = row.get("matched").and_then(Value::as_array) {
            for product in matched.iter().filter_map(Value::as_str) {
                add(&mut products, product);
            }
        }
    }
    for module in modules {
        for &(product, names) in MODULE_MATCHERS {
            if names.iter().any(|name| module.as_str() == *name) {
                add(&mut products, product);
            }
        }
    }
    for dir in dirs {
        if dir.get("present").and_then(Value::as_bool) == Some(true) {
            if let Some(product) = dir.get("product").and_then(Value::as_str) {
                add(&mut products, product);
            }
        }
    }
    if let Some(items) = pods.get("items").and_then(Value::as_array) {
        for pod in items {
            if let Some(images) = pod.get("images").and_then(Value::as_array) {
                for image in images.iter().filter_map(Value::as_str) {
                    let low = image.to_lowercase();
                    for &(product, tokens) in PROCESS_MATCHERS {
                        if tokens.iter().any(|token| low.contains(*token)) {
                            add(&mut products, product);
                        }
                    }
                }
            }
        }
    }
    for group in ["kyverno", "gatekeeper"] {
        if admission_section
            .get(group)
            .and_then(|value| value.get("available"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            add(&mut products, "admission");
        }
    }
    let mut out = Vec::new();
    for key in products {
        let mut evidence: Vec<Value> = Vec::new();
        let mut matched_processes = Vec::new();
        for (row, _) in processes {
            let matched = row
                .get("matched")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str)
                    .any(|name| name == key.as_str()))
                .unwrap_or(false);
            if matched {
                evidence.push(json::string(format!(
                    "process:{}",
                    row.get("comm").and_then(Value::as_str).unwrap_or("?")
                )));
                matched_processes.push(row.clone());
            }
        }
        let matched_modules: Vec<Value> = modules
            .iter()
            .filter(|module| {
                MODULE_MATCHERS.iter().any(|(product, names)| {
                    *product == key.as_str()
                        && names.iter().any(|name| *name == module.as_str())
                })
            })
            .map(|module| json::string(module.clone()))
            .collect();
        for module in &matched_modules {
            if let Some(name) = module.as_str() {
                evidence.push(json::string(format!("kernel_module:{name}")));
            }
        }
        let matched_dirs: Vec<Value> = dirs
            .iter()
            .filter(|dir| {
                dir.get("product").and_then(Value::as_str) == Some(key.as_str())
                    && dir.get("present").and_then(Value::as_bool) == Some(true)
            })
            .cloned()
            .collect();
        for dir in &matched_dirs {
            if let Some(path) = dir.get("path").and_then(Value::as_str) {
                evidence.push(json::string(format!("dir:{path}")));
            }
        }
        let mut version = Value::Null;
        if let Some(items) = pods.get("items").and_then(Value::as_array) {
            for pod in items {
                if let Some(images) = pod.get("images").and_then(Value::as_array) {
                    for image in images.iter().filter_map(Value::as_str) {
                        let low = image.to_lowercase();
                        let hit = PROCESS_MATCHERS.iter().any(|(product, tokens)| {
                            *product == key.as_str()
                                && tokens.iter().any(|token| low.contains(*token))
                        });
                        if hit {
                            version = json::string(image.to_string());
                            evidence.push(json::string(format!("image:{image}")));
                            break;
                        }
                    }
                }
                if !version.is_null() {
                    break;
                }
            }
        }
        if key == "admission" {
            for group in ["kyverno", "gatekeeper"] {
                if let Some(count) = admission_section
                    .get(group)
                    .and_then(|value| value.get("count"))
                    .and_then(Value::as_u64)
                {
                    evidence.push(json::string(format!("admission:{group}:{count}")));
                }
            }
        }
        let rulesets_for_product: Vec<Value> = rulesets
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter(|item| item.get("product").and_then(Value::as_str) == Some(key.as_str()))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        for ruleset in &rulesets_for_product {
            if let Some(path) = ruleset.get("path").and_then(Value::as_str) {
                evidence.push(json::string(format!("ruleset:{path}")));
            }
        }
        let sensor_detail = if key == "falco" {
            sensor.get("falco").cloned().unwrap_or(Value::Null)
        } else if key == "admission" {
            sensor.get("kyverno").cloned().unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        let display = match key.as_str() {
            "admission" => "Approval policy (Kyverno/Gatekeeper)",
            "falco" => "Falco",
            "elkeid" => "Elkeid HIDS",
            "agentsmith" => "AgentSmith-HIDS",
            "kubearmor" => "KubeArmor",
            "tetragon" => "Tetragon",
            "hostagent" => "Host agent (Wazuh/Osquery)",
            "imagescan" => "Image scanner (Trivy/grype)",
            "waf-inference" => "Inference WAF",
            "netobserv" => "Network observability",
            _ => key.as_str(),
        };
        out.push(json::object(vec![
            ("product", json::string(key.clone())),
            ("display", json::string(display)),
            ("evidence", Value::Arr(evidence)),
            ("processes", Value::Arr(matched_processes)),
            ("kernel_modules", Value::Arr(matched_modules)),
            ("agent_dirs", Value::Arr(matched_dirs)),
            ("version", version),
            ("rulesets", Value::Arr(rulesets_for_product)),
            ("sensor", sensor_detail),
        ]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_boundary() {
        assert!(token_hit("falco --modern", "falco"));
        assert!(!token_hit("falconry agent", "falco"));
        assert!(token_hit("kube-system/falco-kvqjn", "falco"));
    }

    #[test]
    fn posture_snapshot_is_read_only_shape() {
        let mut files = Vec::new();
        let value = snapshot(&mut files);
        assert_eq!(value.get("no_write").and_then(Value::as_bool), Some(true));
        assert!(value.get("processes").and_then(Value::as_array).is_some());
    }
}
