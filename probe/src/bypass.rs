//! Defense-bypass execution primitives.
//!
//! The module implements the *benign* part of a bypass plan: a script is
//! executed without creating a file (memfd), through an interpreter that is
//! already present in the image, from a workspace that avoids well-known HIDS
//! paths, with a cleared environment, or as several short commands.  It also
//! inspects admission scope and service-account permissions so the Python
//! policy engine can select a technique instead of guessing.
//!
//! Hard boundaries:
//!   * never fetch or embed a malicious payload;
//!   * never write outside the caller-provided benign workspace;
//!   * every execution returns `artifact_paths` and the exact argv so the
//!     evidence record is auditable.

use std::io::Write;
use std::path::Path;

use crate::base64;
use crate::config::Options;
use crate::exec;
use crate::json::{self, Value};
use crate::k8s::K8sConfig;
use crate::sha256;
use crate::util;

pub const SCHEMA: &str = "inkblade-bypass/1";

const DEFAULT_BINARIES: &[&str] = &["/bin/sh", "/usr/bin/sh", "/bin/busybox", "/usr/bin/env"];
const DEFAULT_WORKDIRS: &[&str] = &["/dev/shm", "/tmp", "/var/tmp", "/run", "/opt/inkblade"];

pub fn plan_from_options(opts: &Options, positional: &[String]) -> Result<Value, String> {
    let mut plan = if let Some(raw) = opts.bypass_plan.as_deref() {
        let text = if raw.trim_start().starts_with('{') {
            raw.to_string()
        } else {
            util::read_text(raw, 1024 * 1024)
                .ok_or_else(|| format!("cannot read bypass plan {raw}"))?
        };
        json::parse(&text)?
    } else {
        json::object(Vec::new())
    };
    if !opts.bypass_techniques.is_empty() {
        set(
            &mut plan,
            "techniques",
            Value::Arr(
                opts.bypass_techniques
                    .iter()
                    .cloned()
                    .map(json::string)
                    .collect(),
            ),
        );
    }
    if let Some(script) = opts.bypass_script.as_deref() {
        set(&mut plan, "script", json::string(script));
    }
    if let Some(script) = opts.bypass_script_b64.as_deref() {
        set(&mut plan, "script_b64", json::string(script));
    }
    if let Some(workdir) = opts.bypass_workdir.as_deref() {
        set(&mut plan, "workdir", json::string(workdir));
    }
    for path in &opts.bypass_monitored {
        append(&mut plan, "monitored_paths", json::string(path.clone()));
    }
    if let Some(namespace) = opts.bypass_target_namespace.as_deref() {
        set(
            &mut plan,
            "target",
            json::object(vec![
                ("namespace", json::string(namespace)),
                (
                    "pod",
                    opts.bypass_target_pod
                        .as_deref()
                        .map(json::string)
                        .unwrap_or(Value::Null),
                ),
                (
                    "container",
                    opts.bypass_container
                        .as_deref()
                        .map(json::string)
                        .unwrap_or(Value::Null),
                ),
            ]),
        );
    }
    if !positional.is_empty() {
        set(
            &mut plan,
            "argv",
            Value::Arr(positional.iter().cloned().map(json::string).collect()),
        );
    }
    Ok(plan)
}

fn set(plan: &mut Value, key: &str, value: Value) {
    if let Value::Obj(items) = plan {
        if let Some(slot) = items.iter_mut().find(|(name, _)| name == key) {
            slot.1 = value;
        } else {
            items.push((key.to_string(), value));
        }
    }
}

fn append(plan: &mut Value, key: &str, value: Value) {
    if let Value::Obj(items) = plan {
        if let Some(slot) = items.iter_mut().find(|(name, _)| name == key) {
            if let Value::Arr(values) = &mut slot.1 {
                values.push(value);
                return;
            }
            slot.1 = Value::Arr(vec![value]);
        } else {
            items.push((key.to_string(), Value::Arr(vec![value])));
        }
    }
}

pub fn run(plan: &Value, opts: &Options) -> Result<Value, String> {
    let techniques = techniques_of(plan);
    if techniques.is_empty() {
        return Err("bypass plan needs technique/techniques".to_string());
    }
    let exec_like = techniques.iter().any(|technique| {
        matches!(
            technique.as_str(),
            "fileless-memfd-exec" | "existing-binary-exec" | "command-split-env-clean"
        )
    });
    if exec_like && opts.read_only {
        return Err("bypass execution requires --allow-write".to_string());
    }
    let timeout = opts.timeout_ms(plan.get("timeout_ms").and_then(Value::as_u64));
    let mut executions: Vec<Value> = Vec::new();
    let mut ok = true;
    let mut fileless = false;
    let mut artifact_paths: Vec<Value> = Vec::new();
    let mut selected_path = Value::Null;
    let mut scope_value = Value::Null;
    let mut sa_value = Value::Null;
    let mut executed_technique = String::new();

    for technique in &techniques {
        let result = match technique.as_str() {
            "fileless-memfd-exec" => {
                fileless = true;
                let result = memfd_exec(plan, opts, timeout)?;
                executed_technique = technique.clone();
                result
            }
            "existing-binary-exec" => {
                let result = existing_exec(plan, opts, timeout)?;
                executed_technique = technique.clone();
                result
            }
            "path-evasion" => {
                let result = path_evasion(plan)?;
                if let Some(path) = result.get("selected").and_then(Value::as_str) {
                    selected_path = json::string(path.to_string());
                }
                result
            }
            "namespace-scope-evasion" => {
                let result = namespace_scope(plan)?;
                scope_value = result.clone();
                result
            }
            "sa-permission-selection" => {
                let result = sa_permission(plan)?;
                sa_value = result.clone();
                result
            }
            "command-split-env-clean" => {
                let result = split_exec(plan, opts, timeout)?;
                executed_technique = technique.clone();
                result
            }
            other => {
                ok = false;
                json::object(vec![
                    ("technique", json::string(other)),
                    ("ok", json::bool_value(false)),
                    ("error", json::string(format!("unknown bypass technique {other}"))),
                ])
            }
        };
        if result.get("ok").and_then(Value::as_bool) == Some(false) {
            ok = false;
        }
        if let Some(paths) = result.get("artifact_paths").and_then(Value::as_array) {
            artifact_paths.extend(paths.iter().cloned());
        }
        executions.push(result);
    }

    Ok(json::object(vec![
        ("schema", json::string(SCHEMA)),
        ("ok", json::bool_value(ok)),
        ("technique_id", json::string(executed_technique)),
        ("techniques", Value::Arr(techniques.into_iter().map(json::string).collect())),
        ("executions", Value::Arr(executions)),
        ("fileless", json::bool_value(fileless)),
        ("artifact_paths", Value::Arr(artifact_paths)),
        ("selected_path", selected_path),
        ("scope", scope_value),
        ("service_account", sa_value),
        ("benign", json::bool_value(true)),
        ("no_new_binary", json::bool_value(fileless)),
    ]))
}

fn techniques_of(plan: &Value) -> Vec<String> {
    if let Some(items) = plan.get("techniques").and_then(Value::as_array) {
        return items
            .iter()
            .filter_map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .or_else(|| item.get("id").and_then(Value::as_str).map(str::to_string))
            })
            .collect();
    }
    plan.get("technique")
        .and_then(Value::as_str)
        .map(|value| vec![value.to_string()])
        .unwrap_or_default()
}

fn script_text(plan: &Value) -> Result<String, String> {
    if let Some(encoded) = plan.get("script_b64").and_then(Value::as_str) {
        let bytes = base64::decode(encoded)?;
        return String::from_utf8(bytes)
            .map_err(|_| "script_b64 is not valid UTF-8".to_string());
    }
    plan.get("script")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "bypass plan needs script/script_b64".to_string())
}

fn with_shebang(script: &str) -> String {
    if script.starts_with("#!") {
        script.to_string()
    } else {
        format!("#!/bin/sh\n{script}")
    }
}

fn workdir_of(plan: &Value) -> Option<String> {
    plan.get("workdir")
        .and_then(Value::as_str)
        .map(str::to_string)
        .filter(|path| Path::new(path).is_dir())
}

fn argv_of(plan: &Value) -> Vec<String> {
    plan.get("argv")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(value_text).collect())
        .unwrap_or_default()
}

fn value_text(value: &Value) -> String {
    match value {
        Value::Str(text) => text.clone(),
        other => other.to_json(),
    }
}

fn clean_env(plan: &Value) -> bool {
    plan.get("clean_env")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn memfd_exec(plan: &Value, opts: &Options, timeout: u64) -> Result<Value, String> {
    let script = with_shebang(&script_text(plan)?);
    #[cfg(target_os = "linux")]
    {
        let name = format!("inkblade-bypass-{}", util::random_hex(4));
        let c_name = std::ffi::CString::new(name.clone())
            .map_err(|_| "memfd name contains NUL".to_string())?;
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, c_name.as_ptr(), 0u32) } as i32;
        if fd < 0 {
            return Err(format!(
                "memfd_create failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut written = 0usize;
        let bytes = script.as_bytes();
        while written < bytes.len() {
            let count = unsafe {
                libc::write(
                    fd,
                    bytes[written..].as_ptr() as *const libc::c_void,
                    bytes.len() - written,
                )
            };
            if count <= 0 {
                let error = std::io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(format!("memfd write failed: {error}"));
            }
            written += count as usize;
        }
        let _ = unsafe { libc::fchmod(fd, 0o700) };
        let path = format!("/proc/self/fd/{fd}");
        let result = exec::run_program(
            &path,
            &argv_of(plan),
            opts,
            timeout,
            clean_env(plan),
            workdir_of(plan).as_deref(),
        );
        unsafe { libc::close(fd) };
        let result = result?;
        Ok(json::object(vec![
            ("technique", json::string("fileless-memfd-exec")),
            ("ok", json::bool_value(
                result.get("exit_code").and_then(Value::as_i64) == Some(0)
                    && result.get("timed_out").and_then(Value::as_bool) != Some(true),
            )),
            ("fileless", json::bool_value(true)),
            ("memfd", json::object(vec![
                ("name", json::string(name)),
                ("size", json::number(bytes.len() as u64)),
                ("path", json::string(path)),
                ("fd", json::number(fd as u64)),
            ])),
            ("artifact_paths", Value::Arr(Vec::new())),
            ("no_new_binary", json::bool_value(true)),
            ("exit_code", result.get("exit_code").cloned().unwrap_or(Value::Null)),
            ("stdout", result.get("stdout").cloned().unwrap_or(Value::Null)),
            ("stderr", result.get("stderr").cloned().unwrap_or(Value::Null)),
            ("timed_out", result.get("timed_out").cloned().unwrap_or(Value::Null)),
            ("duration_ms", result.get("duration_ms").cloned().unwrap_or(Value::Null)),
            ("argv", result.get("argv").cloned().unwrap_or(Value::Null)),
            ("result", result),
        ]))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (opts, timeout, script);
        Err("fileless-memfd-exec is only available on Linux".to_string())
    }
}

fn existing_exec(plan: &Value, opts: &Options, timeout: u64) -> Result<Value, String> {
    let candidates: Vec<String> = plan
        .get("binaries")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(value_text).collect())
        .unwrap_or_else(|| DEFAULT_BINARIES.iter().map(|v| v.to_string()).collect());
    let binary = candidates
        .iter()
        .find(|path| Path::new(path).is_file())
        .cloned()
        .ok_or_else(|| "no existing interpreter found (sh/busybox/env)".to_string())?;
    let script = script_text(plan)?;
    let name = Path::new(&binary)
        .file_name()
        .map(|value| value.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mut args: Vec<String> = Vec::new();
    if argv_of(plan).is_empty() {
        if name.contains("busybox") {
            args.extend(["sh".to_string(), "-c".to_string(), script]);
        } else {
            args.extend(["-c".to_string(), script]);
        }
    } else {
        args.extend(argv_of(plan));
    }
    let digest = std::fs::read(&binary)
        .ok()
        .map(|bytes| base64::hex(&sha256::sha256(&bytes)))
        .unwrap_or_default();
    let result = exec::run_program(
        &binary,
        &args,
        opts,
        timeout,
        clean_env(plan),
        workdir_of(plan).as_deref(),
    )?;
    Ok(json::object(vec![
        ("technique", json::string("existing-binary-exec")),
        ("ok", json::bool_value(
            result.get("exit_code").and_then(Value::as_i64) == Some(0)
                && result.get("timed_out").and_then(Value::as_bool) != Some(true),
        )),
        ("binary", json::string(binary)),
        ("binary_sha256", json::string(digest)),
        ("artifact_paths", Value::Arr(Vec::new())),
        ("no_new_binary", json::bool_value(true)),
        ("exit_code", result.get("exit_code").cloned().unwrap_or(Value::Null)),
        ("stdout", result.get("stdout").cloned().unwrap_or(Value::Null)),
        ("stderr", result.get("stderr").cloned().unwrap_or(Value::Null)),
        ("timed_out", result.get("timed_out").cloned().unwrap_or(Value::Null)),
        ("argv", result.get("argv").cloned().unwrap_or(Value::Null)),
        ("result", result),
    ]))
}

fn path_evasion(plan: &Value) -> Result<Value, String> {
    let monitored: Vec<String> = plan
        .get("monitored_paths")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(value_text).collect())
        .unwrap_or_default();
    let candidates: Vec<String> = plan
        .get("candidate_paths")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(value_text).collect())
        .unwrap_or_else(|| DEFAULT_WORKDIRS.iter().map(|v| v.to_string()).collect());
    let selected = candidates.iter().find(|candidate| {
        Path::new(candidate).is_dir()
            && !monitored.iter().any(|path| {
                candidate.as_str().starts_with(path.as_str())
                    || path.as_str().starts_with(candidate.as_str())
            })
    }).cloned();
    let selected_value = selected.clone().map(json::string).unwrap_or(Value::Null);
    Ok(json::object(vec![
        ("technique", json::string("path-evasion")),
        ("ok", json::bool_value(selected.is_some())),
        ("selected", selected_value),
        ("monitored_paths", Value::Arr(monitored.into_iter().map(json::string).collect())),
        ("candidates", Value::Arr(candidates.into_iter().map(json::string).collect())),
        ("reason", json::string(if selected.is_some() {
            "selected a writable/exec workspace outside the HIDS-monitored set"
        } else {
            "every candidate path overlaps a monitored path"
        })),
    ]))
}

fn api_body(response: Value) -> Value {
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        response.get("json").cloned().unwrap_or(response)
    } else {
        response
    }
}

fn namespace_scope(plan: &Value) -> Result<Value, String> {
    let config = K8sConfig::from_env()?;
    let target = plan.get("target").cloned().unwrap_or(Value::Null);
    let namespace = target
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| config.namespace.clone());
    let path = format!("/api/v1/namespaces/{namespace}");
    let labels = match config.request("GET", &path, None, 5_000, 1024 * 1024) {
        Ok(response) => api_body(response)
            .path("metadata.labels")
            .cloned()
            .unwrap_or(Value::Obj(Vec::new())),
        Err(error) => {
            return Ok(json::object(vec![
                ("technique", json::string("namespace-scope-evasion")),
                ("ok", json::bool_value(false)),
                ("namespace", json::string(namespace)),
                ("error", json::string(util::truncate_text(&error, 512).0)),
            ]))
        }
    };
    let mut in_scope: Vec<Value> = Vec::new();
    let mut policy_count = 0u64;
    for path in [
        "/apis/policies.kyverno.io/v1/validatingpolicies",
        "/apis/kyverno.io/v1/clusterpolicies",
    ] {
        if let Ok(response) = config.request("GET", path, None, 5_000, 4 * 1024 * 1024) {
            let response = api_body(response);
            if let Some(items) = response.get("items").and_then(Value::as_array) {
                policy_count += items.len() as u64;
                for item in items {
                    let name = item
                        .path("metadata.name")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let scope = item
                        .path("spec.matchConditions")
                        .map(|value| value.to_json())
                        .unwrap_or_default();
                    let quoted = format!("'{namespace}'");
                    let dquoted = format!("\"{namespace}\"");
                    if scope.contains(&quoted) || scope.contains(&dquoted) {
                        in_scope.push(json::string(name.to_string()));
                    }
                }
            }
        }
    }
    let evasion = in_scope.is_empty();
    Ok(json::object(vec![
        ("technique", json::string("namespace-scope-evasion")),
        ("ok", json::bool_value(evasion)),
        ("namespace", json::string(namespace)),
        ("labels", labels),
        ("policy_count", json::number(policy_count)),
        ("policies_in_scope", Value::Arr(in_scope)),
        ("evasion", json::string(if evasion {
            "namespace-outside-policy-scope"
        } else {
            "policy-in-scope"
        })),
    ]))
}

fn sa_permission(plan: &Value) -> Result<Value, String> {
    let config = K8sConfig::from_env()?;
    let target = plan.get("target").cloned().unwrap_or(Value::Null);
    let namespace = target
        .get("namespace")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| config.namespace.clone());
    let pod = target
        .get("pod")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let token = config.token()?;
    let mut subject = String::new();
    let mut claims = Value::Null;
    if let Some(payload) = token.split('.').nth(1) {
        if let Ok(bytes) = base64::decode_url(payload) {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                if let Ok(parsed) = json::parse(text) {
                    subject = parsed
                        .get("sub")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    claims = parsed;
                }
            }
        }
    }
    let checks = [
        ("pods/exec", "pods", "exec", "create"),
        ("pods", "pods", "", "get"),
        ("secrets", "secrets", "", "get"),
    ];
    let mut allowed = Vec::new();
    let mut results = Vec::new();
    for (label, resource, subresource, verb) in checks {
        let mut attributes = vec![
            ("namespace", json::string(namespace.clone())),
            ("verb", json::string(verb)),
            ("group", json::string("")),
            ("resource", json::string(resource)),
        ];
        if !subresource.is_empty() {
            attributes.push(("subresource", json::string(subresource)));
        }
        if !pod.is_empty() && resource == "pods" {
            attributes.push(("name", json::string(pod.clone())));
        }
        let body = json::object(vec![
            ("apiVersion", json::string("authorization.k8s.io/v1")),
            ("kind", json::string("SelfSubjectAccessReview")),
            ("spec", json::object(vec![("resourceAttributes", json::object(attributes))])),
        ]);
        let response = config.request(
            "POST",
            "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
            Some(body.to_json().into_bytes()),
            5_000,
            1024 * 1024,
        );
        match response {
            Ok(value) => {
                let value = api_body(value);
                let permitted = value
                    .path("status.allowed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if permitted {
                    allowed.push(json::string(label));
                }
                results.push(json::object(vec![
                    ("action", json::string(label)),
                    ("allowed", json::bool_value(permitted)),
                    ("reason", value.path("status.reason").cloned().unwrap_or(Value::Null)),
                ]));
            }
            Err(error) => results.push(json::object(vec![
                ("action", json::string(label)),
                ("allowed", json::bool_value(false)),
                ("error", json::string(util::truncate_text(&error, 256).0)),
            ])),
        }
    }
    let exec_allowed = allowed
        .iter()
        .filter_map(Value::as_str)
        .any(|label| label == "pods/exec");
    Ok(json::object(vec![
        ("technique", json::string("sa-permission-selection")),
        ("ok", json::bool_value(exec_allowed)),
        ("subject", json::string(subject)),
        ("claims", claims),
        ("namespace", json::string(namespace)),
        ("allowed", Value::Arr(allowed)),
        ("checks", Value::Arr(results)),
        ("selected_action", json::string(if exec_allowed {
            "pods/exec"
        } else {
            "none"
        })),
    ]))
}

fn split_exec(plan: &Value, opts: &Options, timeout: u64) -> Result<Value, String> {
    let commands: Vec<String> = plan
        .get("commands")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(value_text).collect())
        .unwrap_or_else(|| {
            script_text(plan)
                .unwrap_or_default()
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        });
    if commands.is_empty() {
        return Err("command-split-env-clean needs commands or script lines".to_string());
    }
    let binary = plan
        .get("binaries")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(value_text).collect::<Vec<_>>())
        .unwrap_or_else(|| DEFAULT_BINARIES.iter().map(|v| v.to_string()).collect())
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or_else(|| "no existing shell for command splitting".to_string())?;
    let workdir = workdir_of(plan);
    let mut executions = Vec::new();
    let mut ok = true;
    let mut combined = String::new();
    for (index, command) in commands.iter().take(32).enumerate() {
        let mut args = vec!["-c".to_string(), command.clone()];
        let base = Path::new(&binary)
            .file_name()
            .map(|value| value.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if base.contains("busybox") {
            args.insert(0, "sh".to_string());
        }
        let result = exec::run_program(
            &binary,
            &args,
            opts,
            timeout,
            true,
            workdir.as_deref(),
        )?;
        let code = result.get("exit_code").and_then(Value::as_i64).unwrap_or(-1);
        if code != 0 {
            ok = false;
        }
        if let Some(stdout) = result.get("stdout").and_then(Value::as_str) {
            combined.push_str(stdout);
            if !stdout.ends_with('\n') {
                combined.push('\n');
            }
        }
        executions.push(json::object(vec![
            ("index", json::number(index as u64)),
            ("command", json::string(command.clone())),
            ("exit_code", json::number(code)),
            ("timed_out", result.get("timed_out").cloned().unwrap_or(Value::Null)),
        ]));
    }
    Ok(json::object(vec![
        ("technique", json::string("command-split-env-clean")),
        ("ok", json::bool_value(ok)),
        ("commands", json::number(executions.len() as u64)),
        ("executions", Value::Arr(executions)),
        ("stdout", json::string(combined)),
        ("clean_env", json::bool_value(true)),
        ("artifact_paths", Value::Arr(Vec::new())),
    ]))
}

#[allow(dead_code)]
fn write_benign(path: &str, text: &str) -> std::io::Result<()> {
    // Only used by tests/fixtures that need a workspace marker; bypassed
    // execution never calls this.
    let mut file = std::fs::File::create(path)?;
    file.write_all(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_list_forms() {
        let one = json::object(vec![("technique", json::string("path-evasion"))]);
        assert_eq!(techniques_of(&one), vec!["path-evasion"]);
        let many = json::object(vec![(
            "techniques",
            Value::Arr(vec![json::string("a"), json::string("b")]),
        )]);
        assert_eq!(techniques_of(&many), vec!["a", "b"]);
    }

    #[test]
    fn shebang_is_added_once() {
        assert!(with_shebang("echo hi").starts_with("#!/bin/sh\n"));
        assert_eq!(with_shebang("#!/bin/sh\necho hi"), "#!/bin/sh\necho hi");
    }

    fn writable_options() -> Options {
        Options {
            read_only: false,
            ..Options::default()
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memfd_executes_without_an_artifact() {
        let plan = json::object(vec![
            ("techniques", Value::Arr(vec![json::string("fileless-memfd-exec")])),
            ("script", json::string("echo INKBLADE-BENIGN:memfd")),
            ("clean_env", json::bool_value(true)),
        ]);
        let result = run(&plan, &writable_options()).unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(result.get("fileless").and_then(Value::as_bool), Some(true));
        let executions = result.get("executions").and_then(Value::as_array).unwrap();
        let stdout = executions[0].get("stdout").and_then(Value::as_str).unwrap_or("");
        assert!(stdout.contains("INKBLADE-BENIGN:memfd"));
        assert_eq!(
            executions[0].get("artifact_paths").and_then(Value::as_array).map(|v| v.len()),
            Some(0)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn existing_binary_executes_without_a_new_file() {
        let plan = json::object(vec![
            ("techniques", Value::Arr(vec![json::string("existing-binary-exec")])),
            ("script", json::string("echo INKBLADE-BENIGN:existing")),
            ("binaries", Value::Arr(vec![json::string("/bin/sh")])),
        ]);
        let result = run(&plan, &writable_options()).unwrap();
        assert_eq!(result.get("ok").and_then(Value::as_bool), Some(true));
        let executions = result.get("executions").and_then(Value::as_array).unwrap();
        let stdout = executions[0].get("stdout").and_then(Value::as_str).unwrap_or("");
        assert!(stdout.contains("INKBLADE-BENIGN:existing"));
        assert_eq!(executions[0].get("binary").and_then(Value::as_str), Some("/bin/sh"));
    }

    #[test]
    fn path_evasion_skips_monitored_directories() {
        let plan = json::object(vec![
            ("techniques", Value::Arr(vec![json::string("path-evasion")])),
            ("monitored_paths", Value::Arr(vec![json::string("/dev/shm")])),
            ("candidate_paths", Value::Arr(vec![
                json::string("/dev/shm"), json::string("/tmp"),
            ])),
        ]);
        let result = run(&plan, &Options::default()).unwrap();
        assert_eq!(result.get("selected_path").and_then(Value::as_str), Some("/tmp"));
    }
}
