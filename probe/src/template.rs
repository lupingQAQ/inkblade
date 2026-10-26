//! Declarative native template runtime.
//!
//! A module is a JSON/YAML document, not code.  The probe executes its steps
//! (`http`, `tcp`, `exec`, `fs`, `k8s`, `socks`, `spawn`, `assert`,
//! `extract`) and returns structured evidence to the controller.

use std::collections::HashMap;
use std::fs;
use std::time::Instant;

use crate::audit::Audit;
use crate::base64;
use crate::config::Options;
use crate::exec;
use crate::fsops;
use crate::http::{self, HttpRequest};
use crate::json::{self, Value};
use crate::k8s::K8sConfig;
use crate::net;
use crate::spawn;
use crate::util;

struct Runtime<'a> {
    opts: &'a Options,
    audit: &'a Audit,
    probe_id: String,
    parent_id: Option<String>,
    task_id: String,
    vars: HashMap<String, Value>,
    steps: HashMap<String, Value>,
    results: Vec<Value>,
    started: Instant,
    max_steps: usize,
    max_ms: u64,
    bytes: usize,
    max_bytes: usize,
}

pub fn load_template(inline: Option<&Value>, path: Option<&str>) -> Result<Value, String> {
    if let Some(value) = inline {
        return Ok(value.clone());
    }
    let path = path.ok_or_else(|| "task needs template or template_path".to_string())?;
    let text = if path.starts_with("http://") || path.starts_with("https://") {
        let response = http::request(HttpRequest {
            method: "GET",
            url: path,
            headers: Vec::new(),
            body: None,
            timeout_ms: 10_000,
            max_redirects: 3,
            max_body: 2 * 1024 * 1024,
            ca_pem: None,
        })?;
        response
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    } else {
        fs::read_to_string(path).map_err(|error| format!("template read {path}: {error}"))?
    };
    let parsed: serde_json::Value =
        serde_yaml::from_str(&text).map_err(|error| format!("template parse: {error}"))?;
    Ok(Value::from_serde(&parsed))
}

pub fn execute(
    template: &Value,
    params: &Value,
    opts: &Options,
    audit: &Audit,
    probe_id: &str,
    parent_id: Option<&str>,
    task_id: &str,
) -> Result<Value, String> {
    let budget = template.get("budget");
    let max_steps = budget
        .and_then(|value| value.get("max_steps"))
        .and_then(Value::as_u64)
        .unwrap_or(64) as usize;
    let max_ms = budget
        .and_then(|value| value.get("max_ms"))
        .and_then(Value::as_u64)
        .unwrap_or(120_000);
    let max_bytes = budget
        .and_then(|value| value.get("max_bytes"))
        .and_then(Value::as_u64)
        .unwrap_or(16 * 1024 * 1024) as usize;
    let mut runtime = Runtime {
        opts,
        audit,
        probe_id: probe_id.to_string(),
        parent_id: parent_id.map(str::to_string),
        task_id: task_id.to_string(),
        vars: HashMap::new(),
        steps: HashMap::new(),
        results: Vec::new(),
        started: Instant::now(),
        max_steps: max_steps.clamp(1, 512),
        max_ms: max_ms.clamp(100, 3_600_000),
        bytes: 0,
        max_bytes: max_bytes.clamp(1024, 64 * 1024 * 1024),
    };
    if let Value::Obj(items) = params {
        for (key, value) in items {
            runtime.vars.insert(key.clone(), value.clone());
        }
    }
    if let Some(target) = params.get("target") {
        runtime.vars.insert("target".to_string(), target.clone());
    }
    runtime
        .vars
        .insert("probe_id".to_string(), json::string(probe_id));
    runtime.vars.insert(
        "parent_id".to_string(),
        parent_id.map(json::string).unwrap_or(Value::Null),
    );
    runtime.vars.insert("task_id".to_string(), json::string(task_id));
    let steps = template
        .get("steps")
        .and_then(Value::as_array)
        .ok_or_else(|| "template has no steps array".to_string())?;
    if steps.len() > runtime.max_steps {
        return Err(format!(
            "template has {} steps, budget is {}",
            steps.len(),
            runtime.max_steps
        ));
    }
    for (index, raw) in steps.iter().enumerate() {
        if runtime.started.elapsed().as_millis() as u64 > runtime.max_ms {
            return Err("template time budget exceeded".to_string());
        }
        let step = runtime.render_value(raw);
        let step_id = step
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("step-{}", index + 1));
        let op = step
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if op.is_empty() {
            return Err(format!("step {step_id}: missing op"));
        }
        runtime.audit.event(
            "template.step",
            json::object(vec![
                ("task_id", json::string(runtime.task_id.clone())),
                ("step", json::string(step_id.clone())),
                ("op", json::string(op.clone())),
            ]),
        );
        let result = runtime.execute_step(&step_id, &op, &step);
        match result {
            Ok(value) => {
                runtime.steps.insert(step_id.clone(), value.clone());
                runtime
                    .vars
                    .insert(format!("steps.{step_id}"), value.clone());
                runtime.vars.insert("last".to_string(), value.clone());
                runtime.results.push(json::object(vec![
                    ("step", json::string(step_id)),
                    ("op", json::string(op)),
                    ("ok", json::bool_value(true)),
                    ("result", value),
                ]));
            }
            Err(error) => {
                let failure = json::object(vec![
                    ("step", json::string(step_id.clone())),
                    ("op", json::string(op.clone())),
                    ("ok", json::bool_value(false)),
                    ("error", json::string(error.clone())),
                ]);
                runtime.results.push(failure);
                return Err(format!("step {step_id} failed: {error}"));
            }
        }
    }
    Ok(json::object(vec![
        ("ok", json::bool_value(true)),
        ("task_id", json::string(task_id)),
        ("probe_id", json::string(probe_id)),
        ("parent_id", parent_id.map(json::string).unwrap_or(Value::Null)),
        ("template", template.get("name").cloned().unwrap_or_else(|| json::string("unnamed"))),
        ("steps", Value::Arr(runtime.results)),
        (
            "vars",
            Value::Obj(runtime.vars.into_iter().collect()),
        ),
        ("duration_ms", json::number(runtime.started.elapsed().as_millis() as u64)),
    ]))
}

impl<'a> Runtime<'a> {
    fn execute_step(&mut self, step_id: &str, op: &str, step: &Value) -> Result<Value, String> {
        match op {
            "http" => self.http_step(step),
            "tcp" => self.tcp_step(step),
            "exec" => self.exec_step(step),
            "fs" => self.fs_step(step),
            "k8s" => self.k8s_step(step),
            "socks" => self.socks_step(step),
            "spawn" => self.spawn_step(step),
            "assert" => self.assert_step(step),
            "extract" => self.extract_step(step_id, step),
            "sleep" => {
                let ms = step.get("ms").and_then(Value::as_u64).unwrap_or(100);
                std::thread::sleep(std::time::Duration::from_millis(ms.min(10_000)));
                Ok(json::object(vec![("slept_ms", json::number(ms))]))
            }
            other => Err(format!("unsupported op {other}")),
        }
    }

    fn http_step(&mut self, step: &Value) -> Result<Value, String> {
        let method = step.get("method").and_then(Value::as_str).unwrap_or("GET");
        let url = self.required_str(step, "url")?;
        let timeout_ms = self.timeout(step);
        let mut headers = Vec::new();
        if let Some(Value::Obj(items)) = step.get("headers") {
            for (name, value) in items {
                headers.push((name.clone(), value_text(value)));
            }
        }
        let body = match step.get("body") {
            Some(Value::Str(text)) => Some(text.as_bytes().to_vec()),
            Some(Value::Null) | None => None,
            Some(value) => Some(value.to_json().into_bytes()),
        };
        let max_body = self.max_output(step);
        let redirects = step
            .get("max_redirects")
            .and_then(Value::as_u64)
            .unwrap_or(5) as u32;
        let ca_pem = step
            .get("ca_path")
            .and_then(Value::as_str)
            .and_then(|path| util::read_bytes(path, 4 * 1024 * 1024));
        let result = http::request(HttpRequest {
            method,
            url: &url,
            headers,
            body,
            timeout_ms,
            max_redirects: redirects,
            max_body,
            ca_pem,
        })?;
        self.account_bytes(
            result
                .get("body")
                .and_then(Value::as_str)
                .map(str::len)
                .unwrap_or(0),
        )?;
        if let Some(expect) = step.get("expect") {
            self.check_expect(expect, &result)?;
        }
        Ok(result)
    }

    fn tcp_step(&mut self, step: &Value) -> Result<Value, String> {
        let host = self.required_str(step, "host")?;
        let port = step
            .get("port")
            .and_then(Value::as_u64)
            .ok_or_else(|| "tcp requires port".to_string())? as u16;
        let send = step
            .get("send_b64")
            .and_then(Value::as_str)
            .map(base64::decode)
            .transpose()?;
        let read_bytes = step
            .get("read_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(4096) as usize;
        Ok(net::tcp_probe(
            &host,
            port,
            send.as_deref(),
            read_bytes,
            self.timeout(step),
        )?)
    }

    fn exec_step(&mut self, step: &Value) -> Result<Value, String> {
        let argv = if let Some(items) = step.get("argv").and_then(Value::as_array) {
            items.iter().map(value_text).collect::<Vec<_>>()
        } else if let Some(command) = step.get("command").and_then(Value::as_str) {
            if self.opts.read_only {
                return Err("shell exec requires --allow-write".to_string());
            }
            vec!["sh".to_string(), "-c".to_string(), command.to_string()]
        } else {
            return Err("exec requires argv or command".to_string());
        };
        let timeout = self.timeout(step);
        exec::run(&argv, self.opts, timeout)
    }

    fn fs_step(&mut self, step: &Value) -> Result<Value, String> {
        let action = step.get("action").and_then(Value::as_str).unwrap_or("read");
        let path = self.required_str(step, "path")?;
        match action {
            "read" => {
                let offset = step.get("offset").and_then(Value::as_u64).unwrap_or(0);
                let result = fsops::read(&path, offset, self.max_output(step))?;
                self.account_bytes(
                    result
                        .get("data_b64")
                        .and_then(Value::as_str)
                        .map(str::len)
                        .unwrap_or(0),
                )?;
                Ok(result)
            }
            "list" => {
                let glob = step.get("glob").and_then(Value::as_str);
                fsops::list_glob(&path, glob)
            }
            "stat" => fsops::stat(&path),
            "write" => {
                let data = self.data_from_step(step)?;
                let offset = step.get("offset").and_then(Value::as_u64).unwrap_or(0);
                let mode = step.get("mode").and_then(Value::as_u64).map(|v| v as u32);
                fsops::write(&path, &data, offset, mode, self.opts)
            }
            "mkdir" => {
                let recursive = step.get("recursive").and_then(Value::as_bool).unwrap_or(false);
                let mode = step.get("mode").and_then(Value::as_u64).map(|v| v as u32);
                fsops::mkdir(&path, recursive, mode, self.opts)
            }
            "remove" => {
                let recursive = step.get("recursive").and_then(Value::as_bool).unwrap_or(false);
                fsops::remove(&path, recursive, self.opts)
            }
            "chmod" => {
                let mode = step
                    .get("mode")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| "chmod requires mode".to_string())? as u32;
                fsops::set_mode(&path, mode)?;
                Ok(json::object(vec![("path", json::string(path)), ("mode", json::number(mode as u64))]))
            }
            other => Err(format!("unsupported fs action {other}")),
        }
    }

    fn k8s_step(&mut self, step: &Value) -> Result<Value, String> {
        let mut config = K8sConfig::from_env()?;
        if let Some(server) = step.get("server").and_then(Value::as_str) {
            config.server = server.to_string();
        }
        if let Some(path) = step.get("token_path").and_then(Value::as_str) {
            config.token_path = path.to_string();
        }
        if let Some(path) = step.get("ca_path").and_then(Value::as_str) {
            config.ca_path = path.to_string();
        }
        let action = step.get("action").and_then(Value::as_str).unwrap_or("list");
        let timeout = self.timeout(step);
        match action {
            "list" => {
                let resource = self.required_str(step, "resource")?;
                let namespace = step.get("namespace").and_then(Value::as_str);
                config.list(&resource, namespace, timeout)
            }
            "get" => {
                let resource = self.required_str(step, "resource")?;
                let name = self.required_str(step, "name")?;
                let namespace = step.get("namespace").and_then(Value::as_str);
                config.get(&resource, namespace, &name, timeout)
            }
            "exec" => {
                let namespace = step.get("namespace").and_then(Value::as_str).unwrap_or(&config.namespace);
                let pod = self.required_str(step, "pod")?;
                let container = step.get("container").and_then(Value::as_str);
                let argv = step
                    .get("argv")
                    .and_then(Value::as_array)
                    .map(|items| items.iter().map(value_text).collect::<Vec<_>>())
                    .ok_or_else(|| "k8s exec requires argv".to_string())?;
                config.exec(namespace, &pod, container, &argv, timeout)
            }
            "copy" => {
                let namespace = step.get("namespace").and_then(Value::as_str).unwrap_or(&config.namespace);
                let pod = self.required_str(step, "pod")?;
                let container = step.get("container").and_then(Value::as_str);
                let source = self.required_str(step, "source")?;
                let destination = self.required_str(step, "destination")?;
                config.copy(namespace, &pod, container, &source, &destination, timeout)
            }
            other => Err(format!("unsupported k8s action {other}")),
        }
    }

    fn socks_step(&mut self, step: &Value) -> Result<Value, String> {
        let action = step.get("action").and_then(Value::as_str).unwrap_or("serve");
        match action {
            "serve" => {
                let bind = step.get("bind").and_then(Value::as_str).unwrap_or("127.0.0.1");
                let port = step.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
                let handle = net::start_socks5(bind, port)?;
                Ok(json::object(vec![
                    ("address", json::string(handle.address)),
                    ("bind", json::string(bind)),
                    ("listen", json::bool_value(true)),
                ]))
            }
            "connect" => {
                let host = self.required_str(step, "host")?;
                let port = step.get("port").and_then(Value::as_u64).unwrap_or(1080) as u16;
                Ok(net::tcp_probe(&host, port, None, 0, self.timeout(step))?)
            }
            other => Err(format!("unsupported socks action {other}")),
        }
    }

    fn spawn_step(&mut self, step: &Value) -> Result<Value, String> {
        if let Some(items) = step.get("argv").and_then(Value::as_array) {
            let argv = items.iter().map(value_text).collect::<Vec<_>>();
            let detach = step.get("detach").and_then(Value::as_bool).unwrap_or(false);
            return spawn::run_process(&argv, detach, self.opts, self.timeout(step));
        }
        let path = self.required_str(step, "binary_path")?;
        let bytes = fs::read(&path).map_err(|error| format!("child binary read: {error}"))?;
        let binary_b64 = base64::encode(&bytes);
        let expected = step.get("sha256").and_then(Value::as_str);
        let target = step.get("path").and_then(Value::as_str);
        let materialized = spawn::materialize(&binary_b64, target, expected, self.opts)?;
        let probe_id = step
            .get("probe_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("child-{}", util::random_hex(4)));
        Ok(json::object(vec![
            ("probe_id", json::string(probe_id)),
            ("parent_id", json::string(self.probe_id.clone())),
            ("path", json::string(materialized.to_string_lossy().to_string())),
            ("registered", json::bool_value(false)),
            (
                "note",
                json::string("template spawn materialises the binary; use the protocol spawn op for a registered child"),
            ),
        ]))
    }

    fn assert_step(&mut self, step: &Value) -> Result<Value, String> {
        let left_path = step.get("path").and_then(Value::as_str);
        let exists = step.get("exists").and_then(Value::as_bool);
        if let Some(path) = left_path {
            let value = self.lookup(path);
            if let Some(expected) = exists {
                let ok = value.is_some() == expected;
                if !ok {
                    return Err(format!("assert exists({path}) expected {expected}"));
                }
            }
            if let Some(expected) = step.get("equals") {
                let ok = value.map(|v| v == expected).unwrap_or(false);
                if !ok {
                    return Err(format!("assert {path} == {}", expected.to_json()));
                }
            }
            if let Some(expected) = step.get("contains").and_then(Value::as_str) {
                let text = value.map(value_text).unwrap_or_default();
                if !text.contains(expected) {
                    return Err(format!("assert {path} contains {expected}"));
                }
            }
        } else if let Some(expression) = step.get("expr").and_then(Value::as_str) {
            self.assert_expression(expression)?;
        } else {
            return Err("assert requires path or expr".to_string());
        }
        Ok(json::object(vec![("asserted", json::bool_value(true))]))
    }

    fn extract_step(&mut self, _step_id: &str, step: &Value) -> Result<Value, String> {
        let mut extracted = Vec::new();
        if let Some(Value::Obj(items)) = step.get("map") {
            for (name, path_value) in items {
                let path = value_text(path_value);
                let value = self
                    .lookup(&path)
                    .cloned()
                    .unwrap_or(Value::Null);
                self.vars.insert(name.clone(), value.clone());
                extracted.push((name.clone(), value));
            }
        }
        Ok(Value::Obj(extracted))
    }

    fn check_expect(&self, expect: &Value, result: &Value) -> Result<(), String> {
        if let Some(statuses) = expect.get("status").and_then(Value::as_array) {
            let status = result.get("status").and_then(Value::as_u64).unwrap_or(0);
            let ok = statuses.iter().any(|value| value.as_u64() == Some(status));
            if !ok {
                return Err(format!("HTTP status {status} not in expected set"));
            }
        }
        if let Some(status) = expect.get("status").and_then(Value::as_u64) {
            let got = result.get("status").and_then(Value::as_u64).unwrap_or(0);
            if status != got {
                return Err(format!("HTTP status {got}, expected {status}"));
            }
        }
        Ok(())
    }

    fn assert_expression(&mut self, expression: &str) -> Result<(), String> {
        for operator in ["==", "!=", ">=", "<=", ">", "<"] {
            if let Some(index) = expression.find(operator) {
                let left = expression[..index].trim();
                let right = expression[index + operator.len()..].trim();
                let left_value = self.lookup(left).cloned().unwrap_or(Value::Null);
                let right_value = parse_literal(right);
                let ok = match operator {
                    "==" => left_value == right_value,
                    "!=" => left_value != right_value,
                    ">=" => number_of(&left_value) >= number_of(&right_value),
                    "<=" => number_of(&left_value) <= number_of(&right_value),
                    ">" => number_of(&left_value) > number_of(&right_value),
                    "<" => number_of(&left_value) < number_of(&right_value),
                    _ => false,
                };
                if !ok {
                    return Err(format!("assertion failed: {expression}"));
                }
                return Ok(());
            }
        }
        if let Some(path) = expression.strip_prefix("exists ") {
            if self.lookup(path.trim()).is_none() {
                return Err(format!("assertion failed: {expression}"));
            }
            return Ok(());
        }
        Err(format!("unsupported assertion: {expression}"))
    }

    fn required_str(&self, step: &Value, key: &str) -> Result<String, String> {
        step.get(key)
            .map(value_text)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing {key}"))
    }

    fn timeout(&self, step: &Value) -> u64 {
        self.opts
            .timeout_ms(step.get("timeout_ms").and_then(Value::as_u64))
    }

    fn max_output(&self, step: &Value) -> usize {
        step.get("max_output")
            .and_then(Value::as_u64)
            .map(|value| value as usize)
            .unwrap_or_else(|| self.opts.max_output_bytes())
            .min(self.opts.max_output_bytes())
    }

    fn data_from_step(&self, step: &Value) -> Result<Vec<u8>, String> {
        if let Some(text) = step.get("data_b64").and_then(Value::as_str) {
            return base64::decode(text);
        }
        if let Some(text) = step.get("data").and_then(Value::as_str) {
            return Ok(text.as_bytes().to_vec());
        }
        if let Some(value) = step.get("json") {
            return Ok(value.to_json().into_bytes());
        }
        Ok(Vec::new())
    }

    fn account_bytes(&mut self, count: usize) -> Result<(), String> {
        self.bytes = self.bytes.saturating_add(count);
        if self.bytes > self.max_bytes {
            return Err("task byte budget exceeded".to_string());
        }
        Ok(())
    }

    fn lookup(&self, path: &str) -> Option<&Value> {
        if let Some(value) = self.vars.get(path) {
            return Some(value);
        }
        if path == "last" {
            return self.vars.get("last");
        }
        if let Some(rest) = path.strip_prefix("last.") {
            return self.vars.get("last").and_then(|value| value.path(rest));
        }
        let mut parts = path.split('.');
        let first = parts.next()?;
        if first == "steps" {
            let step_id = parts.next()?;
            let step = self.steps.get(step_id)?;
            let rest = parts.collect::<Vec<_>>().join(".");
            return if rest.is_empty() { Some(step) } else { step.path(&rest) };
        }
        if first == "params" {
            return self.vars.get(parts.collect::<Vec<_>>().join(".").as_str());
        }
        self.vars.get(first)
    }

    fn render_value(&self, value: &Value) -> Value {
        match value {
            Value::Str(text) => self.render_string(text),
            Value::Arr(items) => Value::Arr(items.iter().map(|value| self.render_value(value)).collect()),
            Value::Obj(items) => Value::Obj(
                items
                    .iter()
                    .map(|(key, value)| (key.clone(), self.render_value(value)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn render_string(&self, text: &str) -> Value {
        let mut out = String::new();
        let mut rest = text;
        while let Some(start) = rest.find("{{") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let end = match after.find("}}") {
                Some(end) => end,
                None => {
                    out.push_str(&rest[start..]);
                    return json::string(out);
                }
            };
            let token = after[..end].trim();
            let value = self.lookup(token);
            if let Some(value) = value {
                if start == 0 && end + 4 == rest.len() {
                    return value.clone();
                }
                out.push_str(&value_text(value));
            } else {
                out.push_str(&rest[start..start + 2 + end + 2]);
            }
            rest = &after[end + 2..];
        }
        out.push_str(rest);
        json::string(out)
    }
}

fn parse_literal(text: &str) -> Value {
    let trimmed = text.trim();
    if trimmed == "true" {
        return Value::Bool(true);
    }
    if trimmed == "false" {
        return Value::Bool(false);
    }
    if trimmed == "null" {
        return Value::Null;
    }
    if let Ok(value) = trimmed.parse::<f64>() {
        return Value::Num(value);
    }
    let unquoted = trimmed
        .trim_matches('"')
        .trim_matches('\'')
        .to_string();
    Value::Str(unquoted)
}

fn number_of(value: &Value) -> f64 {
    value.as_f64().unwrap_or(0.0)
}

pub fn value_text(value: &Value) -> String {
    match value {
        Value::Str(text) => text.clone(),
        Value::Null => String::new(),
        Value::Bool(value) => value.to_string(),
        Value::Num(value) => {
            if value.fract() == 0.0 {
                format!("{}", *value as i64)
            } else {
                value.to_string()
            }
        }
        other => other.to_json(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditSink;

    #[test]
    fn renders_variables_and_parses_literals() {
        let opts = Options::default();
        let audit = Audit::new(AuditSink::Stderr, None, "p");
        let template = json::parse(
            r#"{"name":"t","steps":[{"id":"s","op":"assert","path":"target","contains":"example"}]}"#,
        )
        .unwrap();
        let params = json::parse(r#"{"target":"https://example.test/x"}"#).unwrap();
        assert!(execute(&template, &params, &opts, &audit, "p", None, "task").is_ok());
        assert_eq!(parse_literal("12"), Value::Num(12.0));
    }

    #[test]
    fn template_rejects_missing_target_assertion() {
        let opts = Options::default();
        let audit = Audit::new(AuditSink::Stderr, None, "p");
        let template = json::parse(
            r#"{"steps":[{"id":"s","op":"assert","path":"target","contains":"example"}]}"#,
        )
        .unwrap();
        let params = json::parse(r#"{"target":"https://other.test"}"#).unwrap();
        assert!(execute(&template, &params, &opts, &audit, "p", None, "task").is_err());
    }
}
