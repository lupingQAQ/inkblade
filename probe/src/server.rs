//! Authenticated framed protocol server.

use std::collections::HashMap;
use std::io::{self, BufWriter, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::Child;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use crate::audit::Audit;
use crate::auth;
use crate::base64;
use crate::collect;
use crate::config::Options;
use crate::exec;
use crate::fsops;
use crate::json::{self, Value};
use crate::net;
use crate::protocol;
use crate::sha256;
use crate::spawn;
use crate::template;
use crate::util;

const VERSION: &str = env!("CARGO_PKG_VERSION");

struct ChildLink {
    probe_id: String,
    stdin: Arc<Mutex<std::process::ChildStdin>>,
    child: Child,
    token_file: std::path::PathBuf,
    binary: std::path::PathBuf,
}

struct State {
    opts: Options,
    audit: Audit,
    writer: Arc<Mutex<BufWriter<io::Stdout>>>,
    streams: Arc<Mutex<HashMap<u64, Arc<Mutex<TcpStream>>>>>,
    children: Arc<Mutex<HashMap<String, ChildLink>>>,
    next_stream: AtomicU64,
    started: Instant,
}

impl State {
    fn send(&self, value: Value) -> Result<(), String> {
        let mut writer = self.writer.lock().map_err(|_| "writer lock".to_string())?;
        protocol::write_frame(&mut *writer, &value)
    }

    fn send_raw(&self, value: Value) {
        let _ = self.send(value);
    }

    fn response(&self, id: &str, data: Value) {
        let mut value = protocol::response(id, data);
        if let Value::Obj(items) = &mut value {
            items.push(("probe_id".to_string(), json::string(self.opts.probe_id.clone())));
            items.push((
                "parent_id".to_string(),
                self.opts.parent_id.clone().map(json::string).unwrap_or(Value::Null),
            ));
        }
        self.send_raw(value);
    }

    fn failure(&self, id: &str, code: &str, message: &str) {
        let mut value = protocol::failure(id, code, message);
        if let Value::Obj(items) = &mut value {
            items.push(("probe_id".to_string(), json::string(self.opts.probe_id.clone())));
            items.push((
                "parent_id".to_string(),
                self.opts.parent_id.clone().map(json::string).unwrap_or(Value::Null),
            ));
        }
        self.send_raw(value);
    }
}

pub fn serve(opts: Options) -> Result<(), String> {
    let probe_id = opts.probe_id.clone();
    let audit = Audit::new(
        crate::audit::AuditSink::Stderr,
        opts.audit_path.clone(),
        &probe_id,
    );
    let state = Arc::new(State {
        opts,
        audit,
        writer: Arc::new(Mutex::new(BufWriter::new(io::stdout()))),
        streams: Arc::new(Mutex::new(HashMap::new())),
        children: Arc::new(Mutex::new(HashMap::new())),
        next_stream: AtomicU64::new(1),
        started: Instant::now(),
    });
    handshake(&state)?;
    state.audit.event(
        "probe.ready",
        json::object(vec![
            ("probe_id", json::string(state.opts.probe_id.clone())),
            ("parent_id", state.opts.parent_id.clone().map(json::string).unwrap_or(Value::Null)),
        ]),
    );
    let stdin = io::stdin();
    let mut input = stdin.lock();
    loop {
        let frame = match protocol::read_frame(&mut input) {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                state.audit.event("protocol.error", json::object(vec![("error", json::string(error))]));
                break;
            }
        };
        if handle_frame(&state, frame).is_err() {
            break;
        }
    }
    shutdown(&state);
    Ok(())
}

fn handshake(state: &State) -> Result<(), String> {
    let challenge = auth::new_challenge();
    let server_nonce = auth::new_challenge();
    state.send(json::object(vec![
        ("v", json::number(1)),
        ("type", json::string("hello")),
        ("server", json::string("inkblade-probe")),
        ("version", json::string(VERSION)),
        ("probe_id", json::string(state.opts.probe_id.clone())),
        ("parent_id", state.opts.parent_id.clone().map(json::string).unwrap_or(Value::Null)),
        ("challenge", json::string(challenge.clone())),
        ("nonce", json::string(server_nonce.clone())),
        ("auth", json::string("hmac-sha256")),
        ("read_only", json::bool_value(state.opts.read_only)),
        ("window", json::number(state.opts.max_window as u64)),
    ]))?;
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let frame = protocol::read_frame(&mut input)?
        .ok_or_else(|| "client disconnected before auth".to_string())?;
    if frame.get("type").and_then(Value::as_str) != Some("auth") {
        return Err("expected auth frame".to_string());
    }
    let nonce = frame
        .get("nonce")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| server_nonce.clone());
    let mac = frame.get("mac").and_then(Value::as_str);
    let proof = frame.get("proof").and_then(Value::as_str);
    let ok = if let Some(mac) = mac {
        auth::verify(&state.opts.token, &nonce, &challenge, mac)
    } else if let Some(proof) = proof {
        verify_proof(state, &nonce, proof)
    } else {
        false
    };
    if !ok {
        state.audit.event(
            "probe.auth_failed",
            json::object(vec![("remote", json::string("stdio"))]),
        );
        state.send_raw(json::object(vec![
            ("v", json::number(1)),
            ("type", json::string("error")),
            ("ok", json::bool_value(false)),
            (
                "error",
                json::object(vec![
                    ("code", json::string("auth_failed")),
                    ("message", json::string("challenge-HMAC verification failed")),
                ]),
            ),
        ]));
        return Err("authentication failed".to_string());
    }
    state.send(json::object(vec![
        ("v", json::number(1)),
        ("type", json::string("ready")),
        ("probe_id", json::string(state.opts.probe_id.clone())),
        ("parent_id", state.opts.parent_id.clone().map(json::string).unwrap_or(Value::Null)),
        ("version", json::string(VERSION)),
        ("read_only", json::bool_value(state.opts.read_only)),
        ("caps", Value::Arr(vec![
            json::string("collect"),
            json::string("exec"),
            json::string("bypass"),
            json::string("dial"),
            json::string("beacon"),
            json::string("cleanup"),
            json::string("upload"),
            json::string("download"),
            json::string("spawn"),
            json::string("task"),
            json::string("socks"),
            json::string("k8s"),
        ])),
        ("window", json::number(state.opts.max_window as u64)),
        ("max_output", json::number(state.opts.max_output_bytes() as u64)),
    ]))?;
    Ok(())
}

fn verify_proof(state: &State, nonce: &str, proof: &str) -> bool {
    let trimmed = proof.strip_prefix("b64:").unwrap_or(proof);
    let provided = base64::decode(trimmed)
        .or_else(|_| base64::decode_url(trimmed))
        .or_else(|_| base64::unhex(trimmed));
    let provided = match provided {
        Ok(value) => value,
        Err(_) => return false,
    };
    let parent = state.opts.parent_id.clone().unwrap_or_default();
    let message = format!("{nonce}{}{parent}", state.opts.probe_id);
    let expected = crate::sha256::hmac_sha256(state.opts.token.as_bytes(), message.as_bytes());
    crate::sha256::constant_time_eq(&provided, &expected)
}

fn handle_frame(state: &Arc<State>, frame: Value) -> Result<(), String> {
    let frame_type = frame.get("type").and_then(Value::as_str).unwrap_or("");
    if frame_type == "data" || frame_type == "stream-eof" || frame_type == "stream-close" {
        return handle_stream_frame(state, &frame);
    }
    if frame_type == "result" || frame_type == "event" {
        return Ok(());
    }
    if frame_type == "bye" {
        return Err("client said bye".to_string());
    }
    if frame_type != "req" && frame_type != "task" {
        return Ok(());
    }
    let id = frame.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    let mut op = frame.get("op").and_then(Value::as_str).unwrap_or("").to_string();
    if frame_type == "task" && (op.is_empty() || op == "template") {
        op = "task".to_string();
    }
    let args = frame.get("args").cloned().unwrap_or(Value::Null);
    if let Some(target) = frame.get("probe").and_then(Value::as_str) {
        if target != state.opts.probe_id {
            return route_to_child(state, target, &frame, &id);
        }
    }
    match op.as_str() {
        "ping" => state.response(&id, json::object(vec![
            ("pong", json::bool_value(true)),
            ("probe_id", json::string(state.opts.probe_id.clone())),
            ("ts", json::number(util::now())),
        ])),
        "beacon" => state.response(&id, beacon(state)),
        "collect" => {
            let snapshot = collect::snapshot(&state.opts);
            state.audit.event(
                "probe.collect",
                json::object(vec![("probe_id", json::string(state.opts.probe_id.clone()))]),
            );
            state.response(&id, snapshot);
        }
        "exec" => match exec_request(state, &args) {
            Ok(value) => state.response(&id, value),
            Err(error) => state.failure(&id, "exec_failed", &error),
        },
        "bypass" => match crate::bypass::run(&args, &state.opts) {
            Ok(value) => {
                state.audit.event("probe.bypass", value.clone());
                state.response(&id, value)
            }
            Err(error) => state.failure(&id, "bypass_failed", &error),
        },
        "dial" => match dial_request(state, &args) {
            Ok(value) => state.response(&id, value),
            Err(error) => state.failure(&id, "dial_failed", &error),
        },
        "task" => match task_request(state, &args, &id) {
            Ok(value) => state.response(&id, value),
            Err(error) => state.failure(&id, "task_failed", &error),
        },
        "upload" => match upload_request(state, &args) {
            Ok(value) => state.response(&id, value),
            Err(error) => state.failure(&id, "upload_failed", &error),
        },
        "download" => match download_request(state, &args) {
            Ok(value) => state.response(&id, value),
            Err(error) => state.failure(&id, "download_failed", &error),
        },
        "spawn" => match spawn_request(state, &args) {
            Ok(value) => state.response(&id, value),
            Err(error) => state.failure(&id, "spawn_failed", &error),
        },
        "cleanup" => {
            let paths = args
                .get("paths")
                .and_then(Value::as_array)
                .map(|items| items.iter().map(template::value_text).collect::<Vec<_>>())
                .unwrap_or_default();
            let removed = spawn::cleanup_paths(&paths);
            cleanup_children(state);
            cleanup_streams(state);
            state.audit.event(
                "probe.cleanup",
                json::object(vec![
                    ("probe_id", json::string(state.opts.probe_id.clone())),
                    ("removed", Value::Arr(removed.iter().map(|v| json::string(v.clone())).collect())),
                ]),
            );
            state.response(&id, json::object(vec![
                ("removed", Value::Arr(removed.into_iter().map(json::string).collect())),
                ("children", json::number(state.children.lock().map(|c| c.len()).unwrap_or(0) as u64)),
            ]));
        }
        "socks" => {
            let bind = args.get("bind").and_then(Value::as_str).unwrap_or("127.0.0.1");
            let port = args.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
            match net::start_socks5(bind, port) {
                Ok(handle) => state.response(&id, json::object(vec![
                    ("address", json::string(handle.address)),
                    ("bind", json::string(bind)),
                ])),
                Err(error) => state.failure(&id, "socks_failed", &error),
            }
        }
        "k8s" => match k8s_request(&args) {
            Ok(value) => state.response(&id, value),
            Err(error) => state.failure(&id, "k8s_failed", &error),
        },
        other => state.failure(&id, "unknown_op", &format!("unknown op {other}")),
    }
    Ok(())
}

fn beacon(state: &State) -> Value {
    json::object(vec![
        ("probe_id", json::string(state.opts.probe_id.clone())),
        ("parent_id", state.opts.parent_id.clone().map(json::string).unwrap_or(Value::Null)),
        ("version", json::string(VERSION)),
        ("read_only", json::bool_value(state.opts.read_only)),
        ("ts", json::number(util::now())),
        ("uptime_ms", json::number(state.started.elapsed().as_millis() as u64)),
        ("streams", json::number(state.streams.lock().map(|s| s.len()).unwrap_or(0) as u64)),
        ("children", json::number(state.children.lock().map(|c| c.len()).unwrap_or(0) as u64)),
        ("window", json::number(state.opts.max_window as u64)),
    ])
}

fn exec_request(state: &State, args: &Value) -> Result<Value, String> {
    let argv = args
        .get("argv")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(template::value_text).collect::<Vec<_>>())
        .ok_or_else(|| "exec requires argv".to_string())?;
    let timeout = state.opts.timeout_ms(args.get("timeout_ms").and_then(Value::as_u64));
    let result = exec::run(&argv, &state.opts, timeout)?;
    state.audit.event(
        "probe.exec",
        json::object(vec![
            ("probe_id", json::string(state.opts.probe_id.clone())),
            ("argv", Value::Arr(argv.iter().map(|v| json::string(v.clone())).collect())),
            ("exit_code", result.get("exit_code").cloned().unwrap_or(Value::Null)),
            ("timed_out", result.get("timed_out").cloned().unwrap_or(Value::Null)),
        ]),
    );
    Ok(result)
}

fn dial_request(state: &State, args: &Value) -> Result<Value, String> {
    let host = args
        .get("host")
        .and_then(Value::as_str)
        .ok_or_else(|| "dial requires host".to_string())?;
    let port = args
        .get("port")
        .and_then(Value::as_u64)
        .ok_or_else(|| "dial requires port".to_string())? as u16;
    let timeout = state.opts.timeout_ms(args.get("timeout_ms").and_then(Value::as_u64));
    let stream = net::connect(host, port, timeout)?;
    let stream_id = state.next_stream.fetch_add(1, Ordering::SeqCst);
    let reader = stream.try_clone().map_err(|error| format!("dial clone: {error}"))?;
    let writer = Arc::new(Mutex::new(stream));
    state
        .streams
        .lock()
        .map_err(|_| "stream lock".to_string())?
        .insert(stream_id, writer);
    let state_clone = state.clone_for_streams();
    thread::spawn(move || stream_reader(state_clone, stream_id, reader));
    state.audit.event(
        "probe.dial",
        json::object(vec![
            ("probe_id", json::string(state.opts.probe_id.clone())),
            ("host", json::string(host)),
            ("port", json::number(port as u64)),
            ("stream", json::number(stream_id)),
        ]),
    );
    Ok(json::object(vec![
        ("stream", json::number(stream_id)),
        ("host", json::string(host)),
        ("port", json::number(port as u64)),
        ("connected", json::bool_value(true)),
    ]))
}

impl State {
    fn clone_for_streams(&self) -> Arc<StateRef> {
        Arc::new(StateRef {
            writer: self.writer.clone(),
            streams: self.streams.clone(),
            probe_id: self.opts.probe_id.clone(),
        })
    }
}

struct StateRef {
    writer: Arc<Mutex<BufWriter<io::Stdout>>>,
    streams: Arc<Mutex<HashMap<u64, Arc<Mutex<TcpStream>>>>>,
    probe_id: String,
}

fn stream_reader(state: Arc<StateRef>, stream_id: u64, mut reader: TcpStream) {
    let mut buffer = [0u8; 32 * 1024];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let frame = json::object(vec![
                    ("v", json::number(1)),
                    ("type", json::string("data")),
                    ("stream", json::number(stream_id)),
                    ("probe_id", json::string(state.probe_id.clone())),
                    ("data", json::string(base64::encode(&buffer[..count]))),
                    ("eof", json::bool_value(false)),
                ]);
                if write_shared(&state.writer, &frame).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = write_shared(
        &state.writer,
        &json::object(vec![
            ("v", json::number(1)),
            ("type", json::string("data")),
            ("stream", json::number(stream_id)),
            ("probe_id", json::string(state.probe_id.clone())),
            ("data", json::string("")),
            ("eof", json::bool_value(true)),
        ]),
    );
    if let Ok(mut streams) = state.streams.lock() {
        streams.remove(&stream_id);
    }
}

fn write_shared(writer: &Arc<Mutex<BufWriter<io::Stdout>>>, value: &Value) -> Result<(), String> {
    let mut writer = writer.lock().map_err(|_| "writer lock".to_string())?;
    protocol::write_frame(&mut *writer, value)
}

fn handle_stream_frame(state: &State, frame: &Value) -> Result<(), String> {
    let stream_id = frame.get("stream").and_then(Value::as_u64).unwrap_or(0);
    let streams = state.streams.lock().map_err(|_| "stream lock".to_string())?;
    let writer = match streams.get(&stream_id) {
        Some(writer) => writer.clone(),
        None => return Ok(()),
    };
    drop(streams);
    let frame_type = frame.get("type").and_then(Value::as_str).unwrap_or("");
    let mut stream = writer.lock().map_err(|_| "stream writer lock".to_string())?;
    match frame_type {
        "data" => {
            if let Some(data) = frame.get("data").and_then(Value::as_str) {
                let bytes = base64::decode(data)?;
                if !bytes.is_empty() {
                    stream
                        .write_all(&bytes)
                        .map_err(|error| format!("stream write: {error}"))?;
                }
            }
        }
        "stream-eof" => {
            let _ = stream.shutdown(Shutdown::Write);
        }
        "stream-close" => {
            let _ = stream.shutdown(Shutdown::Both);
        }
        _ => {}
    }
    Ok(())
}

fn task_request(state: &State, args: &Value, frame_id: &str) -> Result<Value, String> {
    let task_id = args
        .get("task_id")
        .and_then(Value::as_str)
        .unwrap_or(frame_id)
        .to_string();
    let template = match args.get("template") {
        Some(Value::Str(path)) => template::load_template(None, Some(path))?,
        Some(value) => value.clone(),
        None => template::load_template(
            None,
            args.get("template_path").and_then(Value::as_str),
        )?,
    };
    let params = args.get("params").cloned().unwrap_or(Value::Null);
    let result = template::execute(
        &template,
        &params,
        &state.opts,
        &state.audit,
        &state.opts.probe_id,
        state.opts.parent_id.as_deref(),
        &task_id,
    )?;
    state.audit.event(
        "probe.task",
        json::object(vec![
            ("probe_id", json::string(state.opts.probe_id.clone())),
            ("task_id", json::string(task_id)),
            ("ok", json::bool_value(true)),
        ]),
    );
    Ok(result)
}

fn upload_request(state: &State, args: &Value) -> Result<Value, String> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "upload requires path".to_string())?;
    let data = args
        .get("data_b64")
        .and_then(Value::as_str)
        .map(base64::decode)
        .transpose()?
        .unwrap_or_default();
    let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let mode = args.get("mode").and_then(Value::as_u64).map(|v| v as u32);
    let result = fsops::write(path, &data, offset, mode, &state.opts)?;
    if args.get("final").and_then(Value::as_bool).unwrap_or(false) {
        if let Some(expected) = args.get("sha256").and_then(Value::as_str) {
            let data = std::fs::read(path).map_err(|error| format!("verify read: {error}"))?;
            let got = base64::hex(&sha256::sha256(&data));
            if !expected.is_empty() && got != expected {
                return Err(format!("upload sha256 mismatch: expected {expected}, got {got}"));
            }
        }
    }
    Ok(result)
}

fn download_request(_state: &State, args: &Value) -> Result<Value, String> {
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "download requires path".to_string())?;
    let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
    let max = args.get("max_bytes").and_then(Value::as_u64).unwrap_or(1024 * 1024) as usize;
    fsops::read(path, offset, max)
}

fn k8s_request(args: &Value) -> Result<Value, String> {
    let mut config = crate::k8s::K8sConfig::from_env()?;
    if let Some(server) = args.get("server").and_then(Value::as_str) {
        config.server = server.to_string();
    }
    let action = args.get("action").and_then(Value::as_str).unwrap_or("list");
    let timeout = args.get("timeout_ms").and_then(Value::as_u64).unwrap_or(10_000);
    match action {
        "list" => {
            let resource = args.get("resource").and_then(Value::as_str).unwrap_or("pods");
            config.list(resource, args.get("namespace").and_then(Value::as_str), timeout)
        }
        "get" => {
            let resource = args.get("resource").and_then(Value::as_str).unwrap_or("pods");
            let name = args.get("name").and_then(Value::as_str).unwrap_or("");
            config.get(resource, args.get("namespace").and_then(Value::as_str), name, timeout)
        }
        "exec" => {
            let namespace = args.get("namespace").and_then(Value::as_str).unwrap_or(&config.namespace);
            let pod = args.get("pod").and_then(Value::as_str).unwrap_or("");
            let argv = args
                .get("argv")
                .and_then(Value::as_array)
                .map(|items| items.iter().map(template::value_text).collect::<Vec<_>>())
                .unwrap_or_default();
            config.exec(namespace, pod, args.get("container").and_then(Value::as_str), &argv, timeout)
        }
        "copy" => {
            let namespace = args.get("namespace").and_then(Value::as_str).unwrap_or(&config.namespace);
            let pod = args.get("pod").and_then(Value::as_str).unwrap_or("");
            config.copy(
                namespace,
                pod,
                args.get("container").and_then(Value::as_str),
                args.get("source").and_then(Value::as_str).unwrap_or(""),
                args.get("destination").and_then(Value::as_str).unwrap_or(""),
                timeout,
            )
        }
        other => Err(format!("unsupported k8s action {other}")),
    }
}

fn spawn_request(state: &State, args: &Value) -> Result<Value, String> {
    if state.opts.read_only {
        return Err("spawn requires --allow-write".to_string());
    }
    let probe_id = args
        .get("probe_id")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("child-{}", util::random_hex(4)));
    let parent_id = state.opts.probe_id.clone();
    let binary_b64 = if let Some(path) = args.get("binary_path").and_then(Value::as_str) {
        let bytes = std::fs::read(path).map_err(|error| format!("child binary read: {error}"))?;
        base64::encode(&bytes)
    } else {
        args.get("binary_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| "spawn requires binary_b64 or binary_path".to_string())?
            .to_string()
    };
    let target_path = args.get("path").and_then(Value::as_str);
    let expected = args.get("sha256").and_then(Value::as_str);
    let binary = spawn::materialize(&binary_b64, target_path, expected, &state.opts)?;
    let token_file = spawn::write_token_file(&state.opts.token)?;
    let mut process = spawn::start(&binary, &probe_id, &parent_id, &token_file, &state.opts)?;
    let challenge = protocol::read_frame(&mut process.stdout)?
        .ok_or_else(|| "child closed before challenge".to_string())?;
    let challenge_value = challenge
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| "child challenge missing".to_string())?;
    let nonce = util::random_hex(8);
    let message = format!("inkblade-probe/v1|{nonce}|{challenge_value}");
    let mac = base64::hex(&sha256::hmac_sha256(state.opts.token.as_bytes(), message.as_bytes()));
    protocol::write_frame(
        &mut process.stdin,
        &json::object(vec![
            ("v", json::number(1)),
            ("type", json::string("auth")),
            ("nonce", json::string(nonce)),
            ("mac", json::string(mac)),
        ]),
    )?;
    let ready = protocol::read_frame(&mut process.stdout)?
        .ok_or_else(|| "child closed before ready".to_string())?;
    if ready.get("type").and_then(Value::as_str) != Some("ready") {
        process.shutdown();
        let _ = std::fs::remove_file(&token_file);
        let _ = std::fs::remove_file(&binary);
        return Err("child authentication failed".to_string());
    }
    let stdin = Arc::new(Mutex::new(process.stdin));
    let child = process.child;
    let stdout = process.stdout;
    let writer = state.writer.clone();
    let children = state.children.clone();
    let child_id = probe_id.clone();
    let child_probe = probe_id.clone();
    let child_parent = parent_id.clone();
    let child_path = binary.clone();
    {
        let mut map = state.children.lock().map_err(|_| "children lock".to_string())?;
        map.insert(
            probe_id.clone(),
            ChildLink {
                probe_id: probe_id.clone(),
                stdin: stdin.clone(),
                child,
                token_file: token_file.clone(),
                binary: binary.clone(),
            },
        );
    }
    thread::spawn(move || {
        let mut stdout = stdout;
        loop {
            match protocol::read_frame(&mut stdout) {
                Ok(Some(mut frame)) => {
                    if let Value::Obj(items) = &mut frame {
                        if !items.iter().any(|(key, _)| key == "probe_id") {
                            items.push(("probe_id".to_string(), json::string(child_probe.clone())));
                        }
                        if !items.iter().any(|(key, _)| key == "parent_id") {
                            items.push(("parent_id".to_string(), json::string(child_parent.clone())));
                        }
                    }
                    let _ = write_shared(&writer, &frame);
                }
                _ => break,
            }
        }
        if let Ok(mut map) = children.lock() {
            map.remove(&child_id);
        }
        let _ = write_shared(
            &writer,
            &json::object(vec![
                ("v", json::number(1)),
                ("type", json::string("probe-exit")),
                ("probe_id", json::string(child_id)),
                ("parent_id", json::string(child_parent.clone())),
            ]),
        );
        let _ = child_path;
    });
    state.audit.event(
        "probe.spawn",
        json::object(vec![
            ("probe_id", json::string(state.opts.probe_id.clone())),
            ("child_id", json::string(probe_id.clone())),
            ("path", json::string(binary.to_string_lossy().to_string())),
        ]),
    );
    Ok(json::object(vec![
        ("probe_id", json::string(probe_id)),
        ("parent_id", json::string(state.opts.probe_id.clone())),
        ("registered", json::bool_value(true)),
        ("path", json::string(binary.to_string_lossy().to_string())),
    ]))
}

fn route_to_child(state: &State, target: &str, frame: &Value, id: &str) -> Result<(), String> {
    let children = state.children.lock().map_err(|_| "children lock".to_string())?;
    let link = match children.get(target) {
        Some(link) => link,
        None => {
            drop(children);
            state.failure(id, "probe_not_found", &format!("probe {target} is not registered"));
            return Ok(());
        }
    };
    let mut stdin = link.stdin.lock().map_err(|_| "child stdin lock".to_string())?;
    protocol::write_frame(&mut *stdin, frame)
}

fn cleanup_children(state: &State) {
    if let Ok(mut children) = state.children.lock() {
        for (_, mut link) in children.drain() {
            let _ = link.child.kill();
            let _ = link.child.wait();
            let _ = std::fs::remove_file(&link.token_file);
            let _ = std::fs::remove_file(&link.binary);
            let _ = link.probe_id;
        }
    }
}

fn cleanup_streams(state: &State) {
    if let Ok(mut streams) = state.streams.lock() {
        for (_, stream) in streams.drain() {
            if let Ok(stream) = stream.lock() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
    }
}

fn shutdown(state: &State) {
    cleanup_children(state);
    cleanup_streams(state);
    if !state.opts.keep_binary {
        if let Ok(executable) = std::env::current_exe() {
            let name = executable
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.starts_with(".inkblade-probe") {
                let _ = std::fs::remove_file(executable);
            }
        }
    }
    state.audit.event(
        "probe.shutdown",
        json::object(vec![("probe_id", json::string(state.opts.probe_id.clone()))]),
    );
    let _ = state.writer.lock().map(|mut writer| writer.flush());
}
