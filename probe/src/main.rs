//! `inkblade-probe`: a native, single-binary in-pod runtime.
//!
//! Examples:
//!   inkblade-probe run --stdio --token-file /tmp/token --read-only
//!   inkblade-probe collect
//!   inkblade-probe exec -- id
//!   inkblade-probe dial --host 10.0.0.2 --port 5432
//!   inkblade-probe beacon
//!   inkblade-probe cleanup --path /tmp/.inkblade-probe-child-a1b2

mod audit;
mod auditops;
mod auth;
mod base64;
mod bypass;
mod collect;
mod config;
mod exec;
mod fsops;
mod http;
mod json;
mod k8s;
mod net;
mod posture;
mod protocol;
mod server;
mod sha256;
mod spawn;
mod template;
mod transport;
mod util;

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use audit::{Audit, AuditSink};
use config::Options;
use json::Value;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("inkblade-probe: {error}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return Ok(2);
    }
    let mode = args.remove(0);
    if mode == "--version" || mode == "-V" || mode == "version" {
        println!("inkblade-probe {VERSION}");
        return Ok(0);
    }
    if mode == "--help" || mode == "-h" || mode == "help" {
        usage();
        return Ok(0);
    }
    let (opts, positional) = parse_options(args)?;
    match mode.as_str() {
        "run" | "serve" => {
            if !positional.is_empty() {
                return Err("run does not take positional arguments".to_string());
            }
            if opts.token.is_empty() {
                return Err("run --stdio requires --token, --token-file or INKBLADE_PROBE_TOKEN".to_string());
            }
            server::serve(opts)?;
            Ok(0)
        }
        "reverse" => {
            // Probe-initiated transport: dial the controller, then run the
            // exact same authenticated server loop as `run --stdio`.
            if opts.token.is_empty() {
                return Err(
                    "reverse requires --token, --token-file or INKBLADE_PROBE_TOKEN".to_string(),
                );
            }
            let mut host_arg: Option<String> = None;
            let mut port_arg: Option<u16> = None;
            for value in &positional {
                match value.parse::<u16>() {
                    Ok(port) if port_arg.is_none() && port != 0 => port_arg = Some(port),
                    _ if host_arg.is_none() => host_arg = Some(value.clone()),
                    _ => {}
                }
            }
            let host = host_arg
                .or_else(|| std::env::var("INKBLADE_REVERSE_HOST").ok())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "reverse requires --host HOST".to_string())?;
            let port = port_arg
                .or_else(|| {
                    std::env::var("INKBLADE_REVERSE_PORT")
                        .ok()
                        .and_then(|value| value.parse::<u16>().ok())
                })
                .filter(|value| *value != 0)
                .ok_or_else(|| "reverse requires --port PORT".to_string())?;
            let transport_name = if opts.transport == "lab-plaintext" {
                if std::env::var("INKBLADE_ALLOW_PLAINTEXT_LAB").ok().as_deref() != Some("1") {
                    return Err(
                        "plaintext reverse requires INKBLADE_ALLOW_PLAINTEXT_LAB=1 "
                            .to_string(),
                    );
                }
                "lab-plaintext".to_string()
            } else {
                if !matches!(opts.transport.as_str(), "tls" | "wss" | "https") {
                    return Err(format!("unsupported --transport {}", opts.transport));
                }
                if opts.pin.is_none() {
                    return Err("encrypted reverse requires --pin <sha256>".to_string());
                }
                if opts.ca_file.is_none() {
                    return Err("encrypted reverse requires --ca-file <ca.pem>".to_string());
                }
                opts.transport.clone()
            };
            let mut attempt: u32 = 0;
            loop {
                let started = std::time::Instant::now();
                let result = transport::connect(&opts, &host, port).and_then(|(reader, writer)| {
                    server::serve_with_transport(
                        opts.clone(),
                        reader,
                        writer,
                        &transport_name,
                    )
                });
                match result {
                    Ok(()) => {}
                    Err(error) => {
                        if error.contains("authentication failed")
                            || error.contains("client disconnected before auth")
                        {
                            return Err(error);
                        }
                        if opts.no_reconnect
                            || (opts.max_retries > 0 && attempt >= opts.max_retries)
                        {
                            return Err(error);
                        }
                        eprintln!("inkblade-probe: reverse transport error: {error}");
                    }
                }
                if opts.no_reconnect {
                    return Ok(0);
                }
                if started.elapsed() > std::time::Duration::from_secs(60) {
                    attempt = 0;
                }
                let base = if attempt >= 6 { 60u64 } else { 1u64 << attempt };
                let jitter = (util::random_bytes(1)[0] as u64 * 3) % 700;
                let delay = std::time::Duration::from_millis(base * 1000 + jitter);
                std::thread::sleep(delay);
                attempt = attempt.saturating_add(1);
                if attempt > 12 {
                    attempt = 6;
                }
            }
        }
        "collect" => {
            let audit = Audit::new(opts.audit_sink, opts.audit_path.clone(), &opts.probe_id);
            let snapshot = collect::snapshot(&opts);
            audit.event("probe.collect", json::object(vec![("mode", json::string("standalone"))]));
            println!("{}", snapshot.to_json());
            Ok(0)
        }
        "bypass" => {
            let plan = bypass::plan_from_options(&opts, &positional)?;
            let audit = Audit::new(opts.audit_sink, opts.audit_path.clone(), &opts.probe_id);
            let result = bypass::run(&plan, &opts)?;
            audit.event("probe.bypass", result.clone());
            println!("{}", result.to_json());
            Ok(if result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                0
            } else {
                1
            })
        }
        "exec" => {
            if positional.is_empty() {
                return Err("exec requires argv after --".to_string());
            }
            let audit = Audit::new(opts.audit_sink, opts.audit_path.clone(), &opts.probe_id);
            let result = exec::run(&positional, &opts, opts.timeout_ms(None))?;
            audit.event("probe.exec", result.clone());
            println!("{}", result.to_json());
            Ok(result.get("exit_code").and_then(Value::as_i64).unwrap_or(0) as i32)
        }
        "audit-exec" => {
            if positional.is_empty() {
                return Err("audit-exec requires argv after --".to_string());
            }
            let audit = Audit::new(opts.audit_sink, opts.audit_path.clone(), &opts.probe_id);
            let args = json::object(vec![
                ("argv", Value::Arr(positional.iter().cloned().map(json::string).collect())),
                ("timeout_ms", json::number(opts.timeout_ms(None))),
            ]);
            let result = auditops::audit_exec(&args, &opts)?;
            audit.event("probe.audit_exec", result.clone());
            println!("{}", result.to_json());
            let code = result
                .get("audit")
                .and_then(|value| value.get("exit_code"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            Ok(code as i32)
        }
        "read-file" => {
            let path = positional
                .first()
                .cloned()
                .ok_or_else(|| "read-file requires --path".to_string())?;
            let result = auditops::read_file(&path, opts.max_output_bytes())?;
            println!("{}", result.to_json());
            Ok(0)
        }
        "list-files" => {
            let path = positional
                .first()
                .cloned()
                .ok_or_else(|| "list-files requires --path".to_string())?;
            let result = auditops::list_files(&path, "")?;
            println!("{}", result.to_json());
            Ok(0)
        }
        "dial" => {
            let host = positional
                .first()
                .cloned()
                .or_else(|| std::env::var("INKBLADE_DIAL_HOST").ok())
                .ok_or_else(|| "dial requires --host".to_string())?;
            let port = positional
                .get(1)
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(0);
            if port == 0 {
                return Err("dial requires --port".to_string());
            }
            let result = net::tcp_probe(&host, port, None, 0, opts.timeout_ms(None))?;
            println!("{}", result.to_json());
            Ok(0)
        }
        "beacon" => {
            let audit = Audit::new(opts.audit_sink, opts.audit_path.clone(), &opts.probe_id);
            let value = json::object(vec![
                ("probe_id", json::string(opts.probe_id.clone())),
                ("parent_id", opts.parent_id.clone().map(json::string).unwrap_or(Value::Null)),
                ("version", json::string(VERSION)),
                ("read_only", json::bool_value(opts.read_only)),
                ("ts", json::number(util::now())),
            ]);
            audit.event("probe.beacon", value.clone());
            println!("{}", value.to_json());
            Ok(0)
        }
        "cleanup" => {
            let paths: Vec<String> = positional.clone();
            let removed = spawn::cleanup_paths(&paths);
            println!(
                "{}",
                json::object(vec![
                    ("removed", Value::Arr(removed.into_iter().map(json::string).collect())),
                ])
                .to_json()
            );
            Ok(0)
        }
        "socks" => {
            let bind = positional.first().map(String::as_str).unwrap_or("127.0.0.1");
            let port = positional
                .get(1)
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(0);
            let handle = net::start_socks5(bind, port)?;
            println!("{}", json::object(vec![("address", json::string(handle.address))]).to_json());
            std::io::stdout().flush().ok();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        "help" => {
            usage();
            Ok(0)
        }
        other => Err(format!("unknown mode {other}")),
    }
}

fn parse_options(args: Vec<String>) -> Result<(Options, Vec<String>), String> {
    let mut opts = Options {
        probe_id: util::default_probe_id(),
        ..Options::default()
    };
    let mut positional = Vec::new();
    let mut token_file: Option<PathBuf> = None;
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].clone();
        index += 1;
        match arg.as_str() {
            "--stdio" => {}
            "--read-only" => opts.read_only = true,
            "--allow-write" => opts.read_only = false,
            "--keep-binary" => opts.keep_binary = true,
            "--token" => {
                opts.token = next_value(&args, &mut index, "--token")?;
            }
            "--token-file" => {
                token_file = Some(PathBuf::from(next_value(&args, &mut index, "--token-file")?));
            }
            "--probe-id" => {
                opts.probe_id = next_value(&args, &mut index, "--probe-id")?;
            }
            "--parent-id" => {
                opts.parent_id = Some(next_value(&args, &mut index, "--parent-id")?);
            }
            "--allow-cmd" => {
                opts.allow_cmds.push(next_value(&args, &mut index, "--allow-cmd")?);
            }
            "--max-output" => {
                opts.max_output = next_value(&args, &mut index, "--max-output")?
                    .parse::<usize>()
                    .map_err(|_| "--max-output must be a number".to_string())?;
            }
            "--max-timeout-ms" => {
                opts.max_timeout_ms = next_value(&args, &mut index, "--max-timeout-ms")?
                    .parse::<u64>()
                    .map_err(|_| "--max-timeout-ms must be a number".to_string())?;
            }
            "--max-window" => {
                opts.max_window = next_value(&args, &mut index, "--max-window")?
                    .parse::<usize>()
                    .map_err(|_| "--max-window must be a number".to_string())?;
            }
            "--connect-timeout-ms" => {
                opts.connect_timeout_ms = next_value(&args, &mut index, "--connect-timeout-ms")?
                    .parse::<u64>()
                    .map_err(|_| "--connect-timeout-ms must be a number".to_string())?;
            }
            "--transport" => {
                opts.transport = next_value(&args, &mut index, "--transport")?;
            }
            "--lab-plaintext" => {
                opts.transport = "lab-plaintext".to_string();
            }
            "--ca-file" => {
                opts.ca_file = Some(PathBuf::from(next_value(&args, &mut index, "--ca-file")?));
            }
            "--pin" => {
                opts.pin = Some(next_value(&args, &mut index, "--pin")?);
            }
            "--sni" => {
                opts.sni = Some(next_value(&args, &mut index, "--sni")?);
            }
            "--ws-path" => {
                opts.ws_path = next_value(&args, &mut index, "--ws-path")?;
            }
            "--poll-path" => {
                opts.poll_path = next_value(&args, &mut index, "--poll-path")?;
            }
            "--result-path" => {
                opts.result_path = next_value(&args, &mut index, "--result-path")?;
            }
            "--user-agent" => {
                opts.user_agent = next_value(&args, &mut index, "--user-agent")?;
            }
            "--no-reconnect" => opts.no_reconnect = true,
            "--max-retries" => {
                opts.max_retries = next_value(&args, &mut index, "--max-retries")?
                    .parse::<u32>()
                    .map_err(|_| "--max-retries must be a number".to_string())?;
            }
            "--audit" => {
                opts.audit_path = Some(PathBuf::from(next_value(&args, &mut index, "--audit")?));
            }
            "--audit-sink" => {
                let value = next_value(&args, &mut index, "--audit-sink")?;
                opts.audit_sink = match value.as_str() {
                    "stdout" => AuditSink::Stdout,
                    "stderr" => AuditSink::Stderr,
                    other => return Err(format!("unknown audit sink {other}")),
                };
            }
            "--templates-dir" => {
                opts.templates_dir = Some(PathBuf::from(next_value(&args, &mut index, "--templates-dir")?));
            }
            "--plan" => {
                opts.bypass_plan = Some(next_value(&args, &mut index, "--plan")?);
            }
            "--technique" => {
                opts.bypass_techniques.push(next_value(&args, &mut index, "--technique")?);
            }
            "--script" => {
                opts.bypass_script = Some(next_value(&args, &mut index, "--script")?);
            }
            "--script-b64" => {
                opts.bypass_script_b64 = Some(next_value(&args, &mut index, "--script-b64")?);
            }
            "--workdir" => {
                opts.bypass_workdir = Some(next_value(&args, &mut index, "--workdir")?);
            }
            "--monitored-path" => {
                opts.bypass_monitored.push(next_value(&args, &mut index, "--monitored-path")?);
            }
            "--target-namespace" => {
                opts.bypass_target_namespace =
                    Some(next_value(&args, &mut index, "--target-namespace")?);
            }
            "--target-pod" => {
                opts.bypass_target_pod = Some(next_value(&args, &mut index, "--target-pod")?);
            }
            "--container" => {
                opts.bypass_container = Some(next_value(&args, &mut index, "--container")?);
            }
            "--host" => {
                positional.push(next_value(&args, &mut index, "--host")?);
            }
            "--port" => {
                positional.push(next_value(&args, &mut index, "--port")?);
            }
            "--path" => {
                let value = next_value(&args, &mut index, "--path")?;
                opts.ws_path = value.clone();
                positional.push(value);
            }
            "--" => {
                positional.extend(args[index..].iter().cloned());
                break;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other}"));
            }
            other => positional.push(other.to_string()),
        }
    }
    if let Some(path) = token_file {
        let token = fs::read_to_string(&path).map_err(|error| format!("token file: {error}"))?;
        opts.token = token.trim().to_string();
    }
    if opts.token.is_empty() {
        if let Ok(token) = std::env::var("INKBLADE_PROBE_TOKEN") {
            opts.token = token.trim().to_string();
        }
    }
    Ok((opts, positional))
}

fn next_value(args: &[String], index: &mut usize, flag: &str) -> Result<String, String> {
    let value = args
        .get(*index)
        .ok_or_else(|| format!("{flag} requires a value"))?;
    *index += 1;
    Ok(value.clone())
}

fn usage() {
    println!(
        "inkblade-probe {VERSION}\n\
         \n\
         Usage:\n\
           inkblade-probe run --stdio --token-file PATH [--read-only|--allow-write]\n\
           inkblade-probe reverse --transport tls|wss|https --host HOST --port PORT \n\
             --ca-file CA.pem --pin SHA256 [--sni NAME] [--token-file PATH]\n\
           inkblade-probe reverse --host HOST --port PORT --lab-plaintext  (lab tests only)\n\
           inkblade-probe collect [--read-only]\n\
           inkblade-probe bypass --plan JSON [--allow-write]\n\
           inkblade-probe bypass --technique ID --script-b64 B64 [--workdir DIR]\n\
           inkblade-probe exec -- <argv...> [--allow-write] [--allow-cmd CMD]\n\
           inkblade-probe audit-exec -- <argv...> [--allow-write]\n\
           inkblade-probe read-file --path PATH\n\
           inkblade-probe list-files --path DIR\n\
           inkblade-probe dial --host HOST --port PORT\n\
           inkblade-probe beacon\n\
           inkblade-probe cleanup --path PATH...\n\
           inkblade-probe socks [BIND] [PORT]\n\
         \n\
         Protocol: 4-byte big-endian length + UTF-8 JSON. Authentication is\n\
         challenge-HMAC-SHA256 over the shared token. The binary is built for\n\
         linux-musl by CI; no Python or interpreter is required in the pod."
    );
}
