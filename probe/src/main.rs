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
mod base64;
mod collect;
mod config;
mod exec;
mod fsops;
mod http;
mod json;
mod k8s;
mod net;
mod protocol;
mod server;
mod sha256;
mod spawn;
mod template;
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
        "collect" => {
            let audit = Audit::new(opts.audit_sink, opts.audit_path.clone(), &opts.probe_id);
            let snapshot = collect::snapshot(&opts);
            audit.event("probe.collect", json::object(vec![("mode", json::string("standalone"))]));
            println!("{}", snapshot.to_json());
            Ok(0)
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
            let mut paths: Vec<String> = positional.clone();
            for path in &positional {
                paths.push(path.clone());
            }
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
            "--host" => {
                positional.push(next_value(&args, &mut index, "--host")?);
            }
            "--port" => {
                positional.push(next_value(&args, &mut index, "--port")?);
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
           inkblade-probe collect [--read-only]\n\
           inkblade-probe exec -- <argv...> [--allow-write] [--allow-cmd CMD]\n\
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
