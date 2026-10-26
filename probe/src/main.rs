//! inkblade-probe — read-only in-pod fact collector.
//!
//! Reads a fixed allowlist of kernel/procfs paths, prints one JSON document on
//! stdout. It never opens a socket, never executes a subprocess, never reads the
//! contents of a credential file, and never writes anywhere except the optional
//! `--out` path.
//!
//! Output schema: `inkblade-probe/1`. `--emit probes` prints only the `probes`
//! object, which is the shape `inkblade assess cves --probes <file>` expects.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA: &str = "inkblade-probe/1";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_MAX_BYTES: usize = 64 * 1024;

const ENV_NAME_ALLOWLIST: &[&str] = &[
    "KUBERNETES_SERVICE_HOST",
    "KUBERNETES_SERVICE_PORT",
    "KUBERNETES_PORT",
    "HOSTNAME",
    "NVIDIA_VISIBLE_DEVICES",
    "CUDA_VISIBLE_DEVICES",
    "CUDA_DEVICE_ORDER",
    "NCCL_",
    "SGLANG_",
    "VLLM_",
    "HF_HOME",
    "TRANSFORMERS_CACHE",
];

const MOUNT_ALLOWLIST: &[&str] = &[
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/dev/shm",
    "/proc",
    "/sys",
    "/dev",
    "/models",
    "/data",
    "/workspace",
    "/root/.cache/huggingface",
];

#[derive(Debug)]
struct Args {
    emit: Emit,
    out: Option<PathBuf>,
    max_bytes: usize,
}

#[derive(Debug, PartialEq)]
enum Emit {
    Full,
    Probes,
}

fn usage() -> &'static str {
    "inkblade-probe — read-only in-pod fact collector

USAGE:
    inkblade-probe [--emit full|probes] [--out PATH] [--max-bytes N]

OPTIONS:
    --emit full     full document, schema inkblade-probe/1 (default)
    --emit probes   only the probes object (input for `inkblade assess cves --probes`)
    --out PATH      write the document to PATH instead of stdout
    --max-bytes N   per-file read cap, default 65536
    -h, --help      print this help
    -V, --version   print the version

The binary is read-only: no sockets, no subprocesses, no credential contents.
"
}

fn parse_args() -> Result<Args, String> {
    let mut emit = Emit::Full;
    let mut out = None;
    let mut max_bytes = DEFAULT_MAX_BYTES;
    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("inkblade-probe {}", VERSION);
                std::process::exit(0);
            }
            "--emit" => {
                let value = it.next().ok_or("--emit needs a value")?;
                emit = match value.as_str() {
                    "full" => Emit::Full,
                    "probes" => Emit::Probes,
                    other => return Err(format!("unknown --emit value: {other}")),
                };
            }
            "--out" => out = Some(PathBuf::from(it.next().ok_or("--out needs a path")?)),
            "--max-bytes" => {
                let value = it.next().ok_or("--max-bytes needs a number")?;
                max_bytes = value.parse::<usize>().map_err(|_| "bad --max-bytes")?;
                if max_bytes == 0 || max_bytes > 4 * 1024 * 1024 {
                    return Err("--max-bytes must be between 1 and 4194304".into());
                }
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args { emit, out, max_bytes })
}

/// Read at most `cap` bytes of a text file. Returns `None` when unreadable.
fn read_capped(path: &Path, cap: usize) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let slice = if bytes.len() > cap { &bytes[..cap] } else { &bytes[..] };
    Some(String::from_utf8_lossy(slice).to_string())
}

fn first_line(path: &Path, cap: usize) -> Option<String> {
    read_capped(path, cap).map(|text| {
        text.lines().next().unwrap_or("").trim().to_string()
    })
}

/// `/proc/<pid>/status` key lookup (CapEff, Seccomp, NoNewPrivs, ...).
fn status_field(path: &Path, key: &str) -> Option<String> {
    let text = read_capped(path, DEFAULT_MAX_BYTES)?;
    let needle = format!("{key}:");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&needle) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn list_dir(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(path)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

fn env_names() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (key, _value) in env::vars() {
        for allowed in ENV_NAME_ALLOWLIST {
            let hit = if allowed.ends_with('_') {
                key.starts_with(allowed)
            } else {
                key == *allowed
            };
            if hit {
                // Never emit values: they can carry tokens, keys or endpoints.
                out.insert(key.clone(), "<present>".to_string());
                break;
            }
        }
    }
    out
}

fn mount_points() -> Vec<String> {
    let text = match read_capped(Path::new("/proc/self/mountinfo"), 4 * DEFAULT_MAX_BYTES) {
        Some(t) => t,
        None => return Vec::new(),
    };
    let mut seen = Vec::new();
    for line in text.lines() {
        // mountinfo: id parent major:minor root mountpoint options ...
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() < 5 {
            continue;
        }
        let point = parts[4];
        if MOUNT_ALLOWLIST.iter().any(|m| point == *m || point.starts_with(&format!("{m}/"))) {
            let entry = point.to_string();
            if !seen.contains(&entry) {
                seen.push(entry);
            }
        }
    }
    seen.sort();
    seen
}

fn cgroup_text() -> String {
    let mut combined = String::new();
    for path in ["/proc/self/cgroup", "/proc/1/cgroup"] {
        if let Some(text) = read_capped(Path::new(path), DEFAULT_MAX_BYTES) {
            combined.push_str(&text);
        }
    }
    combined
}

fn gpu_devices() -> Vec<String> {
    let mut devices = Vec::new();
    for name in list_dir(Path::new("/dev")) {
        if name.starts_with("nvidia") || name.starts_with("dri") {
            devices.push(format!("/dev/{name}"));
        }
    }
    devices
}

fn nvidia_driver() -> Option<String> {
    for gpu in list_dir(Path::new("/proc/driver/nvidia/gpus")) {
        let info = PathBuf::from("/proc/driver/nvidia/gpus").join(&gpu).join("information");
        if let Some(text) = read_capped(&info, DEFAULT_MAX_BYTES) {
            for line in text.lines() {
                if let Some(v) = line.strip_prefix("NVIDIA") {
                    if let Some(v) = v.trim_start().strip_prefix("Version:") {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
    }
    None
}

fn rdma_devices() -> Vec<String> {
    list_dir(Path::new("/sys/class/infiniband"))
}

fn service_account_facts() -> (bool, Option<u64>) {
    let token = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token");
    match fs::metadata(token) {
        Ok(meta) => (true, Some(meta.len())),
        Err(_) => (false, None),
    }
}

fn os_release() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(text) = read_capped(Path::new("/etc/os-release"), DEFAULT_MAX_BYTES) {
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if k == "ID" || k == "VERSION_ID" || k == "PRETTY_NAME" {
                    out.insert(k.to_string(), v.trim_matches('"').to_string());
                }
            }
        }
    }
    out
}

fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 2);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn json_opt(value: &Option<String>) -> String {
    match value {
        Some(v) => json_string(v),
        None => "null".to_string(),
    }
}

fn json_array(values: &[String]) -> String {
    let body: Vec<String> = values.iter().map(|v| json_string(v)).collect();
    format!("[{}]", body.join(","))
}

fn json_map(map: &BTreeMap<String, String>) -> String {
    let body: Vec<String> = map
        .iter()
        .map(|(k, v)| format!("{}:{}", json_string(k), json_string(v)))
        .collect();
    format!("{{{}}}", body.join(","))
}

fn json_bool(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn probes_document(args: &Args) -> String {
    let caps = status_field(Path::new("/proc/self/status"), "CapEff");
    let seccomp = status_field(Path::new("/proc/self/status"), "Seccomp");
    let nonewprivs = status_field(Path::new("/proc/self/status"), "NoNewPrivs");
    let cgroups = cgroup_text();
    let in_kube = cgroups.contains("kubepods") || cgroups.contains("kube");
    let (sa_present, sa_size) = service_account_facts();
    let gpus = gpu_devices();
    let rdma = rdma_devices();
    let mounts = mount_points();
    let env_map = env_names();

    let fields: Vec<String> = vec![
        format!("\"in_container\":{}", json_bool(in_kube)),
        format!("\"cap_effective\":{}", json_opt(&caps)),
        format!("\"seccomp_mode\":{}", json_opt(&seccomp)),
        format!("\"no_new_privs\":{}", json_opt(&nonewprivs)),
        format!("\"service_account_token_present\":{}", json_bool(sa_present)),
        format!(
            "\"service_account_token_bytes\":{}",
            sa_size.map(|n| n.to_string()).unwrap_or_else(|| "null".into())
        ),
        format!("\"gpu_devices\":{}", json_array(&gpus)),
        format!("\"nvidia_driver\":{}", json_opt(&nvidia_driver())),
        format!("\"rdma_devices\":{}", json_array(&rdma)),
        format!("\"sensitive_mounts\":{}", json_array(&mounts)),
        format!("\"env_names\":{}", json_map(&env_map)),
        format!("\"uid\":{}", getuid_from_proc()),
        format!("\"max_read_bytes\":{}", args.max_bytes),
    ];
    format!("{{{}}}", fields.join(","))
}


/// Real uid from `/proc/self/status` (avoids a libc dependency).
fn getuid_from_proc() -> u64 {
    let text = match read_capped(Path::new("/proc/self/status"), DEFAULT_MAX_BYTES) {
        Some(t) => t,
        None => return 0,
    };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest
                .split_whitespace()
                .next()
                .unwrap_or("0")
                .parse::<u64>()
                .unwrap_or(0);
        }
    }
    0
}


fn full_document(args: &Args) -> String {
    let host = {
        let mut h: Vec<String> = Vec::new();
        h.push(format!("\"hostname\":{}", json_opt(&first_line(Path::new("/proc/sys/kernel/hostname"), 4096))));
        h.push(format!("\"kernel\":{}", json_opt(&first_line(Path::new("/proc/sys/kernel/osrelease"), 4096))));
        h.push(format!("\"os_release\":{}", json_map(&os_release())));
        h.push(format!("\"pid1_cmdline\":{}", json_opt(&first_line(Path::new("/proc/1/cmdline"), 4096).map(|s| s.replace('\0', " ")))));
        format!("{{{}}}", h.join(","))
    };
    let collected_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{{\"schema\":{},\"tool\":\"inkblade-probe\",\"version\":{},\"collected_at\":{},\"host\":{},\"probes\":{}}}",
        json_string(SCHEMA),
        json_string(VERSION),
        collected_at,
        host,
        probes_document(args)
    )
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(message) => {
            eprintln!("inkblade-probe: {message}");
            eprintln!("try --help");
            return ExitCode::from(2);
        }
    };

    let document = match args.emit {
        Emit::Full => full_document(&args),
        Emit::Probes => probes_document(&args),
    };

    match &args.out {
        Some(path) => match fs::write(path, document.as_bytes()) {
            Ok(()) => {
                eprintln!("inkblade-probe: wrote {}", path.display());
                ExitCode::SUCCESS
            }
            Err(exc) => {
                eprintln!("inkblade-probe: cannot write {}: {exc}", path.display());
                ExitCode::from(1)
            }
        },
        None => {
            let mut stdout = io::stdout().lock();
            match writeln!(stdout, "{document}") {
                Ok(()) => ExitCode::SUCCESS,
                Err(exc) => {
                    eprintln!("inkblade-probe: cannot write stdout: {exc}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
