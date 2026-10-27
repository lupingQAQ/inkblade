//! Operation and file-access audit (`audit-exec`, `read-file`, `list-files`).
//!
//! The controller needs to show *what ran* and *which files were opened* inside
//! the target container.  This module implements the probe half of that
//! contract:
//!
//! * `audit-exec` runs an allow-listed argv, records argv/cwd/env digest, then
//!   samples `/proc/<pid>/fd` while the child is alive (Linux).  Fast commands
//!   that exit before the first sample are covered by an argv stat fallback so
//!   the ledger never claims "no files" for `cat /path`.
//! * `read-file` / `list-files` are the explicit, read-only file operations.
//!
//! Every entry point refuses host-escape paths (`/proc/<pid>/root`, `/host`,
//! container-runtime sockets, `/var/lib/kubelet`, …).  Paths are read-only from
//! the target container's point of view; this module never follows a symlink out
//! of the container on purpose.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::base64;
use crate::config::Options;
use crate::json::{self, Value};
use crate::sha256;
use crate::util;

/// Host-escape prefixes that are never read, even if the probe can open them.
pub const HOST_ESCAPE_PREFIXES: &[&str] = &[
    "/host",
    "/hostfs",
    "/mnt/host",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd",
    "/var/run/containerd",
    "/sys/kernel/debug",
    "/dev/mem",
    "/dev/kmem",
    "/dev/kmsg",
    "/proc/sysrq-trigger",
    "/proc/kcore",
];

const MAX_HASH_BYTES: u64 = 1024 * 1024;
const MAX_OPENED: usize = 512;

pub fn validate_path(path: &str) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("empty path".to_string());
    }
    if trimmed.contains('\0') {
        return Err("NUL byte in path".to_string());
    }
    let normalized = trimmed.replace('\\', "/");
    let owned = if normalized.starts_with("//") {
        format!("/{}", normalized.trim_start_matches('/'))
    } else {
        normalized
    };
    if let Some(rest) = owned.strip_prefix("/proc/") {
        let mut parts = rest.split('/');
        let pid = parts.next().unwrap_or("");
        if !pid.is_empty() && parts.next() == Some("root") {
            return Err(format!("host escape via /proc/{pid}/root"));
        }
    }
    for prefix in HOST_ESCAPE_PREFIXES {
        if owned == *prefix || owned.starts_with(&format!("{prefix}/")) {
            return Err(format!("host path is out of scope: {prefix}"));
        }
    }
    if owned.split('/').any(|part| part == "..") {
        return Err("path traversal is not allowed".to_string());
    }
    Ok(())
}

fn text_of(value: &Value) -> String {
    crate::template::value_text(value)
}

pub fn read_file(path: &str, max_bytes: usize) -> Result<Value, String> {
    validate_path(path)?;
    let metadata = fs::metadata(path).map_err(|error| format!("stat {path}: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("{path} is a directory"));
    }
    let limit = max_bytes.clamp(1, 16 * 1024 * 1024);
    let mut file = fs::File::open(path).map_err(|error| format!("open {path}: {error}"))?;
    let mut buffer = vec![0u8; limit];
    let mut read = 0usize;
    while read < limit {
        match file.read(&mut buffer[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) => return Err(format!("read {path}: {error}")),
        }
    }
    buffer.truncate(read);
    let digest = util::file_sha256(Path::new(path)).unwrap_or_default();
    Ok(json::object(vec![
        ("path", json::string(path)),
        ("exists", json::bool_value(true)),
        ("size", json::number(metadata.len())),
        ("bytes", json::number(read as u64)),
        ("eof", json::bool_value(read as u64 >= metadata.len())),
        ("sha256", json::string(digest)),
        ("text", json::string(String::from_utf8_lossy(&buffer).to_string())),
    ]))
}

pub fn list_files(path: &str, pattern: &str) -> Result<Value, String> {
    validate_path(path)?;
    let reader = fs::read_dir(path).map_err(|error| format!("read_dir {path}: {error}"))?;
    let mut items: Vec<_> = reader.filter_map(Result::ok).collect();
    items.sort_by_key(|entry| entry.file_name());
    let needle = pattern.trim_matches('*').to_string();
    let mut entries = Vec::new();
    for entry in items {
        let name = entry.file_name().to_string_lossy().to_string();
        if !needle.is_empty() && !name.contains(&needle) {
            continue;
        }
        let metadata = entry.metadata().ok();
        entries.push(json::object(vec![
            ("name", json::string(name)),
            ("path", json::string(entry.path().to_string_lossy().to_string())),
            ("dir", json::bool_value(metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false))),
            ("size", json::number(metadata.as_ref().map(|m| m.len()).unwrap_or(0))),
        ]));
        if entries.len() >= 4096 {
            break;
        }
    }
    Ok(json::object(vec![
        ("path", json::string(path)),
        ("exists", json::bool_value(true)),
        ("count", json::number(entries.len() as u64)),
        ("entries", Value::Arr(entries)),
    ]))
}

#[derive(Clone)]
struct OpenedFile {
    path: String,
    mode: String,
    fd: u64,
    size_bytes: u64,
    sha256: String,
}

fn insert_opened(
    opened: &mut BTreeMap<String, OpenedFile>,
    path: String,
    mode: &str,
    fd: u64,
    size_bytes: u64,
) {
    if path.is_empty() || opened.len() >= MAX_OPENED {
        return;
    }
    if validate_path(&path).is_err() {
        return;
    }
    let key = format!("{mode}:{path}");
    if opened.contains_key(&key) {
        return;
    }
    let digest = if size_bytes > 0 && size_bytes <= MAX_HASH_BYTES {
        util::file_sha256(Path::new(&path)).unwrap_or_default()
    } else {
        String::new()
    };
    opened.insert(key, OpenedFile {
        path,
        mode: mode.to_string(),
        fd,
        size_bytes,
        sha256: digest,
    });
}

/// Read `/proc/<pid>/fd` once.  Non-Linux builds are a no-op (the probe ships
/// for linux-musl; this keeps `cargo test` on other hosts green).
#[cfg(target_os = "linux")]
fn sample_fds(pid: u32, opened: &mut BTreeMap<String, OpenedFile>) {
    let dir = format!("/proc/{pid}/fd");
    let reader = match fs::read_dir(&dir) {
        Ok(reader) => reader,
        Err(_) => return,
    };
    for entry in reader.filter_map(Result::ok) {
        let fd: u64 = match entry.file_name().to_string_lossy().parse() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(_) => continue,
        };
        let mut path = target.to_string_lossy().to_string();
        if !path.starts_with('/') {
            continue; // socket:[…] / pipe:[…] / anon_inode:…
        }
        if let Some(stripped) = path.strip_suffix(" (deleted)") {
            path = stripped.to_string();
        }
        let mode = fd_access_mode(pid, fd);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        insert_opened(opened, path, &mode, fd, size);
    }
}

#[cfg(not(target_os = "linux"))]
fn sample_fds(_pid: u32, _opened: &mut BTreeMap<String, OpenedFile>) {}

#[cfg(target_os = "linux")]
fn fd_access_mode(pid: u32, fd: u64) -> String {
    let path = format!("/proc/{pid}/fdinfo/{fd}");
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(_) => return "read".to_string(),
    };
    for line in text.lines() {
        if let Some(raw) = line.strip_prefix("flags:") {
            let value = raw.trim();
            let parsed = u64::from_str_radix(value, 8).unwrap_or(0);
            return match parsed & 0o3 {
                0 => "read".to_string(),
                1 => "write".to_string(),
                _ => "rw".to_string(),
            };
        }
    }
    "read".to_string()
}

#[cfg(not(target_os = "linux"))]
fn fd_access_mode(_pid: u32, _fd: u64) -> String {
    "read".to_string()
}

/// argv stat fallback for commands that exit before the first fd sample.
fn argv_hints(argv: &[String], cwd: &str, opened: &mut BTreeMap<String, OpenedFile>) {
    let program = argv
        .first()
        .map(|value| value.rsplit('/').next().unwrap_or(value).to_string())
        .unwrap_or_default();
    let writes = matches!(
        program.as_str(),
        "tee" | "cp" | "mv" | "install" | "dd" | "truncate" | "rm" | "mkdir"
    );
    for token in argv.iter().skip(1) {
        if token.starts_with('-') || token.contains('=') || token.len() > 4096 {
            continue;
        }
        let candidate: PathBuf = if token.starts_with('/') {
            PathBuf::from(token)
        } else if !cwd.is_empty() {
            Path::new(cwd).join(token)
        } else {
            continue;
        };
        let metadata = match fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        let path = candidate.to_string_lossy().to_string();
        let mode = if writes && !metadata.is_dir() { "write" } else { "read" };
        insert_opened(opened, path, mode, 0, metadata.len());
    }
}

fn env_digest() -> String {
    let mut pairs: Vec<String> = std::env::vars_os()
        .map(|(key, value)| {
            format!(
                "{}={}",
                key.to_string_lossy(),
                value.to_string_lossy()
            )
        })
        .filter(|pair| {
            !pair.starts_with("INKBLADE_PROBE_TOKEN=")
                && !pair.starts_with("INKBLADE_PROBE_TOKEN_FILE=")
        })
        .collect();
    pairs.sort();
    base64::hex(&sha256::sha256(pairs.join("\n").as_bytes()))
}

fn opened_values(opened: &BTreeMap<String, OpenedFile>) -> Value {
    Value::Arr(
        opened
            .values()
            .map(|entry| {
                json::object(vec![
                    ("path", json::string(entry.path.clone())),
                    ("mode", json::string(entry.mode.clone())),
                    ("fd", json::number(entry.fd)),
                    ("size_bytes", json::number(entry.size_bytes)),
                    ("sha256", json::string(entry.sha256.clone())),
                ])
            })
            .collect(),
    )
}

fn read_capped<R: Read>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buffer = [0u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if out.len() < cap {
                    let take = (cap - out.len()).min(count);
                    out.extend_from_slice(&buffer[..take]);
                    if take < count {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (out, truncated)
}

fn to_text(data: Vec<u8>, truncated: bool) -> String {
    let mut text = String::from_utf8_lossy(&data).to_string();
    if truncated {
        text.push_str("\n[truncated]");
    }
    text
}

/// Run argv with audit sampling.  Returns `{exec: {...}, audit: {...}}` so the
/// controller can persist both the command result and the file ledger.
pub fn audit_exec(args: &Value, opts: &Options) -> Result<Value, String> {
    let argv: Vec<String> = args
        .get("argv")
        .and_then(Value::as_array)
        .map(|items| items.iter().map(text_of).collect())
        .ok_or_else(|| "audit-exec requires argv".to_string())?;
    if argv.is_empty() {
        return Err("audit-exec requires argv".to_string());
    }
    crate::exec::validate(&argv, opts)?;
    for item in &argv {
        if item.starts_with('/') || item.starts_with("./") || item.starts_with("../") {
            validate_path(item)?;
        }
    }
    let cwd = args.get("cwd").and_then(Value::as_str).unwrap_or("").to_string();
    if !cwd.is_empty() {
        validate_path(&cwd)?;
    }
    let technique = args
        .get("technique")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let timeout = opts.timeout_ms(args.get("timeout_ms").and_then(Value::as_u64));

    let started = Instant::now();
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("INKBLADE_PROBE_TOKEN")
        .env_remove("INKBLADE_PROBE_TOKEN_FILE");
    if !cwd.is_empty() {
        command.current_dir(&cwd);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn {}: {error}", argv[0]))?;
    let pid = child.id();
    let cap = opts.max_output_bytes();
    let (tx, rx) = mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(("stdout", read_capped(stdout, cap)));
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(("stderr", read_capped(stderr, cap)));
        });
    }
    drop(tx);

    let mut opened: BTreeMap<String, OpenedFile> = BTreeMap::new();
    let mut sampled = 0usize;
    let mut timed_out = false;
    let exit_code: i64;
    let deadline = started + Duration::from_millis(timeout.max(50));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code().unwrap_or(-1) as i64;
                break;
            }
            Ok(None) => {
                let before = opened.len();
                sample_fds(pid, &mut opened);
                if opened.len() > before {
                    sampled += opened.len() - before;
                }
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    exit_code = -1;
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => {
                let _ = child.kill();
                return Err(format!("wait {}: {error}", argv[0]));
            }
        }
    }

    let mut stdout_data = (Vec::new(), false);
    let mut stderr_data = (Vec::new(), false);
    while let Ok((stream, data)) = rx.recv_timeout(Duration::from_millis(200)) {
        if stream == "stdout" {
            stdout_data = data;
        } else {
            stderr_data = data;
        }
    }
    argv_hints(&argv, &cwd, &mut opened);
    let sampler = if sampled > 0 && !opened.is_empty() {
        "proc-fd+argv"
    } else if !opened.is_empty() {
        "argv"
    } else {
        "proc-fd"
    };
    let duration_ms = started.elapsed().as_millis() as u64;
    let stdout_hash = base64::hex(&sha256::sha256(&stdout_data.0));
    let truncated = stdout_data.1 || stderr_data.1;
    let stdout_text = to_text(stdout_data.0, stdout_data.1);
    let stderr_text = to_text(stderr_data.0, stderr_data.1);

    let audit = json::object(vec![
        ("pid", json::number(pid as u64)),
        ("argv", Value::Arr(argv.iter().cloned().map(json::string).collect())),
        ("cwd", json::string(cwd.clone())),
        ("technique", json::string(technique)),
        ("env_digest", json::string(env_digest())),
        ("opened_files", opened_values(&opened)),
        ("stdout_hash", json::string(stdout_hash.clone())),
        ("duration_ms", json::number(duration_ms)),
        ("exit_code", json::number(exit_code)),
        ("sampler", json::string(sampler)),
    ]);
    let exec = json::object(vec![
        ("exit_code", json::number(exit_code)),
        ("rc", json::number(exit_code)),
        ("stdout", json::string(stdout_text)),
        ("stderr", json::string(stderr_text)),
        ("timed_out", json::bool_value(timed_out)),
        ("truncated", json::bool_value(truncated)),
        ("duration_ms", json::number(duration_ms)),
        ("argv", Value::Arr(argv.iter().cloned().map(json::string).collect())),
        ("cwd", json::string(cwd)),
        ("pid", json::number(pid as u64)),
        ("clean_env", json::bool_value(false)),
        ("stdout_hash", json::string(stdout_hash)),
    ]);
    Ok(json::object(vec![("exec", exec), ("audit", audit)]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_host_escape_paths() {
        assert!(validate_path("/etc/hostname").is_ok());
        assert!(validate_path("/proc/1/root/etc/shadow").is_err());
        assert!(validate_path("/host/proc/1/environ").is_err());
        assert!(validate_path("/var/lib/kubelet/pods").is_err());
        assert!(validate_path("/tmp/../../etc/passwd").is_err());
    }

    #[test]
    fn list_refuses_out_of_scope() {
        assert!(list_files("/run/containerd", "").is_err());
    }
}
