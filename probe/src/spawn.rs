//! Child probe materialisation and process startup.

use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use crate::base64;
use crate::config::Options;
use crate::sha256;
use crate::util;

pub struct ChildProcess {
    pub probe_id: String,
    pub path: PathBuf,
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
}

impl ChildProcess {
    pub fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn materialize(binary_b64: &str, path: Option<&str>, expected_sha: Option<&str>, opts: &Options) -> Result<PathBuf, String> {
    let bytes = base64::decode(binary_b64)?;
    if bytes.is_empty() {
        return Err("child binary is empty".to_string());
    }
    if let Some(expected) = expected_sha {
        let got = base64::hex(&sha256::sha256(&bytes));
        if !expected.is_empty() && got != expected {
            return Err(format!("child binary sha256 mismatch: expected {expected}, got {got}"));
        }
    }
    let path = PathBuf::from(path.map(str::to_string).unwrap_or_else(|| {
        format!(
            "{}/.inkblade-probe-child-{}",
            util::home_or_tmp().to_string_lossy(),
            util::random_hex(5)
        )
    }));
    if !opts.allows_write() {
        return Err("spawn requires --allow-write".to_string());
    }
    if path.exists() {
        fs::remove_file(&path).map_err(|error| format!("remove existing child: {error}"))?;
    }
    fs::write(&path, bytes).map_err(|error| format!("write child binary: {error}"))?;
    set_executable(&path)?;
    Ok(path)
}

pub fn start(
    path: &Path,
    probe_id: &str,
    parent_id: &str,
    token_file: &Path,
    opts: &Options,
) -> Result<ChildProcess, String> {
    let mut command = Command::new(path);
    command
        .arg("run")
        .arg("--stdio")
        .arg("--probe-id")
        .arg(probe_id)
        .arg("--parent-id")
        .arg(parent_id)
        .arg("--token-file")
        .arg(token_file)
        .arg("--max-output")
        .arg(opts.max_output_bytes().to_string())
        .arg("--max-timeout-ms")
        .arg(opts.max_timeout_ms.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if opts.read_only {
        command.arg("--read-only");
    } else {
        command.arg("--allow-write");
    }
    for command_name in &opts.allow_cmds {
        command.arg("--allow-cmd").arg(command_name);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn child probe: {error}"))?;
    let stdin = child.stdin.take().ok_or_else(|| "child stdin unavailable".to_string())?;
    let stdout = child.stdout.take().ok_or_else(|| "child stdout unavailable".to_string())?;
    Ok(ChildProcess {
        probe_id: probe_id.to_string(),
        path: path.to_path_buf(),
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

pub fn set_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("chmod child probe: {error}"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub fn write_token_file(token: &str) -> Result<PathBuf, String> {
    let path = util::home_or_tmp().join(format!(
        ".inkblade-probe-token-{}",
        util::random_hex(5)
    ));
    fs::write(&path, token).map_err(|error| format!("token file write: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("token file chmod: {error}"))?;
    }
    Ok(path)
}

pub fn cleanup_paths(paths: &[String]) -> Vec<String> {
    let mut removed = Vec::new();
    for raw in paths {
        if !(raw.starts_with("/tmp/.inkblade-probe-")
            || raw.starts_with("/var/tmp/.inkblade-probe-")
            || raw.starts_with("/dev/shm/.inkblade-probe-"))
        {
            continue;
        }
        let path = Path::new(raw);
        if path.is_file() {
            if fs::remove_file(path).is_ok() {
                removed.push(raw.clone());
            }
        }
    }
    removed
}

pub fn copy_from_reader<R: Read>(reader: &mut R, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 8192];
    while out.len() < limit {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => out.extend_from_slice(&buffer[..count]),
            Err(error) => return Err(format!("read: {error}")),
        }
    }
    Ok(out)
}

/// Execute an argv process for the template `spawn` op.  No shell is used.
pub fn run_process(
    argv: &[String],
    detach: bool,
    opts: &Options,
    timeout_ms: u64,
) -> Result<crate::json::Value, String> {
    if argv.is_empty() {
        return Err("spawn requires a non-empty argv".to_string());
    }
    let program = &argv[0];
    let safe = crate::exec::READ_ONLY_COMMANDS.contains(&program.as_str());
    if opts.read_only && !safe {
        return Err(format!("spawn {program} requires --allow-write"));
    }
    if !opts.read_only && !opts.allow_cmds.iter().any(|name| name == program) && !safe {
        return Err(format!("spawn {program} is not in --allow-cmd"));
    }
    let started = std::time::Instant::now();
    if detach {
        let mut command = Command::new(program);
        command
            .args(&argv[1..])
            .env_remove("INKBLADE_PROBE_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|error| format!("spawn {program}: {error}"))?;
        return Ok(crate::json::object(vec![
            ("pid", crate::json::number(child.id() as u64)),
            ("argv", crate::json::Value::Arr(argv.iter().map(|v| crate::json::string(v.clone())).collect())),
            ("detached", crate::json::bool_value(true)),
        ]));
    }
    crate::exec::run(argv, opts, timeout_ms).map(|mut result| {
        if let crate::json::Value::Obj(items) = &mut result {
            items.push(("duration_ms".to_string(), crate::json::number(started.elapsed().as_millis() as u64)));
        }
        result
    })
}
