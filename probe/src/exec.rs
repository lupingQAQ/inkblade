//! Bounded command execution with an explicit allow-list.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Options;
use crate::json::{self, Value};

pub const READ_ONLY_COMMANDS: &[&str] = &[
    "id", "hostname", "uname", "whoami", "ps", "df", "ls", "cat", "head", "tail",
    "wc", "grep", "find", "ip", "ss", "netstat", "getent", "nslookup", "dig",
    "nvidia-smi", "rocm-smi", "lscpu", "free", "uptime", "mount", "lsblk",
    "stat", "readlink", "file", "sha256sum", "sha1sum", "date", "groups",
    "tty", "du", "sort", "uniq", "cut", "tr",
];

const UNSAFE_FIND_FLAGS: &[&str] = &[
    "-exec", "-execdir", "-delete", "-ok", "-okdir", "-fprint", "-fprint0",
    "-fprintf", "-fls",
];

pub fn allowed_commands(opts: &Options) -> Vec<String> {
    let mut commands: Vec<String> = READ_ONLY_COMMANDS.iter().map(|v| v.to_string()).collect();
    for command in &opts.allow_cmds {
        if !commands.contains(command) {
            commands.push(command.clone());
        }
    }
    commands
}

pub fn validate(argv: &[String], opts: &Options) -> Result<(), String> {
    if argv.is_empty() {
        return Err("empty argv".to_string());
    }
    let program = &argv[0];
    if program.is_empty() || program.contains('/') || program.contains('\\') {
        return Err("program must be a bare command name".to_string());
    }
    let read_only = READ_ONLY_COMMANDS.contains(&program.as_str());
    let explicitly_allowed = opts.allow_cmds.iter().any(|value| value == program);
    if !read_only && !(explicitly_allowed && opts.allows_write()) {
        return Err(format!(
            "command '{}' is not in the allow-list (read-only={})",
            program,
            if read_only { "safe" } else { "false" }
        ));
    }
    if !read_only && opts.read_only {
        return Err(format!("command '{}' requires --allow-write", program));
    }
    if program == "find" {
        for argument in argv.iter().skip(1) {
            if UNSAFE_FIND_FLAGS.contains(&argument.as_str()) {
                return Err(format!("find flag {} is not allowed", argument));
            }
        }
    }
    if program == "printenv" && argv.len() > 1 {
        let key = argv[1].to_ascii_uppercase();
        if key.contains("TOKEN") || key.contains("SECRET") || key.contains("PASSWORD") {
            return Err("refusing to print a credential environment variable".to_string());
        }
    }
    Ok(())
}

pub fn run(argv: &[String], opts: &Options, timeout_ms: u64) -> Result<Value, String> {
    validate(argv, opts)?;
    run_program(&argv[0], &argv[1..], opts, timeout_ms, false, None)
}

/// Execute a program without the read-only allow-list.  Only the bypass engine
/// calls this: the caller has already selected a technique and is responsible
/// for the benign payload boundary (no credential theft, no destructive write).
///
/// `clean_env` drops the entire inherited environment and re-adds only a
/// minimal PATH/HOME/TMPDIR.  `cwd` lets the caller avoid HIDS-monitored paths.
pub fn run_program(
    program: &str,
    args: &[String],
    opts: &Options,
    timeout_ms: u64,
    clean_env: bool,
    cwd: Option<&str>,
) -> Result<Value, String> {
    let started = Instant::now();
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if clean_env {
        command.env_clear();
        command
            .env("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
            .env("HOME", "/tmp")
            .env("TMPDIR", "/tmp")
            .env("LANG", "C");
    } else {
        command
            .env_remove("INKBLADE_PROBE_TOKEN")
            .env_remove("INKBLADE_PROBE_TOKEN_FILE");
    }
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("spawn {program}: {error}"))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let cap = opts.max_output_bytes();
    let (tx, rx) = mpsc::channel();
    if let Some(stdout) = stdout {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(("stdout", read_capped(stdout, cap)));
        });
    }
    if let Some(stderr) = stderr {
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(("stderr", read_capped(stderr, cap)));
        });
    }
    drop(tx);
    let mut timed_out = false;
    let mut exit_code: i64 = -1;
    let deadline = started + Duration::from_millis(timeout_ms.max(50));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code().unwrap_or(-1) as i64;
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    exit_code = -1;
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                let _ = child.kill();
                return Err(format!("wait {program}: {error}"));
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
    let (stdout_text, stdout_truncated) = to_text(stdout_data.0, stdout_data.1);
    let (stderr_text, stderr_truncated) = to_text(stderr_data.0, stderr_data.1);
    Ok(json::object(vec![
        ("exit_code", json::number(exit_code)),
        ("rc", json::number(exit_code)),
        ("stdout", json::string(stdout_text)),
        ("stderr", json::string(stderr_text)),
        ("truncated", json::bool_value(stdout_truncated || stderr_truncated)),
        ("timed_out", json::bool_value(timed_out)),
        ("duration_ms", json::number(started.elapsed().as_millis() as u64)),
        ("argv", Value::Arr(
            std::iter::once(program.to_string())
                .chain(args.iter().cloned())
                .map(json::string)
                .collect(),
        )),
        ("clean_env", json::bool_value(clean_env)),
        ("cwd", cwd.map(json::string).unwrap_or(Value::Null)),
    ]))
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

fn to_text(data: Vec<u8>, truncated: bool) -> (String, bool) {
    let mut text = String::from_utf8_lossy(&data).to_string();
    if truncated {
        text.push_str("\n[truncated]");
    }
    (text, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(read_only: bool) -> Options {
        Options {
            read_only,
            ..Options::default()
        }
    }

    #[test]
    fn rejects_shell_in_read_only_mode() {
        assert!(validate(&["sh".into(), "-c".into(), "id".into()], &opts(true)).is_err());
        assert!(validate(&["id".into()], &opts(true)).is_ok());
    }

    #[test]
    fn explicit_write_command_requires_allow_write() {
        let mut write = opts(false);
        write.allow_cmds = vec!["sh".to_string()];
        assert!(validate(&["sh".into(), "-c".into(), "id".into()], &write).is_ok());
        assert!(validate(&["sh".into(), "-c".into(), "id".into()], &opts(true)).is_err());
    }

    #[test]
    fn rejects_find_exec() {
        assert!(validate(
            &["find".into(), "/tmp".into(), "-exec".into(), "id".into()],
            &opts(true)
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_child() {
        let mut options = opts(false);
        options.allow_cmds = vec!["sleep".to_string()];
        let result = run(&["sleep".into(), "5".into()], &options, 120).unwrap();
        assert_eq!(result.get("timed_out").and_then(Value::as_bool), Some(true));
    }
}
