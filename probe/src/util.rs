//! Small platform helpers shared by the probe runtime.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::base64;

pub fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub fn hostname() -> String {
    if let Ok(text) = fs::read_to_string("/etc/hostname") {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string())
}

pub fn read_text(path: &str, limit: usize) -> Option<String> {
    let data = read_bytes(path, limit)?;
    Some(String::from_utf8_lossy(&data).to_string())
}

pub fn read_bytes(path: &str, limit: usize) -> Option<Vec<u8>> {
    let mut file = fs::File::open(path).ok()?;
    let mut buffer = vec![0u8; limit.min(16 * 1024 * 1024)];
    let mut read = 0;
    loop {
        if read >= buffer.len() {
            break;
        }
        match file.read(&mut buffer[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(_) => break,
        }
    }
    buffer.truncate(read);
    Some(buffer)
}

pub fn file_sha256(path: &Path) -> Option<String> {
    let data = fs::read(path).ok()?;
    Some(base64::hex(&crate::sha256::sha256(&data)))
}

pub fn random_bytes(count: usize) -> Vec<u8> {
    let mut buffer = vec![0u8; count];
    if let Ok(mut file) = fs::File::open("/dev/urandom") {
        if file.read_exact(&mut buffer).is_ok() {
            return buffer;
        }
    }
    // Fallback used only on platforms without /dev/urandom.  It is combined
    // with the clock and pid so challenges remain unique per connection.
    let seed = format!("{}-{}-{:?}", now_ms(), std::process::id(), std::thread::current().id());
    let digest = crate::sha256::sha256(seed.as_bytes());
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = digest[index % digest.len()];
    }
    buffer
}

pub fn random_hex(count: usize) -> String {
    base64::hex(&random_bytes(count))
}

pub fn default_probe_id() -> String {
    format!(
        "probe-{}-{}-{}",
        hostname(),
        std::process::id(),
        &random_hex(4)
    )
}

pub fn mask_value(key: &str, value: &str) -> String {
    let upper = key.to_ascii_uppercase();
    if upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("PASSWD")
        || upper.contains("API_KEY")
        || upper.contains("APIKEY")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("CREDENTIAL")
    {
        return "***".to_string();
    }
    if value.len() > 512 {
        format!("{}…", &value[..512])
    } else {
        value.to_string()
    }
}

pub fn proc_status() -> String {
    read_text("/proc/self/status", 256 * 1024).unwrap_or_default()
}

pub fn uid_gid() -> (String, String) {
    let text = proc_status();
    let mut uid = String::new();
    let mut gid = String::new();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            uid = value.split_whitespace().next().unwrap_or("").to_string();
        }
        if let Some(value) = line.strip_prefix("Gid:") {
            gid = value.split_whitespace().next().unwrap_or("").to_string();
        }
    }
    (uid, gid)
}

pub fn effective_caps() -> Vec<String> {
    let text = proc_status();
    let names = [
        "CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID", "KILL",
        "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE", "NET_BIND_SERVICE",
        "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK", "IPC_OWNER",
        "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE", "SYS_PACCT",
        "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE", "SYS_TIME",
        "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE", "AUDIT_CONTROL",
        "SETFCAP",
    ];
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("CapEff:") {
            let mask = u64::from_str_radix(value.trim(), 16).unwrap_or(0);
            return names
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1u64 << index) != 0)
                .map(|(_, name)| format!("CAP_{name}"))
                .collect();
        }
    }
    Vec::new()
}

pub fn home_or_tmp() -> PathBuf {
    std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

pub fn safe_join(base: &Path, relative: &str) -> Result<PathBuf, String> {
    let candidate = base.join(relative);
    let normalized = normalize_path(&candidate);
    let normalized_base = normalize_path(base);
    if !normalized.starts_with(&normalized_base) {
        return Err(format!("path escapes root: {relative}"));
    }
    Ok(normalized)
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

pub fn truncate_text(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.to_string(), false);
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_credentials() {
        assert_eq!(mask_value("API_TOKEN", "abc"), "***");
        assert_eq!(mask_value("HOSTNAME", "node-1"), "node-1");
    }

    #[test]
    fn prevents_path_escape() {
        assert!(safe_join(Path::new("/tmp/root"), "../etc/passwd").is_err());
        assert!(safe_join(Path::new("/tmp/root"), "a/b").is_ok());
    }
}
