//! File system operations used by upload/download and the `fs` template op.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::base64;
use crate::config::Options;
use crate::json::{self, Value};
use crate::sha256;
use crate::util;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn read(path: &str, offset: u64, max: usize) -> Result<Value, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("stat {path}: {error}"))?;
    if metadata.is_dir() {
        return Err(format!("{path} is a directory"));
    }
    let mut file = fs::File::open(path).map_err(|error| format!("open {path}: {error}"))?;
    let size = metadata.len();
    let start = offset.min(size);
    file.seek(SeekFrom::Start(start))
        .map_err(|error| format!("seek {path}: {error}"))?;
    let limit = max.clamp(1, 16 * 1024 * 1024);
    let mut buffer = vec![0u8; limit];
    let mut read = 0;
    while read < limit {
        match file.read(&mut buffer[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) => return Err(format!("read {path}: {error}")),
        }
    }
    buffer.truncate(read);
    let full_sha = util::file_sha256(Path::new(path)).unwrap_or_default();
    Ok(json::object(vec![
        ("path", json::string(path)),
        ("exists", json::bool_value(true)),
        ("offset", json::number(start)),
        ("next_offset", json::number(start + read as u64)),
        ("size", json::number(size)),
        ("eof", json::bool_value(start + read as u64 >= size)),
        ("sha256", json::string(full_sha)),
        ("data_b64", json::string(base64::encode(&buffer))),
        ("bytes", json::number(read as u64)),
    ]))
}

pub fn write(path: &str, data: &[u8], offset: u64, mode: Option<u32>, opts: &Options) -> Result<Value, String> {
    if opts.read_only {
        return Err("filesystem writes require --allow-write".to_string());
    }
    if data.len() > opts.max_output_bytes() {
        return Err("write exceeds max_output".to_string());
    }
    let mut options = OpenOptions::new();
    options.create(true).write(true);
    if offset == 0 {
        options.truncate(true);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("open {path} for write: {error}"))?;
    if offset > 0 {
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| format!("seek {path}: {error}"))?;
    }
    file.write_all(data)
        .map_err(|error| format!("write {path}: {error}"))?;
    file.flush().ok();
    if let Some(mode) = mode {
        set_mode(path, mode)?;
    }
    let metadata = fs::metadata(path).map_err(|error| format!("stat {path}: {error}"))?;
    Ok(json::object(vec![
        ("path", json::string(path)),
        ("written", json::number(data.len() as u64)),
        ("offset", json::number(offset)),
        ("size", json::number(metadata.len())),
        ("sha256", json::string(util::file_sha256(Path::new(path)).unwrap_or_default())),
    ]))
}

pub fn set_mode(path: &str, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions)
            .map_err(|error| format!("chmod {path}: {error}"))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

pub fn list(path: &str) -> Result<Value, String> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|error| format!("read_dir {path}: {error}"))? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let metadata = entry.metadata().ok();
        entries.push(json::object(vec![
            ("name", json::string(entry.file_name().to_string_lossy().to_string())),
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

pub fn list_glob(path: &str, pattern: Option<&str>) -> Result<Value, String> {
    let mut value = list(path)?;
    if let Some(pattern) = pattern {
        if !pattern.is_empty() {
            if let Value::Obj(items) = &mut value {
                let needle = pattern.trim_matches('*').to_string();
                let entries_index = items.iter().position(|(key, _)| key == "entries");
                if let Some(index) = entries_index {
                    if let Value::Arr(entries) = &mut items[index].1 {
                        entries.retain(|entry| {
                            entry
                                .get("name")
                                .and_then(Value::as_str)
                                .map(|name| {
                                    if pattern.starts_with('*') && pattern.ends_with('*') {
                                        name.contains(&needle)
                                    } else if pattern.starts_with('*') {
                                        name.ends_with(&needle)
                                    } else if pattern.ends_with('*') {
                                        name.starts_with(&needle)
                                    } else {
                                        name == pattern
                                    }
                                })
                                .unwrap_or(false)
                        });
                        let count = entries.len() as u64;
                        if let Some((_, count_value)) = items.iter_mut().find(|(key, _)| key == "count") {
                            *count_value = json::number(count);
                        }
                    }
                }
            }
        }
    }
    Ok(value)
}

pub fn stat(path: &str) -> Result<Value, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("stat {path}: {error}"))?;
    Ok(json::object(vec![
        ("path", json::string(path)),
        ("exists", json::bool_value(true)),
        ("dir", json::bool_value(metadata.is_dir())),
        ("file", json::bool_value(metadata.is_file())),
        ("symlink", json::bool_value(metadata.file_type().is_symlink())),
        ("size", json::number(metadata.len())),
        ("modified_ms", json::number(
            metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0),
        )),
        ("mode", json::number(mode_of(&metadata))),
        ("sha256", json::string(
            if metadata.is_file() {
                util::file_sha256(Path::new(path)).unwrap_or_default()
            } else {
                String::new()
            },
        )),
    ]))
}

fn mode_of(metadata: &fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        metadata.permissions().mode() as u64
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        0
    }
}

pub fn remove(path: &str, recursive: bool, opts: &Options) -> Result<Value, String> {
    if opts.read_only {
        return Err("filesystem removal requires --allow-write".to_string());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("stat {path}: {error}"))?;
    if metadata.is_dir() {
        if !recursive {
            return Err(format!("{path} is a directory (use recursive=true)"));
        }
        fs::remove_dir_all(path).map_err(|error| format!("remove_dir_all {path}: {error}"))?;
    } else {
        fs::remove_file(path).map_err(|error| format!("remove_file {path}: {error}"))?;
    }
    Ok(json::object(vec![("path", json::string(path)), ("removed", json::bool_value(true))]))
}

pub fn mkdir(path: &str, recursive: bool, mode: Option<u32>, opts: &Options) -> Result<Value, String> {
    if opts.read_only {
        return Err("mkdir requires --allow-write".to_string());
    }
    let result = if recursive {
        fs::create_dir_all(path)
    } else {
        fs::create_dir(path)
    };
    result.map_err(|error| format!("mkdir {path}: {error}"))?;
    if let Some(mode) = mode {
        set_mode(path, mode)?;
    }
    Ok(json::object(vec![("path", json::string(path)), ("created", json::bool_value(true))]))
}

pub fn verify_chunks(chunks: &[(u64, Vec<u8>)], expected_sha: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut expected_offset = 0u64;
    for (offset, data) in chunks {
        if *offset != expected_offset {
            return Err(format!("non-contiguous chunk at {offset}, expected {expected_offset}"));
        }
        output.extend_from_slice(data);
        expected_offset += data.len() as u64;
    }
    let got = base64::hex(&sha256::sha256(&output));
    if !expected_sha.is_empty() && got != expected_sha {
        return Err(format!("sha256 mismatch: expected {expected_sha}, got {got}"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_verification_detects_corruption() {
        let data = b"hello".to_vec();
        let sha = base64::hex(&sha256::sha256(&data));
        assert!(verify_chunks(&[(0, data.clone())], &sha).is_ok());
        assert!(verify_chunks(&[(0, data)], "00").is_err());
    }
}
