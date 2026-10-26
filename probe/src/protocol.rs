//! Length-prefixed JSON frames: 4-byte big-endian length, then UTF-8 JSON.

use std::io::{Read, Write};

use crate::json::{self, Value};

pub const MAX_FRAME: usize = 8 * 1024 * 1024;

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Value>, String> {
    let mut header = [0u8; 4];
    let mut read = 0;
    while read < 4 {
        match reader.read(&mut header[read..]) {
            Ok(0) => {
                if read == 0 {
                    return Ok(None);
                }
                return Err("truncated frame header".to_string());
            }
            Ok(count) => read += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("frame header read: {error}")),
        }
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(format!("invalid frame length {length}"));
    }
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("frame payload read: {error}"))?;
    let text = std::str::from_utf8(&payload)
        .map_err(|_| "frame payload is not UTF-8".to_string())?;
    let value = json::parse(text)?;
    Ok(Some(value))
}

pub fn write_frame<W: Write>(writer: &mut W, value: &Value) -> Result<(), String> {
    let payload = value.to_json();
    let bytes = payload.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(format!("frame too large: {} bytes", bytes.len()));
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| writer.write_all(bytes))
        .and_then(|_| writer.flush())
        .map_err(|error| format!("frame write: {error}"))
}

pub fn response(id: &str, data: Value) -> Value {
    json::object(vec![
        ("v", json::number(1)),
        ("type", json::string("resp")),
        ("id", json::string(id)),
        ("ok", json::bool_value(true)),
        ("data", data),
    ])
}

pub fn failure(id: &str, code: &str, message: &str) -> Value {
    json::object(vec![
        ("v", json::number(1)),
        ("type", json::string("resp")),
        ("id", json::string(id)),
        ("ok", json::bool_value(false)),
        (
            "error",
            json::object(vec![
                ("code", json::string(code)),
                ("message", json::string(message)),
            ]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let value = json::object(vec![("type", json::string("ping"))]);
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &value).unwrap();
        assert_eq!(&buffer[..4], &[0, 0, 0, 17]);
        let mut cursor = std::io::Cursor::new(buffer);
        let decoded = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(decoded.get("type").and_then(Value::as_str), Some("ping"));
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buffer = vec![0xff, 0xff, 0xff, 0xff];
        let mut cursor = std::io::Cursor::new(buffer.drain(..).collect::<Vec<u8>>());
        assert!(read_frame(&mut cursor).is_err());
    }
}
