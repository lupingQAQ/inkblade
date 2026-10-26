//! Base64 and hex helpers (standard library only).

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let mut index = 0;
    while index + 3 <= data.len() {
        let chunk = ((data[index] as u32) << 16)
            | ((data[index + 1] as u32) << 8)
            | (data[index + 2] as u32);
        out.push(ALPHABET[((chunk >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((chunk >> 12) & 63) as usize] as char);
        out.push(ALPHABET[((chunk >> 6) & 63) as usize] as char);
        out.push(ALPHABET[(chunk & 63) as usize] as char);
        index += 3;
    }
    let remaining = data.len() - index;
    if remaining == 1 {
        let chunk = (data[index] as u32) << 16;
        out.push(ALPHABET[((chunk >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((chunk >> 12) & 63) as usize] as char);
        out.push('=');
        out.push('=');
    } else if remaining == 2 {
        let chunk = ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8);
        out.push(ALPHABET[((chunk >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((chunk >> 12) & 63) as usize] as char);
        out.push(ALPHABET[((chunk >> 6) & 63) as usize] as char);
        out.push('=');
    }
    out
}

pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    let mut padding = 0;
    for &byte in bytes {
        if byte == b'=' {
            padding += 1;
            continue;
        }
        if byte == b'\r' || byte == b'\n' || byte == b' ' || byte == b'\t' {
            continue;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("invalid base64 character".to_string()),
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if padding > 2 {
        return Err("invalid base64 padding".to_string());
    }
    Ok(out)
}

pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("odd hex length".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_digit(bytes[index])?;
        let low = hex_digit(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex digit".to_string()),
    }
}

/// URL-safe base64 (JWT payloads) without requiring padding.
pub fn decode_url(text: &str) -> Result<Vec<u8>, String> {
    let mut normalized: String = text
        .chars()
        .map(|ch| match ch {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    while normalized.len() % 4 != 0 {
        normalized.push('=');
    }
    decode(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg==");
        assert_eq!(encode(b"fo"), "Zm8=");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(decode("Zm9vYmFy").unwrap(), b"foobar");
        assert_eq!(decode_url("eyJhIjoxfQ").unwrap(), b"{\"a\":1}");
    }

    #[test]
    fn hex_round_trip() {
        assert_eq!(hex(&[0, 15, 16, 255]), "000f10ff");
        assert_eq!(unhex("000f10ff").unwrap(), vec![0, 15, 16, 255]);
    }
}
