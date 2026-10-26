//! Minimal JSON encoder/decoder (standard library only).

use std::fmt::Write as _;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(items) => items
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_f64().map(|value| value.max(0.0) as u64)
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64().map(|value| value as i64)
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Value)]> {
        match self {
            Value::Obj(items) => Some(items),
            _ => None,
        }
    }

    pub fn from_serde(value: &serde_json::Value) -> Value {
        match value {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(value) => Value::Bool(*value),
            serde_json::Value::Number(value) => {
                Value::Num(value.as_f64().unwrap_or(0.0))
            }
            serde_json::Value::String(value) => Value::Str(value.clone()),
            serde_json::Value::Array(items) => {
                Value::Arr(items.iter().map(Value::from_serde).collect())
            }
            serde_json::Value::Object(items) => Value::Obj(
                items
                    .iter()
                    .map(|(key, value)| (key.clone(), Value::from_serde(value)))
                    .collect(),
            ),
        }
    }

    /// Dot-path lookup used by the template runtime (`a.b.0.c`).
    pub fn path(&self, path: &str) -> Option<&Value> {
        let mut current = self;
        for part in path.split('.') {
            if part.is_empty() {
                continue;
            }
            if let Ok(index) = part.parse::<usize>() {
                current = current.as_array()?.get(index)?;
            } else {
                current = current.get(part)?;
            }
        }
        Some(current)
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Num(value) => {
                if value.is_finite() {
                    if value.fract() == 0.0 && value.abs() < 1e15 {
                        let _ = write!(out, "{}", *value as i64);
                    } else {
                        let _ = write!(out, "{}", value);
                    }
                } else {
                    out.push_str("null");
                }
            }
            Value::Str(value) => write_escaped(out, value),
            Value::Arr(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            Value::Obj(items) => {
                out.push('{');
                for (index, (key, value)) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_escaped(out, key);
                    out.push(':');
                    value.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_escaped(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

pub fn object(items: Vec<(&str, Value)>) -> Value {
    Value::Obj(
        items
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

pub fn string(value: impl Into<String>) -> Value {
    Value::Str(value.into())
}

pub fn number<T: ToF64>(value: T) -> Value {
    Value::Num(value.to_f64())
}

pub trait ToF64 {
    fn to_f64(self) -> f64;
}

macro_rules! to_f64_int {
    ($($ty:ty),* $(,)?) => {
        $(impl ToF64 for $ty { fn to_f64(self) -> f64 { self as f64 } })*
    };
}

to_f64_int!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);
impl ToF64 for f32 { fn to_f64(self) -> f64 { self as f64 } }
impl ToF64 for f64 { fn to_f64(self) -> f64 { self } }

pub fn bool_value(value: bool) -> Value {
    Value::Bool(value)
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing data at byte {}", parser.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", byte as char, self.pos))
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'"') => Ok(Value::Str(self.parse_string()?)),
            Some(b'[') => self.parse_array(),
            Some(b'{') => self.parse_object(),
            Some(b'-') | Some(b'0'..=b'9') => self.parse_number(),
            Some(other) => Err(format!(
                "unexpected byte '{}' at byte {}",
                other as char, self.pos
            )),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn literal(&mut self, text: &str) -> Result<(), String> {
        if self.bytes[self.pos..].starts_with(text.as_bytes()) {
            self.pos += text.len();
            Ok(())
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let byte = *self
                .bytes
                .get(self.pos)
                .ok_or_else(|| "unterminated string".to_string())?;
            self.pos += 1;
            match byte {
                b'"' => return Ok(out),
                b'\\' => {
                    let esc = *self
                        .bytes
                        .get(self.pos)
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&code) {
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    if self.peek() == Some(b'u') {
                                        self.pos += 1;
                                        let low = self.parse_hex4()?;
                                        let combined = 0x10000
                                            + ((code - 0xD800) << 10)
                                            + (low.wrapping_sub(0xDC00) & 0x3FF);
                                        if let Some(ch) = char::from_u32(combined) {
                                            out.push(ch);
                                        }
                                    }
                                }
                            } else if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                        other => {
                            return Err(format!(
                                "invalid escape '{}' at byte {}",
                                other as char, self.pos
                            ))
                        }
                    }
                }
                byte if byte < 0x20 => {
                    return Err(format!("control byte in string at byte {}", self.pos));
                }
                _ => {
                    // Re-decode the full UTF-8 sequence.
                    let start = self.pos - 1;
                    let width = utf8_width(byte);
                    let end = start + width;
                    if end > self.bytes.len() {
                        return Err("truncated UTF-8 in string".to_string());
                    }
                    let chunk = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| "invalid UTF-8 in string".to_string())?;
                    out.push_str(chunk);
                    self.pos = end;
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("truncated unicode escape".to_string());
        }
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self.bytes[self.pos];
            self.pos += 1;
            let digit = match byte {
                b'0'..=b'9' => (byte - b'0') as u32,
                b'a'..=b'f' => (byte - b'a' + 10) as u32,
                b'A'..=b'F' => (byte - b'A' + 10) as u32,
                _ => return Err("invalid unicode escape".to_string()),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(byte) = self.peek() {
            match byte {
                b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-' => self.pos += 1,
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        let value = text
            .parse::<f64>()
            .map_err(|_| format!("invalid number {}", text))?;
        Ok(Value::Num(value))
    }

    fn parse_array(&mut self) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            items.push(self.parse_value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.pos)),
            }
        }
    }

    fn parse_object(&mut self) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Obj(items));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            items.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Obj(items));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.pos)),
            }
        }
    }
}

fn utf8_width(first: u8) -> usize {
    if first < 0x80 {
        1
    } else if first >> 5 == 0b110 {
        2
    } else if first >> 4 == 0b1110 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_basic() {
        let text = r#"{"a":1,"b":[true,null,"x\n"]}"#;
        let value = parse(text).expect("parse");
        assert_eq!(value.get("a").and_then(Value::as_u64), Some(1));
        assert_eq!(
            value.get("b").and_then(Value::as_array).map(|v| v.len()),
            Some(3)
        );
        let encoded = value.to_json();
        assert!(encoded.contains("\"a\":1"));
        let again = parse(&encoded).expect("reparse");
        assert_eq!(again.get("a").and_then(Value::as_u64), Some(1));
    }

    #[test]
    fn rejects_trailing_data() {
        assert!(parse("{\"a\":1} junk").is_err());
    }
}
