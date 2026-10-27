//! Encrypted outbound transports for the probe-initiated reverse channel.
//!
//! The framed protocol is unchanged: all transports expose a byte stream
//! carrying the same 4-byte length + JSON frames.  Authentication remains
//! challenge-HMAC-SHA256 inside the encrypted channel.
//!
//! * `tls`   - rustls stream (default);
//! * `wss`   - rustls + RFC 6455 WebSocket binary messages;
//! * `https` - rustls + HTTP/1.1 long-poll.
//!
//! Certificate verification uses the supplied CA bundle plus the webpki root
//! store, followed by a mandatory SHA-256 pin over the leaf DER certificate.
//! Plaintext is only reachable through the test-only `lab_plaintext` mode,
//! guarded by `INKBLADE_ALLOW_PLAINTEXT_LAB=1`.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use rustls::{RootCertStore, StreamOwned};

use crate::base64;
use crate::config::Options;
use crate::json::{self, Value};
use crate::util;

const READY_POLL_MS: u64 = 200;

struct PinnedVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pin: [u8; 32],
}

impl std::fmt::Debug for PinnedVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PinnedVerifier")
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let got = crate::sha256::sha256(end_entity.as_ref());
        let expected = self.pin;
        if !crate::sha256::constant_time_eq(&got, &expected) {
            return Err(rustls::Error::General(
                "certificate pin mismatch".to_string(),
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn tls_config(opts: &Options) -> Result<Arc<ClientConfig>, String> {
    let pin_hex = opts
        .pin
        .as_deref()
        .ok_or_else(|| "encrypted reverse requires --pin <sha256>".to_string())?
        .trim()
        .trim_start_matches("sha256:");
    let pin =
        base64::unhex(pin_hex).map_err(|_| "--pin must be a SHA-256 hex digest".to_string())?;
    if pin.len() != 32 {
        return Err("--pin must be a 32-byte SHA-256 hex digest".to_string());
    }
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = &opts.ca_file {
        let data =
            std::fs::read(path).map_err(|error| format!("ca file {}: {error}", path.display()))?;
        let mut cursor = std::io::Cursor::new(data);
        for certificate in rustls_pemfile::certs(&mut cursor) {
            let certificate = certificate.map_err(|error| format!("ca pem: {error}"))?;
            roots
                .add(certificate)
                .map_err(|error| format!("ca cert: {error}"))?;
        }
    } else {
        return Err("encrypted reverse requires --ca-file <ca.pem>".to_string());
    }
    let inner = WebPkiServerVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|error| format!("tls verifier: {error}"))?;
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&pin);
    let verifier = Arc::new(PinnedVerifier {
        inner,
        pin: expected,
    });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn connect_tcp(opts: &Options, host: &str, port: u16) -> Result<TcpStream, String> {
    let stream = crate::net::connect(host, port, opts.connect_timeout_ms)?;
    stream
        .set_read_timeout(Some(Duration::from_millis(READY_POLL_MS)))
        .map_err(|error| format!("tls read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|error| format!("tls write timeout: {error}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

pub struct TlsConn {
    inner: Mutex<StreamOwned<ClientConnection, TcpStream>>,
}

impl TlsConn {
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "tls lock poisoned"))?;
        inner.read(buffer)
    }

    pub fn write(&self, data: &[u8]) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "tls lock poisoned"))?;
        inner.write_all(data)
    }

    pub fn flush(&self) -> io::Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "tls lock poisoned"))?;
        inner.flush()
    }
}

fn tls_connect(opts: &Options, host: &str, port: u16) -> Result<TlsConn, String> {
    let config = tls_config(opts)?;
    let tcp = connect_tcp(opts, host, port)?;
    let sni = opts.sni.clone().unwrap_or_else(|| host.to_string());
    let server_name =
        ServerName::try_from(sni.clone()).map_err(|_| format!("invalid SNI name {sni:?}"))?;
    let connection = ClientConnection::new(config, server_name)
        .map_err(|error| format!("tls client: {error}"))?;
    Ok(TlsConn {
        inner: Mutex::new(StreamOwned::new(connection, tcp)),
    })
}

pub struct TlsReader {
    conn: Arc<TlsConn>,
}

impl Read for TlsReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.conn.read(buffer) {
                Ok(count) => return Ok(count),
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }
}

pub struct TlsWriter {
    conn: Arc<TlsConn>,
}

impl Write for TlsWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.conn.write(buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.conn.flush()
    }
}

/// Connect one encrypted transport and return the framed-protocol reader and
/// writer.  Only `tcp` (lab test) bypasses TLS.
pub fn connect(
    opts: &Options,
    host: &str,
    port: u16,
) -> Result<(Box<dyn Read + Send>, Box<dyn Write + Send>), String> {
    match opts.transport.as_str() {
        "tls" => {
            let conn = Arc::new(tls_connect(opts, host, port)?);
            Ok((
                Box::new(TlsReader { conn: conn.clone() }),
                Box::new(TlsWriter { conn }),
            ))
        }
        "wss" => wss_connect(opts, host, port),
        "https" => https_connect(opts, host, port),
        "lab-plaintext" => {
            if std::env::var("INKBLADE_ALLOW_PLAINTEXT_LAB")
                .ok()
                .as_deref()
                != Some("1")
            {
                return Err("lab plaintext requires INKBLADE_ALLOW_PLAINTEXT_LAB=1".to_string());
            }
            let tcp = crate::net::connect(host, port, opts.connect_timeout_ms)?;
            let _ = tcp.set_read_timeout(None);
            let _ = tcp.set_write_timeout(None);
            let reader = tcp
                .try_clone()
                .map_err(|error| format!("plaintext clone: {error}"))?;
            Ok((Box::new(reader), Box::new(tcp)))
        }
        other => Err(format!("unsupported reverse transport {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------
struct WsReadState {
    leftover: Vec<u8>,
    payload: Vec<u8>,
}

pub struct WsReader {
    conn: Arc<TlsConn>,
    state: Arc<Mutex<WsReadState>>,
}

impl Read for WsReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            {
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "ws state lock"))?;
                if !state.payload.is_empty() {
                    let take = buffer.len().min(state.payload.len());
                    buffer[..take].copy_from_slice(&state.payload[..take]);
                    state.payload.drain(..take);
                    return Ok(take);
                }
            }
            if !ws_read_next(&self.conn, &self.state)? {
                return Ok(0);
            }
        }
    }
}

pub struct WsWriter {
    conn: Arc<TlsConn>,
    outgoing: Arc<Mutex<Vec<u8>>>,
}

impl Write for WsWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut outgoing = self
            .outgoing
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "ws write lock"))?;
        outgoing.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut outgoing = self
            .outgoing
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "ws write lock"))?;
        if outgoing.is_empty() {
            return Ok(());
        }
        let payload = std::mem::take(&mut *outgoing);
        ws_write_frame(&self.conn, 0x2, &payload)
    }
}

fn read_exact_tls(conn: &TlsConn, count: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; count];
    let mut read = 0;
    while read < count {
        match conn.read(&mut out[read..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tls eof")),
            Ok(value) => read += value,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(out)
}

fn ws_read_next(conn: &TlsConn, state: &Arc<Mutex<WsReadState>>) -> io::Result<bool> {
    let header = read_exact_tls(conn, 2)?;
    let opcode = header[0] & 0x0F;
    let masked = header[1] & 0x80 != 0;
    let mut length = (header[1] & 0x7F) as u64;
    if length == 126 {
        let extended = read_exact_tls(conn, 2)?;
        length = u16::from_be_bytes([extended[0], extended[1]]) as u64;
    } else if length == 127 {
        let extended = read_exact_tls(conn, 8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&extended);
        length = u64::from_be_bytes(bytes);
    }
    if length > 8 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ws frame too large",
        ));
    }
    let mask = if masked {
        Some(read_exact_tls(conn, 4)?)
    } else {
        None
    };
    let mut payload = if length > 0 {
        read_exact_tls(conn, length as usize)?
    } else {
        Vec::new()
    };
    if let Some(mask) = mask {
        for (index, value) in payload.iter_mut().enumerate() {
            *value ^= mask[index % 4];
        }
    }
    match opcode {
        0x8 => Ok(false),
        0x9 => {
            ws_write_frame(conn, 0xA, &payload)?;
            Ok(true)
        }
        0xA => Ok(true),
        0x0 | 0x2 => {
            let mut state = state
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "ws state lock"))?;
            state.payload.extend_from_slice(&payload);
            Ok(true)
        }
        _ => Ok(true),
    }
}

fn ws_write_frame(conn: &TlsConn, opcode: u8, payload: &[u8]) -> io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode);
    let length = payload.len();
    if length < 126 {
        frame.push(0x80 | length as u8);
    } else if length <= 0xFFFF {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        frame.push(0x80 | 127);
        frame.extend_from_slice(&(length as u64).to_be_bytes());
    }
    let mask = util::random_bytes(4);
    frame.extend_from_slice(&mask);
    for (index, value) in payload.iter().enumerate() {
        frame.push(*value ^ mask[index % 4]);
    }
    conn.write(&frame)
}

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in message.chunks(64) {
        let mut w = [0u32; 80];
        for index in 0..16 {
            w[index] = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..80 {
            w[index] = (w[index - 3] ^ w[index - 8] ^ w[index - 14] ^ w[index - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (index, word) in w.iter().enumerate() {
            let (function, constant) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(function)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (index, value) in h.iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    out
}

fn wss_connect(
    opts: &Options,
    host: &str,
    port: u16,
) -> Result<(Box<dyn Read + Send>, Box<dyn Write + Send>), String> {
    let conn = Arc::new(tls_connect(opts, host, port)?);
    let key = base64::encode(&util::random_bytes(16));
    let user_agent = if opts.user_agent.is_empty() {
        "Mozilla/5.0".to_string()
    } else {
        opts.user_agent.clone()
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: {user_agent}\r\n\r\n",
        opts.ws_path
    );
    conn.write(request.as_bytes())
        .map_err(|error| format!("wss request: {error}"))?;
    conn.flush()
        .map_err(|error| format!("wss flush: {error}"))?;
    let mut raw = Vec::new();
    loop {
        if raw.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        let mut byte = [0u8; 1];
        match conn.read(&mut byte) {
            Ok(0) => return Err("wss upgrade closed".to_string()),
            Ok(_) => raw.push(byte[0]),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(format!("wss upgrade read: {error}")),
        }
        if raw.len() > 64 * 1024 {
            return Err("wss upgrade header too large".to_string());
        }
    }
    let position = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "wss upgrade header missing".to_string())?;
    let head = String::from_utf8_lossy(&raw[..position]).to_string();
    if !head.starts_with("HTTP/1.1 101") {
        return Err(format!(
            "wss upgrade rejected: {}",
            head.lines().next().unwrap_or("")
        ));
    }
    let expected = base64::encode(&sha1(
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    ));
    let mut accept_ok = false;
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("sec-websocket-accept") && value.trim() == expected {
                accept_ok = true;
            }
        }
    }
    if !accept_ok {
        return Err("wss accept mismatch".to_string());
    }
    let leftover = raw[position + 4..].to_vec();
    let state = Arc::new(Mutex::new(WsReadState {
        leftover,
        payload: Vec::new(),
    }));
    Ok((
        Box::new(WsReader {
            conn: conn.clone(),
            state,
        }),
        Box::new(WsWriter {
            conn,
            outgoing: Arc::new(Mutex::new(Vec::new())),
        }),
    ))
}

// ---------------------------------------------------------------------------
// HTTPS long-poll
// ---------------------------------------------------------------------------
fn https_post(
    opts: &Options,
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
) -> Result<Value, String> {
    let conn = tls_connect(opts, host, port)?;
    let user_agent = if opts.user_agent.is_empty() {
        "Mozilla/5.0".to_string()
    } else {
        opts.user_agent.clone()
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    conn.write(request.as_bytes())
        .map_err(|error| format!("https request: {error}"))?;
    conn.write(body)
        .map_err(|error| format!("https body: {error}"))?;
    conn.flush()
        .map_err(|error| format!("https flush: {error}"))?;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut header_end: Option<usize> = None;
    while header_end.is_none() {
        match conn.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                raw.extend_from_slice(&buffer[..count]);
                if let Some(position) = raw.windows(4).position(|window| window == b"\r\n\r\n") {
                    header_end = Some(position);
                }
            }
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(format!("https response: {error}")),
        }
        if raw.len() > 8 * 1024 * 1024 {
            return Err("https response too large".to_string());
        }
    }
    let position = header_end.ok_or_else(|| "https response header missing".to_string())?;
    let head = String::from_utf8_lossy(&raw[..position]).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(format!("https {path}: status {status}"));
    }
    let mut content_length = 0usize;
    for line in head.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse::<usize>().unwrap_or(0);
            }
        }
    }
    let body_start = position + 4;
    while raw.len() < body_start + content_length {
        match conn.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => raw.extend_from_slice(&buffer[..count]),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => return Err(format!("https body: {error}")),
        }
        if raw.len() > 8 * 1024 * 1024 {
            return Err("https response too large".to_string());
        }
    }
    let body = &raw[body_start..raw.len().min(body_start + content_length)];
    let text = std::str::from_utf8(body).map_err(|_| "https body is not UTF-8".to_string())?;
    crate::json::parse(text)
}

struct HttpsReader {
    opts: Options,
    host: String,
    port: u16,
    buffer: Vec<u8>,
    closed: bool,
    probe_id: String,
    parent_id: Option<String>,
}

impl Read for HttpsReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.closed {
            return Ok(0);
        }
        while self.buffer.is_empty() {
            let payload = json::object(vec![
                ("probe_id", json::string(self.probe_id.clone())),
                (
                    "parent_id",
                    self.parent_id
                        .clone()
                        .map(json::string)
                        .unwrap_or(Value::Null),
                ),
                ("transport", json::string("https")),
            ]);
            let body = payload.to_json().into_bytes();
            let url = self.opts.poll_path.clone();
            match https_post(&self.opts, &self.host, self.port, &url, &body) {
                Ok(value) => {
                    if let Some(Value::Arr(frames)) = value.get("frames") {
                        for frame in frames {
                            if let Some(encoded) = frame.as_str() {
                                if let Ok(bytes) = base64::decode(encoded) {
                                    self.buffer.extend_from_slice(&bytes);
                                }
                            }
                        }
                    }
                }
                Err(_) => {
                    self.closed = true;
                    return Ok(0);
                }
            }
            if self.buffer.is_empty() {
                let jitter = (util::random_bytes(2)
                    .iter()
                    .fold(0u16, |acc, v| acc.wrapping_mul(257).wrapping_add(*v as u16))
                    % 350) as u64;
                std::thread::sleep(Duration::from_millis(50 + jitter));
            }
        }
        let take = buffer.len().min(self.buffer.len());
        buffer[..take].copy_from_slice(&self.buffer[..take]);
        self.buffer.drain(..take);
        Ok(take)
    }
}

struct HttpsWriter {
    opts: Options,
    host: String,
    port: u16,
    outgoing: Vec<u8>,
    closed: bool,
    probe_id: String,
}

impl Write for HttpsWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.outgoing.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.outgoing.is_empty() || self.closed {
            return Ok(());
        }
        let payload = std::mem::take(&mut self.outgoing);
        let body = json::object(vec![
            ("probe_id", json::string(self.probe_id.clone())),
            (
                "frames",
                Value::Arr(vec![json::string(base64::encode(&payload))]),
            ),
        ])
        .to_json()
        .into_bytes();
        let path = self.opts.result_path.clone();
        if https_post(&self.opts, &self.host, self.port, &path, &body).is_err() {
            self.closed = true;
        }
        Ok(())
    }
}

fn https_connect(
    opts: &Options,
    host: &str,
    port: u16,
) -> Result<(Box<dyn Read + Send>, Box<dyn Write + Send>), String> {
    if opts.pin.is_none() || opts.ca_file.is_none() {
        return Err("https transport requires --ca-file and --pin".to_string());
    }
    Ok((
        Box::new(HttpsReader {
            opts: opts.clone(),
            host: host.to_string(),
            port,
            buffer: Vec::new(),
            closed: false,
            probe_id: opts.probe_id.clone(),
            parent_id: opts.parent_id.clone(),
        }),
        Box::new(HttpsWriter {
            opts: opts.clone(),
            host: host.to_string(),
            port,
            outgoing: Vec::new(),
            closed: false,
            probe_id: opts.probe_id.clone(),
        }),
    ))
}
