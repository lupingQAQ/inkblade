//! TCP dial/probe and a small SOCKS5 server used by the `socks` template op.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::base64;
use crate::json::{self, Value};

pub fn connect(host: &str, port: u16, timeout_ms: u64) -> Result<TcpStream, String> {
    let timeout = Duration::from_millis(timeout_ms.clamp(50, 120_000));
    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("resolve {host}:{port}: {error}"))?
        .collect();
    if addresses.is_empty() {
        return Err(format!("no address for {host}:{port}"));
    }
    let mut last_error = String::new();
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(timeout));
                let _ = stream.set_write_timeout(Some(timeout));
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last_error = format!("{address}: {error}"),
        }
    }
    Err(format!("connect {host}:{port} failed: {last_error}"))
}

pub fn tcp_probe(
    host: &str,
    port: u16,
    send: Option<&[u8]>,
    read_bytes: usize,
    timeout_ms: u64,
) -> Result<Value, String> {
    let mut stream = connect(host, port, timeout_ms)?;
    let started = std::time::Instant::now();
    if let Some(payload) = send {
        if !payload.is_empty() {
            stream
                .write_all(payload)
                .map_err(|error| format!("tcp write: {error}"))?;
        }
    }
    let mut out = Vec::new();
    let limit = read_bytes.clamp(0, 16 * 1024 * 1024);
    if limit > 0 {
        let mut buffer = vec![0u8; limit];
        let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms.clamp(50, 120_000))));
        loop {
            match stream.read(&mut buffer[out.len()..]) {
                Ok(0) => break,
                Ok(count) => {
                    out.extend_from_slice(&buffer[out.len()..out.len() + count]);
                    if out.len() >= limit {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }
    let local = stream.local_addr().ok().map(|addr| addr.to_string()).unwrap_or_default();
    let peer = stream.peer_addr().ok().map(|addr| addr.to_string()).unwrap_or_default();
    Ok(json::object(vec![
        ("host", json::string(host)),
        ("port", json::number(port as u64)),
        ("connected", json::bool_value(true)),
        ("local", json::string(local)),
        ("peer", json::string(peer)),
        ("data_b64", json::string(base64::encode(&out))),
        ("bytes", json::number(out.len() as u64)),
        ("duration_ms", json::number(started.elapsed().as_millis() as u64)),
    ]))
}

pub struct SocksHandle {
    pub address: String,
    pub stop: Arc<AtomicBool>,
}

impl SocksHandle {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(&self.address) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

pub fn start_socks5(bind: &str, port: u16) -> Result<SocksHandle, String> {
    if bind != "127.0.0.1" && bind != "::1" && bind != "localhost" {
        return Err("SOCKS listener must bind to loopback".to_string());
    }
    let listener = TcpListener::bind((bind, port)).map_err(|error| format!("socks bind: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("socks nonblocking: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("socks addr: {error}"))?
        .to_string();
    let stop = Arc::new(AtomicBool::new(false));
    let child_stop = stop.clone();
    thread::spawn(move || {
        while !child_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    thread::spawn(move || {
                        let _ = handle_client(stream);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
    });
    Ok(SocksHandle { address, stop })
}

fn handle_client(mut client: TcpStream) -> Result<(), String> {
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let mut header = [0u8; 2];
    read_exact(&mut client, &mut header)?;
    if header[0] != 5 {
        return Err("not socks5".to_string());
    }
    let mut methods = vec![0u8; header[1] as usize];
    read_exact(&mut client, &mut methods)?;
    client
        .write_all(&[5, 0])
        .map_err(|error| format!("socks greeting: {error}"))?;
    let mut request = [0u8; 4];
    read_exact(&mut client, &mut request)?;
    if request[0] != 5 || request[1] != 1 {
        let _ = client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        return Err("only CONNECT is supported".to_string());
    }
    let host = match request[3] {
        1 => {
            let mut addr = [0u8; 4];
            read_exact(&mut client, &mut addr)?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        3 => {
            let mut length = [0u8; 1];
            read_exact(&mut client, &mut length)?;
            let mut name = vec![0u8; length[0] as usize];
            read_exact(&mut client, &mut name)?;
            String::from_utf8_lossy(&name).to_string()
        }
        4 => {
            let mut addr = [0u8; 16];
            read_exact(&mut client, &mut addr)?;
            let mut segments = Vec::new();
            for chunk in addr.chunks(2) {
                segments.push(format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])));
            }
            segments.join(":")
        }
        _ => {
            let _ = client.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Err("bad address type".to_string());
        }
    };
    let mut port_bytes = [0u8; 2];
    read_exact(&mut client, &mut port_bytes)?;
    let port = u16::from_be_bytes(port_bytes);
    let target = match connect(&host, port, 10_000) {
        Ok(stream) => stream,
        Err(_) => {
            let _ = client.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
            return Err("target refused".to_string());
        }
    };
    client
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(|error| format!("socks reply: {error}"))?;
    relay(client, target)
}

fn relay(client: TcpStream, target: TcpStream) -> Result<(), String> {
    let mut client_read = client.try_clone().map_err(|error| error.to_string())?;
    let mut target_write = target.try_clone().map_err(|error| error.to_string())?;
    let upstream = thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match client_read.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if target_write.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = target_write.shutdown(Shutdown::Write);
    });
    let mut target_read = target;
    let mut client_write = client;
    let mut buffer = [0u8; 16 * 1024];
    loop {
        match target_read.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if client_write.write_all(&buffer[..count]).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = upstream.join();
    Ok(())
}

fn read_exact(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), String> {
    let mut read = 0;
    while read < buffer.len() {
        match stream.read(&mut buffer[read..]) {
            Ok(0) => return Err("eof".to_string()),
            Ok(count) => read += count,
            Err(error) => return Err(format!("read: {error}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_to_closed_port_fails_quickly() {
        let result = connect("127.0.0.1", 1, 50);
        assert!(result.is_err());
    }
}
