//! QUIC transport for the probe-initiated reverse channel.
//!
//! The probe opens one QUIC bidirectional stream and carries the exact same
//! 4-byte big-endian length + UTF-8 JSON frames used by `tls`/`wss`/`https`.
//! After the QUIC/TLS 1.3 handshake the probe still verifies the leaf
//! certificate SHA-256 pin (through the shared `PinnedVerifier`) and then the
//! common `server::serve_with_transport` performs challenge-HMAC authentication.
//!
//! UDP can be blocked independently of TCP.  A handshake timeout is reported
//! as `udp-blocked` so the probe can fall back to `tls`/`wss` on the same
//! controller port.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Connection, Endpoint, TransportConfig};
use tokio::io::AsyncWriteExt;

use crate::config::Options;

pub const ALPN: &[u8] = b"inkblade-reverse/1";

struct QuicSession {
    // Holding the runtime, endpoint and connection keeps the QUIC driver and
    // every spawned pump alive for as long as the reader/writer pair exists.
    _runtime: tokio::runtime::Runtime,
    _endpoint: Endpoint,
    _connection: Connection,
}

pub struct QuicReader {
    _session: Arc<QuicSession>,
    incoming: Receiver<Option<Vec<u8>>>,
    buffer: Vec<u8>,
    offset: usize,
    eof: bool,
}

impl Read for QuicReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.offset >= self.buffer.len() {
            if self.eof {
                return Ok(0);
            }
            match self.incoming.recv() {
                Ok(Some(data)) => {
                    self.buffer = data;
                    self.offset = 0;
                }
                Ok(None) | Err(_) => {
                    self.eof = true;
                    return Ok(0);
                }
            }
        }
        let available = self.buffer.len() - self.offset;
        let take = available.min(out.len());
        out[..take].copy_from_slice(&self.buffer[self.offset..self.offset + take]);
        self.offset += take;
        if self.offset >= self.buffer.len() {
            self.buffer.clear();
            self.offset = 0;
        }
        Ok(take)
    }
}

pub struct QuicWriter {
    _session: Arc<QuicSession>,
    outgoing: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
}

impl Write for QuicWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.outgoing
            .send(data.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "quic stream closed"))?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    let mut addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("quic resolve {host}:{port}: {error}"))?;
    addresses
        .next()
        .ok_or_else(|| format!("quic resolve {host}:{port}: no address"))
}

/// Connect one QUIC bidirectional stream and return the framed-protocol
/// reader/writer.  The caller owns the `Options` token and pin exactly as for
/// TCP/TLS; this function does not authenticate the peer by itself.
pub fn connect(
    opts: &Options,
    host: &str,
    port: u16,
) -> Result<(Box<dyn Read + Send>, Box<dyn Write + Send>), String> {
    let address = resolve(host, port)?;
    let rustls_config =
        crate::transport::client_config_with_alpn(opts, vec![ALPN.to_vec()])?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|error| format!("quic crypto: {error}"))?;
    let mut client = ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    let idle = Duration::from_secs(60);
    transport.max_idle_timeout(Some(
        idle.try_into()
            .map_err(|_| "quic idle timeout out of range".to_string())?,
    ));
    client.transport_config(Arc::new(transport));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("quic runtime: {error}"))?;
    let handle = runtime.handle().clone();
    let sni = opts.sni.clone().unwrap_or_else(|| host.to_string());
    let timeout_ms = opts.connect_timeout_ms.max(1_500);
    let bind_address = if address.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let created = runtime.block_on(async {
        let bind: SocketAddr = bind_address
            .parse()
            .map_err(|_| format!("quic bind address {bind_address}"))?;
        let mut endpoint = Endpoint::client(bind)
            .map_err(|error| format!("udp-blocked: cannot bind UDP socket: {error}"))?;
        endpoint.set_default_client_config(client);
        let connecting = endpoint
            .connect(address, &sni)
            .map_err(|error| format!("udp-blocked: quic connect: {error}"))?;
        let connection = match tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            connecting,
        )
        .await
        {
            Err(_) => {
                return Err(format!(
                    "udp-blocked: QUIC handshake timed out after {timeout_ms}ms; \
                     UDP may be blocked"
                ))
            }
            Ok(Err(error)) => return Err(format!("quic handshake: {error}")),
            Ok(Ok(connection)) => connection,
        };
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| format!("quic open stream: {error}"))?;
        let (read_tx, read_rx) = mpsc::channel::<Option<Vec<u8>>>();
        handle.spawn(async move {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                match recv.read(&mut buffer).await {
                    Ok(Some(count)) if count > 0 => {
                        if read_tx.send(Some(buffer[..count].to_vec())).is_err() {
                            break;
                        }
                    }
                    Ok(Some(_)) | Ok(None) => break,
                    Err(_) => break,
                }
            }
            let _ = read_tx.send(None);
        });
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        handle.spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if send.write_all(&data).await.is_err() {
                    break;
                }
                let _ = send.flush().await;
            }
            let _ = send.finish();
        });
        Ok::<_, String>((endpoint, connection, read_rx, write_tx))
    })?;

    let (endpoint, connection, read_rx, write_tx) = created;
    let session = Arc::new(QuicSession {
        _runtime: runtime,
        _endpoint: endpoint,
        _connection: connection,
    });
    Ok((
        Box::new(QuicReader {
            _session: session.clone(),
            incoming: read_rx,
            buffer: Vec::new(),
            offset: 0,
            eof: false,
        }),
        Box::new(QuicWriter {
            _session: session,
            outgoing: write_tx,
        }),
    ))
}
