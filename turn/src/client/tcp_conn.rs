use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use util::conn::Conn;

use stun::message::MESSAGE_HEADER_SIZE;

const CHANNEL_DATA_HEADER_SIZE: usize = 4;
const INITIAL_BUF_CAPACITY: usize = 65536;

/// Combined async I/O trait for use as a trait object.
trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}

/// A STUN/TURN-framed TCP connection implementing the [`Conn`] trait.
///
/// Handles message boundary detection for multiplexed STUN messages and
/// ChannelData on a single TCP stream (RFC 5766 Section 11.4/11.5).
/// Works with both plain TCP and TLS-over-TCP (TURNS).
pub struct TcpConn {
    reader: Mutex<ReadState>,
    writer: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    closed: AtomicBool,
}

struct ReadState {
    inner: Box<dyn AsyncRead + Send + Unpin>,
    buf: BytesMut,
}

impl TcpConn {
    /// Creates a new TcpConn from any async stream (TCP or TLS).
    fn new<S: AsyncStream + 'static>(
        stream: S,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Arc<Self> {
        let (reader, writer) = tokio::io::split(stream);
        Arc::new(Self {
            reader: Mutex::new(ReadState {
                inner: Box::new(reader),
                buf: BytesMut::with_capacity(INITIAL_BUF_CAPACITY),
            }),
            writer: Mutex::new(Box::new(writer)),
            local_addr,
            remote_addr,
            closed: AtomicBool::new(false),
        })
    }

    /// Connects to a TURN server over plain TCP.
    pub async fn connect(addr: SocketAddr) -> std::io::Result<Arc<Self>> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        let local_addr = stream.local_addr()?;
        Ok(Self::new(stream, local_addr, addr))
    }

    /// Connects to a TURN server over TLS (TURNS) using system CA roots.
    pub async fn connect_tls(addr: SocketAddr, domain: &str) -> std::io::Result<Arc<Self>> {
        let stream = tokio::net::TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        let local_addr = stream.local_addr()?;

        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
        let server_name = rustls_pki_types::ServerName::try_from(domain.to_owned())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
        let tls_stream = connector.connect(server_name, stream).await?;

        Ok(Self::new(tls_stream, local_addr, addr))
    }
}

/// Determines the total wire length of the next STUN or ChannelData message
/// from the first 4+ bytes of the buffer.
///
/// STUN messages: first two bits are `00`, magic cookie at bytes 4-7.
///   Total = 20 (header) + body_length (bytes 2-3).
///
/// ChannelData: channel number 0x4000-0x7FFF (first byte >= 0x40).
///   Total = 4 (header) + data_length (bytes 2-3), padded to 4-byte boundary.
fn message_length(header: &[u8]) -> usize {
    debug_assert!(header.len() >= 4);
    let data_len = u16::from_be_bytes([header[2], header[3]]) as usize;

    if header[0] < 0x40 {
        // STUN message
        MESSAGE_HEADER_SIZE + data_len
    } else {
        // ChannelData — pad to 4-byte boundary (RFC 5766 Section 11.5)
        let unpadded = CHANNEL_DATA_HEADER_SIZE + data_len;
        (unpadded + 3) & !3
    }
}

#[async_trait]
impl Conn for TcpConn {
    async fn connect(&self, _addr: SocketAddr) -> util::Result<()> {
        // Already connected
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        let (n, _) = self.recv_from(buf).await?;
        Ok(n)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        if self.closed.load(Ordering::Acquire) {
            return Err(std::io::Error::from(ErrorKind::NotConnected).into());
        }

        let state = &mut *self.reader.lock().await;
        let ReadState {
            inner,
            buf: ref mut read_buf,
        } = state;

        // Read until we have at least 4 bytes (minimum header)
        while read_buf.len() < 4 {
            let n = inner.read_buf(read_buf).await?;
            if n == 0 {
                return Err(std::io::Error::from(ErrorKind::UnexpectedEof).into());
            }
        }

        let expected = message_length(read_buf);

        // Read until we have the full message
        while read_buf.len() < expected {
            let n = inner.read_buf(read_buf).await?;
            if n == 0 {
                return Err(std::io::Error::from(ErrorKind::UnexpectedEof).into());
            }
        }

        // Copy to caller's buffer, consume full message to keep framing aligned
        let copy_len = expected.min(buf.len());
        buf[..copy_len].copy_from_slice(&read_buf[..copy_len]);
        let _ = read_buf.split_to(expected);

        Ok((copy_len, self.remote_addr))
    }

    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        self.send_to(buf, self.remote_addr).await
    }

    async fn send_to(&self, buf: &[u8], _target: SocketAddr) -> util::Result<usize> {
        if self.closed.load(Ordering::Acquire) {
            return Err(std::io::Error::from(ErrorKind::NotConnected).into());
        }

        let mut writer = self.writer.lock().await;
        writer.write_all(buf).await?;
        writer.flush().await?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> util::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    async fn close(&self) -> util::Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(()); // already closed
        }

        let mut writer = self.writer.lock().await;
        let _ = writer.shutdown().await;
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stun::message::MAGIC_COOKIE;

    // --- message_length unit tests ---

    /// Build a minimal STUN header: type (2B) + body_length (2B) + magic cookie (4B) + txn_id (12B)
    fn make_stun_header(body_len: u16) -> Vec<u8> {
        let mut h = vec![0u8; MESSAGE_HEADER_SIZE];
        // Type = 0x0001 (Binding Request) — first byte < 0x40 → classified as STUN
        h[0] = 0x00;
        h[1] = 0x01;
        h[2..4].copy_from_slice(&body_len.to_be_bytes());
        h[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        h
    }

    /// Build a ChannelData header: channel_number (2B) + data_length (2B)
    fn make_channel_data_header(channel: u16, data_len: u16) -> Vec<u8> {
        let mut h = vec![0u8; CHANNEL_DATA_HEADER_SIZE];
        h[0..2].copy_from_slice(&channel.to_be_bytes());
        h[2..4].copy_from_slice(&data_len.to_be_bytes());
        h
    }

    #[test]
    fn test_message_length_stun_no_body() {
        let h = make_stun_header(0);
        assert_eq!(message_length(&h), MESSAGE_HEADER_SIZE); // 20
    }

    #[test]
    fn test_message_length_stun_with_body() {
        let h = make_stun_header(48);
        assert_eq!(message_length(&h), MESSAGE_HEADER_SIZE + 48); // 68
    }

    #[test]
    fn test_message_length_channel_data_aligned() {
        // data_len = 100 → 4 + 100 = 104 → already 4-byte aligned
        let h = make_channel_data_header(0x4001, 100);
        assert_eq!(message_length(&h), 104);
    }

    #[test]
    fn test_message_length_channel_data_needs_padding() {
        // data_len = 5 → 4 + 5 = 9 → padded to 12
        let h = make_channel_data_header(0x4001, 5);
        assert_eq!(message_length(&h), 12);
    }

    #[test]
    fn test_message_length_channel_data_one_byte() {
        // data_len = 1 → 4 + 1 = 5 → padded to 8
        let h = make_channel_data_header(0x4001, 1);
        assert_eq!(message_length(&h), 8);
    }

    // --- TcpConn framing tests using tokio::io::duplex ---

    /// Build a complete STUN message (header + body of zeros)
    fn make_stun_message(body_len: u16) -> Vec<u8> {
        let mut msg = make_stun_header(body_len);
        msg.resize(MESSAGE_HEADER_SIZE + body_len as usize, 0xAA);
        msg
    }

    /// Build a complete ChannelData message (header + data), padded to 4 bytes
    fn make_channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
        let mut msg = make_channel_data_header(channel, data.len() as u16);
        msg.extend_from_slice(data);
        // Pad to 4-byte boundary
        while msg.len() % 4 != 0 {
            msg.push(0x00);
        }
        msg
    }

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:3478".parse().unwrap()
    }

    #[tokio::test]
    async fn test_recv_single_stun_message() {
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        let msg = make_stun_message(8);
        let msg_len = msg.len();

        // Write message from "server" side
        server_stream.write_all(&msg).await.unwrap();

        // Read from TcpConn
        let mut buf = vec![0u8; 1500];
        let (n, addr) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, msg_len);
        assert_eq!(&buf[..n], &msg);
        assert_eq!(addr, dummy_addr());
    }

    #[tokio::test]
    async fn test_recv_single_channel_data() {
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        let data = b"hello";
        let msg = make_channel_data(0x4001, data);
        let msg_len = msg.len(); // 4 + 5 = 9 → padded to 12

        server_stream.write_all(&msg).await.unwrap();

        let mut buf = vec![0u8; 1500];
        let (n, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, msg_len);
        assert_eq!(n, 12); // padded
    }

    #[tokio::test]
    async fn test_recv_multiple_messages_concatenated() {
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        let msg1 = make_stun_message(4); // 24 bytes
        let msg2 = make_channel_data(0x4001, b"test data!"); // 4 + 10 = 14 → padded to 16
        let msg3 = make_stun_message(0); // 20 bytes

        // Write all three messages in one TCP write (simulates buffered send)
        let mut combined = Vec::new();
        combined.extend_from_slice(&msg1);
        combined.extend_from_slice(&msg2);
        combined.extend_from_slice(&msg3);
        server_stream.write_all(&combined).await.unwrap();

        let mut buf = vec![0u8; 1500];

        // Should get msg1 first
        let (n1, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(n1, msg1.len());
        assert_eq!(&buf[..n1], &msg1);

        // Then msg2
        let (n2, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(n2, msg2.len());
        assert_eq!(&buf[..n2], &msg2);

        // Then msg3
        let (n3, _) = conn.recv_from(&mut buf).await.unwrap();
        assert_eq!(n3, msg3.len());
        assert_eq!(&buf[..n3], &msg3);
    }

    #[tokio::test]
    async fn test_recv_fragmented_stun_message() {
        // Simulate a STUN message arriving in small TCP fragments
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        let msg = make_stun_message(12); // 32 bytes total

        // Write in tiny chunks to simulate TCP fragmentation
        let conn_clone = Arc::clone(&conn);
        let recv_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            conn_clone.recv_from(&mut buf).await.map(|(n, _)| {
                buf.truncate(n);
                buf
            })
        });

        // Send 2 bytes at a time
        for chunk in msg.chunks(2) {
            server_stream.write_all(chunk).await.unwrap();
            server_stream.flush().await.unwrap();
            tokio::task::yield_now().await;
        }

        let result = recv_handle.await.unwrap().unwrap();
        assert_eq!(result, msg);
    }

    #[tokio::test]
    async fn test_send_to() {
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        let msg = make_stun_message(4);
        let n = conn.send_to(&msg, dummy_addr()).await.unwrap();
        assert_eq!(n, msg.len());

        // Read from "server" side and verify
        let mut buf = vec![0u8; 1500];
        let n = server_stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &msg);
    }

    #[tokio::test]
    async fn test_close_prevents_send() {
        let (client_stream, _server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        conn.close().await.unwrap();

        let result = conn.send_to(b"hello", dummy_addr()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_prevents_recv() {
        let (client_stream, _server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        conn.close().await.unwrap();

        let mut buf = vec![0u8; 1500];
        let result = conn.recv_from(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_eof_on_closed_stream() {
        let (client_stream, server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, dummy_addr(), dummy_addr());

        // Drop server side → client reads will get EOF
        drop(server_stream);

        let mut buf = vec![0u8; 1500];
        let result = conn.recv_from(&mut buf).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_local_and_remote_addr() {
        let local: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let remote: SocketAddr = "10.0.0.2:3478".parse().unwrap();

        let (client_stream, _server_stream) = tokio::io::duplex(8192);
        let conn = TcpConn::new(client_stream, local, remote);

        assert_eq!(conn.local_addr().unwrap(), local);
        assert_eq!(conn.remote_addr(), Some(remote));
    }
}
