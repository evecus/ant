//! VLESS XHTTP (SplitHTTP) transport -- HTTP/1.1 stream-one.
//!
//! Bidirectional pipe: request body (chunked) = uplink, response body = downlink.
//! Works over plain TCP, normal TLS, and REALITY without hyper H2.
//!
//! Uplink framing is chunked (hex-len `\r\n` data `\r\n`); the downlink is
//! chunk-decoded when the server answers with `Transfer-Encoding: chunked`
//! (mandatory on persistent HTTP/1.1), and passed through verbatim otherwise
//! (HTTP/2-style raw streams).

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskCtx, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// XHTTP dial options (subset of sing-box / Xray / reflex fields).
#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub host: String,
    pub path: String,
    /// `auto` | `stream-one` | `packet-up` | `stream-up` (non-stream-one currently map to stream-one)
    pub mode: String,
    pub headers: HashMap<String, String>,
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            path: "/".into(),
            mode: "auto".into(),
            headers: HashMap::new(),
        }
    }
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

/// Open XHTTP stream-one over an already-connected transport (TCP / TLS / REALITY).
pub async fn connect_over_stream<S>(stream: S, cfg: &XhttpConfig) -> Result<XhttpPipe<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncWriteExt;
    let path = normalize_path(&cfg.path);
    let host = if cfg.host.is_empty() {
        "localhost"
    } else {
        cfg.host.as_str()
    };

    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\n\
Content-Type: application/octet-stream\r\nUser-Agent: Go-http-client/1.1\r\n\
Connection: keep-alive\r\n"
    );
    for (k, v) in &cfg.headers {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    let mut stream = stream;
    stream
        .write_all(req.as_bytes())
        .await
        .context("xhttp write request headers")?;

    tracing::debug!(path = %path, host = %host, mode = %cfg.mode, "xhttp stream-one started");
    Ok(XhttpPipe {
        inner: stream,
        write_closed: false,
        header_done: false,
        header_buf: BytesMut::new(),
        chunked: false,
        chunk_state: ChunkState::Size,
        raw_buf: BytesMut::new(),
        read_buf: BytesMut::new(),
        write_buf: BytesMut::new(),
    })
}

// ── chunked 下行解码状态机 ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// Reading the hex size line (possibly with `;ext` chunk extensions).
    Size,
    /// Reading `remaining` bytes of chunk data.
    Data { remaining: usize },
    /// The `\r\n` after a complete chunk.
    DataCrlf,
    /// After the terminating `0` chunk: skip trailer lines until empty line.
    Trailer,
    /// Terminal chunk consumed — response body is complete.
    Done,
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Bidirectional HTTP/1.1 chunked pipe (stream-one).
pub struct XhttpPipe<S> {
    inner: S,
    write_closed: bool,
    header_done: bool,
    header_buf: BytesMut,
    /// Server answered with `Transfer-Encoding: chunked` → decode the downlink.
    chunked: bool,
    chunk_state: ChunkState,
    /// Raw bytes read from `inner`, awaiting chunk framing removal.
    raw_buf: BytesMut,
    read_buf: BytesMut,
    write_buf: BytesMut,
}

impl<S: AsyncRead + Unpin> XhttpPipe<S> {
    /// Parse chunk sizes / strip framing from `raw_buf` into `read_buf`.
    fn feed_chunked(&mut self) -> io::Result<()> {
        loop {
            match self.chunk_state {
                ChunkState::Size => {
                    let Some(pos) = find_crlf(&self.raw_buf) else {
                        // Keep at most one line buffered to bound memory.
                        if self.raw_buf.len() > 8192 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "xhttp chunk size line too long",
                            ));
                        }
                        break;
                    };
                    let line = self.raw_buf.split_to(pos + 2);
                    let text = String::from_utf8_lossy(&line[..pos]);
                    let hex = text.split(';').next().unwrap_or("").trim();
                    let size = usize::from_str_radix(hex, 16).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("xhttp bad chunk size {hex:?}"),
                        )
                    })?;
                    if size == 0 {
                        self.chunk_state = ChunkState::Trailer;
                    } else {
                        self.chunk_state = ChunkState::Data { remaining: size };
                    }
                }
                ChunkState::Data { remaining } => {
                    if self.raw_buf.is_empty() {
                        break;
                    }
                    let n = remaining.min(self.raw_buf.len());
                    let data = self.raw_buf.split_to(n);
                    self.read_buf.extend_from_slice(&data);
                    if n == remaining {
                        self.chunk_state = ChunkState::DataCrlf;
                    } else {
                        self.chunk_state = ChunkState::Data {
                            remaining: remaining - n,
                        };
                    }
                }
                ChunkState::DataCrlf => {
                    if self.raw_buf.len() < 2 {
                        break;
                    }
                    let _ = self.raw_buf.split_to(2);
                    self.chunk_state = ChunkState::Size;
                }
                ChunkState::Trailer => {
                    // Trailer section: zero or more header lines, ended by an
                    // empty line. Tolerate servers that send nothing at all
                    // after the `0` chunk before closing.
                    if self.raw_buf.starts_with(b"\r\n") {
                        let _ = self.raw_buf.split_to(2);
                        self.chunk_state = ChunkState::Done;
                    } else if let Some(pos) = find_crlf(&self.raw_buf) {
                        let _ = self.raw_buf.split_to(pos + 2);
                    } else {
                        break;
                    }
                }
                ChunkState::Done => {
                    // Response body finished; anything further belongs to the
                    // next HTTP exchange, which stream-one never has.
                    break;
                }
            }
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for XhttpPipe<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.header_done {
                if let Some(pos) = this.header_buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = this.header_buf.split_to(pos + 4);
                    let status_line: &[u8] = headers
                        .as_ref()
                        .split(|&b| b == b'\n')
                        .next()
                        .unwrap_or_default();
                    let status_str = String::from_utf8_lossy(status_line);
                    // Exact check: "HTTP/1.x <code>" with 2xx.
                    let ok = status_str.starts_with("HTTP/")
                        && status_str
                            .split_whitespace()
                            .nth(1)
                            .and_then(|c| c.parse::<u16>().ok())
                            .is_some_and(|c| (200..300).contains(&c));
                    if !ok {
                        return Poll::Ready(Err(io::Error::other(format!(
                            "xhttp bad status: {}",
                            status_str.trim()
                        ))));
                    }
                    // Persistent HTTP/1.1 responses are chunked; detect and decode.
                    this.chunked = headers
                        .windows(7)
                        .any(|w| w.eq_ignore_ascii_case(b"chunked"));
                    if !this.header_buf.is_empty() {
                        this.raw_buf.extend_from_slice(&this.header_buf);
                        this.header_buf.clear();
                    }
                    this.header_done = true;
                    continue;
                }
                if this.header_buf.len() > 64 * 1024 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "xhttp headers too large",
                    )));
                }
                let mut tmp = [0u8; 1024];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "xhttp eof before headers",
                            )));
                        }
                        this.header_buf.extend_from_slice(rb.filled());
                    }
                }
                continue;
            }

            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                let data = this.read_buf.split_to(n);
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }

            if !this.chunked {
                // Non-chunked downlink (raw stream): pass through verbatim.
                // Body bytes that arrived together with the response header
                // sit in `raw_buf` — hand them out before touching `inner`.
                if !this.raw_buf.is_empty() {
                    let n = buf.remaining().min(this.raw_buf.len());
                    let data = this.raw_buf.split_to(n);
                    buf.put_slice(&data);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            // Try to make progress from buffered raw bytes first.
            this.feed_chunked()?;
            if !this.read_buf.is_empty() {
                continue;
            }
            if this.chunk_state == ChunkState::Done {
                // Terminating chunk seen; stream-one ends here.
                return Poll::Ready(Ok(()));
            }

            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        // EOF: tolerate servers that close without the final
                        // chunk once everything buffered has been drained.
                        return Poll::Ready(Ok(()));
                    }
                    this.raw_buf.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for XhttpPipe<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp write after close",
            )));
        }
        // Flush pending framed data first.
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "xhttp write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Frame as chunked: hex-len\r\ndata\r\n
        let mut chunk = Vec::with_capacity(buf.len() + 16);
        chunk.extend_from_slice(format!("{:x}\r\n", buf.len()).as_bytes());
        chunk.extend_from_slice(buf);
        chunk.extend_from_slice(b"\r\n");
        match Pin::new(&mut this.inner).poll_write(cx, &chunk) {
            Poll::Pending => {
                this.write_buf.extend_from_slice(&chunk);
                // Report full user buf accepted once framed data is queued.
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                if n < chunk.len() {
                    this.write_buf.extend_from_slice(&chunk[n..]);
                }
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "xhttp flush zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.write_closed {
            this.write_buf.extend_from_slice(b"0\r\n\r\n");
            this.write_closed = true;
        }
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "xhttp shutdown zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = this.write_buf.split_to(n);
                }
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[allow(dead_code)]
pub async fn resolve(host: &str, port: u16) -> Result<std::net::SocketAddr> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(std::net::SocketAddr::new(ip, port));
    }
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}"))?;
    addrs
        .next()
        .ok_or_else(|| anyhow!("no address for {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn pipe_with_raw(raw: &[u8], chunked: bool) -> XhttpPipe<tokio::io::DuplexStream> {
        let (client, server) = tokio::io::duplex(1024);
        let mut pipe = XhttpPipe {
            inner: server,
            write_closed: false,
            header_done: false,
            header_buf: BytesMut::new(),
            chunked: false,
            chunk_state: ChunkState::Size,
            raw_buf: BytesMut::new(),
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
        };
        // Pre-fill the response header as if already parsed.
        let head = if chunked {
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        } else {
            "HTTP/1.1 200 OK\r\n\r\n"
        };
        let mut all = head.as_bytes().to_vec();
        all.extend_from_slice(raw);
        pipe.header_buf.extend_from_slice(&all);
        pipe.header_done = false;
        // Mark inner side dead: we never read from it in these tests beyond EOF.
        drop(client);
        pipe
    }

    #[tokio::test]
    async fn chunked_decode_single_chunk() {
        let body = b"hello world";
        let mut raw = format!("{:x}\r\n", body.len()).into_bytes();
        raw.extend_from_slice(body);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut p = pipe_with_raw(&raw, true);
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"hello world");
    }

    #[tokio::test]
    async fn chunked_decode_multiple_chunks_and_trailer() {
        let mut raw = Vec::new();
        for part in [b"foo".as_slice(), b"barbaz".as_slice()] {
            raw.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
            raw.extend_from_slice(part);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"0\r\nX-Trail: er\r\n\r\n");
        let mut p = pipe_with_raw(&raw, true);
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"foobarbaz");
    }

    #[tokio::test]
    async fn non_chunked_passthrough() {
        let mut p = pipe_with_raw(b"raw-bytes", false);
        let mut out = Vec::new();
        p.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"raw-bytes");
    }

    #[tokio::test]
    async fn bad_status_is_error() {
        let (client, server) = tokio::io::duplex(64);
        let mut p = XhttpPipe {
            inner: server,
            write_closed: false,
            header_done: false,
            header_buf: BytesMut::new(),
            chunked: false,
            chunk_state: ChunkState::Size,
            raw_buf: BytesMut::new(),
            read_buf: BytesMut::new(),
            write_buf: BytesMut::new(),
        };
        drop(client);
        p.header_buf
            .extend_from_slice(b"HTTP/1.1 403 Forbidden\r\n\r\n");
        let mut out = [0u8; 8];
        let err = p.read(&mut out).await.unwrap_err();
        assert!(err.to_string().contains("403"));
    }
}
