//! WebSocket transport (tokio-tungstenite), shared by outbounds.
//!
//! * [`connect`] performs the HTTP/1.1 upgrade over an already established
//!   (and, if wanted, TLS-wrapped) byte stream.
//! * [`WsStream`] adapts the resulting `WebSocketStream` to
//!   `AsyncRead + AsyncWrite`:
//!   - every write becomes one binary frame;
//!   - an optional protocol header is merged into the first frame;
//!   - an optional response-header parser strips the server's header from the
//!     first incoming binary frame;
//!   - Ping/Pong are handled by tungstenite, Close → EOF.

use super::BoxedStream;
use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, http::HeaderName, http::HeaderValue, protocol::WebSocketConfig,
    Message,
};
use tokio_tungstenite::{client_async_with_config, WebSocketStream};

/// TLS + WS upgrade timeout (matches sing-box TCPTimeout).
pub(super) const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Parameters of the WebSocket upgrade request.
#[derive(Clone, Debug)]
pub(super) struct WsOptions {
    /// Host header value (without port unless the port is non-default).
    pub host: String,
    /// true when the user set ws-host explicitly (Host header is then sent verbatim).
    pub host_explicit: bool,
    pub port: u16,
    /// Whether `io` passed to [`connect`] is TLS-wrapped. Only used to decide
    /// the default port for the Host header.
    pub tls: bool,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

/// WebSocket upgrade over `io` (TCP, TLS or anything else already set up).
pub(super) async fn connect(io: BoxedStream, opts: &WsOptions) -> Result<WebSocketStream<BoxedStream>> {
    // Host header: a user supplied ws-host is sent verbatim; otherwise
    // host[:port] with the port omitted when it is the scheme default.
    let default_port = if opts.tls { 443 } else { 80 };
    let authority = if opts.host_explicit || opts.port == default_port {
        opts.host.clone()
    } else {
        format!("{}:{}", opts.host, opts.port)
    };
    // The URL only feeds tungstenite's request builder (Host / path);
    // TLS has already been handled by the caller.
    let url = format!("ws://{}{}", authority, opts.path);
    let mut request = url
        .clone()
        .into_client_request()
        .with_context(|| format!("invalid ws url {url}"))?;
    for (k, v) in &opts.headers {
        request.headers_mut().insert(
            HeaderName::from_bytes(k.as_bytes()).with_context(|| format!("bad ws header {k}"))?,
            HeaderValue::from_str(v).with_context(|| format!("bad ws header value for {k}"))?,
        );
    }
    if !request.headers().contains_key("user-agent") {
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::USER_AGENT,
            HeaderValue::from_static("Go-http-client/1.1"),
        );
    }

    // write_buffer_size = 0: every write is framed and pushed out immediately.
    let cfg = WebSocketConfig {
        write_buffer_size: 0,
        ..Default::default()
    };
    let (ws, _resp) = client_async_with_config(request, io, Some(cfg))
        .await
        .map_err(|e| anyhow!("ws upgrade: {e}"))?;
    Ok(ws)
}

/// Returns the length of the response header at the start of `buf`,
/// or `None` if it is incomplete / invalid.
pub(super) type ResponseHeaderLen = fn(&[u8]) -> Option<usize>;

/// Adapts a `WebSocketStream` to `AsyncRead + AsyncWrite`.
pub(super) struct WsStream<S> {
    inner: S,
    pending_header: Option<Bytes>,
    read_buf: Bytes,
    /// When set, the first binary frame must start with a response header whose
    /// length is determined by this function; that prefix is dropped.
    response_header_len: Option<ResponseHeaderLen>,
    response_header_skipped: bool,
}

impl<S> WsStream<S> {
    /// `header` is prepended to the first written payload (same frame).
    pub(super) fn with_header(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
            response_header_len: None,
            response_header_skipped: false,
        }
    }

    /// Strip the server's response header from the first binary frame.
    pub(super) fn skip_response_header(mut self, len_fn: ResponseHeaderLen) -> Self {
        self.response_header_len = Some(len_fn);
        self
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, e)
}

impl<S> AsyncRead for WsStream<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf = this.read_buf.slice(n..);
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(ws_err(e))),
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        let data = Bytes::from(data);
                        match this.response_header_len {
                            Some(len_fn) if !this.response_header_skipped => {
                                this.response_header_skipped = true;
                                match len_fn(&data) {
                                    Some(skip) => this.read_buf = data.slice(skip..),
                                    None => {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::InvalidData,
                                            "bad response header over ws",
                                        )))
                                    }
                                }
                            }
                            _ => this.read_buf = data,
                        }
                    }
                    // tungstenite answers Ping automatically.
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    _ => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if Pin::new(&mut this.inner)
            .poll_ready(cx)
            .map_err(ws_err)?
            .is_pending()
        {
            return Poll::Pending;
        }
        // Only consume the header once start_send succeeded.
        let (payload, header_consumed) = if let Some(h) = this.pending_header.as_ref() {
            let mut b = BytesMut::with_capacity(h.len() + data.len());
            b.put_slice(h);
            b.put_slice(data);
            (b.to_vec(), true)
        } else {
            (data.to_vec(), false)
        };
        match Pin::new(&mut this.inner).start_send(Message::Binary(payload)) {
            Ok(()) => {
                if header_consumed {
                    this.pending_header = None;
                }
                Poll::Ready(Ok(data.len()))
            }
            Err(e) => Poll::Ready(Err(ws_err(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(ws_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(ws_err)
    }
}
