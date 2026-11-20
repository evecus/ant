//! VLESS/Trojan XHTTP over HTTP/3 (QUIC) — stream-one client.
//!
//! 对齐 Xray `transport/internet/splithttp/dialer.go` 的 H3 分支：
//! `alpn` 含 `h3` 时，stream-one 的单个 POST 跑在 HTTP/3 上：
//!   - 请求头：一条双向流的 HEADERS 帧（QPACK，零动态表引用）
//!   - 上行：应用数据直接写 DATA 帧（HTTP/3 无 chunked 语义，
//!     服务端 HTTP 层拿到的就是原始 body，与 h1/h2 的解码结果一致）
//!   - 下行：响应 HEADERS（校验 :status 2xx）后的 DATA 帧流
//!   - 写关闭：FIN（quinn finish），等价于 h1 的终止块
//!
//! 复用 hy2_h3 的手写 H3 原语（不引入 h3/h3-quinn crate，与项目
//! "minimal H3 client" 的取舍一致）。服务端侧已由 flux 的
//! `xhttp_h3`（h3 crate）实现，两端帧语义对齐。

use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, BytesMut};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCtx, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::hy2_h3::{
    open_h3_control_streams, parse_headers_from_qpack, put_literal_header, read_h3_frame,
    write_varint, H3_FRAME_DATA, H3_FRAME_HEADERS,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 下行 DATA 泵的 channel 容量（背压上限，单位：帧）。
const DOWNLINK_BUFFER: usize = 64;

/// 下行帧：DATA 载荷或致命错误（如 :status 非 2xx）。
type DownItem = io::Result<Vec<u8>>;

/// 建立 HTTP/3 连接并发起 XHTTP stream-one POST，返回可读写的双向管道。
///
/// `tls` 为已配置 ALPN=`h3` 的 rustls 客户端配置（由调用方构建，与节点的
/// skip-cert-verify / 根证书设置一致）；`sni` 作为 QUIC SNI；`host` 为
/// `:authority`（与 h1 的 Host 语义一致）。
pub async fn connect(
    server: &str,
    port: u16,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
    host: &str,
    path: &str,
    extra_headers: &HashMap<String, String>,
) -> Result<XhttpH3Pipe> {
    let addr = super::xhttp::resolve(server, port)
        .await
        .with_context(|| format!("xhttp-h3 resolve {server}:{port}"))?;

    let quinn_client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .context("xhttp-h3 build quic client config (requires TLS 1.3)")?,
    ));

    // 复用 sockopt 的 UDP 绑定（Android protect / 接口绑定随主程序生效）。
    let udp = crate::app::sockopt::bind_udp("0.0.0.0:0".parse()?).await?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        udp.into_std()?,
        Arc::new(quinn::TokioRuntime),
    )?;

    let connecting = endpoint
        .connect_with(quinn_client, addr, sni)
        .context("xhttp-h3 quic connect")?;
    let conn = tokio::time::timeout(HANDSHAKE_TIMEOUT, connecting)
        .await
        .map_err(|_| anyhow!("xhttp-h3 quic handshake timeout (10s)"))?
        .context("xhttp-h3 quic handshake")?;

    // 服务端打开的 H3 control / SETTINGS uni 流必须被读取，否则其
    // 发送缓冲填满后会停止处理请求（与 hy2 相同的处理方式）。
    {
        let conn_bg = conn.clone();
        tokio::spawn(async move {
            for _ in 0..8 {
                match tokio::time::timeout(Duration::from_secs(5), conn_bg.accept_uni()).await {
                    Ok(Ok(mut stream)) => {
                        let c = conn_bg.clone();
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 4096];
                            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                            c.closed().await;
                            drop(stream);
                        });
                    }
                    Ok(Err(_)) | Err(_) => break,
                }
            }
        });
    }

    // 客户端侧的 control(SETTINGS) / QPACK encoder / decoder uni 流
    // （RFC 9114 §6.2 + RFC 9204 §4.2；h3 服务端强制要求）。
    open_h3_control_streams(&conn)
        .context("xhttp-h3 open h3 control streams")?;

    // 请求双向流 + HEADERS（QPACK：Required Insert Count = 0, Delta Base = 0）。
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("xhttp-h3 open request stream")?;

    let mut hb = BytesMut::new();
    hb.put_u8(0x00); // required insert count = 0
    hb.put_u8(0x00); // delta base = 0（无 base 条目）
    put_literal_header(&mut hb, b":method", b"POST");
    put_literal_header(&mut hb, b":scheme", b"https");
    put_literal_header(&mut hb, b":authority", host.as_bytes());
    put_literal_header(&mut hb, b":path", path.as_bytes());
    put_literal_header(&mut hb, b"content-type", b"application/octet-stream");
    put_literal_header(&mut hb, b"user-agent", b"Go-http-client/1.1");
    for (k, v) in extra_headers {
        // 与 h1 路径一致：连接管理头由 HTTP 层语义决定，不允许覆盖。
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        put_literal_header(&mut hb, k.as_bytes(), v.as_bytes());
    }
    write_frame(&mut send, H3_FRAME_HEADERS, &hb).await?;

    // 下行泵：读响应 HEADERS（校验 :status）与 DATA 帧，经 channel 交给
    // poll_read。连接关闭 / 出错时 drop tx 触发 EOF。
    let (tx, rx) = mpsc::channel::<DownItem>(DOWNLINK_BUFFER);
    tokio::spawn(async move {
        let mut header_seen = false;
        loop {
            match read_h3_frame(&mut recv).await {
                Ok((H3_FRAME_HEADERS, payload)) => {
                    if header_seen {
                        continue; // trailer section — 忽略
                    }
                    header_seen = true;
                    if let Err(e) = check_status(&payload) {
                        let _ = tx.send(Err(e)).await;
                        break;
                    }
                }
                Ok((H3_FRAME_DATA, payload)) => {
                    if payload.is_empty() {
                        continue;
                    }
                    if tx.send(Ok(payload)).await.is_err() {
                        break; // 读端已关闭（连接被上层终止）
                    }
                }
                Ok(_) => {} // 其他帧类型：忽略（SETTINGS 等）
                Err(e) => {
                    if !header_seen {
                        let _ = tx
                            .send(Err(io::Error::other(format!("xhttp-h3 response: {e}"))))
                            .await;
                    }
                    break;
                }
            }
        }
    });

    tracing::debug!(server = %addr, sni = %sni, host = %host, path = %path, "xhttp-h3 stream-one started");
    Ok(XhttpH3Pipe {
        send,
        rx,
        pending: None,
        pending_off: 0,
        write_buf: BytesMut::new(),
    })
}

/// 异步写一个 H3 帧（帧头 varint 对 + 载荷）。
async fn write_frame(send: &mut quinn::SendStream, ty: u64, payload: &[u8]) -> Result<()> {
    let mut head = BytesMut::new();
    write_varint(&mut head, ty);
    write_varint(&mut head, payload.len() as u64);
    send.write_all(&head)
        .await
        .context("xhttp-h3 write frame head")?;
    if !payload.is_empty() {
        send.write_all(payload)
            .await
            .context("xhttp-h3 write frame payload")?;
    }
    Ok(())
}

/// 从 QPACK 响应头块提取 `:status` 并要求 2xx。
fn check_status(payload: &[u8]) -> io::Result<()> {
    let headers = parse_headers_from_qpack(payload).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("xhttp-h3 {e}"))
    })?;
    let status = headers
        .iter()
        .find(|(n, _)| n == ":status")
        .map(|(_, v)| v.clone());
    let Some(status) = status else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xhttp-h3 response missing :status",
        ));
    };
    let code: u16 = status.parse().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, format!("xhttp-h3 bad status {status:?}"))
    })?;
    if !(200..300).contains(&code) {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            format!("xhttp-h3 bad status: {code}"),
        ));
    }
    Ok(())
}

/// XHTTP over H3 的双向管道。
///
/// 写侧直接在请求双向流上发 DATA 帧（部分写经 `write_buf` 缓冲）；
/// 读侧消费下行泵 channel（帧载荷，无分帧残留）。
pub struct XhttpH3Pipe {
    send: quinn::SendStream,
    rx: mpsc::Receiver<DownItem>,
    /// 泵交付但尚未被应用层取走的载荷（单帧最大 1MiB，逐字节读也无妨）。
    pending: Option<Vec<u8>>,
    pending_off: usize,
    /// 已组帧但未完全写入的 DATA 帧（部分写时暂存）。
    write_buf: BytesMut,
}

impl XhttpH3Pipe {
    /// 把 `write_buf` 里暂存的帧尽量写出去；Pending 时返回 false。
    fn drain_write_buf(
        &mut self,
        cx: &mut TaskCtx<'_>,
    ) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.send).poll_write(cx, &self.write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "xhttp-h3 write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = self.write_buf.split_to(n);
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for XhttpH3Pipe {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            // 先交付缓冲中的数据。
            if let Some(data) = &this.pending {
                let n = buf.remaining().min(data.len() - this.pending_off);
                if n > 0 {
                    buf.put_slice(&data[this.pending_off..this.pending_off + n]);
                    this.pending_off += n;
                    if this.pending_off == data.len() {
                        this.pending = None;
                        this.pending_off = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                // buf.remaining() == 0：不该出现在正常的 poll_read 契约里，
                // 直接当作无数据返回，避免死循环。
                this.pending = None;
                this.pending_off = 0;
            }
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    if data.is_empty() {
                        continue;
                    }
                    this.pending = Some(data);
                    this.pending_off = 0;
                    continue;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                // 泵任务结束：响应 body 完成（含服务端未发终止块就关闭的情形）。
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for XhttpH3Pipe {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // 先排掉上次部分写残留的帧数据。
        ready!(this.drain_write_buf(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // DATA 帧：type varint(0x0) + len varint + payload。
        let mut frame = BytesMut::with_capacity(buf.len() + 8);
        write_varint(&mut frame, H3_FRAME_DATA);
        write_varint(&mut frame, buf.len() as u64);
        frame.put_slice(buf);
        match Pin::new(&mut this.send).poll_write(cx, &frame) {
            Poll::Pending => {
                // 整帧入队（quinn poll_write 语义：Pending 表示本轮无法写入）。
                this.write_buf = frame;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                if n < frame.len() {
                    this.write_buf = frame.split_off(n);
                }
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain_write_buf(cx))?;
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        // 请求 body 完成 = 流 FIN（quinn finish），等价于 h1 终止块。
        ready!(self.drain_write_buf(cx))?;
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

/// 帧载荷上限（与 hy2_h3::read_h3_frame 的 1MiB 守卫一致）。
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// 静态断言：下行泵容量不会让单连接内存失控。
const _: () = assert!(DOWNLINK_BUFFER * MAX_FRAME_SIZE / 1024 / 1024 <= 64);
