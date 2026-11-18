//! NaiveProxy outbound (client only — ant has no naive inbound).
//!
//! NaiveProxy = "用 Chrome 的网络栈做代理"：一条 TLS(HTTP/2) 连接上用
//! `CONNECT` 方法建立隧道，并在前若干个数据帧上加 padding，使流量特征贴近
//! 普通 HTTPS 浏览。本实现与 sing-box `protocol/naive` / reflex
//! `outbound/naive.rs` 对齐。
//!
//! ## 报文结构
//!
//! ### 请求
//! `CONNECT host:port HTTP/2` + `Proxy-Authorization: Basic base64(user:pass)`
//! + `Padding: <30..61 字节随机头>`；服务端返回 200 即隧道建立。
//!
//! ### padding 分帧（前 8 次读写，与 sing-box `paddingConn` 一致）
//! * 写：`[data_size u16 BE][padding_size u8][data][padding zeros]`
//!   单次最多 65535 字节数据
//! * 读：解析 3 字节头，取 data_size 字节数据，跳过 padding_size 字节填充
//! * 8 帧之后转为原始读写
//!
//! ### UDP
//! sing UoT v2（connectionless）：向 magic 地址
//! `sp.v2.udp-over-tcp.arpa:443` 发起 CONNECT，随后写 UoT 头 + 每包自带地址。
//! 复用 `anytls` 的 UoT 编解码，语义完全一致。
//!
//! ## 防回环（重点）
//!
//! 底层 TCP socket 一律通过 `app::sockopt::connect_tcp` 创建，因此会应用
//! `SO_MARK`（Linux/Android）、`SO_BINDTODEVICE` / `IP_BOUND_IF`（macOS）、
//! `IP_UNICAST_IF`（Windows），与直连和其他协议出站完全一致。
//! TLS / HTTP/2 只是在这条已打标的 socket 之上做封装，不会另建连接，所以
//! TCP 与 UDP（UoT 复用同一条隧道）都天然带 mark。

use super::anytls::{
    build_tls_config, build_uot_packet, build_uot_request, resolve_server, uot_magic_target,
    uot_read_loop, Target,
};
use super::utls::{connect_utls, TlsStreamBox, UtlsFingerprint, UtlsVerify};
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{Method, Request, StatusCode, Uri};
use rand::Rng;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tracing::debug;

// ── 协议常量 ─────────────────────────────────────────────────────────────────

/// padding 帧数（与 sing-box naive inbound `paddingCount` 一致）
const PADDING_COUNT: u32 = 8;

/// 单个 padding 帧最大数据尺寸（与 sing-box `writeChunked` 一致，u16 上限）
const MAX_PADDING_CHUNK: usize = 65535;

/// padding 头字符集（与 sing-box `generatePaddingHeader` 一致）
const PADDING_HEADER_CHARSET: &[u8] = b"!#$()+<>?@[]^`{}";

/// HTTP/2 ALPN。naive 服务端只认 h2（QUIC/h3 模式 ant 不支持）。
const ALPN_H2: &str = "h2";

// ── 出站 ─────────────────────────────────────────────────────────────────────

struct NaiveOption {
    server: String,
    port: u16,
    username: String,
    password: String,
    sni: String,
    alpn: Vec<String>,
    utls: Option<UtlsFingerprint>,
    /// uTLS 自实现握手的证书校验选项（skip-cert-verify / 证书 pin）。
    verify: UtlsVerify,
}

/// 可共享的出站内核：UDP 会话需要 `'static`，所以配置与 TLS 配置放进 Arc。
struct NaiveInner {
    opts: NaiveOption,
    tls_config: Arc<ClientConfig>,
}

pub struct NaiveOutbound {
    inner: Arc<NaiveInner>,
}

impl NaiveOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        // naive 必须走 TLS，配置里 `tls: false` 属于无效配置 —— fail-fast。
        if !cfg.tls {
            return Err(anyhow!("naive node `{}`: tls must be true", cfg.name));
        }
        let username = cfg
            .username
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("naive node `{}`: `username` is required", cfg.name))?;
        let password = cfg
            .password
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("naive node `{}`: `password` is required", cfg.name))?;

        // ALPN 强制 h2：naive 服务端只接受 HTTP/2 CONNECT。
        let alpn = vec![ALPN_H2.to_string()];
        let tls_config = Arc::new(build_tls_config(
            cfg.skip_cert_verify,
            &cfg.fingerprint,
            &alpn,
        )?);

        let utls = cfg
            .client_fingerprint
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                UtlsFingerprint::parse(s).with_context(|| {
                    format!("naive `{}`: unknown client-fingerprint {s:?}", cfg.name)
                })
            })
            .transpose()?;

        Ok(Self {
            inner: Arc::new(NaiveInner {
                opts: NaiveOption {
                    server: cfg.server.clone(),
                    port: cfg.port,
                    username,
                    password,
                    sni: cfg.effective_sni(),
                    alpn,
                    utls,
                    verify: UtlsVerify {
                        skip_cert_verify: cfg.skip_cert_verify,
                        fingerprint: cfg.fingerprint.clone(),
                    },
                },
                tls_config,
            }),
        })
    }
}

impl NaiveInner {
    /// 建立到 `target` 的 naive 隧道（TCP 打标 → TLS → h2 → CONNECT）。
    async fn dial(&self, target: &Target) -> Result<NaiveStream> {
        // 1. TCP 连接：sockopt::connect_tcp 统一应用 SO_MARK / 出接口绑定。
        let addr = resolve_server(&self.opts.server, self.opts.port).await?;
        let tcp = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("naive tcp connect {addr}"))?;
        let _ = tcp.set_nodelay(true);

        // 2. TLS 握手（ALPN = h2）
        let tls: TlsStreamBox = match self.opts.utls {
            Some(ref fp) => TlsStreamBox::Utls(Box::new(
                connect_utls(
                    tcp,
                    &self.opts.sni,
                    fp,
                    &self.opts.verify,
                    &self.opts.alpn,
                )
                .await
                .context("naive utls handshake")?,
            )),
            None => {
                let name = ServerName::try_from(self.opts.sni.clone())
                    .map_err(|_| anyhow!("naive: invalid sni {}", self.opts.sni))?;
                TlsStreamBox::Plain(
                    tokio_rustls::TlsConnector::from(self.tls_config.clone())
                        .connect(name, tcp)
                        .await
                        .context("naive tls handshake")?,
                )
            }
        };

        // 3. h2 握手 + 后台驱动连接
        let (send_req, connection) = h2::client::handshake(tls)
            .await
            .map_err(|e| anyhow!("naive: h2 handshake failed: {e}"))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("naive: h2 connection ended: {e}");
            }
        });

        // 4. CONNECT 请求
        let authority = match target {
            Target::Domain(host, port) => format!("{host}:{port}"),
            Target::Socket(addr) => addr.to_string(),
        };
        let uri = Uri::builder()
            .scheme("https")
            .authority(authority.as_str())
            .build()
            .map_err(|e| anyhow!("naive: invalid authority '{authority}': {e}"))?;

        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.opts.username, self.opts.password));
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("Proxy-Authorization", format!("Basic {auth}"))
            .header("Padding", generate_padding_header())
            .body(())
            .map_err(|e| anyhow!("naive: build CONNECT request failed: {e}"))?;

        let mut h2_ready = send_req
            .ready()
            .await
            .map_err(|e| anyhow!("naive: h2 ready failed: {e}"))?;
        let (response, send_stream) = h2_ready
            .send_request(request, false)
            .map_err(|e| anyhow!("naive: send CONNECT failed: {e}"))?;

        // 5. 等待 200
        let response = response
            .await
            .map_err(|e| anyhow!("naive: CONNECT response failed: {e}"))?;
        if response.status() != StatusCode::OK {
            return Err(anyhow!(
                "naive: CONNECT failed with status {}",
                response.status()
            ));
        }

        debug!(target = %authority, "naive: CONNECT tunnel established");

        Ok(NaiveStream::new(send_stream, response.into_body()))
    }
}

#[async_trait]
impl OutboundDialer for NaiveOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let target = match host_hint {
            Some(h) => Target::Domain(
                h.to_string(),
                if addr.port() != 0 { addr.port() } else { 443 },
            ),
            None => Target::Socket(addr),
        };
        let stream = self.inner.dial(&target).await?;
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let (tx, rx) = mpsc::channel(64);
        Ok(Box::new(NaiveUdpSession {
            inner: self.inner.clone(),
            io: TokioMutex::new(None),
            tx,
            rx: TokioMutex::new(rx),
        }))
    }
}

// ── padding header 生成 ──────────────────────────────────────────────────────

/// 生成 Padding HTTP 头（与 sing-box `generatePaddingHeader` 完全一致）。
///
/// 长度 30~61，前 16 字符取自 `PADDING_HEADER_CHARSET`，其余为 `~`。
fn generate_padding_header() -> String {
    let mut rng = rand::thread_rng();
    let padding_len = rng.gen_range(30..=61); // rand.Intn(32) + 30
    let mut padding = vec![0u8; padding_len];

    let mut bits = rng.gen::<u64>();
    for b in padding.iter_mut().take(16.min(padding_len)) {
        *b = PADDING_HEADER_CHARSET[(bits & 15) as usize];
        bits >>= 4;
    }
    padding[16..padding_len].fill(b'~');

    // 全部字符在 ASCII 范围内，from_utf8 不会失败
    String::from_utf8(padding).expect("padding header is ASCII")
}

// ── NaiveStream：h2 SendStream + RecvStream，带 padding 分帧 ────────────────
//
// 与 sing-box naive inbound 的 paddingConn 对齐：
// - 前 8 个写操作：每帧 [data_size u16 BE][padding_size u8][data][padding zeros]
//   数据按 65535 上限分块（writeChunked）
// - 前 8 个读操作：解析 3 字节头，读取 data_size 字节数据，跳过 padding_size 字节
// - 之后：原始读写

pub struct NaiveStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,

    // 读侧 padding 状态
    read_buf: BytesMut,
    /// 剩余 padding 帧数（初始 = 8）
    read_padding_left: u32,
    /// 当前帧剩余数据字节数
    read_data_left: usize,
    /// 当前帧剩余填充字节数
    read_pad_left: usize,

    // 写侧 padding 状态
    /// 剩余 padding 帧数（初始 = 8）
    write_padding_left: u32,
}

impl NaiveStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            read_padding_left: PADDING_COUNT,
            read_data_left: 0,
            read_pad_left: 0,
            write_padding_left: PADDING_COUNT,
        }
    }

    /// 从 h2 RecvStream 拉取一个数据块到 read_buf。
    /// 返回 Poll<Ok(())>：表示有新数据到达或遇到 EOF（read_buf 可能为空）。
    fn poll_recv_data(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                let len = bytes.len();
                self.read_buf.extend_from_slice(&bytes);
                // 释放流量控制窗口，否则对端窗口耗尽后阻塞
                let _ = self.recv.flow_control().release_capacity(len);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for NaiveStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{ready, Poll};
        let this = &mut *self;

        loop {
            // 1. 当前数据帧还有数据未读
            if this.read_data_left > 0 {
                if this.read_buf.is_empty() {
                    ready!(this.poll_recv_data(cx))?;
                    if this.read_buf.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                }
                let n = buf
                    .remaining()
                    .min(this.read_data_left)
                    .min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                this.read_data_left -= n;
                return Poll::Ready(Ok(()));
            }

            // 2. 跳过当前帧的 padding
            while this.read_pad_left > 0 {
                if this.read_buf.is_empty() {
                    ready!(this.poll_recv_data(cx))?;
                    if this.read_buf.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                }
                let n = this.read_pad_left.min(this.read_buf.len());
                this.read_buf.advance(n);
                this.read_pad_left -= n;
            }

            // 3. 还在 padding 阶段 → 读取下一帧的 3 字节头
            if this.read_padding_left > 0 {
                while this.read_buf.len() < 3 {
                    ready!(this.poll_recv_data(cx))?;
                    if this.read_buf.is_empty() {
                        // header 未读完就 EOF
                        return Poll::Ready(Ok(()));
                    }
                }
                let data_size = u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]) as usize;
                let padding_size = this.read_buf[2] as usize;
                this.read_buf.advance(3);
                this.read_data_left = data_size;
                this.read_pad_left = padding_size;
                this.read_padding_left -= 1;
                // continue → 回到步骤 1 返回数据
                continue;
            }

            // 4. 原始模式（padding 帧已全部消费完）
            if this.read_buf.is_empty() {
                ready!(this.poll_recv_data(cx))?;
                if this.read_buf.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }
            }
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for NaiveStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = &mut *self;

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // padding 阶段：分块为 ≤65535 的帧；非 padding 阶段：直接发
        let (chunk_size, frame) = if this.write_padding_left > 0 {
            let cs = data.len().min(MAX_PADDING_CHUNK);
            let padding_size: u8 = rand::thread_rng().gen();
            let mut f = BytesMut::with_capacity(3 + cs + padding_size as usize);
            f.extend_from_slice(&(cs as u16).to_be_bytes());
            f.put_u8(padding_size);
            f.extend_from_slice(&data[..cs]);
            f.put_bytes(0, padding_size as usize);
            (cs, f.freeze())
        } else {
            (data.len(), Bytes::copy_from_slice(data))
        };

        // 等待流控容量
        this.send.reserve_capacity(frame.len());
        if this.send.capacity() < frame.len() {
            // poll_capacity 返回 Poll<Option<Result<usize, Error>>>
            // None 表示流已关闭
            match this.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "naive: h2 stream closed",
                    )))
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(std::io::Error::other(e))),
                Poll::Ready(Some(Ok(_))) => {}
            }
        }

        match this.send.send_data(frame, false) {
            Ok(()) => {
                if this.write_padding_left > 0 {
                    this.write_padding_left -= 1;
                }
                Poll::Ready(Ok(chunk_size))
            }
            Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        let _ = this.send.send_data(Bytes::new(), true);
        std::task::Poll::Ready(Ok(()))
    }
}

// ── UDP：sing UoT v2 over naive 隧道 ────────────────────────────────────────

/// UDP over naive via sing UoT v2 (connectionless mode)。
/// 到 magic 地址的隧道在第一次 `send_to` 时惰性建立；请求头用首个目标地址，
/// 之后每个数据报自带地址。底层是同一条已打标的 TCP 连接。
struct NaiveUdpSession {
    inner: Arc<NaiveInner>,
    /// writer half + 头状态，首次发送时创建
    io: TokioMutex<Option<UdpIo>>,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    rx: TokioMutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

struct UdpIo {
    writer: tokio::io::WriteHalf<NaiveStream>,
    header_sent: bool,
}

#[async_trait]
impl UdpSession for NaiveUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let target = match dst_host {
            Some(h) => Target::Domain(h.to_string(), dst.port()),
            None => Target::Socket(dst),
        };
        let mut io = self.io.lock().await;
        if io.is_none() {
            let stream = self.inner.dial(&uot_magic_target()).await?;
            let (read_half, writer) = tokio::io::split(stream);
            let tx = self.tx.clone();
            tokio::spawn(async move {
                uot_read_loop(read_half, tx).await;
            });
            *io = Some(UdpIo {
                writer,
                header_sent: false,
            });
        }
        let io = io.as_mut().unwrap();
        if !io.header_sent {
            io.writer
                .write_all(&build_uot_request(&target))
                .await
                .context("naive uot send header")?;
            io.header_sent = true;
        }
        io.writer
            .write_all(&build_uot_packet(&target, data))
            .await
            .context("naive uot send packet")?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow!("naive udp session closed"))
    }
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_header_format() {
        let hdr = generate_padding_header();
        assert!(hdr.len() >= 30 && hdr.len() <= 61);
        for b in hdr.bytes().take(16) {
            assert!(
                PADDING_HEADER_CHARSET.contains(&b),
                "char {} not in charset",
                b
            );
        }
        for b in hdr.bytes().skip(16) {
            assert_eq!(b, b'~');
        }
    }

    #[test]
    fn base64_auth_encoding() {
        let auth = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert_eq!(auth, "dXNlcjpwYXNz");
    }

    #[test]
    fn new_rejects_tls_disabled() {
        let cfg = ProxyConfig {
            name: "n".into(),
            ty: "naive".into(),
            server: "example.com".into(),
            port: 443,
            username: Some("u".into()),
            password: Some("p".into()),
            tls: false,
            ..sample_cfg()
        };
        assert!(NaiveOutbound::new(&cfg).is_err());
    }

    #[test]
    fn new_rejects_missing_credentials() {
        let mut cfg = ProxyConfig {
            name: "n".into(),
            ty: "naive".into(),
            server: "example.com".into(),
            port: 443,
            username: None,
            password: Some("p".into()),
            tls: true,
            ..sample_cfg()
        };
        assert!(NaiveOutbound::new(&cfg).is_err());
        cfg.username = Some("u".into());
        cfg.password = None;
        assert!(NaiveOutbound::new(&cfg).is_err());
    }

    #[test]
    fn new_builds_h2_alpn() {
        let cfg = ProxyConfig {
            name: "n".into(),
            ty: "naive".into(),
            server: "example.com".into(),
            port: 443,
            username: Some("u".into()),
            password: Some("p".into()),
            tls: true,
            ..sample_cfg()
        };
        let ob = NaiveOutbound::new(&cfg).unwrap();
        assert_eq!(ob.inner.opts.alpn, vec![ALPN_H2.to_string()]);
        assert_eq!(ob.inner.opts.sni, "example.com");
        assert_eq!(ob.inner.tls_config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    /// 其余字段用 Default 填的样板，避免测试随字段增减而失效。
    fn sample_cfg() -> ProxyConfig {
        serde_yaml::from_str(
            "name: n\ntype: naive\nserver: example.com\nport: 443\n",
        )
        .expect("sample ProxyConfig")
    }
}
