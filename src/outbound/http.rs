//! HTTP 代理出站（HTTP CONNECT 隧道）。
//!
//! 握手逻辑对齐 sing 官方实现 `github.com/sagernet/sing/protocol/http`
//! （`client.go` 的 `Client.DialContext`），要点：
//!
//! - 仅支持 TCP；UDP（`dial_udp`）直接报错，与官方 `ListenPacket`
//!   返回 `os.ErrInvalid` 语义一致——HTTP/1.1 CONNECT 不承载 UDP。
//! - 认证使用 HTTP Basic：`Proxy-Authorization: Basic base64(user:pass)`。
//! - `headers` 中若包含 `Host` 键（大小写不敏感），会被摘出单独使用：
//!   当 Host 头与目标域名不同时按 sing 的 Opaque 语义处理，且此时若同时
//!   配置了 `path` 则直接报错——官方行为原样保留。
//! - 读取 CONNECT 响应时可能多缓冲出属于隧道数据的字节，这部分要放到
//!   返回的流最前面，避免连接开始阶段丢包。
//! - 可选 TLS：配置了 `sni`（或 `servername` / `client-fingerprint` /
//!   `fingerprint`）时先与代理服务器完成 TLS/uTLS 握手，再在加密通道内
//!   发送明文 CONNECT 请求（HTTPS 代理）。注意：全局 `tls` 字段默认 true，
//!   会误伤明文 HTTP 代理，因此 http 出站与 shadowsocks 一样不读取该字段，
//!   仅凭上述 TLS 专属字段判断（`skip-cert-verify` 跟随 TLS 生效）。
//!   `path` 复用共享的 `path`（`xhttp-path`）字段，仅少数网关需要。

use super::anytls::{build_tls_config, resolve_server, Target};
use super::utls::{connect_utls, TlsStreamBox, UtlsFingerprint, UtlsVerify};
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use rustls::pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf,
};
use tracing::debug;

/// CONNECT 响应头读取的最大字节数（含状态行）。防止异常/恶意服务端
/// 不发送 "\r\n\r\n" 终止符导致无限读取占用内存。
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// 单次底层读取的缓冲块大小。
const READ_CHUNK: usize = 4096;
/// CONNECT 握手超时（与 socks 出站一致）。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct HttpOutbound {
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    /// CONNECT 请求行里的 path（sing 兼容，少数网关要求）。
    path: Option<String>,
    /// 从 `headers` 里摘出的 `Host`（大小写不敏感）。
    host_header: Option<String>,
    /// 其余自定义请求头（保持配置值原样）。
    headers: Vec<(String, String)>,
    /// HTTPS 代理：先 TLS/uTLS 握手再发 CONNECT。
    tls: bool,
    sni: String,
    skip_cert_verify: bool,
    fingerprint: Option<String>,
    utls: Option<UtlsFingerprint>,
    tls_config: Option<Arc<rustls::ClientConfig>>,
}

impl HttpOutbound {
    pub fn new(cfg: &ProxyConfig) -> Result<Self> {
        let utls = cfg
            .client_fingerprint
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                UtlsFingerprint::parse(s)
                    .with_context(|| format!("http `{}`: unknown client-fingerprint {s:?}", cfg.name))
            })
            .transpose()?;

        // TLS 判定：与 shadowsocks 相同的处理——全局 `tls` 默认 true 会误伤
        // 明文 HTTP 代理，因此仅在给出 TLS 专属字段时才启用（HTTPS 代理）。
        let non_empty = |s: &Option<String>| {
            s.as_deref().map(|v| !v.trim().is_empty()).unwrap_or(false)
        };
        let tls = non_empty(&cfg.sni)
            || non_empty(&cfg.servername)
            || non_empty(&cfg.client_fingerprint)
            || non_empty(&cfg.fingerprint);

        let tls_config = if tls {
            let alpn = cfg.alpn.clone().unwrap_or_default();
            Some(Arc::new(build_tls_config(
                cfg.skip_cert_verify,
                &cfg.fingerprint,
                &alpn,
            )?))
        } else {
            None
        };

        // headers：摘出 Host（大小写不敏感，官方行为），其余原样发送。
        let mut host_header = None;
        let mut headers = Vec::new();
        if let Some(map) = &cfg.http_headers {
            for (k, v) in map {
                if k.eq_ignore_ascii_case("host") {
                    host_header = Some(v.clone());
                } else {
                    headers.push((k.clone(), v.clone()));
                }
            }
        }

        Ok(Self {
            server: cfg.server.clone(),
            port: cfg.port,
            username: cfg.username.clone().filter(|u| !u.is_empty()),
            password: cfg.password.clone(),
            path: cfg.xhttp_path.clone(),
            host_header,
            headers,
            tls,
            sni: cfg.effective_sni(),
            skip_cert_verify: cfg.skip_cert_verify,
            fingerprint: cfg.fingerprint.clone(),
            utls,
            tls_config,
        })
    }

    // ── 连接到代理服务器（含可选 TLS）───────────────────────────────────────

    /// 建立底层连接：TLS 关闭时直接返回 TCP 流，
    /// TLS 启用时先完成 TLS/uTLS 握手（即 HTTPS 代理）。
    async fn connect_proxy(&self) -> Result<BoxedStream> {
        let addr = resolve_server(&self.server, self.port)
            .await
            .with_context(|| format!("http: DNS lookup failed for {}", self.server))?;
        let tcp = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("http tcp connect {addr}"))?;
        let _ = tcp.set_nodelay(true);

        if !self.tls {
            return Ok(Box::new(tcp));
        }

        let tls: TlsStreamBox = match &self.utls {
            Some(fp) => TlsStreamBox::Utls(Box::new(
                connect_utls(
                    tcp,
                    &self.sni,
                    fp,
                    &UtlsVerify {
                        skip_cert_verify: self.skip_cert_verify,
                        fingerprint: self.fingerprint.clone(),
                    },
                    &[],
                )
                .await
                .context("http utls handshake")?,
            )),
            None => {
                let name = ServerName::try_from(self.sni.clone())
                    .map_err(|_| anyhow!("http: invalid sni {}", self.sni))?;
                TlsStreamBox::Plain(
                    tokio_rustls::TlsConnector::from(self.tls_config.clone().expect("tls"))
                        .connect(name, tcp)
                        .await
                        .context("http tls handshake")?,
                )
            }
        };
        Ok(Box::new(tls))
    }

    // ── HTTP CONNECT 握手 ────────────────────────────────────────────────────

    /// 发送 CONNECT 请求并校验响应，返回已完成握手、可直接用于透明转发
    /// 的流（响应头之后可能多读到的字节已重新放回流最前面）。
    async fn connect_tunnel(&self, target: &Target) -> Result<BoxedStream> {
        let stream = self.connect_proxy().await?;
        self.handshake_on(stream, target).await
    }

    /// 在已建立的底层连接上完成 CONNECT 握手（拆出来便于内存流测试）。
    async fn handshake_on<S>(&self, mut stream: S, target: &Target) -> Result<BoxedStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let dest_authority = target_authority(target);
        let dest_fqdn_matches_host = match (target, &self.host_header) {
            (Target::Domain(host, _), Some(h)) => host == h,
            _ => false,
        };

        // ── Host 头 与 path 互斥校验（原样保留官方行为）───────────────────
        // 官方逻辑：仅当 `c.host != "" && c.host != destination.Fqdn` 时才会
        // 视为 Opaque 形式并校验 path 冲突；如果 Host 头恰好等于目标域名，
        // 则视为未设置（走普通 authority 形式），此时允许 path 生效。
        let use_opaque_host = self.host_header.is_some() && !dest_fqdn_matches_host;
        if use_opaque_host && self.path.is_some() {
            bail!("http: Host header and path are not allowed at the same time");
        }

        // ── 构造请求行 ────────────────────────────────────────────────────
        // 普通形式：CONNECT host:port HTTP/1.1
        // 带 path 形式：CONNECT host:port/path HTTP/1.1（少数网关要求）
        let request_target = if let Some(p) = &self.path {
            let p = p.strip_prefix('/').unwrap_or(p);
            format!("{dest_authority}/{p}")
        } else {
            dest_authority.clone()
        };

        let effective_host = if use_opaque_host {
            self.host_header.clone().unwrap()
        } else {
            dest_authority.clone()
        };

        let mut req = String::with_capacity(256);
        req.push_str(&format!("CONNECT {request_target} HTTP/1.1\r\n"));
        req.push_str(&format!("Host: {effective_host}\r\n"));
        req.push_str("Proxy-Connection: Keep-Alive\r\n");

        if let Some(user) = &self.username {
            let pass = self.password.as_deref().unwrap_or("");
            let credential =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            req.push_str(&format!("Proxy-Authorization: Basic {credential}\r\n"));
        }

        for (name, value) in &self.headers {
            if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
                bail!("http: header '{name}' contains illegal control characters");
            }
            req.push_str(&format!("{name}: {value}\r\n"));
        }

        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        // ── 读取响应：累积字节直到 "\r\n\r\n" ─────────────────────────────
        // 多读到的字节（属于隧道数据本体）保留下来，随连接一起返回。
        let mut raw = Vec::with_capacity(1024);
        let mut chunk = [0u8; READ_CHUNK];
        let header_end = loop {
            let n = stream.read(&mut chunk).await?;
            anyhow::ensure!(n > 0, "http: connection closed before CONNECT response");
            raw.extend_from_slice(&chunk[..n]);
            anyhow::ensure!(
                raw.len() <= MAX_RESPONSE_HEADER_BYTES,
                "http: CONNECT response header too large"
            );
            if let Some(end) = find_header_end(&raw) {
                break end;
            }
        };

        // 只认 200；其余状态一律失败，对常见失败给出可读提示——
        // 与官方 `Client.DialContext` 的 switch 分支保持一致。
        match parse_status_code(&raw[..header_end])? {
            200 => {}
            407 => bail!("http: proxy authentication required"),
            405 => bail!("http: proxy rejected CONNECT method (405 method not allowed)"),
            other => bail!("http: unexpected status from proxy: {other}"),
        }

        // 响应头之后多读到的字节属于隧道数据本体，塞回流最前面。
        let leftover = raw[header_end..].to_vec();
        Ok(Box::new(PrefixedStream {
            prefix: leftover,
            prefix_pos: 0,
            inner: stream,
        }))
    }
}

// ── OutboundDialer 实现 ───────────────────────────────────────────────────────

#[async_trait]
impl OutboundDialer for HttpOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        debug!(server = %self.server, target = ?addr, hint = ?host_hint, "http tcp");
        let fut = async {
            let target = match host_hint {
                Some(h) if !h.is_empty() && h.parse::<IpAddr>().is_err() => {
                    Target::Domain(h.to_string(), addr.port())
                }
                _ => Target::Socket(addr),
            };
            self.connect_tunnel(&target).await
        };
        let s = tokio::time::timeout(HANDSHAKE_TIMEOUT, fut)
            .await
            .context("http handshake timeout")??;
        Ok(s)
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        // HTTP CONNECT 不承载 UDP，等价于官方 `ListenPacket` 返回
        // `os.ErrInvalid`：直接报错，由上层丢弃该包。
        bail!("http outbound does not support UDP (CONNECT tunnels TCP only)")
    }
}

// ── 辅助函数 / 类型 ────────────────────────────────────────────────────────────

/// 目标的 `host:port` 形式，用于 CONNECT 请求行 authority 与默认 Host 头。
fn target_authority(target: &Target) -> String {
    match target {
        Target::Domain(host, port) => format!("{host}:{port}"),
        Target::Socket(addr) => addr.to_string(),
    }
}

/// 在缓冲里找 "\r\n\r\n"，返回其后第一个字节的偏移（响应头结束位置）。
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// 解析状态行 `HTTP/1.x <code> ...`，返回状态码。
fn parse_status_code(head: &[u8]) -> Result<u16> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .context("http: malformed CONNECT response (no status line)")?;
    let status_line = std::str::from_utf8(&head[..line_end])
        .context("http: CONNECT status line is not UTF-8")?;
    let mut parts = status_line.split_whitespace();
    let ver = parts.next().unwrap_or("");
    anyhow::ensure!(
        ver.starts_with("HTTP/"),
        "http: malformed CONNECT response: {status_line}"
    );
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .context("http: CONNECT response missing status code")?;
    Ok(code)
}

/// 包装底层流：把 CONNECT 响应解析时多读到、但属于隧道数据本体的字节
/// 放在最前面读出，读完 prefix 后透明转发到 inner。
///
/// 对应官方实现中 `bufio.NewCachedConn(conn, buffer)` 的作用——
/// 块读取经常会连带把紧跟在响应头后面的首批隧道数据一并读入缓冲区，
/// 如果不回放这部分字节，会导致连接开始阶段丢包。
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_authority_domain() {
        let t = Target::Domain("example.com".into(), 443);
        assert_eq!(target_authority(&t), "example.com:443");
    }

    #[test]
    fn target_authority_socket() {
        let t = Target::Socket("1.2.3.4:80".parse().unwrap());
        assert_eq!(target_authority(&t), "1.2.3.4:80");
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody"), Some(26));
        assert_eq!(find_header_end(b"HTTP/1.1 20"), None);
    }

    #[test]
    fn status_line_parse() {
        assert_eq!(
            parse_status_code(b"HTTP/1.1 200 Connection established\r\n").unwrap(),
            200
        );
        assert_eq!(parse_status_code(b"HTTP/1.0 407\r\n").unwrap(), 407);
        assert!(parse_status_code(b"garbage\r\n").is_err());
        assert!(parse_status_code(b"HTTP/1.1\r\n").is_err());
    }

    #[tokio::test]
    async fn prefixed_stream_yields_prefix_then_inner() {
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"world").await.unwrap();
        drop(writer); // 让 inner 读到 EOF 前只有这一次写入

        let mut s = PrefixedStream {
            prefix: b"hello ".to_vec(),
            prefix_pos: 0,
            inner: reader,
        };
        let mut buf = [0u8; 32];
        let n1 = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], b"hello ");
        let n2 = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"world");
    }

    #[tokio::test]
    async fn connect_tunnel_full_handshake() {
        // 内存代理：校验 CONNECT 请求（含 Basic 认证），回 200 + 隧道数据，
        // 验证多读字节回放（响应头与首批隧道数据在同一次读取里到达）。
        let (client, mut server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 512];
            let n = server.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(req.contains("Host: example.com:443\r\n"));
            assert!(req.contains("Proxy-Connection: Keep-Alive\r\n"));
            // base64("user:pass")
            assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            assert!(req.contains("X-Extra: v\r\n"));
            assert!(req.ends_with("\r\n\r\n"));
            // 响应头 + 首批隧道数据一次写出（模拟 bufio 块读取多缓冲）
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\nHELLO")
                .await
                .unwrap();
        });

        let ob = HttpOutbound {
            server: "127.0.0.1".into(),
            port: 8080,
            username: Some("user".into()),
            password: Some("pass".into()),
            path: None,
            host_header: None,
            headers: vec![("X-Extra".into(), "v".into())],
            tls: false,
            sni: String::new(),
            skip_cert_verify: false,
            fingerprint: None,
            utls: None,
            tls_config: None,
        };
        let mut s = ob
            .handshake_on(client, &Target::Domain("example.com".into(), 443))
            .await
            .unwrap();
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"HELLO");
    }
}
