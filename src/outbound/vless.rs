//! VLESS outbound — protocol aligned with Xray / clash-rs.
//!
//! Transports: `tcp` | `ws` | `xhttp`; TLS layers: plain TLS (rustls) or
//! REALITY (self-implemented TLS 1.3, see `super::reality`).
//!
//! * tcp / reality: header written directly, response header read eagerly.
//! * ws / xhttp: the VLESS header is merged into the first upstream write and
//!   the response header is skipped lazily on the first read (same as reflex /
//!   sing-box). Waiting for the response eagerly would deadlock, since servers
//!   only answer once they got payload.
//!
//! Request: version(1) + uuid(16) + addon_len(1) + addon + cmd(1) + port(2 BE) + atyp + addr
//! Response: version(1) + addon_len(1) + addon

use super::ech as ech_cfg;
use super::hpke::ECH_HPKE_SUITES;
use super::reality::{reality_connect, RealityDialConfig};
use super::utls::{connect_utls, TlsStreamBox, UtlsFingerprint};
use super::vision::{TlsLayer, VisionConn};
use super::xhttp::connect_over_stream;
use super::xhttp::XhttpConfig;
use super::xhttp_h2;
use super::{BoxedStream, OutboundDialer, UdpSession};
use crate::config::ProxyConfig;
use crate::dns::DnsUpstream;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchConfig, EchMode};
use rustls::pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest, http::HeaderName, http::HeaderValue, protocol::WebSocketConfig,
    Message,
};
use tokio_tungstenite::{client_async_with_config, WebSocketStream};
use uuid::Uuid;

/// TLS + WS upgrade timeout (matches sing-box TCPTimeout).
const WS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

const VLESS_VERSION: u8 = 0;
const VLESS_CMD_TCP: u8 = 1;
const VLESS_CMD_UDP: u8 = 2;
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 2;
const ATYP_IPV6: u8 = 3;

/// xhttp 运行模式（配置在 `new()` 阶段解析完成，对齐 Xray dialer.go:362-371）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XhttpResolved {
    /// 手写 HTTP/1.1 单 POST 双向流（`super::xhttp`，REALITY 唯一支持的模式）。
    StreamOne,
    /// hyper：GET 长轮询下行 + 攒批分包 POST 上行。
    PacketUp,
    /// hyper：GET 长轮询下行 + 单条流式 POST 上行。
    StreamUp,
}

#[derive(Clone)]
struct VlessOption {
    server: String,
    port: u16,
    uuid: Uuid,
    network: String,
    tls: bool,
    sni: String,
    skip_cert_verify: bool,
    ws_path: String,
    ws_host: String,
    /// true when the user set ws-host explicitly (Host header is then sent verbatim).
    ws_host_explicit: bool,
    ws_headers: Vec<(String, String)>,
    /// Set when `reality-public-key` is configured — replaces rustls entirely.
    reality: Option<RealityDialConfig>,
    /// VLESS flow addon（已校验：仅 `xtls-rprx-vision` 且 network == tcp）。
    flow: Option<String>,
    /// Set when network == "xhttp".
    xhttp: Option<XhttpConfig>,
    /// xhttp 运行模式（`auto` 已在此处展开）。
    xhttp_resolved: XhttpResolved,
    /// uTLS 浏览器指纹（`client-fingerprint`）。REALITY 下不生效（REALITY
    /// 是自实现 TLS 1.3，不经过 rustls 握手）。
    utls: Option<UtlsFingerprint>,
    /// ECH（Encrypted Client Hello）：rustls 已选定的 ECH 配置。启用后
    /// ClientConfig 走 `with_ech`（TLS 1.3-only），握手时把 sni 作为 inner
    /// SNI 加密，outer SNI 由 rustls 取 ECH 配置的 public_name。
    /// 与 REALITY / uTLS 互斥（new() fail-fast）。
    ech: Option<EchConfig>,
    /// 传给 rustls ClientConfig 与伪造 ClientHello 的有效 ALPN（二者必须一致）。
    tls_alpn: Vec<String>,
    /// xhttp packet-up / stream-up 用的 TLS 配置（ALPN 强制 h2）；
    /// REALITY 下为 None（这些模式不支持 REALITY，已在 new() fail-fast）。
    xhttp_h2_tls: Option<Arc<rustls::ClientConfig>>,
}

#[derive(Clone)]
pub struct VlessOutbound {
    opts: VlessOption,
    /// Plain-rustls client config（REALITY 下为 None）。uTLS 与普通 TLS 共用。
    tls_config: Option<Arc<ClientConfig>>,
}

impl VlessOutbound {
    /// 构建节点。`ech_dns` 提供 ECH DNS HTTPS RR 查询可用的 upstream 列表
    /// （按优先级：proxy-nameserver → nameserver → default-nameserver）。
    /// `ech: true` 且未提供 `ech-config` / `ech-config-path` 时必须传入，
    /// 否则构建失败（fail-fast）。
    pub async fn new_with_ech_dns(cfg: &ProxyConfig, ech_dns: &[DnsUpstream]) -> Result<Self> {
        Self::build(cfg, ech_dns).await
    }

    async fn build(cfg: &ProxyConfig, ech_dns: &[DnsUpstream]) -> Result<Self> {
        let uuid_str = cfg.vless_uuid()?;
        let uuid = Uuid::parse_str(&uuid_str).context("invalid vless uuid")?;
        let sni = cfg.effective_sni();
        let ws_host_explicit = cfg.ws_host.is_some();
        let ws_host = cfg.ws_host.clone().unwrap_or_else(|| sni.clone());
        let mut ws_path = cfg.ws_path.clone().unwrap_or_else(|| "/".into());
        if !ws_path.starts_with('/') {
            ws_path.insert(0, '/');
        }
        let ws_headers = cfg
            .ws_headers
            .clone()
            .map(|m| m.into_iter().collect::<Vec<_>>())
            .unwrap_or_default();
        let alpn = cfg.alpn.clone().unwrap_or_default();

        let network = cfg.network.to_lowercase();

        // REALITY: any non-empty reality-public-key enables it, overriding
        // plain rustls (same gating as reflex: reality wins over plain TLS).
        let reality_key = cfg
            .reality_public_key
            .as_ref()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty());
        let reality = reality_key.map(|public_key| RealityDialConfig {
            public_key,
            short_id: cfg.reality_short_id.clone().unwrap_or_default(),
            server_name: Some(sni.clone()),
            server: cfg.server.clone(),
            alpn: alpn.clone(),
        });

        // uTLS 浏览器指纹（client-fingerprint），未知值 fail-fast。
        let utls = cfg
            .client_fingerprint
            .as_ref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| {
                UtlsFingerprint::parse(s).with_context(|| {
                    format!(
                        "vless `{}`: unknown client-fingerprint {s:?} \
                         (supported: chrome/firefox/safari/edge/ios/android/360/qq/random)",
                        cfg.name
                    )
                })
            })
            .transpose()?;
        if utls.is_some() && reality.is_some() {
            tracing::warn!(
                "vless `{}`: client-fingerprint is ignored under REALITY \
                 (REALITY handshake is self-implemented TLS 1.3)",
                cfg.name
            );
        } else if utls.is_some() && !cfg.tls {
            tracing::warn!(
                "vless `{}`: client-fingerprint set but tls is disabled — no effect",
                cfg.name
            );
        }

        // ECH 门控（fail-fast）：仅 rustls TLS 路径支持 ECH。
        // * REALITY 是自实现 TLS 1.3，不经过 rustls，无法叠加 ECH；
        // * uTLS 伪造的 ClientHello 与 rustls ECH 的 inner/outer 分裂不兼容；
        // * ECH 加密的就是 TLS ClientHello，关掉 TLS 无从谈起。
        let ech_enabled = cfg.ech;
        if ech_enabled {
            if reality.is_some() {
                bail!(
                    "vless `{}`: ech cannot be combined with reality-public-key \
                     (REALITY handshake is self-implemented TLS 1.3, not the rustls ECH path)",
                    cfg.name
                );
            }
            if !cfg.tls {
                bail!("vless `{}`: ech requires tls", cfg.name);
            }
            if utls.is_some() {
                bail!(
                    "vless `{}`: ech cannot be combined with client-fingerprint \
                     (uTLS patches the ClientHello, rustls ECH constructs its own)",
                    cfg.name
                );
            }
        }

        // fail-fast 配置校验（对齐 sing-box KTLSCompatible 门控）：
        // * flow 只支持 xtls-rprx-vision，且只能在 TCP 直连（含 REALITY）上使用；
        // * REALITY 本身是 TLS 1.3 over TCP，ws 传输无法承载（xhttp 保留既有支持）。
        let flow = cfg
            .flow
            .as_ref()
            .map(|f| f.trim().to_string())
            .filter(|f| !f.is_empty());
        if let Some(f) = &flow {
            if f != "xtls-rprx-vision" {
                bail!("vless `{}`: unsupported flow {f:?} (only \"xtls-rprx-vision\")", cfg.name);
            }
            if network != "tcp" {
                bail!(
                    "vless `{}`: flow requires network=tcp (got {network:?}); \
                     xtls-rprx-vision cannot run over ws/xhttp",
                    cfg.name
                );
            }
            if !(cfg.tls || reality.is_some()) {
                bail!("vless `{}`: flow requires tls or reality", cfg.name);
            }
        }
        if reality.is_some() && network == "ws" {
            bail!(
                "vless `{}`: REALITY is TCP-only and cannot be combined with network=ws",
                cfg.name
            );
        }

        // xhttp 运行模式解析（对齐 Xray dialer.go:362-371）：
        //   auto / 空 → packet-up；REALITY 下 → stream-one（Xray REALITY 默认）。
        //   显式 packet-up / stream-up + REALITY → fail-fast（hyper 连接器无法
        //   承载自实现 REALITY TLS）。
        let xhttp = if network == "xhttp" {
            let host = cfg
                .xhttp_host
                .clone()
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| sni.clone());
            let mut path = cfg.xhttp_path.clone().unwrap_or_else(|| "/".into());
            if !path.starts_with('/') {
                path.insert(0, '/');
            }
            let raw_mode = cfg
                .xhttp_mode
                .as_ref()
                .map(|m| m.trim())
                .filter(|m| !m.is_empty())
                .unwrap_or("auto");
            let resolved = match raw_mode {
                "auto" => {
                    if reality.is_some() {
                        XhttpResolved::StreamOne
                    } else {
                        XhttpResolved::PacketUp
                    }
                }
                "stream-one" => XhttpResolved::StreamOne,
                "packet-up" if reality.is_none() => XhttpResolved::PacketUp,
                "stream-up" if reality.is_none() => XhttpResolved::StreamUp,
                other @ ("packet-up" | "stream-up") => bail!(
                    "vless `{}`: xhttp-mode {other:?} cannot run over REALITY \
                     (REALITY only supports stream-one; use `auto` or `stream-one`)",
                    cfg.name
                ),
                other => bail!(
                    "vless `{}`: unknown xhttp-mode {other:?} \
                     (supported: auto/packet-up/stream-up/stream-one)",
                    cfg.name
                ),
            };
            (
                Some(XhttpConfig {
                    host,
                    path,
                    mode: raw_mode.to_string(),
                    headers: cfg.xhttp_headers.clone().unwrap_or_default(),
                }),
                resolved,
            )
        } else {
            (None, XhttpResolved::StreamOne)
        };
        let (xhttp, xhttp_resolved) = xhttp;

        let opts = VlessOption {
            server: cfg.server.clone(),
            port: cfg.port,
            uuid,
            network,
            // REALITY is TLS by definition.
            tls: cfg.tls || reality.is_some(),
            sni: sni.clone(),
            skip_cert_verify: cfg.skip_cert_verify,
            ws_path,
            ws_host,
            ws_host_explicit,
            ws_headers,
            reality,
            flow,
            utls,
            ech: None,
            xhttp,
            xhttp_resolved,
            tls_alpn: Vec::new(),
            xhttp_h2_tls: None,
        };

        // Plain-rustls client config is skipped when REALITY handles TLS itself.
        //
        // 有效 ALPN：伪造 ClientHello 的 ALPN 必须与 rustls config 一致
        // （服务端按伪造 ClientHello 选择协议，rustls 拒绝自身未 offer 的选择）。
        // ws / xhttp stream-one upgrade 走 HTTP/1.1：强制 http/1.1；
        // tcp(+utls) 未配置 ALPN 时用浏览器默认 [h2, http/1.1]。
        if opts.tls && opts.reality.is_none() {
            // ECH：解析 ECHConfigList（inline / 文件 / DNS HTTPS RR）并交给
            // rustls 选择与本地 HPKE suite 兼容的第一条配置。
            let ech = if ech_enabled {
                let list = ech_cfg::resolve_ech_config_list(
                    cfg,
                    &opts.sni,
                    if ech_dns.is_empty() { None } else { Some(ech_dns) },
                )
                .await?;
                let ech_config = EchConfig::new(EchConfigListBytes::from(list), ECH_HPKE_SUITES)
                    .map_err(|e| {
                        anyhow!("vless `{}`: no usable ECH config: {e}", cfg.name)
                    })?;
                tracing::info!(
                    "vless `{}`: ech enabled (rustls client-side, TLS 1.3 only)",
                    cfg.name
                );
                Some(ech_config)
            } else {
                None
            };

            let force_http11 = opts.network == "ws"
                || (opts.network == "xhttp" && opts.xhttp_resolved == XhttpResolved::StreamOne);
            let effective_alpn: Vec<String> = if force_http11 {
                vec!["http/1.1".to_string()]
            } else if !alpn.is_empty() {
                alpn.clone()
            } else if opts.utls.is_some() {
                vec!["h2".to_string(), "http/1.1".to_string()]
            } else {
                Vec::new()
            };

            let client_config = Arc::new(build_tls_client_config(
                opts.skip_cert_verify,
                &effective_alpn,
                ech.as_ref(),
            )?);

            // xhttp packet-up / stream-up：独立的 h2 TLS 配置（ALPN 强制 h2，
            // 对齐 Xray downloadSettings.streamSettings 必须为 h2）。
            let xhttp_h2_tls = if opts.network == "xhttp"
                && opts.xhttp_resolved != XhttpResolved::StreamOne
            {
                Some(Arc::new(build_tls_client_config(
                    opts.skip_cert_verify,
                    &["h2".to_string()],
                    ech.as_ref(),
                )?))
            } else {
                None
            };

            let mut opts = opts;
            opts.tls_alpn = effective_alpn;
            opts.xhttp_h2_tls = xhttp_h2_tls;
            opts.ech = ech;
            Ok(Self {
                opts,
                tls_config: Some(client_config),
            })
        } else {
            Ok(Self {
                opts,
                tls_config: None,
            })
        }
    }

    async fn connect_raw(&self) -> Result<TcpStream> {
        let addr = resolve_server(&self.opts.server, self.opts.port).await?;
        let s = crate::app::sockopt::connect_tcp(addr)
            .await
            .with_context(|| format!("vless tcp connect {addr}"))?;
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    /// 建立 rustls TLS 层（普通 rustls 或 uTLS 浏览器指纹），
    /// 返回统一类型供 Vision / ws / xhttp stream-one 使用。
    async fn connect_tls_layer(&self, stream: TcpStream) -> Result<TlsStreamBox> {
        let cfg = self
            .tls_config
            .as_ref()
            .context("tls not configured")?;
        match self.opts.utls {
            Some(fp) => {
                // 伪造 ClientHello 的 ALPN 与 rustls config 一致（见 new()）。
                Ok(TlsStreamBox::Utls(Box::new(
                    connect_utls(
                        stream,
                        &self.opts.sni,
                        &fp,
                        cfg.clone(),
                        &self.opts.tls_alpn,
                    )
                    .await
                    .context("vless utls handshake")?,
                )))
            }
            None => {
                let name = ServerName::try_from(self.opts.sni.clone())
                    .map_err(|_| anyhow!("invalid sni {}", self.opts.sni))?;
                Ok(TlsStreamBox::Plain(
                    TlsConnector::from(cfg.clone())
                        .connect(name, stream)
                        .await
                        .context("vless tls handshake")?,
                ))
            }
        }
    }

    async fn wrap_tls(&self, stream: TcpStream) -> Result<BoxedStream> {
        Ok(Box::new(self.connect_tls_layer(stream).await?))
    }

    fn is_ws(&self) -> bool {
        self.opts.network == "ws"
    }

    /// Open the underlying transport and send the VLESS request.
    ///
    /// * tcp/reality: write header, then read the response header eagerly.
    /// * ws/xhttp: the VLESS header is merged into the first upstream write
    ///   together with the first payload, and the response header is skipped
    ///   lazily on the first read (same as reflex / sing-box). Waiting for the
    ///   response here would deadlock, since servers only answer once they got
    ///   payload.
    async fn open_vless(
        &self,
        host_hint: Option<&str>,
        addr: SocketAddr,
        cmd: u8,
    ) -> Result<BoxedStream> {
        // flow addon 只随 TCP 命令发送（对齐 reflex build_udp_request：UDP 不带 flow）。
        let flow = if cmd == VLESS_CMD_TCP {
            self.opts.flow.as_deref()
        } else {
            None
        };
        let header = build_vless_header(&self.opts.uuid, host_hint, addr, cmd, flow);

        // XHTTP：stream-one 走手写 HTTP/1.1 单 POST 双向流（支持 REALITY）；
        // packet-up / stream-up 走 hyper 客户端（TLS 时 ALPN 强制 h2）。
        if let Some(xcfg) = &self.opts.xhttp {
            match self.opts.xhttp_resolved {
                XhttpResolved::StreamOne => {
                    let transport = self.connect_xhttp_transport().await?;
                    let pipe = connect_over_stream(transport, xcfg).await?;
                    return Ok(Box::new(VlessStreamIo::with_header(
                        pipe,
                        Bytes::from(header),
                    )));
                }
                XhttpResolved::PacketUp | XhttpResolved::StreamUp => {
                    let mode = match self.opts.xhttp_resolved {
                        XhttpResolved::PacketUp => "packet-up",
                        XhttpResolved::StreamUp => "stream-up",
                        XhttpResolved::StreamOne => unreachable!("handled above"),
                    };
                    let tls = self.opts.xhttp_h2_tls.clone().map(|config| {
                        xhttp_h2::XhttpH2Tls {
                            config,
                            server_name: self.opts.sni.clone(),
                            utls: self.opts.utls,
                        }
                    });
                    let pipe = xhttp_h2::connect(
                        &self.opts.server,
                        self.opts.port,
                        &xcfg.host,
                        &xcfg.path,
                        mode,
                        &xcfg.headers,
                        tls,
                    )
                    .await?;
                    return Ok(Box::new(VlessStreamIo::with_header(
                        pipe,
                        Bytes::from(header),
                    )));
                }
            }
        }

        if self.is_ws() {
            let ws = tokio::time::timeout(WS_HANDSHAKE_TIMEOUT, self.connect_ws())
                .await
                .map_err(|_| {
                    anyhow!(
                        "vless ws handshake timed out after {}s ({}:{})",
                        WS_HANDSHAKE_TIMEOUT.as_secs(),
                        self.opts.server,
                        self.opts.port
                    )
                })??;
            return Ok(Box::new(
                WsStream::with_header(ws, Bytes::from(header)).skip_vless_response(),
            ));
        }

        // tcp / reality path.
        let tcp = self.connect_raw().await?;
        let layer: TlsLayer = if let Some(rcfg) = &self.opts.reality {
            TlsLayer::Reality(
                reality_connect(tcp, rcfg).await.context("vless reality handshake")?,
            )
        } else if self.opts.tls {
            match self.connect_tls_layer(tcp).await? {
                TlsStreamBox::Plain(s) => TlsLayer::Rustls(Box::new(s)),
                TlsStreamBox::Utls(s) => TlsLayer::RustlsUtls(s),
            }
        } else {
            TlsLayer::Plain(tcp)
        };

        // XTLS Vision：padding + TLS-in-TLS 检测 + direct 直通（性能核心路径）。
        // 响应头经 padding 帧携带，eager 读取同样适用（VisionConn 负责 unpadding）。
        if self.opts.flow.is_some() {
            let mut vision = VisionConn::new(layer, *self.opts.uuid.as_bytes());
            vision
                .write_all(&header)
                .await
                .context("vless write request")?;
            read_vless_response(&mut vision).await?;
            return Ok(Box::new(vision));
        }

        let mut transport: BoxedStream = match layer {
            TlsLayer::Rustls(s) => Box::new(s),
            TlsLayer::RustlsUtls(s) => Box::new(s),
            TlsLayer::Reality(s) => Box::new(s),
            TlsLayer::Plain(s) => Box::new(s),
        };
        transport
            .write_all(&header)
            .await
            .context("vless write request")?;
        read_vless_response(&mut transport).await?;
        Ok(transport)
    }

    /// Underlying stream for the XHTTP pipe: TCP → (REALITY | TLS | plain).
    async fn connect_xhttp_transport(&self) -> Result<BoxedStream> {
        let tcp = self.connect_raw().await?;
        if let Some(rcfg) = &self.opts.reality {
            return Ok(Box::new(
                reality_connect(tcp, rcfg).await.context("vless reality handshake")?,
            ));
        }
        if self.opts.tls {
            return self.wrap_tls(tcp).await;
        }
        Ok(Box::new(tcp))
    }

    /// TCP → (TLS, ALPN http/1.1) → WebSocket upgrade.
    async fn connect_ws(&self) -> Result<WebSocketStream<BoxedStream>> {
        let tcp = self.connect_raw().await?;
        let io: BoxedStream = if self.opts.tls {
            self.wrap_tls(tcp).await?
        } else {
            Box::new(tcp)
        };

        // Host header: a user supplied ws-host is sent verbatim; otherwise
        // sni[:port] with the port omitted when it is the scheme default.
        let default_port = if self.opts.tls { 443 } else { 80 };
        let authority = if self.opts.ws_host_explicit || self.opts.port == default_port {
            self.opts.ws_host.clone()
        } else {
            format!("{}:{}", self.opts.ws_host, self.opts.port)
        };
        // The URL only feeds tungstenite's request builder (Host / path);
        // TLS has already been handled above.
        let url = format!("ws://{}{}", authority, self.opts.ws_path);
        let mut request = url.clone()
            .into_client_request()
            .with_context(|| format!("invalid ws url {url}"))?;
        for (k, v) in &self.opts.ws_headers {
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
            .map_err(|e| anyhow!("vless ws upgrade: {e}"))?;
        Ok(ws)
    }
}

#[async_trait]
impl OutboundDialer for VlessOutbound {
    async fn dial_tcp(&self, addr: SocketAddr, host_hint: Option<&str>) -> Result<BoxedStream> {
        let transport = self.open_vless(host_hint, addr, VLESS_CMD_TCP).await?;

        tracing::debug!(
            "vless ok {}://{}:{} net={} → {:?}",
            if self.opts.reality.is_some() {
                "reality"
            } else if self.opts.tls {
                "tls"
            } else {
                "tcp"
            },
            self.opts.server,
            self.opts.port,
            self.opts.network,
            host_hint.unwrap_or(&addr.to_string())
        );
        Ok(transport)
    }

    async fn dial_udp(&self, _local_hint: Option<SocketAddr>) -> Result<Box<dyn UdpSession>> {
        let (tx, rx) = mpsc::channel(256);
        Ok(Box::new(VlessUdpSession {
            ob: self.clone(),
            peers: Mutex::new(HashMap::new()),
            incoming: Mutex::new(rx),
            incoming_tx: tx,
        }))
    }
}

/// One VLESS stream per destination (command=UDP).
/// Packet framing matches clash-rs / Xray native UDP: u16be length + payload.
struct VlessUdpSession {
    ob: VlessOutbound,
    peers: Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>,
    incoming: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    incoming_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl VlessUdpSession {
    async fn ensure_peer(&self, dst: SocketAddr, host: Option<&str>) -> Result<mpsc::Sender<Vec<u8>>> {
        let key = if let Some(h) = host {
            format!("{h}:{}", dst.port())
        } else {
            dst.to_string()
        };
        {
            let peers = self.peers.lock().await;
            if let Some(tx) = peers.get(&key) {
                if !tx.is_closed() {
                    return Ok(tx.clone());
                }
            }
        }
        let stream = self.ob.open_vless(host, dst, VLESS_CMD_UDP).await?;
        let (pkt_tx, pkt_rx) = mpsc::channel(64);
        let out_tx = self.incoming_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = udp_peer_loop(stream, dst, pkt_rx, out_tx).await {
                tracing::debug!("vless udp peer {dst} end: {e:#}");
            }
        });
        self.peers.lock().await.insert(key, pkt_tx.clone());
        tracing::debug!("vless udp associate {dst}");
        Ok(pkt_tx)
    }
}

async fn udp_peer_loop(
    stream: BoxedStream,
    src: SocketAddr,
    mut pkt_rx: mpsc::Receiver<Vec<u8>>,
    out_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(stream);
    loop {
        tokio::select! {
            pkt = pkt_rx.recv() => {
                let Some(data) = pkt else { break };
                if data.is_empty() || data.len() > 65535 {
                    continue;
                }
                let mut frame = Vec::with_capacity(2 + data.len());
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(&data);
                wr.write_all(&frame).await.context("vless udp write")?;
            }
            res = read_len_packet(&mut rd) => {
                let data = res?;
                if out_tx.send((data, src)).await.is_err() {
                    break;
                }
            }
        }
    }
    Ok(())
}

async fn read_len_packet<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Vec<u8>> {
    let mut lenb = [0u8; 2];
    rd.read_exact(&mut lenb).await.context("vless udp len")?;
    let n = u16::from_be_bytes(lenb) as usize;
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; n];
    rd.read_exact(&mut buf).await.context("vless udp body")?;
    Ok(buf)
}

#[async_trait]
impl UdpSession for VlessUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, dst_host: Option<&str>) -> Result<()> {
        let tx = self.ensure_peer(dst, dst_host).await?;
        tx.send(data.to_vec())
            .await
            .map_err(|_| anyhow!("vless udp peer closed"))?;
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut rx = self.incoming.lock().await;
        rx.recv().await.ok_or_else(|| anyhow!("vless udp session closed"))
    }
}


fn build_vless_header(
    uuid: &Uuid,
    host_hint: Option<&str>,
    addr: SocketAddr,
    cmd: u8,
    flow: Option<&str>,
) -> Vec<u8> {
    // addon（protobuf-like，对齐 Xray Addons.Flow：field 1, wire type 2）
    // `0x0a` = (1 << 3) | 2；flow 长度远小于 128，单字节 varint 即可。
    let mut addon: Vec<u8> = Vec::new();
    if let Some(f) = flow.filter(|f| !f.is_empty()) {
        addon.push(0x0a);
        addon.push(f.len() as u8);
        addon.extend_from_slice(f.as_bytes());
    }

    let mut buf = Vec::with_capacity(21 + 18 + addon.len());
    buf.push(VLESS_VERSION);
    buf.extend_from_slice(uuid.as_bytes());
    buf.push(addon.len() as u8);
    buf.extend_from_slice(&addon);
    buf.push(cmd);

    let port = if addr.port() != 0 {
        addr.port()
    } else if host_hint.is_some() {
        443
    } else {
        addr.port()
    };
    buf.extend_from_slice(&port.to_be_bytes());

    if let Some(host) = host_hint {
        if host.parse::<IpAddr>().is_err() {
            let h = host.as_bytes();
            let len = h.len().min(255);
            buf.push(ATYP_DOMAIN);
            buf.push(len as u8);
            buf.extend_from_slice(&h[..len]);
            return buf;
        }
    }

    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf
}

/// 读取 VLESS 响应头 `[ver 1B][addon_len 1B][addon]`（tcp/reality/vision 路径）。
async fn read_vless_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut ver = [0u8; 1];
    r.read_exact(&mut ver)
        .await
        .context("vless read response version")?;
    if ver[0] != VLESS_VERSION {
        bail!("vless unexpected response version {}", ver[0]);
    }
    let mut alen = [0u8; 1];
    r.read_exact(&mut alen)
        .await
        .context("vless read addon len")?;
    if alen[0] > 0 {
        let mut addon = vec![0u8; alen[0] as usize];
        r.read_exact(&mut addon)
            .await
            .context("vless read addon")?;
    }
    Ok(())
}

/// 构建 rustls 客户端配置（普通 TLS 与 uTLS 共用）。
/// `alpn` 同时用于 rustls config 与伪造 ClientHello（调用方保证一致）。
///
/// `ech` 非 None 时走 `with_ech`（rustls 客户端 ECH，强制 TLS 1.3-only）：
/// 握手时 rustls 以 ECH 配置的 public_name 作 outer SNI，把传入的
/// server_name（即节点 sni）加密为 inner ClientHello。ECH 配置与域名绑定，
/// 因此该 ClientConfig 不可跨节点共享（见 rustls `with_ech` 文档）。
fn build_tls_client_config(
    skip: bool,
    alpn: &[String],
    ech: Option<&EchConfig>,
) -> Result<ClientConfig> {
    let builder = match ech {
        Some(ech_config) => {
            // 注意：0.23.45 的 `ClientConfig::builder()` 直接返回
            // WantsVerifier（已选默认版本），而 `with_ech` 定义在
            // WantsVersions 状态上 —— 必须经 builder_with_provider。
            ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_ech(EchMode::Enable(ech_config.clone()))
            .context("enable ECH on rustls client config")?
        }
        None => ClientConfig::builder(),
    };
    let mut config = if skip {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerify))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    if !alpn.is_empty() {
        config.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }
    Ok(config)
}

#[derive(Debug)]
struct SkipVerify;

impl ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn resolve_server(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // 域名：default-nameserver（bootstrap）优先，系统解析回落，
    // 避免系统 DNS 指回 ant 自身时的解析回环；失败仅影响当次拨号。
    crate::dns::resolve_host_via_bootstrap(host, port).await
}

// ─── VLESS stream adapter for stream transports (xhttp, same design as reflex
// VlessTcpStream) ────────────────────────────────────────────────────────────

/// Wraps a stream transport (XHTTP pipe) carrying raw VLESS framing:
///
/// * the first write carries the VLESS request header + first payload;
/// * the VLESS response header (`ver, addon_len, addon`) is skipped on first
///   read;
/// * partial writes are buffered so no data is ever dropped on `Pending`.
struct VlessStreamIo<S> {
    inner: S,
    pending_header: Option<Bytes>,
    pending_write: Option<Bytes>,
    /// Bytes of the *user* payload reported as written once `pending_write`
    /// (header + payload combined) has been fully flushed.
    pending_reported: usize,
    raw_buf: Vec<u8>,
    read_buf: Bytes,
    response_header_skipped: bool,
}

impl<S> VlessStreamIo<S> {
    fn with_header(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
            raw_buf: Vec::new(),
            read_buf: Bytes::new(),
            response_header_skipped: false,
        }
    }
}

impl<S> AsyncRead for VlessStreamIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf = this.read_buf.slice(n..);
            return Poll::Ready(Ok(()));
        }

        if !this.response_header_skipped {
            // Accumulate until the full [ver][addon_len][addon] header is here.
            loop {
                if this.raw_buf.len() >= 2 {
                    if this.raw_buf[0] != VLESS_VERSION {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("vless: bad response version {}", this.raw_buf[0]),
                        )));
                    }
                    let hdr_len = 2 + this.raw_buf[1] as usize;
                    if this.raw_buf.len() >= hdr_len {
                        this.response_header_skipped = true;
                        let payload = Bytes::copy_from_slice(&this.raw_buf[hdr_len..]);
                        this.raw_buf.clear();
                        if !payload.is_empty() {
                            this.read_buf = payload;
                            let n = buf.remaining().min(this.read_buf.len());
                            buf.put_slice(&this.read_buf[..n]);
                            this.read_buf = this.read_buf.slice(n..);
                        }
                        break;
                    }
                }
                let mut tmp = [0u8; 512];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let filled = rb.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        this.raw_buf.extend_from_slice(filled);
                    }
                }
            }
        }

        if !this.read_buf.is_empty() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for VlessStreamIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. Finish a partially-written combined buffer first.
        if let Some(pending) = this.pending_write.take() {
            return match Pin::new(&mut this.inner).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = this.pending_reported;
                    this.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    this.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    this.pending_reported = 0;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    this.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. First write: merge header + data into one upstream write.
        if let Some(header) = this.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            return match Pin::new(&mut this.inner).poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) if n >= combined.len() => Poll::Ready(Ok(data.len())),
                Poll::Ready(Ok(n)) => {
                    this.pending_write = Some(combined.slice(n..));
                    this.pending_reported = data.len();
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    this.pending_write = Some(combined);
                    this.pending_reported = data.len();
                    Poll::Pending
                }
            };
        }

        // 3. Plain passthrough.
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ─── WebSocket stream adapter (tokio-tungstenite, same design as reflex) ────

/// Adapts a `WebSocketStream` to `AsyncRead + AsyncWrite`.
///
/// * every write becomes one binary frame;
/// * the first write carries the VLESS request header + first payload;
/// * the VLESS response header (`ver, addon_len, addon`) is skipped on first read;
/// * Ping/Pong handled by tungstenite, Close → EOF.
struct WsStream<S> {
    inner: S,
    pending_header: Option<Bytes>,
    read_buf: Bytes,
    skip_vless_response: bool,
    response_header_skipped: bool,
}

impl<S> WsStream<S> {
    fn with_header(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
            skip_vless_response: false,
            response_header_skipped: false,
        }
    }

    fn skip_vless_response(mut self) -> Self {
        self.skip_vless_response = true;
        self
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, e)
}

/// Returns number of bytes of the VLESS response header, or None if incomplete/invalid.
fn vless_response_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 2 || buf[0] != VLESS_VERSION {
        return None;
    }
    let n = 2 + buf[1] as usize;
    (buf.len() >= n).then_some(n)
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
                        if this.skip_vless_response && !this.response_header_skipped {
                            this.response_header_skipped = true;
                            match vless_response_len(&data) {
                                Some(skip) => this.read_buf = data.slice(skip..),
                                None => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "vless: bad response header over ws",
                                    )))
                                }
                            }
                        } else {
                            this.read_buf = data;
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};
    use tokio::net::TcpListener;

    /// VLESS over plain WS: header merged with first payload in one frame,
    /// response header skipped, Host header has the port when non-default.
    #[tokio::test]
    #[allow(clippy::result_large_err)] // tungstenite handshake callback signature
    async fn vless_ws_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut host = String::new();
            let cb = |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
                      resp: tokio_tungstenite::tungstenite::handshake::server::Response| {
                host = req.headers().get("host").unwrap().to_str().unwrap().to_string();
                assert_eq!(req.uri().path(), "/ws");
                Ok(resp)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(tcp, cb).await.unwrap();
            let frame = ws.next().await.unwrap().unwrap().into_data();
            // 1 + 16 + 1 + 1 + 2 + 1 + 1 + 11 = 34 header bytes, then payload.
            assert_eq!(frame[0], 0);
            assert_eq!(&frame[34..], b"hello");
            let mut reply = vec![0u8, 0u8];
            reply.extend_from_slice(b"world");
            ws.send(Message::Binary(reply)).await.unwrap();
            ws.flush().await.unwrap();
            host
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: vless\nserver: '127.0.0.1'\nport: {port}\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: ws\ntls: false\nws-path: ws\nsni: example.com\n"
        ))
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        let mut s = ob
            .dial_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        assert_eq!(server.await.unwrap(), format!("example.com:{port}"));
    }

    /// VLESS over plain XHTTP stream-one: POST + chunked body, VLESS header
    /// merged into the first chunk, chunked response downlink with the VLESS
    /// response header at the start of the body.
    #[tokio::test]
    async fn vless_xhttp_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            // 1. Read until the request head is complete.
            loop {
                let n = tcp.read(&mut buf).await.unwrap();
                assert!(n > 0, "server eof before request head");
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let split = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let head = String::from_utf8_lossy(&req[..split]).to_lowercase();
            assert!(head.starts_with("post /xhttp-t http/1.1"), "head: {head}");
            assert!(head.contains("transfer-encoding: chunked"), "head: {head}");
            assert!(head.contains("host: example.com"), "head: {head}");

            // 2. Read the first chunk size line, then exactly `size` bytes.
            let size = loop {
                if let Some(pos) = req[split..].windows(2).position(|w| w == b"\r\n") {
                    let s = String::from_utf8_lossy(&req[split..split + pos]).to_string();
                    let sz = usize::from_str_radix(&s, 16).unwrap();
                    let need = split + pos + 2 + sz;
                    while req.len() < need {
                        let n = tcp.read(&mut buf).await.unwrap();
                        assert!(n > 0, "server eof inside first chunk");
                        req.extend_from_slice(&buf[..n]);
                    }
                    break sz;
                }
                let n = tcp.read(&mut buf).await.unwrap();
                assert!(n > 0, "server eof before chunk size");
                req.extend_from_slice(&buf[..n]);
            };
            let size_end = req[split..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap();
            let data_start = split + size_end + 2;
            let data = &req[data_start..data_start + size];
            assert_eq!(data[0], 0, "vless version");
            assert_eq!(&data[34..], b"hello");

            // Chunked reply: VLESS response header ([0,0]) + payload.
            let payload = [&[0u8, 0u8][..], b"world".as_slice()].concat();
            let mut reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            reply.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
            reply.extend_from_slice(&payload);
            reply.extend_from_slice(b"\r\n0\r\n\r\n");
            tcp.write_all(&reply).await.unwrap();
            tcp.flush().await.unwrap();
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: vless\nserver: '127.0.0.1'\nport: {port}\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: xhttp\ntls: false\nxhttp-path: /xhttp-t\nxhttp-host: example.com\nxhttp-mode: stream-one\n"
        ))
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        let mut s = ob
            .dial_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        server.await.unwrap();
    }

    /// VLESS + xhttp packet-up 回环：GET 长轮询下行（VLESS 响应头在 body
    /// 开头被剥离），上行 VLESS 头 + payload 经分包 POST 发出。
    /// 无 TLS → hyper 客户端走 HTTP/1.1（与 Xray 无 TLS 行为一致）。
    #[tokio::test]
    async fn vless_xhttp_packet_up_roundtrip() {
        use http_body_util::{BodyExt, Full};
        use hyper::service::service_fn;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(tcp),
                            service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                                if req.method() == hyper::Method::GET {
                                    // 下行：VLESS 响应头 [0,0] + payload。
                                    let payload = [&[0u8, 0u8][..], b"world".as_slice()].concat();
                                    let resp = hyper::Response::builder()
                                        .status(hyper::StatusCode::OK)
                                        .body(Full::new(bytes::Bytes::from(payload)))
                                        .unwrap();
                                    Ok::<_, std::io::Error>(resp)
                                } else {
                                    // 上行 POST：读完 body，返回 200。
                                    let body = req.into_body().collect().await.unwrap();
                                    let body = body.to_bytes();
                                    // 第一个 POST 应携带 VLESS 请求头 + 首段 payload。
                                    if !body.is_empty() {
                                        assert_eq!(body[0], 0, "vless version");
                                    }
                                    let resp = hyper::Response::builder()
                                        .status(hyper::StatusCode::OK)
                                        .body(Full::new(bytes::Bytes::new()))
                                        .unwrap();
                                    Ok(resp)
                                }
                            }),
                        )
                        .await;
                });
            }
        });

        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "type: vless\nserver: '127.0.0.1'\nport: {port}\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: xhttp\ntls: false\nxhttp-path: /xh\nxhttp-host: example.com\nxhttp-mode: packet-up\n"
        ))
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::PacketUp);
        let mut s = ob
            .dial_tcp("1.2.3.4:443".parse().unwrap(), Some("example.com"))
            .await
            .unwrap();
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 16];
        let n = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
        drop(s);
        server.abort();
    }

    /// flow addon：请求头携带 protobuf Flow 字段；非法组合在 new() 阶段 fail-fast。
    #[tokio::test]
    async fn vless_flow_header_and_gating() {
        let uuid = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let hdr = build_vless_header(
            &uuid,
            Some("example.com"),
            "1.2.3.4:443".parse().unwrap(),
            VLESS_CMD_TCP,
            Some("xtls-rprx-vision"),
        );
        // [ver 1][uuid 16][addon_len 1][0x0a][16][flow 16][cmd 1][port 2][atyp+addr...]
        assert_eq!(hdr[0], 0);
        assert_eq!(&hdr[1..17], uuid.as_bytes());
        assert_eq!(hdr[17], 18, "addon = tag(1) + len(1) + flow(16)");
        assert_eq!(hdr[18], 0x0a);
        assert_eq!(hdr[19], 16);
        assert_eq!(&hdr[20..36], b"xtls-rprx-vision");
        assert_eq!(hdr[36], VLESS_CMD_TCP);

        // 无 flow 时 addon_len 必须为 0（与旧行为一致）。
        let hdr = build_vless_header(
            &uuid,
            Some("example.com"),
            "1.2.3.4:443".parse().unwrap(),
            VLESS_CMD_TCP,
            None,
        );
        assert_eq!(hdr[17], 0);

        // gating: flow + ws → new() 直接报错
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: ws\nflow: xtls-rprx-vision\n",
        )
        .unwrap();
        assert!(VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(), "flow+ws must fail fast");

        // gating: 未支持的 flow 值 → new() 直接报错
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: tcp\ntls: true\nflow: xtls-rprx-direct\n",
        )
        .unwrap();
        assert!(VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(), "unknown flow must fail fast");

        // gating: REALITY + ws → new() 直接报错
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: ws\nsni: example.com\nreality-public-key: q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s\n",
        )
        .unwrap();
        assert!(VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(), "reality+ws must fail fast");
    }

    /// vless + tcp + tls + flow：构造成功，vision 生效（无需真实服务器）。
    #[tokio::test]
    async fn vless_flow_config_parses() {
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: tcp\ntls: true\nsni: example.com\nflow: xtls-rprx-vision\n",
        )
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    /// XHTTP + REALITY must resolve without the plain-rustls connector being
    /// built (config sanity; a full handshake needs a REALITY server).
    #[tokio::test]
    async fn vless_reality_xhttp_config_parses() {
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: xhttp\ntls: true\nsni: example.com\nreality-public-key: q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s\nreality-short-id: '0123abcd'\nxhttp-path: /xh\n",
        )
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert!(ob.opts.reality.is_some(), "reality must be enabled");
        assert!(ob.opts.tls, "reality implies tls");
        assert!(
            ob.tls_config.is_none(),
            "rustls connector must be skipped under REALITY"
        );
        assert_eq!(ob.opts.xhttp.as_ref().unwrap().path, "/xh");
        assert_eq!(ob.opts.xhttp.as_ref().unwrap().host, "example.com");
        // auto + REALITY → stream-one（Xray REALITY 默认模式）
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::StreamOne);
    }

    /// client-fingerprint：合法值解析为 uTLS 指纹，非法值 fail-fast。
    #[tokio::test]
    async fn vless_utls_config() {
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: tcp\ntls: true\nsni: example.com\nclient-fingerprint: chrome\n",
        )
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.utls, Some(UtlsFingerprint::Chrome));
        // 未配置 ALPN 时，utls 用浏览器默认 [h2, http/1.1]，rustls config 同步。
        assert_eq!(ob.opts.tls_alpn, vec!["h2", "http/1.1"]);
        assert!(ob.tls_config.is_some());

        // 非法值 fail-fast
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: tcp\ntls: true\nclient-fingerprint: nosuch\n",
        )
        .unwrap();
        assert!(
            VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(),
            "unknown client-fingerprint must fail fast"
        );

        // ws + utls：ALPN 强制 http/1.1（伪造 hello 与 rustls config 一致）
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: ws\ntls: true\nsni: example.com\nclient-fingerprint: firefox\n",
        )
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.tls_alpn, vec!["http/1.1"]);
    }

    /// xhttp 运行模式解析（对齐 Xray dialer.go：auto → packet-up）。
    #[tokio::test]
    async fn vless_xhttp_mode_resolution() {
        let base = "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: xhttp\ntls: true\nsni: example.com\nxhttp-path: /xh\n";

        // 显式 packet-up
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}xhttp-mode: packet-up\n")).unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::PacketUp);
        // packet-up 需要 h2 TLS 配置
        assert!(ob.opts.xhttp_h2_tls.is_some());

        // 显式 stream-up
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}xhttp-mode: stream-up\n")).unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::StreamUp);

        // 显式 stream-one：不建 h2 TLS 配置
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}xhttp-mode: stream-one\n")).unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::StreamOne);
        assert!(ob.opts.xhttp_h2_tls.is_none());

        // auto（无 REALITY）→ packet-up
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}xhttp-mode: auto\n")).unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::PacketUp);

        // 未知模式 fail-fast
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}xhttp-mode: bogus\n")).unwrap();
        assert!(
            VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(),
            "unknown xhttp-mode must fail fast"
        );

        // packet-up + REALITY fail-fast；auto + REALITY → stream-one
        let reality = "reality-public-key: q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s\n";
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}xhttp-mode: packet-up\n{reality}")).unwrap();
        assert!(
            VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(),
            "packet-up + REALITY must fail fast"
        );
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}xhttp-mode: auto\n{reality}")).unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert_eq!(ob.opts.xhttp_resolved, XhttpResolved::StreamOne);
    }

    /// 合成一条最小合法 ECHConfigList（X25519 + HKDF-SHA256/AES-128-GCM，
    /// 与 `ECH_HPKE_SUITES` 兼容），供 rustls `EchConfig::new` 选择。
    fn test_ech_config_list() -> Vec<u8> {
        let pk = vec![0x42u8; 32];
        let mut contents = Vec::new();
        contents.push(0x01); // config_id
        contents.extend_from_slice(&0x0020u16.to_be_bytes()); // DHKEM_X25519_HKDF_SHA256
        contents.extend_from_slice(&(pk.len() as u16).to_be_bytes());
        contents.extend_from_slice(&pk);
        let suite = [0x0001u16.to_be_bytes(), 0x0001u16.to_be_bytes()].concat();
        contents.extend_from_slice(&(suite.len() as u16).to_be_bytes());
        contents.extend_from_slice(&suite);
        contents.push(0); // maximum_name_length
        let pn = b"cloudflare-ech.com";
        contents.push(pn.len() as u8);
        contents.extend_from_slice(pn);
        contents.extend_from_slice(&0u16.to_be_bytes()); // extensions

        let mut ech_config = 0xfe0du16.to_be_bytes().to_vec();
        ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        ech_config.extend_from_slice(&contents);

        let mut list = (ech_config.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&ech_config);
        list
    }

    /// build_tls_client_config：ECH 配置能被本地 HPKE suite 选中，
    /// 产出 ECH-enabled（TLS 1.3-only）ClientConfig。
    #[test]
    fn tls_client_config_with_ech() {
        let list = test_ech_config_list();
        let ech = EchConfig::new(EchConfigListBytes::from(list.clone()), ECH_HPKE_SUITES)
            .expect("local HPKE suites must match the synthetic config");
        // with_ech 内部强制 TLS 1.3-only（with_protocol_versions(&[TLS13])），
        // 与本地 ring provider 组合能成功产出 ClientConfig 即验证了整条链路。
        let _cfg = build_tls_client_config(true, &[], Some(&ech)).expect("build");

        // 非 ECH 路径不受影响。
        let _plain = build_tls_client_config(false, &[], None).expect("build plain");
    }

    /// ECH 门控：ech + REALITY / ech + uTLS / ech + tls=false 在构建期 fail-fast；
    /// ech + inline ech-config 构建成功且 opts.ech 已设置。
    #[tokio::test]
    async fn vless_ech_gating_and_wiring() {
        let base = "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: tcp\ntls: true\nsni: example.com\n";

        // ech + reality-public-key → fail
        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "{base}ech: true\nreality-public-key: q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s\n"
        ))
        .unwrap();
        assert!(
            VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(),
            "ech + reality must fail fast"
        );

        // ech + client-fingerprint → fail
        let cfg: ProxyConfig =
            serde_yaml::from_str(&format!("{base}ech: true\nclient-fingerprint: chrome\n"))
                .unwrap();
        assert!(
            VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(),
            "ech + utls must fail fast"
        );

        // ech + tls=false → fail
        let cfg: ProxyConfig = serde_yaml::from_str(
            "type: vless\nserver: '1.2.3.4'\nport: 443\nuuid: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\nnetwork: tcp\ntls: false\nech: true\n",
        )
        .unwrap();
        assert!(
            VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(),
            "ech without tls must fail fast"
        );

        // ech 启用但无任何配置来源（无 inline/path、无 DNS upstream）→ fail
        let cfg: ProxyConfig = serde_yaml::from_str(&format!("{base}ech: true\n")).unwrap();
        assert!(
            VlessOutbound::new_with_ech_dns(&cfg, &[]).await.is_err(),
            "ech without config source must fail fast"
        );

        // ech + inline ech-config（PEM）→ 构建成功，opts.ech 生效。
        let b64 = {
            // 与 test_ech_config_list 相同字节的 base64。
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(test_ech_config_list())
        };
        let pem = format!("-----BEGIN ECH CONFIGS-----\n{b64}\n-----END ECH CONFIGS-----\n");
        let cfg: ProxyConfig = serde_yaml::from_str(&format!(
            "{base}ech: true\nech-config: {:?}\n",
            pem
        ))
        .unwrap();
        let ob = VlessOutbound::new_with_ech_dns(&cfg, &[]).await.unwrap();
        assert!(ob.opts.ech.is_some(), "ech must be resolved from inline config");
        assert!(ob.tls_config.is_some());
    }
}
