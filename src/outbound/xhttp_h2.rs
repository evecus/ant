//! XHTTP packet-up / stream-up 模式 — ported from reflex
//! `src/outbound/transport/xhttp.rs`（对齐 Xray dialer.go / client.go）。
//!
//! 与 `super::xhttp`（手写 HTTP/1.1 stream-one）互补：
//!
//! * `stream-one`：单条 POST 双向流（见 `super::xhttp`，支持 REALITY）。
//! * `packet-up`：GET 长轮询下行 + 每包一个 POST 上行（可攒批拆分）。
//! * `stream-up`：GET 长轮询下行 + 单条流式 POST 上行。
//!
//! 本模块基于 hyper 客户端：TLS 时强制 ALPN=h2（三种模式依赖 HTTP/2 流式
//! 语义，与 Xray `downloadSettings.streamSettings` 一致）；无 TLS 时 HTTP/1.1
//! （与 Xray `http.Transport` 行为一致）。支持 uTLS 指纹（可选）。
//!
//! REALITY 不经此模块：REALITY 是自实现 TLS 1.3，hyper 连接器无法承载；
//! REALITY 下的 xhttp 固定走 stream-one（Xray 对 REALITY 的默认模式）。

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use anyhow::Context as _;
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header::{HeaderName, HeaderValue, HOST},
    Method, Request, StatusCode, Uri,
};
use hyper_util::{
    client::legacy::Client,
    rt::TokioExecutor,
};
// StreamExt 供 ReceiverStream.map 使用（产生 futures::stream::Map，与
// XhttpBody::Stream 的类型声明一致）。
use futures::StreamExt as _;
use portable_atomic::AtomicI64;
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use tower::Service;
use tracing::{debug, warn};
use uuid::Uuid;

use super::utls::{connect_utls, UtlsFingerprint};

// ── 公共接口 ─────────────────────────────────────────────────────────────────

/// TLS 设置（调用方已把 ALPN 强制为 h2 的 rustls ClientConfig）。
pub struct XhttpH2Tls {
    pub config: Arc<rustls::ClientConfig>,
    /// TLS SNI / 证书校验名（server 字段是 IP 但证书签发给域名时必需）。
    pub server_name: String,
    /// 可选 uTLS 指纹（对握手连接生效；连接由 hyper 连接池复用，指纹一致）。
    pub utls: Option<UtlsFingerprint>,
}

/// 建立一条 XHTTP 双工流（packet-up 或 stream-up）。
///
/// `mode` 必须已被调用方解析为 `"packet-up"` 或 `"stream-up"`。
pub async fn connect(
    server: &str,
    port: u16,
    host: &str,
    path: &str,
    mode: &str,
    headers: &HashMap<String, String>,
    tls: Option<XhttpH2Tls>,
) -> anyhow::Result<XhttpStream> {
    anyhow::ensure!(
        mode == "packet-up" || mode == "stream-up",
        "xhttp_h2: unsupported mode {mode:?} (only packet-up / stream-up)"
    );

    let tls_enabled = tls.is_some();
    let scheme = if tls_enabled { "https" } else { "http" };

    let (path_part, query) = split_path_query(path);
    // URL host 用真实 server（连接目标）；Host 头用 xhttp-host/SNI（CDN 场景）。
    let base_url = format!("{scheme}://{server}:{port}{path_part}");

    let client = build_http_client(tls.as_ref())?;

    // stream-one 无 session；packet-up/stream-up 每条连接一个 session（路径携带）。
    let session_id = Some(Uuid::new_v4().to_string());

    debug!(mode, %base_url, ?session_id, "xhttp_h2 connecting");

    let mut hdrs = headers.clone();
    hdrs.entry("Host".to_string()).or_insert_with(|| host.to_string());

    let shared = Arc::new(XhttpShared {
        client,
        base_url,
        query,
        session_id,
        headers: hdrs,
        seq: AtomicI64::new(0),
        // Xray config.go:139-148 / 150-159 默认值：1_000_000 / 30ms。
        max_post_bytes: 1_000_000,
        min_post_interval_ms: 30,
        no_grpc_header: false,
    });

    match mode {
        "stream-up" => connect_stream_up_down(shared).await,
        _ => connect_packet_up(shared).await,
    }
}

// ── hyper 连接器（TCP → TLS[h2, uTLS] | TCP plain）──────────────────────────

#[derive(Clone)]
struct AntConnector {
    tls: Option<(Arc<rustls::ClientConfig>, String, Option<UtlsFingerprint>)>,
}

/// hyper 连接类型：裸 TCP / rustls TLS / uTLS
#[allow(clippy::large_enum_variant)] // 与 reflex MaybeHttps 一致：Tls 变体 >1KB
pub enum MaybeHttps {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
    Utls(Box<tokio_rustls::client::TlsStream<super::utls::UtlsStream>>),
}

impl AsyncRead for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttps::Tls(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttps::Utls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttps::Tls(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttps::Utls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeHttps::Tls(s) => Pin::new(s).poll_flush(cx),
            MaybeHttps::Utls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttps::Tls(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttps::Utls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

impl hyper::rt::Read for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // hyper 的 ReadBufCursor 内部是 MaybeUninit<u8>，不能强转为 &[u8]：
        // 未初始化字节被当作 u8 属于 UB（Rust 的初始化模型禁止）。
        // 改用 tokio::io::ReadBuf::uninit 接受未初始化内存，安全桥接。
        let n = {
            // SAFETY: as_mut 返回未初始化的 spare 内存，我们只把它传给
            // ReadBuf::uninit（不读取其内容），poll_read 填充后按实际填充
            // 字节数 advance，不访问未初始化部分。
            let spare = unsafe { buf.as_mut() };
            let mut rb = ReadBuf::uninit(spare);
            match AsyncRead::poll_read(self, cx, &mut rb) {
                Poll::Ready(Ok(())) => rb.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        // SAFETY: n 为 poll_read 实际写入 rb 的字节数，advance 不超过已初始化范围
        unsafe { buf.advance(n) };
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(self, cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for MaybeHttps {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl Service<Uri> for AntConnector {
    type Response = MaybeHttps;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = anyhow::Result<MaybeHttps>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls = self.tls.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| anyhow::anyhow!("xhttp: missing host in URI"))?;
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") { 443 } else { 80 });

            // DNS 解析（与 vless resolve_server 一致，走系统解析）。
            let addr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                std::net::SocketAddr::new(ip, port)
            } else {
                let mut addrs = tokio::net::lookup_host((host, port))
                    .await
                    .with_context(|| format!("xhttp: resolve {host}"))?;
                addrs
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("xhttp: no address for {host}"))?
            };

            let tcp = crate::app::sockopt::connect_tcp(addr)
                .await
                .with_context(|| format!("xhttp tcp connect {addr}"))?;
            let _ = tcp.set_nodelay(true);

            if let Some((cfg, server_name, utls)) = tls {
                let sni_str = server_name.as_str();
                if let Some(fp) = utls {
                    let stream = connect_utls(tcp, sni_str, &fp, cfg, &["h2".to_string()])
                        .await
                        .map_err(|e| anyhow::anyhow!("xhttp: utls handshake failed: {e}"))?;
                    return Ok(MaybeHttps::Utls(Box::new(stream)));
                }
                let sni = rustls::pki_types::ServerName::try_from(sni_str.to_string())
                    .map_err(|e| anyhow::anyhow!("xhttp: invalid SNI {sni_str}: {e}"))?;
                let connector = tokio_rustls::TlsConnector::from(cfg);
                let tls_stream = connector
                    .connect(sni, tcp)
                    .await
                    .map_err(|e| anyhow::anyhow!("xhttp: TLS handshake failed: {e}"))?;
                return Ok(MaybeHttps::Tls(tls_stream));
            }

            Ok(MaybeHttps::Plain(tcp))
        })
    }
}

type XhttpClient = Client<AntConnector, XhttpBody>;

/// 上行 body 类型：可以是空 body、固定字节、或流式 channel
enum XhttpBody {
    Empty(Empty<Bytes>),
    Full(Full<Bytes>),
    #[allow(clippy::type_complexity)]
    Stream(
        StreamBody<
            futures::stream::Map<
                ReceiverStream<Bytes>,
                fn(Bytes) -> Result<Frame<Bytes>, io::Error>,
            >,
        >,
    ),
}

impl hyper::body::Body for XhttpBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            // Empty/Full 的 Infallible 错误不可能发生
            XhttpBody::Empty(b) => Pin::new(b)
                .poll_frame(cx)
                .map_err(|e: Infallible| match e {}),
            XhttpBody::Full(b) => Pin::new(b)
                .poll_frame(cx)
                .map_err(|e: Infallible| match e {}),
            XhttpBody::Stream(b) => Pin::new(b).poll_frame(cx),
        }
    }
}

fn stream_body(rx: mpsc::Receiver<Bytes>) -> XhttpBody {
    fn wrap(b: Bytes) -> Result<Frame<Bytes>, io::Error> {
        Ok(Frame::data(b))
    }
    XhttpBody::Stream(StreamBody::new(
        ReceiverStream::new(rx).map(wrap as fn(Bytes) -> Result<Frame<Bytes>, io::Error>),
    ))
}

// ── 内部共享状态 ──────────────────────────────────────────────────────────────

struct XhttpShared {
    client: XhttpClient,
    base_url: String,
    /// URL query string（从 `path` 中 `?` 后分离，与 Xray `GetNormalizedQuery`
    /// 对齐）。session_id/seq 追加到 path，query 追加到 URL 末尾。
    query: String,
    session_id: Option<String>,
    headers: HashMap<String, String>,
    seq: AtomicI64,
    max_post_bytes: usize,
    min_post_interval_ms: u64,
    /// 禁用 `Content-Type: application/grpc` 头（Xray `NoGRPCHeader`）。
    /// Xray config.go:325-327：stream-up/one（有 body 时）默认设置 grpc 头，
    /// 服务端据此识别为流式上行。ant 固定 false（保持 Xray 默认行为）。
    no_grpc_header: bool,
}

impl XhttpShared {
    fn apply_headers(&self, mut req: Request<XhttpBody>) -> Request<XhttpBody> {
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                req.headers_mut().insert(name, val);
            }
        }
        req
    }

    fn stream_url(&self) -> String {
        // Xray xhttp 默认 SessionIDPlacement = PlacementPath，session_id 追加到路径末尾。
        // query 追加到 URL 末尾（与 Xray requestURL.RawQuery 对齐）。
        match &self.session_id {
            Some(sid) => append_query(&format!("{}{}", self.base_url, sid), &self.query),
            None => append_query(&self.base_url, &self.query),
        }
    }

    fn packet_url(&self, seq: i64) -> String {
        // Xray xhttp 默认 SeqPlacement = PlacementPath，seq 追加到 session_id 之后。
        // 格式：{base_url}{session_id}/{seq}?{query}
        match &self.session_id {
            Some(sid) => append_query(
                &format!("{}{}/{}", self.base_url, sid, seq),
                &self.query,
            ),
            None => append_query(&self.base_url, &self.query),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn build_request(
        &self,
        method: &Method,
        url: &str,
        body: XhttpBody,
        has_body: bool,
    ) -> anyhow::Result<Request<XhttpBody>> {
        let uri: Uri = url.parse()?;
        let host = uri.host().unwrap_or("").to_string();
        debug!(%method, %url, host = %host, "xhttp: building HTTP request");
        let req = Request::builder()
            .method(method)
            .uri(uri.clone())
            .header(HOST, &host)
            .body(body)?;
        // apply custom headers（覆盖同名 header）
        let mut req = self.apply_headers(req);

        // 浏览器伪装头：与 Xray `TryDefaultHeadersWith(header, "fetch")`
        // 对齐。用户未设置 `User-Agent` 时，注入 Chrome fetch 风格默认头。
        apply_default_masquerade(&mut req);

        // Content-Type: application/grpc
        // 与 Xray config.go:325-327 对齐：有 body 的请求（stream-one、stream-up）
        // 默认设置 grpc 头，服务端据此识别为流式上行。no_grpc_header=true 时跳过。
        if !self.no_grpc_header && has_body {
            req.headers_mut()
                .insert("content-type", HeaderValue::from_static("application/grpc"));
        }

        // XPadding：Xray xhttp 默认要求每个请求带 100-1000 字节 padding，
        // 放在 Referer 头的 query string 里（key=x_padding）。
        // 参考 Xray xpadding.go：
        //   - GetNormalizedXPaddingBytes 默认 {From:100, To:1000}
        //   - ApplyXPaddingToHeader: PlacementQueryInHeader, header="Referer", key="x_padding"
        //   - GeneratePadding: 默认方法生成全 'X' 字符串
        //
        // Referer URL 使用 base path（不含 session_id/seq），与 Xray 的填充顺序
        // 一致：Xray 先 ApplyXPaddingToRequest（此时 URL path 仅为 normalized
        // path），后 ApplyMetaToRequest（追加 session/seq 到 path）。
        let mut rng = rand::thread_rng();
        let padding_len: usize = rng.gen_range(100..=1000);
        let padding = generate_padding(padding_len);
        let scheme = uri.scheme_str().unwrap_or("https");
        // Referer host 使用 Host 头值（域名），而非连接 IP（server）。
        let referer_host = self
            .headers
            .get("Host")
            .map(|s| s.as_str())
            .or_else(|| uri.authority().map(|a| a.as_str()))
            .unwrap_or("");
        // base_path 从 base_url 提取（不含 session_id/seq）。
        let base_path = self
            .base_url
            .parse::<Uri>()
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| "/".to_string());
        let referer_value = format!("{scheme}://{referer_host}{base_path}?x_padding={padding}");
        if let Ok(val) = HeaderValue::from_str(&referer_value) {
            req.headers_mut().insert("referer", val);
        }
        debug!(padding_len, "xhttp: applied XPadding to Referer header");

        Ok(req)
    }
}

// ── 模式：stream-up + 独立 GET 下行 ─────────────────────────────────────────

async fn connect_stream_up_down(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(
        &Method::GET,
        &down_url,
        XhttpBody::Empty(Empty::new()),
        false,
    )?;
    debug!("xhttp stream-up: sending GET download request");
    let down_resp = shared.client.request(req).await?;
    debug!(status = %down_resp.status(), "xhttp stream-up: download response received");
    check_status(down_resp.status(), "stream-down")?;

    // 关闭信号：上传 POST 失败时通知下行读取器返回错误。
    // 与 Xray client.go:86-92 对齐：uploadOnly 的 OpenStream 在失败/非200 时
    // 调用 wrc.Close()，使 download 侧的 Read 返回 io.ErrClosedPipe。
    let close_flag = Arc::new(AtomicBool::new(false));
    let read_half =
        RespBodyReader::with_close_flag(down_resp.into_body(), Some(close_flag.clone()));

    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let up_url = shared.stream_url();
    let req = shared.build_request(&Method::POST, &up_url, stream_body(body_rx), true)?;
    {
        let client = shared.client.clone();
        tokio::spawn(async move {
            debug!("xhttp stream-up: sending POST upload request (background)");
            let failed = match client.request(req).await {
                Ok(resp) => {
                    debug!(status = %resp.status(), "xhttp stream-up: upload response received");
                    // 4xx/5xx 表示服务端拒绝上行
                    match check_status(resp.status(), "stream-up") {
                        Ok(()) => false,
                        Err(e) => {
                            warn!("xhttp stream-up POST rejected: {e}");
                            true
                        }
                    }
                }
                Err(e) => {
                    warn!("xhttp stream-up POST failed: {e}");
                    true
                }
            };
            if failed {
                // 通知下行读取器：上行已断开，关闭连接（避免连接假死）。
                close_flag.store(true, Ordering::Relaxed);
            }
        });
    }

    debug!("xhttp stream-up: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式：packet-up（默认）──────────────────────────────────────────────────

async fn connect_packet_up(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(
        &Method::GET,
        &down_url,
        XhttpBody::Empty(Empty::new()),
        false,
    )?;
    debug!("xhttp packet-up: sending GET download request");
    let down_resp = shared.client.request(req).await?;
    debug!(status = %down_resp.status(), "xhttp packet-up: download response received");
    check_status(down_resp.status(), "packet-up/stream-down")?;
    let read_half = RespBodyReader::new(down_resp.into_body());

    let (up_tx, mut up_rx) = mpsc::channel::<Bytes>(128);
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut last_post = tokio::time::Instant::now();
            debug!(
                max_post_bytes = shared.max_post_bytes,
                min_post_interval_ms = shared.min_post_interval_ms,
                "xhttp packet-up: upload loop started"
            );

            // 批处理缓冲区：与 Xray dialer.go:490-568 的 pipe 机制对齐。
            //
            // Xray 使用 size-limited pipe：多个 Write 调用积累在 pipe 中，
            // 读循环通过 ReadMultiBuffer 一次性读出所有已缓冲数据，
            // 然后按 maxUploadSize 拆分成多个 POST。这样多个小写
            // （如 TLS 握手、VLESS 头）被合并为一个大 POST，大幅提升带宽。
            //
            // 实现：从 channel 攒数据到 buffer，直到：
            //   1. buffer 达到 max_post_bytes（满了，必须发），或
            //   2. channel 暂时无数据（try_recv 失败），立即发送已缓冲的数据
            //      （不等待攒满，避免延迟——对齐 Xray ReadMultiBuffer 行为）。
            while let Some(first_chunk) = up_rx.recv().await {
                let mut buffer = BytesMut::new();
                buffer.extend_from_slice(&first_chunk);

                // 尝试攒更多数据，直到达到 max_post_bytes 或 channel 暂时为空
                while buffer.len() < shared.max_post_bytes {
                    match up_rx.try_recv() {
                        Ok(more) => {
                            buffer.extend_from_slice(&more);
                        }
                        Err(_) => {
                            // channel 暂时无数据，立即发送已缓冲的内容
                            break;
                        }
                    }
                }

                // 按 max_post_bytes 拆分发送（与 Xray buf.SplitSize 对齐）
                let mut remaining = buffer.freeze();
                while !remaining.is_empty() {
                    let payload: Bytes = if remaining.len() > shared.max_post_bytes {
                        let split = shared.max_post_bytes;
                        let mut tail = remaining.split_off(split);
                        std::mem::swap(&mut tail, &mut remaining);
                        tail
                    } else {
                        std::mem::take(&mut remaining)
                    };

                    // POST 间隔控制，与 Xray dialer.go:536-538 对齐
                    if shared.min_post_interval_ms > 0 {
                        let elapsed = last_post.elapsed().as_millis() as u64;
                        if elapsed < shared.min_post_interval_ms {
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                shared.min_post_interval_ms - elapsed,
                            ))
                            .await;
                        }
                    }

                    // 与 Xray dialer.go:547-565 对齐：POST 异步发送，
                    // 不等待完整响应即可发送下一个 chunk。
                    let shared_clone = shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) = post_packet(&shared_clone, payload).await {
                            warn!("xhttp packet-up POST error: {e}");
                        }
                    });

                    last_post = tokio::time::Instant::now();
                }
            }
            debug!("xhttp packet-up: upload channel closed, upload loop exiting");
        });
    }

    debug!("xhttp packet-up: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Packet(up_tx)))
}

async fn post_packet(shared: &XhttpShared, payload: Bytes) -> anyhow::Result<()> {
    let seq = shared.seq.fetch_add(1, Ordering::Relaxed);
    let url = shared.packet_url(seq);
    let payload_len = payload.len();
    let req = shared.build_request(&Method::POST, &url, XhttpBody::Full(Full::new(payload)), false)?;
    debug!(seq, payload_len, "xhttp packet-up: POST upload");
    let resp = shared.client.request(req).await?;
    debug!(seq, status = %resp.status(), "xhttp packet-up: POST response");
    check_status(resp.status(), &format!("packet POST {seq}"))
}

// ── 下行响应体读取器 ──────────────────────────────────────────────────────────

struct RespBodyReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
    /// 可选的关闭信号：当上行流（stream-up POST）失败时设置，
    /// 使后续 poll_read 返回 ConnectionReset 错误，通知调用方连接已断开。
    /// 与 Xray client.go:86-92 对齐。
    close_flag: Option<Arc<AtomicBool>>,
}

impl RespBodyReader {
    fn new(body: Incoming) -> Self {
        Self::with_close_flag(body, None)
    }

    fn with_close_flag(
        body: Incoming,
        close_flag: Option<Arc<AtomicBool>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut stream = body;
            loop {
                match stream.frame().await {
                    None => break,
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if tx.send(Ok(data)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!(error = %e, "xhttp download: frame error");
                        let _ = tx
                            .send(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))
                            .await;
                        break;
                    }
                }
            }
        });
        Self {
            rx,
            current: Bytes::new(),
            close_flag,
        }
    }
}

impl AsyncRead for RespBodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 检查上行流是否已失败（stream-up 模式）
        if let Some(flag) = &this.close_flag {
            if flag.load(Ordering::Relaxed) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "xhttp: upload stream failed, closing download",
                )));
            }
        }
        if !this.current.is_empty() {
            let n = buf.remaining().min(this.current.len());
            buf.put_slice(&this.current[..n]);
            this.current = this.current.slice(n..);
            return Poll::Ready(Ok(()));
        }
        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.current = chunk.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ── XhttpStream：对外暴露的双工流 ─────────────────────────────────────────────

pub struct XhttpStream {
    reader: RespBodyReader,
    writer: XhttpWriter,
}

enum XhttpWriter {
    Stream(mpsc::Sender<Bytes>),
    Packet(mpsc::Sender<Bytes>),
}

impl XhttpStream {
    fn new(reader: RespBodyReader, writer: XhttpWriter) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let tx = match &this.writer {
            XhttpWriter::Stream(tx) | XhttpWriter::Packet(tx) => tx.clone(),
        };
        // 用 BytesMut::from(data).split() 复用 inline 优化路径（≤16B 小写零堆分配）。
        let chunk = BytesMut::from(data).split().freeze();
        match tx.try_send(chunk) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    let _ = tx.reserve().await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp: upload channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let (dead_tx, _) = mpsc::channel(1);
        match &mut this.writer {
            XhttpWriter::Stream(tx) => *tx = dead_tx,
            XhttpWriter::Packet(tx) => *tx = dead_tx,
        }
        Poll::Ready(Ok(()))
    }
}

// ── HTTP Client 构建 ──────────────────────────────────────────────────────────

fn build_http_client(tls: Option<&XhttpH2Tls>) -> anyhow::Result<XhttpClient> {
    let rustls_cfg = tls.map(|t| {
        (
            t.config.clone(),
            t.server_name.clone(),
            t.utls,
        )
    });

    let connector = AntConnector { tls: rustls_cfg };

    // HTTP 版本选择，与 Xray dialer.go:84-101 decideHTTPVersion 对齐：
    //   - 有 TLS（含 REALITY）→ HTTP/2（ALPN 已强制 h2）
    //   - 无 TLS → HTTP/1.1
    let client = if tls.is_some() {
        Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build(connector)
    } else {
        Client::builder(TokioExecutor::new()).build(connector)
    };

    Ok(client)
}

// ── 辅助函数 ─────────────────────────────────────────────────────────────────

/// 生成 padding 字符串。默认使用 `repeat-x`（全 'X'），与 Xray
/// `GeneratePadding` 默认方法一致。'X' 在 HPACK Huffman 编码中占 8 位，
/// 压缩后不改变实际 padding 长度（RFC 7541 / RFC 9204）。
fn generate_padding(len: usize) -> String {
    "X".repeat(len)
}

/// 计算当前 Chrome 主版本号，与 Xray `ChromeVersion()` 对齐：
/// 从 2026-01-13 Chrome 144 起，每 ~35 天递增一个大版本，
/// 引入随机抖动模拟 Xray 的 PRNG 行为。
/// Xray common/utils/browser.go:25-32
fn chrome_major_version() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 2026-01-13 00:00 UTC = epoch day 20466
    const DAYS_START_2026_01_13: i64 = 20466;
    const START_VERSION: i64 = 144;
    const CADENCE_DAYS: i64 = 35;

    let days_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0);

    let mut rng = rand::thread_rng();
    let jitter = (rng.gen::<f64>().powi(2) * 105.0).floor() as i64;
    let time_diff = (days_now - DAYS_START_2026_01_13 - 35) - jitter;
    (START_VERSION + (time_diff.max(0) / CADENCE_DAYS)) as u32
}

/// 构造 Chrome User-Agent 字符串，与 Xray `ChromeUA` 格式一致。
fn chrome_user_agent() -> String {
    let ver = chrome_major_version();
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"
    )
}

/// 构造 Sec-CH-UA 头值，与 Xray `getGreasedChUa(version, "chrome")` 格式一致。
/// 包含一个 GREASE 无效品牌 + Chromium + Google Chrome。
fn sec_chua_value() -> String {
    let ver = chrome_major_version();
    format!(
        "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"{ver}\", \"Google Chrome\";v=\"{ver}\""
    )
}

/// 注入浏览器伪装头，与 Xray `TryDefaultHeadersWith(header, "fetch")` +
/// `applyMasqueradedHeaders(header, "chrome", "fetch")` 完全对齐。
///
/// 仅当请求未设置 `User-Agent` 时注入。注入后流量特征与 Chrome 浏览器
/// fetch 请求一致：
/// - chrome 头：User-Agent、Sec-CH-UA、Sec-CH-UA-Mobile、Sec-CH-UA-Platform、
///   DNT、Accept-Language（覆盖同名头）
/// - fetch 头：Sec-Fetch-Mode、Sec-Fetch-Dest、Sec-Fetch-Site（覆盖），
///   Priority、Cache-Control、Pragma、Accept（仅当未设置时填充）
fn apply_default_masquerade(req: &mut Request<XhttpBody>) {
    let headers = req.headers();
    let has_ua = headers.contains_key("user-agent");
    if has_ua {
        return;
    }

    let h = req.headers_mut();
    // ── chrome masquerade（覆盖）──
    h.insert(
        "user-agent",
        HeaderValue::from_str(&chrome_user_agent()).unwrap(),
    );
    h.insert(
        "sec-ch-ua",
        HeaderValue::from_str(&sec_chua_value()).unwrap(),
    );
    h.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    h.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
    h.insert("dnt", HeaderValue::from_static("1"));
    h.insert("accept-language", HeaderValue::from_static("en-US,en;q=0.9"));

    // ── fetch variant ──
    // Sec-Fetch-* 覆盖（与 Xray header.Set 一致）
    h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    // 以下仅当未设置时填充（与 Xray `if header.Get(x) == ""` 一致）
    if !h.contains_key("priority") {
        h.insert("priority", HeaderValue::from_static("u=1, i"));
    }
    if !h.contains_key("cache-control") {
        h.insert("cache-control", HeaderValue::from_static("no-cache"));
    }
    if !h.contains_key("pragma") {
        h.insert("pragma", HeaderValue::from_static("no-cache"));
    }
    if !h.contains_key("accept") {
        h.insert("accept", HeaderValue::from_static("*/*"));
    }
}

fn check_status(status: StatusCode, ctx: &str) -> anyhow::Result<()> {
    if status.is_success() {
        debug!(status = %status, ctx, "xhttp: HTTP status ok");
        Ok(())
    } else {
        warn!(status = %status, ctx, "xhttp: HTTP status error");
        anyhow::bail!("xhttp {ctx}: server returned {status}")
    }
}

/// 将 path 拆分为路径和 query 两部分，与 Xray `GetNormalizedPath`/
/// `GetNormalizedQuery` 对齐。用户配置 `path: "/xhttp?token=abc"` 时，
/// path=`/xhttp/`，query=`token=abc`。
fn split_path_query(raw: &str) -> (String, String) {
    let (path_part, query_part) = match raw.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw, ""),
    };
    (normalize_path(path_part), query_part.to_string())
}

/// 确保路径以 '/' 开头，并以 '/' 结尾（与 Xray 行为一致）。
/// 仅处理 path 部分，不处理 query string（由 `split_path_query` 分离）。
fn normalize_path(path: &str) -> String {
    let p = if path.is_empty() || !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    if !p.ends_with('/') {
        format!("{p}/")
    } else {
        p
    }
}

/// 追加 query 到 URL，若 query 为空则原样返回。
fn append_query(url: &str, query: &str) -> String {
    if query.is_empty() {
        url.to_string()
    } else {
        format!("{url}?{query}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("ws"), "/ws/");
        assert_eq!(normalize_path("/ws"), "/ws/");
        assert_eq!(normalize_path("/ws/"), "/ws/");
        assert_eq!(normalize_path("/a/b"), "/a/b/");
    }

    #[test]
    fn test_split_path_query() {
        // 无 query
        assert_eq!(split_path_query("/ws/"), ("/ws/".to_string(), "".to_string()));
        assert_eq!(split_path_query("/ws"), ("/ws/".to_string(), "".to_string()));
        // 有 query
        assert_eq!(
            split_path_query("/ws?token=abc"),
            ("/ws/".to_string(), "token=abc".to_string())
        );
        // 空路径
        assert_eq!(split_path_query(""), ("/".to_string(), "".to_string()));
        assert_eq!(split_path_query("?q=1"), ("/".to_string(), "q=1".to_string()));
    }

    #[test]
    fn test_append_query() {
        assert_eq!(append_query("https://h/p", ""), "https://h/p");
        assert_eq!(
            append_query("https://h/p", "token=abc"),
            "https://h/p?token=abc"
        );
    }

    #[test]
    fn test_generate_padding() {
        let p = generate_padding(100);
        assert_eq!(p.len(), 100);
        assert!(p.chars().all(|c| c == 'X'));
    }

    #[test]
    fn test_chrome_major_version_reasonable() {
        let v = chrome_major_version();
        // 2026-08 应在 144-160 范围内
        assert!((144..=160).contains(&v), "chrome version {v} out of range");
    }

    #[test]
    fn test_chrome_user_agent_format() {
        let ua = chrome_user_agent();
        assert!(ua.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
        assert!(ua.contains("Chrome/"));
        assert!(ua.contains("Safari/537.36"));
    }

    #[test]
    fn test_sec_chua_value_format() {
        let v = sec_chua_value();
        assert!(v.contains("Chromium"));
        assert!(v.contains("Google Chrome"));
        assert!(v.contains("Not/A)Brand"));
    }
}
