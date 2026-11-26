//! VLESS/Trojan XHTTP over HTTP/3 (QUIC) — 全模式客户端（stream-one /
//! packet-up / stream-up）。
//!
//! 对齐 Xray `transport/internet/splithttp/dialer.go` 的 H3 分支：H3 只是
//! 传输层不同（QUIC 承载 HTTP/3），三种模式语义与 h1/h2 完全一致：
//!
//! * `stream-one`：单条 POST 双向流：
//!   - 请求头：一条双向流的 HEADERS 帧（QPACK，零动态表引用）
//!   - 上行：应用数据直接写 DATA 帧（HTTP/3 无 chunked 语义，
//!     服务端 HTTP 层拿到的就是原始 body，与 h1/h2 的解码结果一致）
//!   - 下行：响应 HEADERS（校验 :status 2xx）后的 DATA 帧流
//!   - 写关闭：FIN（quinn finish），等价于 h1 的终止块
//! * `stream-up`：GET 长轮询下行 + 单条流式 POST 上行（各自的双向流）。
//! * `packet-up`：GET 长轮询下行 + 攒批分包 POST 上行（每包一条双向流，
//!   seq 由上传循环同步分配，服务端按 seq 重排）。
//!
//! padding：每个请求都带 `Referer: https://{host}{base}?x_padding=XXX...`
//! （对齐 Xray `FillStreamRequest`/`FillPacketRequest`；当前 Xray / flux /
//! shoes 服务端会 400 拒绝无 padding 请求）。
//!
//! 复用 hy2_h3 的手写 H3 原语（不引入 h3/h3-quinn crate，与项目
//! "minimal H3 client" 的取舍一致）。服务端侧已由 flux 的
//! `xhttp_h3`（h3 crate）实现，两端帧语义对齐。

use anyhow::{anyhow, Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context as TaskCtx, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::hysteria2::hy2_h3::{
    open_h3_control_streams, parse_headers_from_qpack, put_literal_header, read_h3_frame,
    write_varint, H3_FRAME_DATA, H3_FRAME_HEADERS,
};
use super::xhttp::padding_referer_value;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 下行 DATA 泵的 channel 容量（背压上限，单位：帧）。
const DOWNLINK_BUFFER: usize = 64;
/// packet-up 上行攒批 channel 容量（与 `super::xhttp_h2` 一致）。
const UPLOAD_BUFFER: usize = 128;
/// packet-up 单个 POST body 上限（Xray `scMaxEachPostBytes` 默认 To）。
const MAX_POST_BYTES: usize = 1_000_000;
/// 相邻 packet POST 的最小间隔（Xray `scMinPostsIntervalMs` 默认 30ms）。
const MIN_POST_INTERVAL_MS: u64 = 30;
/// 在途 packet POST 并发上限（与 `super::xhttp_h2` 一致）。
const MAX_CONCURRENT_POSTS: usize = 8;

/// 下行帧：DATA 载荷或致命错误（如 :status 非 2xx）。
type DownItem = io::Result<Vec<u8>>;

/// 建立 HTTP/3 连接并按 `mode` 发起 XHTTP，返回可读写的双向管道。
///
/// `mode`：`stream-one` | `packet-up` | `stream-up`（调用方已解析，不支持
/// `auto`）。`tls` 为已配置 ALPN=`h3` 的 rustls 客户端配置；`host` 为
/// `:authority`（与 h1 的 Host 语义一致）。
#[allow(clippy::too_many_arguments)]
pub async fn connect(
    server: &str,
    port: u16,
    sni: &str,
    tls: Arc<rustls::ClientConfig>,
    host: &str,
    path: &str,
    mode: &str,
    extra_headers: &HashMap<String, String>,
) -> Result<XhttpH3Pipe> {
    anyhow::ensure!(
        matches!(mode, "stream-one" | "packet-up" | "stream-up"),
        "xhttp-h3: unsupported mode {mode:?}"
    );

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
        .await
        .context("xhttp-h3 open h3 control streams")?;

    match mode {
        "stream-one" => connect_stream_one(conn, host, path, extra_headers).await,
        // packet-up / stream-up：GET 长轮询下行共用，上行形态不同。
        _ => {
            let reader = connect_get_downlink(&conn, host, path, extra_headers).await?;
            let writer = if mode == "stream-up" {
                connect_stream_up(&conn, host, path, extra_headers).await?
            } else {
                connect_packet_up(&conn, host, path, extra_headers).await?
            };
            Ok(XhttpH3Pipe {
                reader,
                writer,
            })
        }
    }
}

// ── 路径 / 请求头工具 ──────────────────────────────────────────────────────────

/// 拆分用户配置的 path 为规范 base（以 `/` 结尾）与 query，与
/// `super::xhttp_h2::split_path_query` / Xray `GetNormalizedPath`+
/// `GetNormalizedQuery` 对齐。
fn split_path_query(raw: &str) -> (String, String) {
    let (path_part, query_part) = match raw.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw, ""),
    };
    let mut p = if path_part.is_empty() || !path_part.starts_with('/') {
        format!("/{path_part}")
    } else {
        path_part.to_string()
    };
    if !p.ends_with('/') {
        p.push('/');
    }
    (p, query_part.to_string())
}

/// 追加 query 到 path（query 为空则原样返回）。
fn append_query(path: &str, query: &str) -> String {
    if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    }
}

/// 构造一个请求的 QPACK 头块（Required Insert Count = 0, Delta Base = 0）。
///
/// `content_type` 仅 stream-one / stream-up 的 body 请求携带
/// （Xray `FillStreamRequest` 的 `Content-Type: application/grpc`；
/// packet-up 的 `FillPacketRequest` 不带 grpc 头）。连接管理头
/// （host / transfer-encoding / content-length / connection）不允许覆盖。
fn build_headers_block(
    method: &str,
    authority: &str,
    path_query: &str,
    content_type: Option<&str>,
    extra_headers: &HashMap<String, String>,
    referer: &str,
) -> BytesMut {
    let mut hb = BytesMut::new();
    hb.put_u8(0x00); // required insert count = 0
    hb.put_u8(0x00); // delta base = 0（无 base 条目）
    put_literal_header(&mut hb, b":method", method.as_bytes());
    put_literal_header(&mut hb, b":scheme", b"https");
    put_literal_header(&mut hb, b":authority", authority.as_bytes());
    put_literal_header(&mut hb, b":path", path_query.as_bytes());
    if let Some(ct) = content_type {
        put_literal_header(&mut hb, b"content-type", ct.as_bytes());
    }
    put_literal_header(&mut hb, b"user-agent", b"Go-http-client/1.1");
    // Referer padding（每个请求都必须携带；服务端校验 x_padding 长度）。
    put_literal_header(&mut hb, b"referer", referer.as_bytes());
    for (k, v) in extra_headers {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("referer")
        {
            continue;
        }
        put_literal_header(&mut hb, k.as_bytes(), v.as_bytes());
    }
    hb
}

/// 在双向流上发送请求 HEADERS 帧。
async fn send_request_headers(
    send: &mut quinn::SendStream,
    method: &str,
    authority: &str,
    path_query: &str,
    content_type: Option<&str>,
    extra_headers: &HashMap<String, String>,
    referer: &str,
) -> Result<()> {
    let hb = build_headers_block(
        method,
        authority,
        path_query,
        content_type,
        extra_headers,
        referer,
    );
    write_frame(send, H3_FRAME_HEADERS, &hb).await
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

/// 响应泵：读取一条流的响应 HEADERS（校验 :status 2xx）与 DATA 帧，
/// 经 channel 交给 poll_read。连接关闭 / 出错时 drop tx 触发 EOF。
/// `report_body_errors`：响应头已收到后的传输错误是否上报（GET 下行要上报，
/// POST 响应的 body 本应被忽略，错误静默）。
async fn response_pump(
    mut recv: quinn::RecvStream,
    tx: mpsc::Sender<DownItem>,
    peer: String,
    report_body_errors: bool,
) {
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
                        .send(Err(io::Error::other(format!("xhttp-h3 {peer} response: {e}"))))
                        .await;
                } else if report_body_errors {
                    // 下行流被服务端中途重置（连接断开）：必须上报，
                    // 否则上层把半截响应当作正常 EOF。
                    let _ = tx.send(Err(io::Error::other(e.to_string()))).await;
                }
                break;
            }
        }
    }
}

/// 打开响应读取端并启动泵，返回 H3Reader。
async fn spawn_response_reader(
    recv: quinn::RecvStream,
    peer: &str,
    report_body_errors: bool,
) -> H3Reader {
    let (tx, rx) = mpsc::channel::<DownItem>(DOWNLINK_BUFFER);
    tokio::spawn(response_pump(recv, tx, peer.to_string(), report_body_errors));
    H3Reader {
        rx,
        pending: None,
        pending_off: 0,
    }
}

// ── stream-one ────────────────────────────────────────────────────────────────

async fn connect_stream_one(
    conn: quinn::Connection,
    host: &str,
    path: &str,
    extra_headers: &HashMap<String, String>,
) -> Result<XhttpH3Pipe> {
    // 请求双向流 + HEADERS。
    let (mut send, recv) = conn
        .open_bi()
        .await
        .context("xhttp-h3 open request stream")?;

    let referer_base = path.split('?').next().unwrap_or(path);
    let referer = padding_referer_value(host, referer_base);
    send_request_headers(
        &mut send,
        "POST",
        host,
        path,
        Some("application/grpc"),
        extra_headers,
        &referer,
    )
    .await?;

    let reader = spawn_response_reader(recv, "stream-one", true).await;
    tracing::debug!(server = %addr_of(&conn), sni = %host, path = %path, "xhttp-h3 stream-one started");
    Ok(XhttpH3Pipe {
        reader,
        writer: H3Writer::Direct {
            send,
            write_buf: BytesMut::new(),
        },
    })
}

fn addr_of(conn: &quinn::Connection) -> std::net::SocketAddr {
    conn.remote_address()
}

// ── GET 下行（packet-up / stream-up 共用）────────────────────────────────────

/// GET 长轮询下行：`GET {base}{session_id}?{query}`，返回 reader。
async fn connect_get_downlink(
    conn: &quinn::Connection,
    host: &str,
    path: &str,
    extra_headers: &HashMap<String, String>,
) -> Result<H3Reader> {
    let (base, query) = split_path_query(path);
    let session_id = Uuid::new_v4().to_string();
    let path_query = append_query(&format!("{base}{session_id}"), &query);

    let (mut send, recv) = conn
        .open_bi()
        .await
        .context("xhttp-h3 open GET stream")?;
    let referer = padding_referer_value(host, &base);
    send_request_headers(
        &mut send,
        "GET",
        host,
        &path_query,
        None,
        extra_headers,
        &referer,
    )
    .await?;
    // GET 无请求 body：立即 FIN（等价 h1 无 body 请求）。
    send.finish().context("xhttp-h3 finish GET stream")?;

    let reader = spawn_response_reader(recv, "stream-down", true).await;
    tracing::debug!(host = %host, %path_query, "xhttp-h3 GET download started");
    Ok(reader)
}

// ── stream-up ────────────────────────────────────────────────────────────────

/// stream-up 上行：单条流式 POST（`POST {base}{session_id}?{query}`），
/// 应用数据写 DATA 帧，写关闭 = FIN。
async fn connect_stream_up(
    conn: &quinn::Connection,
    host: &str,
    path: &str,
    extra_headers: &HashMap<String, String>,
) -> Result<H3Writer> {
    let (base, query) = split_path_query(path);
    let session_id = Uuid::new_v4().to_string();
    let path_query = append_query(&format!("{base}{session_id}"), &query);

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("xhttp-h3 open stream-up POST")?;
    let referer = padding_referer_value(host, &base);
    send_request_headers(
        &mut send,
        "POST",
        host,
        &path_query,
        Some("application/grpc"),
        extra_headers,
        &referer,
    )
    .await?;

    // POST 响应只需校验状态码；body（服务端 keepalive padding）后台排空，
    // 不占用 flow control 也不阻塞上行。
    tokio::spawn(async move {
        let mut header_seen = false;
        loop {
            match read_h3_frame(&mut recv).await {
                Ok((H3_FRAME_HEADERS, payload)) => {
                    if header_seen {
                        continue;
                    }
                    header_seen = true;
                    if let Err(e) = check_status(&payload) {
                        tracing::warn!("xhttp-h3 stream-up rejected: {e}");
                        return;
                    }
                }
                Ok((_, _)) => {}
                Err(_) => return,
            }
        }
    });

    tracing::debug!(host = %host, %path_query, "xhttp-h3 stream-up started");
    Ok(H3Writer::Direct {
        send,
        write_buf: BytesMut::new(),
    })
}

// ── packet-up ────────────────────────────────────────────────────────────────

/// packet-up 上行：应用写侧走攒批 channel，上传循环把缓冲按
/// `MAX_POST_BYTES` 拆包，每包一条独立双向流
/// （`POST {base}{session_id}/{seq}?{query}` + 单个 DATA 帧 + FIN）。
/// seq 在上传循环内同步分配（保证 seq 严格等于应用写入顺序，服务端按
/// seq 重排），在途 POST 数量受信号量限制（对齐 `super::xhttp_h2`）。
async fn connect_packet_up(
    conn: &quinn::Connection,
    host: &str,
    path: &str,
    extra_headers: &HashMap<String, String>,
) -> Result<H3Writer> {
    let (base, query) = split_path_query(path);
    let session_id = Uuid::new_v4().to_string();
    let prefix = format!("{base}{session_id}/");

    tracing::debug!(host = %host, base = %base, "xhttp-h3 packet-up started");
    let (tx, mut up_rx) = mpsc::channel::<Bytes>(UPLOAD_BUFFER);
    let conn = conn.clone();
    let host = host.to_string();
    let extra = extra_headers.clone();
    tokio::spawn(async move {
        let in_flight = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_POSTS));
        let mut last_post = tokio::time::Instant::now();
        let mut seq: u64 = 0;

        while let Some(first) = up_rx.recv().await {
            let mut buffer = BytesMut::new();
            buffer.extend_from_slice(&first);
            // 攒批：达到 MAX_POST_BYTES 或 channel 暂时为空即发
            //（对齐 Xray ReadMultiBuffer 行为，不等待攒满）。
            while buffer.len() < MAX_POST_BYTES {
                match up_rx.try_recv() {
                    Ok(more) => buffer.extend_from_slice(&more),
                    Err(_) => break,
                }
            }

            let mut remaining = buffer.freeze();
            while !remaining.is_empty() {
                let payload = if remaining.len() > MAX_POST_BYTES {
                    remaining.split_to(MAX_POST_BYTES)
                } else {
                    std::mem::take(&mut remaining)
                };

                // POST 间隔控制（Xray scMinPostsIntervalMs 默认 30ms）。
                let elapsed = last_post.elapsed().as_millis() as u64;
                if elapsed < MIN_POST_INTERVAL_MS {
                    tokio::time::sleep(Duration::from_millis(MIN_POST_INTERVAL_MS - elapsed))
                        .await;
                }

                // seq 同步分配（不能放进 spawn 的任务里，会乱序）。
                let this_seq = seq;
                seq += 1;

                let _permit = in_flight.clone().acquire_owned().await;

                let conn = conn.clone();
                let host = host.clone();
                let extra = extra.clone();
                let prefix = prefix.clone();
                let path_query = append_query(&format!("{prefix}{this_seq}"), &query);
                tokio::spawn(async move {
                    if let Err(e) = post_packet(
                        &conn,
                        &host,
                        &path_query,
                        &extra,
                        payload,
                    )
                    .await
                    {
                        tracing::warn!("xhttp-h3 packet-up POST {this_seq} error: {e}");
                    }
                    drop(_permit);
                });

                last_post = tokio::time::Instant::now();
            }
        }
        tracing::debug!("xhttp-h3 packet-up: upload channel closed, upload loop exiting");
    });

    Ok(H3Writer::Packet { tx })
}

/// 发送单个 packet POST：open_bi → HEADERS → 单个 DATA 帧 → FIN，
/// 然后校验响应状态并排空 body。
async fn post_packet(
    conn: &quinn::Connection,
    host: &str,
    path_query: &str,
    extra_headers: &HashMap<String, String>,
    payload: Bytes,
) -> Result<()> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .context("xhttp-h3 open packet POST stream")?;
    let referer = padding_referer_value(host, path_query);
    send_request_headers(
        &mut send,
        "POST",
        host,
        path_query,
        None,
        extra_headers,
        &referer,
    )
    .await?;
    write_frame(&mut send, H3_FRAME_DATA, &payload).await?;
    send.finish().context("xhttp-h3 finish packet POST")?;

    // 响应：校验 :status 2xx，body 排空直到流结束。
    let mut header_seen = false;
    loop {
        match read_h3_frame(&mut recv).await {
            Ok((H3_FRAME_HEADERS, hp)) => {
                if header_seen {
                    continue;
                }
                header_seen = true;
                check_status(&hp).context("xhttp-h3 packet POST rejected")?;
            }
            Ok(_) => {}
            Err(e) => {
                if !header_seen {
                    anyhow::bail!("xhttp-h3 packet POST response: {e}");
                }
                return Ok(());
            }
        }
    }
}

// ── 双向管道 ──────────────────────────────────────────────────────────────────

/// XHTTP over H3 的双向管道。
///
/// 读侧：响应泵 channel（所有模式一致）。
/// 写侧：`Direct` = 单条流的 DATA 帧（stream-one / stream-up）；
/// `Packet` = 攒批 channel（packet-up，由上传循环发独立 POST）。
pub struct XhttpH3Pipe {
    reader: H3Reader,
    writer: H3Writer,
}

struct H3Reader {
    rx: mpsc::Receiver<DownItem>,
    /// 泵交付但尚未被应用层取走的载荷（单帧最大 1MiB，逐字节读也无妨）。
    pending: Option<Vec<u8>>,
    pending_off: usize,
}

enum H3Writer {
    Direct {
        send: quinn::SendStream,
        /// 已组帧但未完全写入的 DATA 帧（部分写时暂存）。
        write_buf: BytesMut,
    },
    Packet {
        tx: mpsc::Sender<Bytes>,
    },
}

impl H3Writer {
    fn drain_write_buf(&mut self, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        let H3Writer::Direct { send, write_buf } = self else {
            return Poll::Ready(Ok(()));
        };
        while !write_buf.is_empty() {
            match Pin::new(&mut *send).poll_write(cx, write_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "xhttp-h3 write zero",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = write_buf.split_to(n);
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
        let this = &mut self.reader;
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
        let this = &mut self.writer;
        // 先排掉上次部分写残留的帧数据。
        ready!(this.drain_write_buf(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this {
            H3Writer::Direct { send, write_buf } => {
                // DATA 帧：type varint(0x0) + len varint + payload。
                let mut frame = BytesMut::with_capacity(buf.len() + 8);
                write_varint(&mut frame, H3_FRAME_DATA);
                write_varint(&mut frame, buf.len() as u64);
                frame.put_slice(buf);
                match Pin::new(&mut *send).poll_write(cx, &frame) {
                    Poll::Pending => {
                        // 整帧入队（quinn poll_write 语义：Pending 表示本轮无法写入）。
                        *write_buf = frame;
                        Poll::Ready(Ok(buf.len()))
                    }
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                    Poll::Ready(Ok(n)) => {
                        if n < frame.len() {
                            *write_buf = frame.split_off(n);
                        }
                        Poll::Ready(Ok(buf.len()))
                    }
                }
            }
            H3Writer::Packet { tx } => {
                // 攒批 channel 满时挂起等待容量（与 super::xhttp_h2 一致）。
                let chunk = Bytes::copy_from_slice(buf);
                match tx.try_send(chunk) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        let waker = cx.waker().clone();
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let _ = tx.reserve().await;
                            waker.wake();
                        });
                        Poll::Pending
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "xhttp-h3 upload channel closed",
                        )))
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        ready!(self.writer.drain_write_buf(cx))?;
        if let H3Writer::Direct { send, .. } = &mut self.writer {
            return Pin::new(&mut *send).poll_flush(cx);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskCtx<'_>) -> Poll<io::Result<()>> {
        match &mut self.writer {
            H3Writer::Direct { .. } => {
                // 先排掉暂存的帧数据（本次可变借用结束后再借 send 发 FIN）。
                ready!(self.writer.drain_write_buf(cx))?;
                let H3Writer::Direct { send, .. } = &mut self.writer else {
                    unreachable!("checked above");
                };
                // 请求 body 完成 = 流 FIN（quinn finish），等价于 h1 终止块。
                Pin::new(&mut *send).poll_shutdown(cx)
            }
            H3Writer::Packet { tx } => {
                // 关闭上传 channel：tx 被 drop 后上传循环 recv() 返回 None
                // 退出（各包已带 seq，无需额外结束信号）。
                let (dead, _) = mpsc::channel(1);
                *tx = dead;
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// 帧载荷上限（与 hy2_h3::read_h3_frame 的 1MiB 守卫一致）。
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

/// 静态断言：下行泵容量不会让单连接内存失控。
const _: () = assert!(DOWNLINK_BUFFER * MAX_FRAME_SIZE / 1024 / 1024 <= 64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_path_query() {
        assert_eq!(split_path_query("/x"), ("/x/".to_string(), "".to_string()));
        assert_eq!(split_path_query("/x/"), ("/x/".to_string(), "".to_string()));
        assert_eq!(
            split_path_query("/x?t=1"),
            ("/x/".to_string(), "t=1".to_string())
        );
        assert_eq!(split_path_query(""), ("/".to_string(), "".to_string()));
    }

    #[test]
    fn test_append_query() {
        assert_eq!(append_query("/x/sid", ""), "/x/sid");
        assert_eq!(append_query("/x/sid", "t=1"), "/x/sid?t=1");
    }

    #[test]
    fn test_headers_block_shape() {
        let mut extra = HashMap::new();
        extra.insert("X-Custom".to_string(), "v".to_string());
        let referer = padding_referer_value("cdn.example.com", "/x/");
        let hb = build_headers_block(
            "GET",
            "cdn.example.com",
            "/x/sid?t=1",
            None,
            &extra,
            &referer,
        );
        let text = String::from_utf8_lossy(&hb);
        assert!(text.contains(":method"));
        assert!(text.contains("GET"));
        assert!(text.contains("referer"));
        assert!(text.contains("x_padding"));
        assert!(text.contains("X-Custom"));
        // GET 请求不携带 content-type
        assert!(!text.contains("content-type"));
    }
}
