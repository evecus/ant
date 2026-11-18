//! Transparent relay: consumes the transparent listeners created inside
//! `antns` and published into the LISTEN_SOCKETS sockmap (sk_lookup assigns
//! connections/datagrams to them while preserving the original destination).
//!
//! TCP: accepted conns carry the original destination; DNS-over-TCP (:53,
//! RFC 7766) is answered in-place by ant's DNS engine, everything else is
//! dialled through the outbound selected by ant's Router and relayed.
//!
//! UDP: each datagram carries its original destination via
//! IP_RECVORIGDSTADDR; :53 goes to the DNS engine, other flows go through the
//! outbound's UDP session. Replies are sent from a socket bound to the
//! original destination inside `antns` so the datapath restores framing.

use super::dns;
use super::listener::{create_reply_socket, orig_dst_tcp};
use super::rules::{StaticMaps, Verdict};
use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use crate::dns::answer_query;
use crate::outbound::{BoxedStream, OutboundManager, UdpSession};
use ant_ebpf_common::DNS_PORT;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const SNIFF_TIMEOUT: Duration = Duration::from_millis(300);
const SNIFF_MAX: usize = 4096;
const DIRECT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

type FlowTable = Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Arc<UdpFlow>>>>;

/// Shared state for both TCP and UDP flows.
pub struct RelayCtx {
    pub router: Arc<Router>,
    pub outbounds: Arc<OutboundManager>,
    pub maps: Arc<Mutex<StaticMaps>>,
}

/// Answer a single DNS query (already assembled bytes) and publish kernel
/// verdicts for the answered addresses.
///
/// Publication policy (deliberately narrow): only DIRECT/BLOCK verdicts are
/// written into the kernel DOMAIN_ROUTE map. Proxy/node verdicts are NEVER
/// published — proxy routing always happens in userspace, where the Router
/// re-evaluates every flow against fresh rules and live proxy-group state.
///
/// Why per-IP full-route evaluation for the direct side: DOMAIN_ROUTE is
/// consulted before the CIDR tries in the kernel, so a published verdict must
/// be the Router's final answer for that (domain, ip) pair — evaluating only
/// domain rules would shadow route: IP rules (GEOIP / IP-CIDR / RULE-SET).
///
/// Fake-IP answers are skipped entirely: a fake address must never receive a
/// kernel DIRECT short-circuit (the client would dial the bogus address
/// straight out the WAN), and proxy-intended fake addresses gain nothing from
/// a Proxy publication anyway.
async fn answer_and_publish(
    query: &[u8],
    _client: SocketAddr,
    ctx: &RelayCtx,
) -> Result<Vec<u8>> {
    let response = answer_query(query, &ctx.router).await?;

    let Some(name) = dns::extract_qname(query) else {
        return Ok(response);
    };
    let ips = dns::answer_addresses(&response);
    if ips.is_empty() {
        return Ok(response);
    }
    let mut maps = ctx.maps.lock().await;
    for ip in ips {
        // Fake addresses never enter the kernel routing maps (see doc above).
        if ctx.router.domain_for_fakeip(ip).is_some() {
            continue;
        }
        match ctx.router.match_outbound(Some(&name), Some(ip)) {
            Outbound::Direct => {
                if let Err(e) = maps.publish_domain_ip(ip, Verdict::Direct) {
                    tracing::debug!(error = %e, "publish DOMAIN_ROUTE direct");
                }
            }
            Outbound::Block => {
                if let Err(e) = maps.publish_domain_ip(ip, Verdict::Block) {
                    tracing::debug!(error = %e, "publish DOMAIN_ROUTE block");
                }
            }
            // Proxy / named node: userspace-only. Not published, so the kernel
            // falls through to the static CIDR surfaces (bypass-ip, private,
            // local) and otherwise captures the flow with the default verdict.
            _ => {}
        }
    }
    Ok(response)
}

// ---------------------------------------------------------------- TCP

pub async fn run_tcp(listeners: Vec<TcpListener>, ctx: Arc<RelayCtx>) -> Result<()> {
    if listeners.is_empty() {
        anyhow::bail!("no TCP listeners to serve");
    }
    let mut set = tokio::task::JoinSet::new();
    for listener in listeners {
        let ctx = ctx.clone();
        set.spawn(async move { accept_loop(listener, ctx).await });
    }
    if let Some(res) = set.join_next().await {
        set.abort_all();
        return match res {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("tcp accept loop panicked: {e}")),
        };
    }
    Ok(())
}

async fn accept_loop(listener: TcpListener, ctx: Arc<RelayCtx>) -> Result<()> {
    loop {
        let (conn, client) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!(error = %e, "tcp accept");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp(conn, client, ctx).await {
                // Dial failures (node / direct) are the actionable ones: show
                // the full cause chain at warn so they are visible without
                // debug logging. Ordinary resets / EOFs stay at debug.
                let chain = format!("{e:#}");
                if chain.contains("dial") {
                    tracing::warn!(error = %chain, "tcp dial failed");
                } else {
                    tracing::debug!(error = %chain, "tcp flow ended");
                }
            }
        });
    }
}

async fn handle_tcp(mut conn: TcpStream, client: SocketAddr, ctx: Arc<RelayCtx>) -> Result<()> {
    let orig = orig_dst_tcp(&conn)?;
    if orig.port() == DNS_PORT {
        // DNS is answered in-place and is never tracked as a connection.
        return handle_tcp_dns(&mut conn, client, orig, &ctx).await;
    }

    // Recover the domain: fake-IP maps straight back; else sniff first bytes.
    let mut early: Vec<u8> = Vec::new();
    let mut domain: Option<String> = ctx.router.domain_for_fakeip(orig.ip());
    let fake = domain.is_some();
    if domain.is_none() && ctx.router.sniff() {
        let (bytes, sniffed) = sniff_client(&mut conn).await?;
        early = bytes;
        domain = sniffed;
    }

    // Re-run ant's route rules on the recovered name; keep the rule label for
    // the connection panel (match_route is the same decision as match_outbound,
    // just without discarding `rule`).
    let matched = ctx.router.match_route(domain.as_deref(), Some(orig.ip()), &[]);
    let route_ob = matched.outbound;
    if matches!(route_ob, Outbound::Block) {
        tracing::debug!(%orig, domain = ?domain, "tcp blocked by route");
        return Ok(());
    }

    // Register the transparent flow under a single "ebpf" inbound label.
    // `while_alive` below ties the panel's close button to this relay loop.
    let guard = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
        peer: client,
        dest: orig,
        dest_host: domain.clone(),
        network: "tcp",
        inbound: "ebpf",
        rule: matched.rule,
        outbound: route_ob.label(),
    });

    if matches!(route_ob, Outbound::Direct) {
        let up = dial_direct(orig).await?;
        let up: BoxedStream = Box::new(up);
        return guard.while_alive(relay(conn, up, early)).await;
    }

    // Named outbound (or default). A fake address must be dialled by name.
    let dial_name = if fake || ctx.router.sniff() {
        domain.clone()
    } else {
        None
    };
    let Some(dialer) = ctx.outbounds.select(route_ob) else {
        tracing::debug!(%orig, "no dialer for outbound");
        return Ok(());
    };
    let upstream: BoxedStream = dialer
        .dial_tcp(orig, dial_name.as_deref())
        .await
        .with_context(|| format!("dial tcp {orig}"))?;
    guard.while_alive(relay(conn, upstream, early)).await
}

/// DNS over TCP: length-prefixed queries answered in-place on the accepted
/// transparent connection.
async fn handle_tcp_dns(
    conn: &mut TcpStream,
    client: SocketAddr,
    _orig: SocketAddr,
    ctx: &RelayCtx,
) -> Result<()> {
    const MAX_MSG: usize = u16::MAX as usize;
    const IDLE: Duration = Duration::from_secs(30);
    loop {
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(IDLE, conn.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e).context("dns/tcp read length"),
            Err(_) => return Ok(()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_MSG {
            anyhow::bail!("dns/tcp invalid message length {len}");
        }
        let mut query = vec![0u8; len];
        match conn.read_exact(&mut query).await {
            Ok(_) => {}
            // Half-frame at EOF: a client disconnecting mid-query. Close
            // cleanly instead of surfacing a spurious error.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e).context("dns/tcp read message"),
        }

        let response = match answer_and_publish(&query, client, ctx).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "dns/tcp query failed; closing");
                return Ok(());
            }
        };
        if response.len() > MAX_MSG {
            anyhow::bail!("dns/tcp answer too large: {}", response.len());
        }
        conn.write_all(&(response.len() as u16).to_be_bytes()).await?;
        conn.write_all(&response).await?;
    }
}

/// True while a TCP prefix may still grow into a sniffable one (partial TLS
/// record, HTTP request whose headers have not ended yet).
fn tcp_needs_more(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return true;
    }
    if buf[0] == 0x16 {
        if buf.len() < 5 {
            return true;
        }
        let rec = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        return buf.len() < 5 + rec;
    }
    const METHODS: [&[u8]; 7] = [
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"CONNECT ", b"OPTIONS ", b"DELETE ",
    ];
    if METHODS.iter().any(|m| buf.starts_with(m)) {
        return !buf.windows(4).any(|w| w == b"\r\n\r\n");
    }
    buf.len() < 8 && METHODS.iter().any(|m| m.starts_with(buf))
}

async fn sniff_client(conn: &mut TcpStream) -> Result<(Vec<u8>, Option<String>)> {
    let mut buf = vec![0u8; SNIFF_MAX];
    let mut n = 0usize;
    let mut domain = None;
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;
    while n < buf.len() {
        match tokio::time::timeout_at(deadline, conn.read(&mut buf[n..])).await {
            Err(_) => break,
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(0)) => break,
            Ok(Ok(k)) => {
                n += k;
                let r = sniffer::sniff_tcp_ex(&buf[..n], true, false);
                if let Some(d) = r.domain {
                    domain = Some(d);
                    break;
                }
                // Not TLS / HTTP (e.g. Telegram MTProto, SSH, custom TCP):
                // nothing more to learn, do not sit out the whole window.
                if !tcp_needs_more(&buf[..n]) {
                    break;
                }
            }
        }
    }
    buf.truncate(n);
    Ok((buf, domain))
}

async fn dial_direct(dst: SocketAddr) -> Result<TcpStream> {
    // sockopt::connect_tcp applies the control-plane mark (plus Android
    // protect / SO_MARK) before connect(), so the dial is never re-captured.
    tokio::time::timeout(DIRECT_DIAL_TIMEOUT, crate::app::sockopt::connect_tcp(dst))
        .await
        .map_err(|_| anyhow::anyhow!("direct dial {dst}: timeout"))?
        .with_context(|| format!("direct dial {dst}"))
}

async fn relay(conn: TcpStream, mut upstream: BoxedStream, early: Vec<u8>) -> Result<()> {
    // The sniff window consumed the client's first bytes from the accepted
    // connection. They MUST be replayed to the upstream before copying starts,
    // otherwise every sniffed flow loses its first segment (TLS ClientHello,
    // MTProto handshake, ...) and the handshake breaks.
    if !early.is_empty() {
        upstream
            .write_all(&early)
            .await
            .context("replay sniffed prefix to upstream")?;
        upstream.flush().await.ok();
    }
    let client: BoxedStream = Box::new(conn);
    crate::outbound::relay(client, upstream).await?;
    Ok(())
}

// ---------------------------------------------------------------- UDP

struct UdpFlow {
    upstream: Box<dyn UdpSession>,
    reply: tokio::net::UdpSocket,
    client: SocketAddr,
    domain: Option<String>,
    /// Connection-tracking guard; dropped (= Leave) when the flow is removed.
    guard: crate::app::stats::ConnGuard,
}

pub async fn run_udp(
    socks: Vec<std::net::UdpSocket>,
    ctx: Arc<RelayCtx>,
) -> Result<()> {
    if socks.is_empty() {
        anyhow::bail!("no UDP listeners to serve");
    }
    let mut set = tokio::task::JoinSet::new();
    for (i, sock) in socks.into_iter().enumerate() {
        let ctx = ctx.clone();
        set.spawn(async move { run_udp_worker(i, sock, ctx).await });
    }
    if let Some(res) = set.join_next().await {
        set.abort_all();
        return match res {
            Ok(r) => r,
            Err(e) => Err(anyhow::anyhow!("udp worker panicked: {e}")),
        };
    }
    Ok(())
}

async fn run_udp_worker(id: usize, sock: std::net::UdpSocket, ctx: Arc<RelayCtx>) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<UdpEvent>();
    std::thread::Builder::new().name(format!("ant-udp-recv-{id}")).spawn({
        move || {
            // One buffer for the thread's lifetime: allocating + zeroing 64 KiB
            // per datagram dominated CPU on UDP-heavy traffic (QUIC, calls).
            let mut buf = vec![0u8; 65535];
            let mut errs = 0u32;
            loop {
                match unsafe { recv_orig_dst_blocking(sock.as_raw_fd(), &mut buf) } {
                    Ok((n, client, orig)) => {
                        errs = 0;
                        let payload = buf[..n].to_vec();
                        if tx.send(UdpEvent { payload, client, orig }).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        errs = errs.saturating_add(1);
                        if errs <= 3 {
                            tracing::warn!(error = %e, "udp recvmsg");
                        }
                        // A persistent error must not turn this into a busy loop.
                        std::thread::sleep(Duration::from_millis(if errs > 3 { 200 } else { 10 }));
                    }
                }
            }
        }
    })?;

    let flows: FlowTable = Arc::new(Mutex::new(HashMap::new()));

    while let Some(UdpEvent { payload, client, orig }) = rx.recv().await {
        if orig.port() == DNS_PORT {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_udp_dns(&payload, client, orig, ctx).await {
                    tracing::warn!(error = %e, "udp dns flow");
                }
            });
            continue;
        }
        let key = (client, orig);
        let flow = {
            let mut table = flows.lock().await;
            if let Some(f) = table.get(&key) {
                f.clone()
            } else {
                let flow = match create_udp_flow(&ctx, &key, &payload).await {
                    Ok(Some(f)) => Arc::new(f),
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(error = %e, "udp flow setup");
                        continue;
                    }
                };
                table.insert(key, flow.clone());
                let pump_flow = flow.clone();
                let table_ref = flows.clone();
                tokio::spawn(async move {
                    if let Err(e) = pump_udp_replies(pump_flow).await {
                        tracing::debug!(error = %e, "udp pump ended");
                    }
                    table_ref.lock().await.remove(&key);
                });
                flow
            }
        };
        if let Err(e) = flow.upstream.send_to(&payload, orig, flow.domain.as_deref()).await {
            tracing::warn!(error = %e, "udp upstream send");
        }
    }
    Ok(())
}

/// UDP DNS: answer and send the reply from a socket bound to the original
/// destination, so the datapath restores the client-facing framing.
///
/// The reply socket is bound to `orig` (the resolver address the client
/// queried), NOT to `client`: it lives inside `antns`, and a datagram whose
/// source and destination are both the client address has no valid route there
/// (`ENETUNREACH`), so no DNS answer was ever delivered.
async fn handle_udp_dns(
    payload: &[u8],
    client: SocketAddr,
    orig: SocketAddr,
    ctx: Arc<RelayCtx>,
) -> Result<()> {
    let response = answer_and_publish(payload, client, &ctx).await?;
    let reply = create_reply_socket(orig).context("dns reply socket")?;
    reply
        .send_to(&response, client)
        .await
        .with_context(|| format!("dns reply {orig} -> {client}"))?;
    Ok(())
}

async fn create_udp_flow(
    ctx: &RelayCtx,
    key: &(SocketAddr, SocketAddr),
    first: &[u8],
) -> Result<Option<UdpFlow>> {
    let (client, orig) = *key;
    let mut domain = ctx.router.domain_for_fakeip(orig.ip());
    let fake = domain.is_some();
    if domain.is_none() && ctx.router.sniff() {
        domain = sniffer::sniff_udp_ex(first, true, false).domain;
    }
    if let Some(ref d) = domain {
        // Fake-IP with no mapping is unreachable; Router already filters it.
        tracing::debug!(%orig, domain = %d, "udp flow domain");
    }

    let matched = ctx.router.match_route(domain.as_deref(), Some(orig.ip()), &[]);
    let route_ob = matched.outbound;
    if matches!(route_ob, Outbound::Block) {
        return Ok(None);
    }
    let outbound_label = route_ob.label();
    let dial_name = if fake || ctx.router.sniff() {
        domain.clone()
    } else {
        None
    };

    let (upstream, flow_domain) = if matches!(route_ob, Outbound::Direct) {
        let sess = direct_udp_session(orig).await?;
        (sess, None)
    } else {
        let Some(dialer) = ctx.outbounds.select(route_ob) else {
            return Ok(None);
        };
        (dialer.dial_udp(None).await?, dial_name)
    };

    // UDP is long-lived: the guard lives inside UdpFlow, so dropping the flow
    // (idle timeout or panel close) leaves the tracked connection. DNS never
    // reaches here (handled by handle_udp_dns in the worker loop).
    let guard = crate::app::stats::global().register(crate::app::stats::ConnectionInfo {
        peer: client,
        dest: orig,
        dest_host: domain.clone(),
        network: "udp",
        inbound: "ebpf",
        rule: matched.rule,
        outbound: outbound_label,
    });

    Ok(Some(UdpFlow {
        upstream,
        reply: create_reply_socket(orig)?,
        client,
        domain: flow_domain,
        guard,
    }))
}

struct DirectUdpSession {
    sock: tokio::net::UdpSocket,
    dst: SocketAddr,
    /// Scratch receive buffer, reused across datagrams (only the pump task reads).
    rx_buf: tokio::sync::Mutex<Vec<u8>>,
}
#[async_trait::async_trait]
impl UdpSession for DirectUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, _host: Option<&str>) -> Result<()> {
        let _ = dst;
        self.sock.send_to(data, self.dst).await?;
        Ok(())
    }
    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        let mut buf = self.rx_buf.lock().await;
        let (n, from) = self.sock.recv_from(&mut buf[..]).await?;
        Ok((buf[..n].to_vec(), from))
    }
}

/// Direct UDP upstream. The socket MUST be created in the host netns (this
/// task never enters `antns`): inside `antns` the only route is back through
/// `ant0peer`, so a direct send would fail with ENETUNREACH. `bind_udp` applies
/// the control-plane mark (and Android protect/SO_MARK) so the TC hooks don't
/// re-capture it.
async fn direct_udp_session(dst: SocketAddr) -> Result<Box<dyn UdpSession>> {
    let bind: SocketAddr = if dst.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let sock = crate::app::sockopt::bind_udp(bind)
        .await
        .context("direct udp socket")?;
    Ok(Box::new(DirectUdpSession {
        sock,
        dst,
        rx_buf: tokio::sync::Mutex::new(vec![0u8; 65535]),
    }))
}

async fn pump_udp_replies(flow: Arc<UdpFlow>) -> Result<()> {
    loop {
        tokio::select! {
            // "关闭此连接" cancels the guard -> stop pumping; the worker then
            // removes the flow from the table, dropping the guard (Leave).
            _ = flow.guard.cancelled() => return Ok(()),
            resp = tokio::time::timeout(Duration::from_secs(300), flow.upstream.recv_from()) => {
                let (data, _) = resp??;
                flow.reply.send_to(&data, flow.client).await?;
            }
        }
    }
}

struct UdpEvent {
    payload: Vec<u8>,
    client: SocketAddr,
    orig: SocketAddr,
}

unsafe fn recv_orig_dst_blocking(
    fd: std::os::fd::RawFd,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr)> {
    unsafe {
        let mut iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut cmsg_buf = [0u8; 128];
        let mut from: libc::sockaddr_storage = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iovec;
        msg.msg_iovlen = 1;
        msg.msg_name = &mut from as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;
        let n = loop {
            let rc = libc::recvmsg(fd, &mut msg, 0);
            if rc >= 0 {
                break rc as usize;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted
                || err.kind() == std::io::ErrorKind::WouldBlock
            {
                continue;
            }
            anyhow::bail!("recvmsg: {err}");
        };
        let client = sockaddr_to_addr(&from).context("client addr")?;
        let mut orig = None;
        let mut cpos = cmsg_buf.as_mut_ptr();
        let end = cmsg_buf.as_mut_ptr().add(msg.msg_controllen as usize);
        while cpos < end {
            let ch = cpos as *const libc::cmsghdr;
            if ((*ch).cmsg_level == libc::IPPROTO_IP && (*ch).cmsg_type == libc::IP_RECVORIGDSTADDR)
                || ((*ch).cmsg_level == libc::IPPROTO_IPV6
                    && (*ch).cmsg_type == libc::IPV6_RECVORIGDSTADDR)
            {
                let data =
                    cpos.add(std::mem::size_of::<libc::cmsghdr>()) as *const libc::sockaddr_storage;
                orig = sockaddr_to_addr(&*data);
                break;
            }
            #[allow(clippy::unnecessary_cast)]
            let clen = (*ch).cmsg_len as usize;
            cpos = cpos.add(cmsg_align(clen));
        }
        let orig = orig.context("no orig dst ancillary")?;
        Ok((n, client, orig))
    }
}

fn cmsg_align(len: usize) -> usize {
    (len + std::mem::size_of::<usize>() - 1) & !(std::mem::size_of::<usize>() - 1)
}

fn sockaddr_to_addr(ss: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match ss.ss_family as libc::c_int {
        libc::AF_INET => {
            let a: &libc::sockaddr_in = unsafe { &*(ss as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin_port)))
        }
        libc::AF_INET6 => {
            let a: &libc::sockaddr_in6 = unsafe { &*(ss as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(a.sin6_addr.s6_addr);
            Some(SocketAddr::new(ip.into(), u16::from_be(a.sin6_port)))
        }
        _ => None,
    }
}
