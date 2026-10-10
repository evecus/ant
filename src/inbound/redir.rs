//! Linux REDIR (iptables TPROXY/REDIRECT) TCP inbound.
//! Dual-stack: 0.0.0.0 and [::]. Original destination via SO_ORIGINAL_DST /
//! IP6T_SO_ORIGINAL_DST (same as clash-rs).

use crate::outbound::OutboundManager;
use crate::app::router::{Outbound, Router};
use crate::app::sniffer;
use super::target;
use anyhow::{Context, Result};
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run_redir(
    port: u16,
    bind_address: String,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    let mut handles = Vec::new();
    for bind in crate::app::sockopt::listen_addrs(&bind_address, port) {
        match crate::app::sockopt::bind_tcp_listener(bind) {
            Ok((listener, bind)) => {
                tracing::info!("redir TCP listening on {bind}");
                let router = router.clone();
                let outbounds = outbounds.clone();
                handles.push(tokio::spawn(async move {
                    loop {
                        let (stream, peer) = match listener.accept().await {
                            Ok((s, p)) => (s, crate::app::sockopt::canonical(p)),
                            Err(e) => {
                                tracing::warn!("redir accept failed: {e}");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                continue;
                            }
                        };
                        let router = router.clone();
                        let outbounds = outbounds.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_redir(stream, peer, router, outbounds).await {
                                tracing::debug!("redir {peer}: {e:#}");
                            }
                        });
                    }
                }));
            }
            Err(e) => tracing::warn!("redir bind {bind}: {e}"),
        }
    }
    if handles.is_empty() {
        anyhow::bail!("redir: no bind succeeded");
    }
    futures::future::join_all(handles).await;
    Ok(())
}

async fn handle_redir(
    stream: TcpStream,
    peer: SocketAddr,
    router: Arc<Router>,
    outbounds: Arc<OutboundManager>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let dest = get_original_destination(&stream)
        .with_context(|| format!("SO_ORIGINAL_DST for {peer}"))?;
    tracing::debug!("redir tcp {peer} -> {dest}");

    let mut domain = None;
    let mut peek_buf = vec![0u8; 2048];
    // Peek is only needed for protocol sniffing (`sniff`) or DNS-stream detection
    // (`dns.route-hijack`, port 53 is hijacked unconditionally below).
    let want_peek = router.sniff() || (router.hijack_dns() && dest.port() != 53);
    if want_peek {
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(300), stream.peek(&mut peek_buf)).await
        {
            let sniffed = sniffer::sniff_tcp_ex(&peek_buf[..n], router.sniff(), router.hijack_dns());
            domain = sniffed.domain;
            if router.hijack_dns() && (dest.port() == 53 || sniffed.dns) {
                tracing::debug!("redir hijack dns {peer} -> {dest}");
                return hijack_dns_tcp(stream, router).await;
            }
        }
    }
    if router.hijack_dns() && dest.port() == 53 {
        tracing::debug!("redir hijack dns {peer} -> {dest}");
        return hijack_dns_tcp(stream, router).await;
    }

    let target = target::decide(&router, dest, domain).await;
    if target.outbound == Outbound::Block {
        tracing::debug!("redir block {dest} ({:?})", target.host);
        return Ok(());
    }
    let dialer = outbounds.select(target.outbound).context("no dialer")?;
    let remote = dialer
        .dial_tcp(target.addr, target.host.as_deref())
        .await
        .with_context(|| format!("dial tcp {}", target.addr))?;
    let local: crate::outbound::BoxedStream = Box::new(stream);
    crate::outbound::relay(local, remote).await?;
    Ok(())
}

fn get_original_destination(s: &TcpStream) -> io::Result<SocketAddr> {
    let fd = s.as_raw_fd();
    unsafe {
        let (_, target_addr) = socket2::SockAddr::try_init(|target_addr, target_addr_len| {
            const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;
            let ret = libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IP6T_SO_ORIGINAL_DST,
                target_addr as *mut _,
                target_addr_len,
            );
            if ret == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ENOPROTOOPT) | Some(libc::ENOENT) | Some(libc::EOPNOTSUPP) => {}
                _ => return Err(err),
            }
            let ret = libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                target_addr as *mut _,
                target_addr_len,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        })?;
        target_addr
            .as_socket()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not a socket address"))
    }
}

async fn hijack_dns_tcp(mut stream: TcpStream, router: Arc<Router>) -> Result<()> {
    let (direct, proxy) = router.dns_upstreams();
    loop {
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            anyhow::bail!("bad dns tcp length {len}");
        }
        let mut query = vec![0u8; len];
        stream.read_exact(&mut query).await?;
        let resp = crate::dns::answer_query(&query, &router, direct, proxy).await?;
        stream.write_all(&(resp.len() as u16).to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
}
