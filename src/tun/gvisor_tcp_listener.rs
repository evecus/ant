use super::{
    device::NetstackDevice, packet::IpPacket, ring_buffer::LockFreeRingBuffer, stack::IfaceEvent,
    tcp_stream::TcpStream, Packet,
};
use futures::task::AtomicWaker;
use smoltcp::{
    iface::Interface,
    socket::tcp,
    wire::{IpProtocol, TcpPacket},
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::{debug, error, trace, warn};

const DEFAULT_TCP_SEND_BUFFER_SIZE: u32 = 128 * 1024; // 128 KiB
const DEFAULT_TCP_RECV_BUFFER_SIZE: u32 = 128 * 1024; // 128 KiB

/// Time-to-live for SYN tracker entries. Duplicates within this window are
/// suppressed to prevent the same SYN from creating multiple smoltcp sockets.
const SYN_TRACK_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// Maximum tracked half-open SYN entries.
const SYN_TRACK_MAX: usize = 10_000;

/// 并发 socket 容量上限。
///
/// 每个 SYN 即分配 smoltcp 缓冲 2×128KiB + 应用侧 ring 2×128KiB = 512KiB，
/// SYN 洪泛（SYN_TRACK_MAX=10000 个伪造源）若无上限可达 ~5GiB 内存放大：
/// - 活跃 socket 数达到上限后直接丢弃新 SYN（客户端按 TCP 标准退避重传）；
/// - 最坏内存：1024 × 512KiB = 512MiB（可控）。
const MAX_TCP_SOCKETS: usize = 1024;

pub(crate) struct TcpStreamHandle {
    pub(crate) recv_buffer: LockFreeRingBuffer,
    pub(crate) recv_waker: AtomicWaker,
    pub(crate) send_buffer: LockFreeRingBuffer,
    pub(crate) send_waker: AtomicWaker,

    /// Set by the relay task (via TcpStream::drop) when the app-side stream is
    /// dropped. Triggers drain-before-close in poll_sockets: remaining
    /// send_buffer data is flushed into smoltcp's TX ring, then
    /// socket.close() initiates the FIN handshake.
    pub(crate) socket_dropped: AtomicBool,
    /// Set by poll_sockets when the smoltcp socket becomes inactive (FIN
    /// handshake complete, RST received, or timeout). Causes poll_read to
    /// return EOF once recv_buffer is drained, even if read_closed was
    /// never set by the data path.
    pub(crate) socket_closed: AtomicBool,
    /// Set by the data path when smoltcp reports !may_recv() (peer FIN
    /// received). Also set defensively in TcpStream::drop(). Causes
    /// poll_read to return EOF.
    pub(crate) read_closed: AtomicBool,
    /// Set by the data path when smoltcp reports !may_send() (send path
    /// closed), and in TcpStream::drop(). Causes poll_write to return
    /// BrokenPipe.
    pub(crate) write_closed: AtomicBool,
    /// Set by poll_shutdown(). The data path watches this flag and calls
    /// socket.close() once send_buffer is drained, initiating a graceful FIN.
    pub(crate) write_shutdown: AtomicBool,
    /// Set by TcpStream::abort() when the relay side wants to discard the
    /// connection immediately (dial 失败 / 规则拒绝): poll_sockets issues
    /// smoltcp abort() (RST) and removes the socket without draining
    /// send_buffer. 对齐 sing-tun NAT 失败时的 RST 语义。
    pub(crate) abort_requested: AtomicBool,
}

impl TcpStreamHandle {
    pub fn new() -> Self {
        Self {
            recv_buffer: LockFreeRingBuffer::new(DEFAULT_TCP_RECV_BUFFER_SIZE as usize),
            recv_waker: AtomicWaker::new(),
            send_buffer: LockFreeRingBuffer::new(DEFAULT_TCP_SEND_BUFFER_SIZE as usize),
            send_waker: AtomicWaker::new(),
            socket_dropped: AtomicBool::new(false),
            socket_closed: AtomicBool::new(false),
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            abort_requested: AtomicBool::new(false),
        }
    }
}

pub struct TcpListener {
    socket_stream: mpsc::UnboundedReceiver<TcpStream>,
    socket_stream_waker: Arc<AtomicWaker>,

    task_handle: tokio::task::JoinHandle<()>,
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.task_handle.abort();
    }
}

impl TcpListener {
    /// 创建 TCP 监听器。
    ///
    /// `mtu` 应与上层 TUN 设备的 MTU 一致，否则大于设备 MTU 的出站包
    /// 会被 smoltcp 丢弃。
    pub fn new(
        inbound: mpsc::UnboundedReceiver<Packet>,
        outbound: mpsc::Sender<Packet>,
        mtu: usize,
    ) -> Self {
        // the global bus that drives the iface polling
        let (iface_notifier, iface_notifier_rx) = mpsc::unbounded_channel();

        let mut config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut device = NetstackDevice::new(outbound, iface_notifier.clone(), mtu);
        let mut iface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::now());
        // any_ip：TUN 网段任意目标地址（客户端 addr、DNS hijack addr 等）都可
        // 被本栈终结，等价 sing-tun gvisor 栈对任意 dst 的处理。
        iface.set_any_ip(true);
        iface.update_ip_addrs(|ip_addrs| {
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv4Address::new(10, 0, 0, 1).into(),
                24,
            ));
            let _ = ip_addrs.push(smoltcp::wire::IpCidr::new(
                smoltcp::wire::Ipv6Address::new(0, 0xfac, 0, 0, 0, 0, 0, 1).into(),
                64,
            ));
        });

        iface
            .routes_mut()
            .add_default_ipv4_route(smoltcp::wire::Ipv4Address::new(10, 0, 0, 1))
            .expect("Failed to add default IPv4 route");
        iface
            .routes_mut()
            .add_default_ipv6_route(smoltcp::wire::Ipv6Address::new(
                0, 0xfac, 0, 0, 0, 0, 0, 1,
            ))
            .expect("Failed to add default IPv6 route");

        let (socket_stream_emitter, socket_stream) = mpsc::unbounded_channel::<TcpStream>();

        let socket_stream_waker = Arc::new(AtomicWaker::new());

        let waker = socket_stream_waker.clone();
        // 活跃 socket 计数，poll_packets 用它做容量准入，poll_sockets 维护
        let live_sockets = Arc::new(AtomicUsize::new(0));
        let task_handle = tokio::spawn(async move {
            let rv = tokio::select! {
                biased;
                rv = Self::poll_packets(inbound, device.create_injector(), iface_notifier, socket_stream_emitter, waker, live_sockets.clone()) => rv,
                rv = Self::poll_sockets(&mut iface, &mut device, iface_notifier_rx, live_sockets) => rv,
            };
            if let Err(e) = rv {
                error!("Error in TCP listener: {e}");
            }
        });

        TcpListener {
            socket_stream,
            task_handle,
            socket_stream_waker,
        }
    }

    async fn poll_packets(
        mut inbound: mpsc::UnboundedReceiver<Packet>,
        device_injector: mpsc::UnboundedSender<Packet>,
        iface_notifier: mpsc::UnboundedSender<IfaceEvent<'static>>,
        tcp_stream_emitter: mpsc::UnboundedSender<TcpStream>,
        tcp_stream_waker: Arc<AtomicWaker>,
        live_sockets: Arc<AtomicUsize>,
    ) -> std::io::Result<()> {
        let mut packet_buf = Vec::with_capacity(32);
        let mut syn_tracker: HashMap<(SocketAddr, SocketAddr), std::time::Instant> = HashMap::new();
        let mut last_prune_time = std::time::Instant::now();

        loop {
            let n = inbound.recv_many(&mut packet_buf, 32).await;
            if n == 0 {
                break;
            }
            let now = std::time::Instant::now();
            if now.duration_since(last_prune_time) > SYN_TRACK_TTL {
                syn_tracker.retain(|_, time| now.duration_since(*time) < SYN_TRACK_TTL);
                last_prune_time = now;
            }

            for frame in packet_buf.drain(..) {
                let packet = match IpPacket::new_checked(frame.data()) {
                    Ok(packet) => packet,
                    Err(err) => {
                        warn!("Invalid packet: {err}");
                        continue;
                    }
                };

                // 用 transport() 跳过 IPv6 扩展头；`protocol()`/`payload()` 对
                // 带扩展头的包会误判协议且 TCP 载荷切片错位。
                let (proto, transport_payload) = match packet.transport() {
                    Some(v) => v,
                    None => {
                        debug!(
                            "TCP stack packet ignored (unlocatable transport header, \
                             e.g. IPv6 fragment / malformed ext chain)"
                        );
                        continue;
                    }
                };

                // Specially handle icmp packet by TCP interface.
                // smoltcp Interface 自动应答 ICMP echo（any_ip 模式下对任意
                // TUN 网段目标地址生效）。
                if matches!(proto, IpProtocol::Icmp | IpProtocol::Icmpv6) {
                    if let Err(err) = device_injector.send(frame) {
                        warn!("Failed to send packet to device: {err}");
                        continue;
                    }
                    if iface_notifier.send(IfaceEvent::Icmp).is_err() {
                        continue;
                    }
                    continue;
                }

                let src_ip = packet.src_addr();
                let dst_ip = packet.dst_addr();

                let packet = match TcpPacket::new_checked(transport_payload) {
                    Ok(p) => p,
                    Err(err) => {
                        debug!("invalid TCP packet: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}");
                        continue;
                    }
                };
                let src_port = packet.src_port();
                let dst_port = packet.dst_port();

                let src_addr = SocketAddr::new(src_ip, src_port);
                let dst_addr = SocketAddr::new(dst_ip, dst_port);

                if packet.syn() && !packet.ack() {
                    let conn_tuple = (src_addr, dst_addr);

                    let is_recent = syn_tracker.get_mut(&conn_tuple).is_some_and(|time| {
                        if now.duration_since(*time) < SYN_TRACK_TTL {
                            // Refresh timestamp so the entry doesn't expire
                            // while the connection is still retransmitting SYNs.
                            *time = now;
                            true
                        } else {
                            false
                        }
                    });
                    if is_recent {
                        // 重传的 SYN 直接注入既有 socket（不重复建连）
                        device_injector.send(frame).map_err(|e| {
                            error!("Failed to inject retransmitted SYN packet: {e}");
                            std::io::Error::other("Failed to inject retransmitted SYN packet")
                        })?;
                        continue;
                    }

                    if syn_tracker.len() >= SYN_TRACK_MAX {
                        continue;
                    }

                    // 容量准入 —— 活跃 socket 达上限时丢弃新 SYN（不进
                    // tracker，后续重传在负载下降后可成功）。
                    if live_sockets.load(Ordering::Relaxed) >= MAX_TCP_SOCKETS {
                        debug!(
                            "tcp listener: live socket cap ({}) reached, dropping SYN {} -> {}",
                            MAX_TCP_SOCKETS, src_addr, dst_addr
                        );
                        continue;
                    }

                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0u8; DEFAULT_TCP_RECV_BUFFER_SIZE as usize]),
                        tcp::SocketBuffer::new(vec![0u8; DEFAULT_TCP_SEND_BUFFER_SIZE as usize]),
                    );
                    // 对齐 sing-tun stack_gvisor_lazy.go（15s keepalive 探测）；
                    // 过大的 keepalive 间隔会让 NAT/防火墙中间设备更早断连
                    socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(15)));

                    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(
                        if cfg!(target_os = "linux") { 7200 } else { 60 },
                    )));
                    socket.set_ack_delay(Some(Duration::from_millis(10).into()));
                    socket.set_nagle_enabled(false);
                    socket.set_congestion_control(tcp::CongestionControl::Cubic);

                    if let Err(err) = socket.listen(dst_addr) {
                        error!("listen error: {err:?}");
                        continue;
                    }

                    // Track after listen() succeeds so a failed listen
                    // doesn't block future SYNs for the same tuple.
                    syn_tracker.insert(conn_tuple, now);

                    trace!("created TCP connection for {src_addr} <-> {dst_addr}");

                    let handle = Arc::new(TcpStreamHandle::new());

                    tcp_stream_emitter
                        .send(TcpStream {
                            local_addr: src_addr,
                            remote_addr: dst_addr,

                            handle: handle.clone(),
                            stack_notifier: iface_notifier.clone(),
                        })
                        .map_err(|e| {
                            error!("Failed to send TCP stream: {e}");
                            std::io::Error::other("Failed to send TCP stream")
                        })?;
                    iface_notifier
                        .send(IfaceEvent::TcpStream(Box::new((socket, handle))))
                        .map_err(|e| {
                            error!("Failed to send TCP stream event: {e}");
                            std::io::Error::other("Failed to send TCP stream event")
                        })?;
                    tcp_stream_waker.wake();
                } else {
                    // Non-SYN packet: the connection has progressed past the
                    // handshake, so remove the tracker entry to free the slot.
                    syn_tracker.remove(&(src_addr, dst_addr));
                }

                device_injector.send(frame).map_err(|e| {
                    error!("Failed to send packet to device: {e}");
                    std::io::Error::other("Failed to inject packet to device")
                })?;
            }

            // trigger another poll to drive the socket state machine
            iface_notifier
                .send(IfaceEvent::DeviceReady)
                .map_err(|e| {
                    error!("Failed to send device ready event: {e}");
                    std::io::Error::other("Failed to send device ready event")
                })?;
        }

        Ok(())
    }

    async fn poll_sockets(
        iface: &mut Interface,
        device: &mut NetstackDevice,
        mut notifier_rx: mpsc::UnboundedReceiver<IfaceEvent<'_>>,
        live_sockets: Arc<AtomicUsize>,
    ) -> std::io::Result<()> {
        // Create a socket set for TCP sockets
        let mut sockets = smoltcp::iface::SocketSet::new(vec![]);
        let mut socket_maps: HashMap<smoltcp::iface::SocketHandle, Arc<TcpStreamHandle>> =
            HashMap::new();
        let mut next_poll = None;

        loop {
            let should_poll_now = match (next_poll, socket_maps.len()) {
                (None, 0) => false,
                (None, _) => true,
                (Some(_), _) => false,
            };
            let now = smoltcp::time::Instant::now();

            if should_poll_now {
                // Drain any pending notifier events before calling iface.poll().
                //
                // The critical case is IfaceEvent::TcpStream: poll_packets creates
                // a smoltcp socket and queues it here *before* injecting the raw SYN
                // packet into the device buffer.  If iface.poll() runs before the
                // socket is added to the SocketSet, smoltcp sees the SYN with no
                // matching listener and sends RST — immediately failing the
                // connection.
                //
                // During active downloads poll_delay often returns 0/None, keeping
                // should_poll_now=true and never entering the else branch below.
                // Draining here ensures sockets are always registered in time.
                loop {
                    match notifier_rx.try_recv() {
                        Ok(IfaceEvent::TcpStream(stream)) => {
                            let socket_handle = sockets.add(stream.0);
                            socket_maps.insert(socket_handle, stream.1);
                            live_sockets.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(_) => {
                            // DeviceReady, TcpSocketReady, TcpSocketClosed,
                            // Icmp: "poll soon" — we're already about to.
                        }
                        Err(_) => break,
                    }
                }

                iface.poll(now, device, &mut sockets);
                // Poll the sockets for new connections or data
                for (socket_handle, socket_control) in socket_maps.iter() {
                    let socket = sockets.get_mut::<tcp::Socket>(*socket_handle);

                    let buf = &socket_control.recv_buffer;
                    let mut notify_read = false;
                    while socket.can_recv() && !buf.is_full() {
                        if socket
                            .recv(|buffer| {
                                let n = buf.enqueue_slice(buffer);
                                (n, n)
                            })
                            .is_ok()
                        {
                            notify_read = true;
                        }
                    }
                    if notify_read {
                        socket_control.recv_waker.wake();
                    }

                    let buf = &socket_control.send_buffer;
                    let mut notify_write = false;
                    while socket.can_send() && !buf.is_empty() {
                        if socket
                            .send(|buffer| {
                                let n = buf.dequeue_slice(buffer);
                                (n, n)
                            })
                            .is_ok()
                        {
                            notify_write = true;
                        }
                    }

                    if notify_write {
                        socket_control.send_waker.wake();
                    }

                    // Only signal EOF/close after the socket has moved past
                    // the handshake states (Listen, SynSent, SynReceived).
                    // During the handshake may_recv()/may_send() return false
                    // but that does NOT mean the connection is closing — the
                    // flags are one-way and would permanently break the stream.
                    let past_handshake = !matches!(
                        socket.state(),
                        tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
                    );

                    if past_handshake
                        && !socket.may_recv()
                        && !socket.can_recv()
                        && !socket_control.read_closed.swap(true, Ordering::AcqRel)
                    {
                        socket_control.recv_waker.wake();
                    }

                    if socket_control.write_shutdown.load(Ordering::Acquire)
                        && buf.is_empty()
                        && socket.may_send()
                    {
                        trace!("Closing TCP socket send half after buffer drained");
                        socket.close();
                    }

                    if past_handshake
                        && !socket.may_send()
                        && !socket_control.write_closed.swap(true, Ordering::AcqRel)
                    {
                        socket_control.send_waker.wake();
                    }
                }

                socket_maps.retain(|handle, socket_control| {
                    let socket = sockets.get_mut::<tcp::Socket>(*handle);

                    // Abort requested (RST on relay failure): discard all
                    // queued data immediately and send RST (smoltcp abort).
                    if socket_control
                        .abort_requested
                        .load(std::sync::atomic::Ordering::Acquire)
                    {
                        trace!("Aborting TCP socket (RST requested)");
                        socket.abort();
                        sockets.remove(*handle);
                        live_sockets.fetch_sub(1, Ordering::Relaxed);
                        socket_control
                            .socket_closed
                            .store(true, std::sync::atomic::Ordering::Release);
                        socket_control
                            .read_closed
                            .store(true, std::sync::atomic::Ordering::Release);
                        socket_control.write_closed.store(true, Ordering::Release);
                        socket_control.recv_waker.wake();
                        socket_control.send_waker.wake();
                        return false;
                    }

                    if socket_control
                        .socket_dropped
                        .load(std::sync::atomic::Ordering::Acquire)
                    {
                        // The app-side TcpStream was dropped.  Flush any
                        // remaining data from send_buffer into smoltcp's TX
                        // buffer, then initiate a graceful FIN.  We must NOT
                        // remove the socket immediately — doing so discards all
                        // data still queued in smoltcp's TX ring and causes
                        // "last N KB missing" stalls.
                        let buf = &socket_control.send_buffer;
                        while socket.can_send() && !buf.is_empty() {
                            let _ = socket.send(|buffer| {
                                let n = buf.dequeue_slice(buffer);
                                (n, n)
                            });
                        }
                        // Once all app data is enqueued, issue the FIN.
                        // Calling close() on an already-closing socket is a
                        // no-op in smoltcp, so this is safe to repeat each
                        // cycle until send_buffer is fully drained.
                        if buf.is_empty() {
                            socket.close();
                        }
                        // Fall through to is_active() check: keep the socket
                        // in socket_maps until smoltcp finishes the close
                        // handshake and reports is_active() == false.
                    }

                    if socket.is_active() {
                        true
                    } else {
                        trace!("Removing inactive TCP socket");
                        sockets.remove(*handle);
                        live_sockets.fetch_sub(1, Ordering::Relaxed);
                        // Unblock any in-flight poll_read / poll_write on this
                        // stream. socket_closed covers RST/timeout where
                        // read_closed may not have been set yet by the data
                        // path; write_closed prevents silent phantom writes to
                        // a dead socket.
                        socket_control
                            .socket_closed
                            .store(true, std::sync::atomic::Ordering::Release);
                        socket_control.write_closed.store(true, Ordering::Release);
                        socket_control.recv_waker.wake();
                        socket_control.send_waker.wake();
                        false
                    }
                });

                next_poll = match iface.poll_delay(now, &sockets) {
                    Some(smoltcp::time::Duration::ZERO) => None,
                    Some(delay) => Some(delay.into()),
                    None => None,
                };

                // Yield to the tokio scheduler so that other tasks (e.g.
                // StackSplitStream draining the tx packet channel) get a chance
                // to run between iface.poll() calls.  Without this yield, a
                // sustained smoltcp poll_delay == ZERO response (which occurs
                // whenever packets are waiting to be transmitted) creates a tight
                // synchronous loop that starves StackSplitStream, preventing the
                // consumer from receiving data and sending ACKs back.  That
                // starvation fills smoltcp's send window and triggers RTO.
                tokio::task::yield_now().await;
            } else {
                tokio::select! {
                    Some(event) = notifier_rx.recv() => {
                        trace!("Received iface event, will poll sockets");
                        next_poll = None; // reset the next poll time
                        match event {
                            IfaceEvent::TcpStream(stream) => {
                                let socket_handle = sockets.add(stream.0);
                                socket_maps.insert(socket_handle, stream.1);
                                live_sockets.fetch_add(1, Ordering::Relaxed);
                                trace!("Added new TCP socket: {socket_handle:?}");
                            }
                            IfaceEvent::TcpSocketReady
                            | IfaceEvent::TcpSocketClosed
                            | IfaceEvent::DeviceReady
                            | IfaceEvent::Icmp => {}
                        }
                    }
                    _ = tokio::time::sleep(next_poll.unwrap_or(Duration::MAX)) => {
                        trace!("Woke up to poll sockets after delay");
                        next_poll = None; // reset the next poll time
                    }
                }
            }
        }
    }
}

impl futures::Stream for TcpListener {
    type Item = TcpStream;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.socket_stream.try_recv() {
            Ok(stream) => std::task::Poll::Ready(Some(stream)),
            Err(e) => match e {
                mpsc::error::TryRecvError::Empty => {
                    // Register waker FIRST, then re-check to close the TOCTOU
                    // window: if poll_packets calls tcp_stream_waker.wake()
                    // between try_recv() and register(), the wake is lost.
                    self.socket_stream_waker.register(cx.waker());
                    match self.socket_stream.try_recv() {
                        Ok(stream) => std::task::Poll::Ready(Some(stream)),
                        Err(mpsc::error::TryRecvError::Empty) => std::task::Poll::Pending,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            std::task::Poll::Ready(None)
                        }
                    }
                }
                mpsc::error::TryRecvError::Disconnected => std::task::Poll::Ready(None),
            },
        }
    }
}
