//! WireGuard 隧道内的用户态 TCP/IP 协议栈（smoltcp）。
//!
//! WG 隧道承载的是 IP 包：dial 出的 TCP/UDP 会话由本模块的 smoltcp Interface
//! 封装成 IP 包交给 WG 加密，WG 解密出的 IP 包注入回本栈拆封。
//! 结构对齐 reflex `inbound/tun/netstack`（mpsc 化的 smoltcp Device + ring buffer
//! 异步桥接），但方向相反：reflex 是 inbound accept（listen 端），这里是
//! outbound dial（connect 端）；UDP 也走 smoltcp socket 而非手工封 IP 包。
//!
//! IP 包出口/入口：
//! - 出口（栈 → WG）：`Device::transmit` 的 tx token 把包 push 进 tx channel，
//!   由 wireguard.rs 的 wire task `Tunn::encapsulate` 后发 endpoint；
//! - 入口（WG → 栈）：wire task `Tunn::decapsulate` 得到明文 IP 包，经 rx injector
//!   进入 `Device::receive` 的 rx queue，由 poll task 驱动 `iface.poll` 消费。
//!
//! 唤醒模型：
//! - 应用 → 栈（新数据/新 dial）：`StackCmd::Nudge` 唤醒 poll task；
//! - 栈 → 应用（数据就绪/连接建立）：poll task 直接 wake 应用注册的 AtomicWaker。

use super::UdpSession;
use anyhow::Result;
use async_trait::async_trait;
use futures::task::AtomicWaker;
use smoltcp::{
    iface::{Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpCidr},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

// ── 常量 ─────────────────────────────────────────────────────────────────────

/// 每条 TCP 连接的应用侧 ring buffer（收/发各一份）。
/// 对齐 reflex netstack T1 之后的缓冲档位（2×64KiB/连接）。
const TCP_RING_BUF: usize = 64 * 1024;
/// smoltcp socket 内部缓冲（收/发各一份，与 ring buffer 同尺寸）。
const TCP_SOCK_BUF: usize = 64 * 1024;
/// 每个 UDP 会话的 smoltcp PacketBuffer 包数。
const UDP_PACKETS: usize = 32;
/// 应用侧 UDP 收发队列上限（包数）。满了丢最旧的（UDP 语义允许）。
const UDP_APP_QUEUE: usize = 128;
/// TCP dial 建立等待。外层 dial 无总超时，靠这里兜底。
const CONNECT_WAIT: Duration = Duration::from_secs(15);
/// poll task 无定时器时的默认轮询间隔（packet 到达有 Nudge 即时唤醒）。
const IDLE_POLL: u64 = 250;

/// Ephemeral 本地端口分配范围（对齐 Linux `ip_local_port_range` 默认值）。
const PORT_MIN: u16 = 32768;
const PORT_MAX: u16 = 60999;

// ── 端口分配 ─────────────────────────────────────────────────────────────────

#[derive(Default)]
struct PortAlloc {
    next: u16,
    used: HashSet<u16>,
}

impl PortAlloc {
    fn alloc(&mut self) -> io::Result<u16> {
        let span = (PORT_MAX - PORT_MIN) as u32 + 1;
        for _ in 0..span {
            let p = if !(PORT_MIN..=PORT_MAX).contains(&self.next) {
                PORT_MIN
            } else {
                self.next
            };
            self.next = p.wrapping_add(1);
            if self.used.insert(p) {
                return Ok(p);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::ResourceBusy,
            "wg: ephemeral local port pool exhausted",
        ))
    }

    fn free(&mut self, p: u16) {
        self.used.remove(&p);
    }
}

// ── 栈命令 ───────────────────────────────────────────────────────────────────

pub(crate) enum StackCmd {
    /// dial 一条 TCP 连接（poll task 内创建 smoltcp socket 并 connect）。
    TcpConnect {
        remote: SocketAddr,
        local: SocketAddr,
        handle: Arc<TcpStreamHandle>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    /// 绑定一个 UDP 会话端口。
    UdpBind {
        local: SocketAddr,
        handle: Arc<UdpHandle>,
        reply: oneshot::Sender<io::Result<()>>,
    },
    /// UDP 会话关闭（应用侧 drop）：移除 socket 并归还端口。
    UdpClose(Arc<UdpHandle>),
    /// 唤醒 poll task（有新数据/新事件，立即 poll 一轮）。
    Nudge,
}

// ── TCP ring buffer（对齐 reflex netstack LockFreeRingBuffer）────────────────

struct LockFreeRingBuffer {
    buffer: std::cell::UnsafeCell<Box<[u8]>>,
    capacity: usize,
    write_pos: AtomicUsize,
    read_pos: AtomicUsize,
}

unsafe impl Send for LockFreeRingBuffer {}
unsafe impl Sync for LockFreeRingBuffer {}

impl LockFreeRingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: std::cell::UnsafeCell::new(vec![0u8; capacity].into_boxed_slice()),
            capacity,
            write_pos: AtomicUsize::new(0),
            read_pos: AtomicUsize::new(0),
        }
    }

    /// poll task 调用（单生产者）。
    fn enqueue_slice(&self, data: &[u8]) -> usize {
        use std::sync::atomic::Ordering::*;
        let write_pos = self.write_pos.load(Relaxed);
        let read_pos = self.read_pos.load(Acquire);
        let available = if read_pos <= write_pos {
            self.capacity - write_pos + read_pos - 1
        } else {
            read_pos - write_pos - 1
        };
        let to_write = std::cmp::min(data.len(), available);
        if to_write == 0 {
            return 0;
        }
        unsafe {
            let buffer = &mut *self.buffer.get();
            if write_pos + to_write <= self.capacity {
                buffer[write_pos..write_pos + to_write].copy_from_slice(&data[..to_write]);
            } else {
                let first_part = self.capacity - write_pos;
                buffer[write_pos..].copy_from_slice(&data[..first_part]);
                buffer[..to_write - first_part].copy_from_slice(&data[first_part..to_write]);
            }
        }
        self.write_pos
            .store((write_pos + to_write) % self.capacity, Release);
        to_write
    }

    /// 应用线程调用（单消费者）。
    fn dequeue_slice(&self, buf: &mut [u8]) -> usize {
        use std::sync::atomic::Ordering::*;
        let read_pos = self.read_pos.load(Relaxed);
        let write_pos = self.write_pos.load(Acquire);
        let available = if write_pos >= read_pos {
            write_pos - read_pos
        } else {
            self.capacity - read_pos + write_pos
        };
        let to_read = std::cmp::min(buf.len(), available);
        if to_read == 0 {
            return 0;
        }
        unsafe {
            let buffer = &*self.buffer.get();
            if read_pos + to_read <= self.capacity {
                buf[..to_read].copy_from_slice(&buffer[read_pos..read_pos + to_read]);
            } else {
                let first_part = self.capacity - read_pos;
                buf[..first_part].copy_from_slice(&buffer[read_pos..]);
                buf[first_part..to_read].copy_from_slice(&buffer[..to_read - first_part]);
            }
        }
        self.read_pos
            .store((read_pos + to_read) % self.capacity, Release);
        to_read
    }

    fn is_empty(&self) -> bool {
        self.read_pos.load(Ordering::Acquire) == self.write_pos.load(Ordering::Acquire)
    }

    fn is_full(&self) -> bool {
        let read_pos = self.read_pos.load(Ordering::Acquire);
        let write_pos = self.write_pos.load(Ordering::Acquire);
        ((write_pos + 1) % self.capacity) == read_pos
    }
}

// ── TCP 连接控制块 ───────────────────────────────────────────────────────────

/// dial 建立状态：0 pending / 1 established / 2 failed。
const CONN_PENDING: u8 = 0;
const CONN_ESTABLISHED: u8 = 1;
const CONN_FAILED: u8 = 2;

pub(crate) struct TcpStreamHandle {
    pub(crate) recv_buffer: LockFreeRingBuffer,
    pub(crate) recv_waker: AtomicWaker,
    pub(crate) send_buffer: LockFreeRingBuffer,
    pub(crate) send_waker: AtomicWaker,
    /// 应用侧 stream 已 drop：poll task 排空 send_buffer 后发 FIN。
    pub(crate) socket_dropped: AtomicBool,
    /// smoltcp socket 不再活跃（FIN 完成/RST/超时）：read 返回 EOF。
    pub(crate) socket_closed: AtomicBool,
    pub(crate) read_closed: AtomicBool,
    pub(crate) write_closed: AtomicBool,
    /// poll_shutdown 后置位：send_buffer 排空时由 poll task 调 socket.close()。
    pub(crate) write_shutdown: AtomicBool,
    pub(crate) abort_requested: AtomicBool,
    /// connect 结果（dial 等待用）。
    connect_status: AtomicU8,
    connect_waker: AtomicWaker,
    /// 分配的本地端口（socket 移除时归还端口池）。
    local_port: u16,
}

impl TcpStreamHandle {
    fn new(local_port: u16) -> Self {
        Self {
            recv_buffer: LockFreeRingBuffer::new(TCP_RING_BUF),
            recv_waker: AtomicWaker::new(),
            send_buffer: LockFreeRingBuffer::new(TCP_RING_BUF),
            send_waker: AtomicWaker::new(),
            socket_dropped: AtomicBool::new(false),
            socket_closed: AtomicBool::new(false),
            read_closed: AtomicBool::new(false),
            write_closed: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            abort_requested: AtomicBool::new(false),
            connect_status: AtomicU8::new(CONN_PENDING),
            connect_waker: AtomicWaker::new(),
            local_port,
        }
    }

    fn set_connect_status(&self, status: u8) {
        self.connect_status.store(status, Ordering::Release);
        self.connect_waker.wake();
    }
}

// ── UDP 会话控制块 ───────────────────────────────────────────────────────────

pub(crate) struct UdpHandle {
    /// 应用 → 栈 的待发包（poll task 排空进 smoltcp tx buffer）。
    tx_queue: StdMutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// 栈 → 应用 的已收包。
    rx_queue: StdMutex<QueueState>,
    pub(crate) rx_waker: AtomicWaker,
    local_port: u16,
}

struct QueueState {
    packets: VecDeque<(Vec<u8>, SocketAddr)>,
    closed: bool,
}

impl UdpHandle {
    fn new(local_port: u16) -> Self {
        Self {
            tx_queue: StdMutex::new(VecDeque::new()),
            rx_queue: StdMutex::new(QueueState {
                packets: VecDeque::new(),
                closed: false,
            }),
            rx_waker: AtomicWaker::new(),
            local_port,
        }
    }

    fn push_tx(&self, data: Vec<u8>, dst: SocketAddr) {
        let mut q = self.tx_queue.lock().unwrap();
        if q.len() >= UDP_APP_QUEUE {
            q.pop_front();
        }
        q.push_back((data, dst));
    }
}

// ── 栈句柄（WG outbound 持有）────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct StackHandle {
    cmd_tx: mpsc::UnboundedSender<StackCmd>,
    ports: Arc<StdMutex<PortAlloc>>,
}

impl StackHandle {
    fn send_cmd(&self, cmd: StackCmd) {
        // 接收端是长驻 poll task；send 失败说明栈已死，忽略（后续 IO 自然报错）。
        let _ = self.cmd_tx.send(cmd);
    }

    /// 唤醒 poll task（wire task 注入解密 IP 包后调用，保证 ingress 即时被消费）。
    pub(crate) fn nudge(&self) {
        self.send_cmd(StackCmd::Nudge);
    }

    /// dial TCP：创建 socket + connect，等待 Established（或失败）。
    pub(crate) async fn connect_tcp(
        &self,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> io::Result<WgTcpStream> {
        let port = self.alloc_port()?;
        let handle = Arc::new(TcpStreamHandle::new(port));
        let (tx, rx) = oneshot::channel();
        self.send_cmd(StackCmd::TcpConnect {
            remote,
            local,
            handle: handle.clone(),
            reply: tx,
        });
        // rx：connect() 同步失败（参数/栈错误）走这里；否则等 poll task 报握手结果。
        let established = async {
            match rx.await {
                Ok(res) => res?,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "wg stack closed",
                    ))
                }
            }
            wait_established(&handle).await
        };
        match tokio::time::timeout(CONNECT_WAIT, established).await {
            Ok(Ok(())) => Ok(WgTcpStream {
                local,
                remote,
                handle,
                stack: self.clone(),
            }),
            Ok(Err(e)) => {
                self.ports.lock().unwrap().free(port);
                Err(e)
            }
            Err(_) => {
                // 超时：标记 abort，poll task reap 时 RST 并归还端口。
                handle.set_connect_status(CONN_FAILED);
                handle.abort_requested.store(true, Ordering::Release);
                self.send_cmd(StackCmd::Nudge);
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("wg tcp connect {remote} timed out"),
                ))
            }
        }
    }

    /// dial UDP：绑定本地端口，返回 UdpSession。
    pub(crate) async fn bind_udp(&self, local: SocketAddr) -> io::Result<WgUdpSession> {
        let port = self.alloc_port()?;
        let handle = Arc::new(UdpHandle::new(port));
        let (tx, rx) = oneshot::channel();
        self.send_cmd(StackCmd::UdpBind {
            local: SocketAddr::new(local.ip(), port),
            handle: handle.clone(),
            reply: tx,
        });
        match tokio::time::timeout(CONNECT_WAIT, rx).await {
            Ok(Ok(Ok(()))) => Ok(WgUdpSession {
                stack: self.clone(),
                handle,
            }),
            Ok(Ok(Err(e))) => {
                self.ports.lock().unwrap().free(port);
                Err(e)
            }
            Ok(Err(_)) | Err(_) => {
                self.ports.lock().unwrap().free(port);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "wg udp bind failed or timed out",
                ))
            }
        }
    }
}

/// 等待 poll task 把 connect 状态推到终态。
async fn wait_established(handle: &TcpStreamHandle) -> io::Result<()> {
    let refused = || {
        io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "wg tcp connection failed (RST / no route in tunnel)",
        )
    };
    std::future::poll_fn(|cx| {
        match handle.connect_status.load(Ordering::Acquire) {
            CONN_ESTABLISHED => return Poll::Ready(Ok(())),
            CONN_FAILED => return Poll::Ready(Err(refused())),
            _ => {}
        }
        // 先 register 再复查，关掉 TOCTOU 窗口（对齐 reflex poll_read 写法）。
        handle.connect_waker.register(cx.waker());
        match handle.connect_status.load(Ordering::Acquire) {
            CONN_ESTABLISHED => Poll::Ready(Ok(())),
            CONN_FAILED => Poll::Ready(Err(refused())),
            _ => Poll::Pending,
        }
    })
    .await
}

// ── smoltcp Device（mpsc 化，对齐 reflex netstack device）────────────────────

struct WgDevice {
    rx_queue: mpsc::UnboundedReceiver<Vec<u8>>,
    tx_sender: mpsc::Sender<Vec<u8>>,
    caps: DeviceCapabilities,
}

impl Device for WgDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // 先占 tx slot 再取 rx 包：若先取包而 tx 无 slot，包（可能是 ACK）会被
        // 静默丢掉，smoltcp 发送窗口无法推进（reflex netstack 修过的 bug）。
        let permit = self.tx_sender.try_reserve().ok()?;
        let packet = self.rx_queue.try_recv().ok()?;
        Some((RxTokenImpl { packet }, TxTokenImpl { tx_sender: permit }))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        self.tx_sender
            .try_reserve()
            .map(|permit| TxTokenImpl { tx_sender: permit })
            .ok()
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

struct RxTokenImpl {
    packet: Vec<u8>,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

struct TxTokenImpl<'a> {
    tx_sender: mpsc::Permit<'a, Vec<u8>>,
}

impl TxToken for TxTokenImpl<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tx_sender.send(buffer);
        result
    }
}

// ── 栈创建 + poll task ───────────────────────────────────────────────────────

pub(crate) struct WgStack;

impl WgStack {
    /// 创建栈并启动 poll task。
    ///
    /// 返回 (StackHandle, tx_rx, rx_tx)：
    /// - `tx_rx`：栈产出的 IP 包（WG 出站，wire task 拿去 encapsulate）；
    /// - `rx_tx`：WG 解密出的明文 IP 包注入口（wire task 持有）。
    pub(crate) fn new(
        mtu: u32,
        local_cidrs: &[IpCidr],
        v4_gateway: Option<std::net::Ipv4Addr>,
        v6_gateway: Option<std::net::Ipv6Addr>,
    ) -> (
        StackHandle,
        mpsc::Receiver<Vec<u8>>,
        mpsc::UnboundedSender<Vec<u8>>,
    ) {
        let (tx_sender, tx_rx) = mpsc::channel::<Vec<u8>>(4096);
        let (rx_sender, rx_queue) = mpsc::unbounded_channel::<Vec<u8>>();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<StackCmd>();

        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = mtu as usize;
        caps.medium = Medium::Ip;
        let mut device = WgDevice {
            rx_queue,
            tx_sender,
            caps,
        };

        let mut config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random::<u64>();
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        iface.update_ip_addrs(|addrs| {
            for cidr in local_cidrs {
                let _ = addrs.push(*cidr);
            }
        });
        // Medium::Ip 无 ARP/NDISC，default route 的网关只是查表用，任意可达值即可；
        // WG 对端隧道地址（local + 1）是惯例取值（wireguard-go 同款语义）。
        if let Some(gw) = v4_gateway {
            let _ = iface.routes_mut().add_default_ipv4_route(gw.into());
        }
        if let Some(gw) = v6_gateway {
            let _ = iface.routes_mut().add_default_ipv6_route(gw.into());
        }

        let ports = Arc::new(StdMutex::new(PortAlloc::default()));
        tokio::spawn(poll_loop(
            iface,
            device,
            cmd_rx,
            Arc::clone(&ports),
            mtu as usize,
        ));

        (
            StackHandle { cmd_tx, ports },
            tx_rx,
            rx_sender,
        )
    }
}

/// 单 UDP datagram 的应用侧上限：内层 IP 包 ≤ MTU，IP+UDP 头 28 字节。
/// 超过的 datagram 在 `send_slice` 阶段即被拒（Truncated），不会堵住 tx buffer。
fn udp_dgram_buf(mtu: usize) -> usize {
    mtu.saturating_sub(28).max(576)
}

#[allow(clippy::too_many_arguments)]
async fn poll_loop(
    mut iface: Interface,
    mut device: WgDevice,
    mut cmd_rx: mpsc::UnboundedReceiver<StackCmd>,
    ports: Arc<StdMutex<PortAlloc>>,
    mtu: usize,
) {
    let mut sockets: SocketSet = SocketSet::new(vec![]);
    let mut tcp_map: HashMap<SocketHandle, Arc<TcpStreamHandle>> = HashMap::new();
    let mut udp_map: HashMap<SocketHandle, Arc<UdpHandle>> = HashMap::new();
    let mut pending_connect: HashMap<SocketHandle, oneshot::Sender<io::Result<()>>> =
        HashMap::new();
    let dgram_buf = udp_dgram_buf(mtu);

    loop {
        // 1. 应用待处理命令（Nudge / dial / bind / close）。
        while let Ok(cmd) = cmd_rx.try_recv() {
            apply_cmd(
                &mut iface,
                &mut sockets,
                &mut tcp_map,
                &mut udp_map,
                &mut pending_connect,
                &ports,
                dgram_buf,
                cmd,
            );
        }

        // 2. 驱动协议栈（ingress + egress + 定时器）。
        let now = SmolInstant::now();
        iface.poll(now, &mut device, &mut sockets);

        // 3. 在栈 socket 与应用 ring/queue 之间搬运数据。
        for (h, ctl) in tcp_map.iter() {
            pump_tcp(
                sockets.get_mut::<tcp::Socket>(*h),
                ctl,
                *h,
                &mut pending_connect,
            );
        }
        for (h, ctl) in udp_map.iter() {
            pump_udp(sockets.get_mut::<udp::Socket>(*h), ctl);
        }

        // 4. 回收：已关闭/已 abort 的 TCP socket 出册并归还端口。
        //    （UDP 会话的回收走 StackCmd::UdpClose，见 WgUdpSession::drop。）
        reap_tcp(&mut sockets, &mut tcp_map, &mut pending_connect, &ports);

        // yield 给调度器，避免 poll_delay==0 时饿死其他 task（reflex 同款处理）。
        tokio::task::yield_now().await;

        // 5. 等下一轮：栈定时器到期 / 新命令（Nudge）/ 空转兜底。
        let delay = iface.poll_delay(SmolInstant::now(), &sockets);
        let wait = match delay {
            Some(d) if d.total_millis() == 0 => Duration::ZERO,
            Some(d) => Duration::from_millis(d.millis().max(1) as u64),
            None => Duration::from_millis(IDLE_POLL),
        };
        tokio::select! {
            cmd = cmd_rx.recv() => match cmd {
                Some(cmd) => apply_cmd(
                    &mut iface,
                    &mut sockets,
                    &mut tcp_map,
                    &mut udp_map,
                    &mut pending_connect,
                    &ports,
                    dgram_buf,
                    cmd,
                ),
                None => break,
            },
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_cmd(
    iface: &mut Interface,
    sockets: &mut SocketSet,
    tcp_map: &mut HashMap<SocketHandle, Arc<TcpStreamHandle>>,
    udp_map: &mut HashMap<SocketHandle, Arc<UdpHandle>>,
    pending_connect: &mut HashMap<SocketHandle, oneshot::Sender<io::Result<()>>>,
    ports: &StdMutex<PortAlloc>,
    dgram_buf: usize,
    cmd: StackCmd,
) {
    match cmd {
        StackCmd::TcpConnect {
            remote,
            local,
            handle,
            reply,
        } => {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_SOCK_BUF]),
                tcp::SocketBuffer::new(vec![0u8; TCP_SOCK_BUF]),
            );
            // keepalive/ack-delay/超时对齐 reflex netstack（sing-tun gvisor 栈语义）。
            socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(15)));
            socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
            socket.set_ack_delay(Some(smoltcp::time::Duration::from_millis(10)));
            socket.set_nagle_enabled(false);
            match socket.connect(iface.context(), remote, local) {
                Ok(()) => {
                    let h = sockets.add(socket);
                    tcp_map.insert(h, handle);
                    pending_connect.insert(h, reply);
                }
                Err(e) => {
                    let _ = reply.send(Err(io::Error::other(format!(
                        "wg tcp connect {remote}: {e:?}"
                    ))));
                }
            }
        }
        StackCmd::UdpBind {
            local,
            handle,
            reply,
        } => {
            let bufs = || {
                udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::default(); UDP_PACKETS],
                    vec![0u8; dgram_buf * UDP_PACKETS],
                )
            };
            let mut socket = udp::Socket::new(bufs(), bufs());
            match socket.bind(local) {
                Ok(()) => {
                    let h = sockets.add(socket);
                    udp_map.insert(h, handle);
                    let _ = reply.send(Ok(()));
                }
                Err(e) => {
                    let _ = reply.send(Err(io::Error::other(format!(
                        "wg udp bind {local}: {e:?}"
                    ))));
                }
            }
        }
        StackCmd::UdpClose(h) => {
            let mut removed = Vec::new();
            udp_map.retain(|sk, v| {
                if Arc::ptr_eq(v, &h) {
                    removed.push(*sk);
                    false
                } else {
                    true
                }
            });
            for sk in removed {
                sockets.remove(sk);
                ports.lock().unwrap().free(h.local_port);
            }
        }
        StackCmd::Nudge => {}
    }
}

/// 在一条 TCP 连接的 smoltcp socket 与应用 ring buffer 间搬数据（对齐 reflex）。
fn pump_tcp(
    socket: &mut tcp::Socket,
    ctl: &TcpStreamHandle,
    h: SocketHandle,
    pending_connect: &mut HashMap<SocketHandle, oneshot::Sender<io::Result<()>>>,
) {
    // 栈 → 应用
    let mut notify_read = false;
    while socket.can_recv() && !ctl.recv_buffer.is_full() {
        let Ok(n) = socket.recv(|buf| {
            let n = ctl.recv_buffer.enqueue_slice(buf);
            (n, n)
        }) else {
            break;
        };
        let _ = n;
        notify_read = true;
    }
    if notify_read {
        ctl.recv_waker.wake();
    }

    // 应用 → 栈（未 Established 时 send 返回 Illegal，数据留在 ring 里下轮重试）
    let mut notify_write = false;
    while socket.can_send() && !ctl.send_buffer.is_empty() {
        let Ok(n) = socket.send(|buf| {
            let n = ctl.send_buffer.dequeue_slice(buf);
            (n, n)
        }) else {
            break;
        };
        let _ = n;
        notify_write = true;
    }
    if notify_write {
        ctl.send_waker.wake();
    }

    // EOF/close 标志：只在握手之后判（握手期 may_recv/may_send 为 false 不代表关闭）。
    let past_handshake = !matches!(
        socket.state(),
        tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
    );
    if past_handshake
        && !socket.may_recv()
        && !socket.can_recv()
        && !ctl.read_closed.swap(true, Ordering::AcqRel)
    {
        ctl.recv_waker.wake();
    }
    if ctl.write_shutdown.load(Ordering::Acquire)
        && ctl.send_buffer.is_empty()
        && socket.may_send()
    {
        socket.close();
    }
    if past_handshake
        && !socket.may_send()
        && !ctl.write_closed.swap(true, Ordering::AcqRel)
    {
        ctl.send_waker.wake();
    }

    // dial 建立结果上报。
    if ctl.connect_status.load(Ordering::Acquire) == CONN_PENDING {
        match socket.state() {
            tcp::State::Established => {
                ctl.set_connect_status(CONN_ESTABLISHED);
                if let Some(reply) = pending_connect.remove(&h) {
                    let _ = reply.send(Ok(()));
                }
            }
            tcp::State::Closed
            | tcp::State::TimeWait
            | tcp::State::CloseWait
            | tcp::State::FinWait1
            | tcp::State::FinWait2
            | tcp::State::LastAck => {
                // 未 Established 就进入关闭态：RST（拒绝/无路由）或立即 FIN。
                ctl.set_connect_status(CONN_FAILED);
                if let Some(reply) = pending_connect.remove(&h) {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("wg tcp connect failed in tunnel (state {:?})", socket.state()),
                    )));
                }
            }
            _ => {}
        }
    }
}

/// 在一个 UDP 会话的 smoltcp socket 与应用队列间搬数据。
fn pump_udp(socket: &mut udp::Socket, ctl: &UdpHandle) {
    // 应用 → 栈
    {
        let mut q = ctl.tx_queue.lock().unwrap();
        while let Some((data, dst)) = q.front() {
            match socket.send_slice(data, *dst) {
                Ok(()) => {
                    q.pop_front();
                }
                Err(udp::SendError::Exhausted) => break, // tx buffer 满，下轮重试
                Err(e) => {
                    // Unaddressable / Truncated：坏包直接丢（UDP 语义）。
                    tracing::debug!("wg udp send to {dst}: {e:?}");
                    q.pop_front();
                }
            }
        }
    }
    // 栈 → 应用
    let mut deliver: Vec<(Vec<u8>, SocketAddr)> = Vec::new();
    loop {
        match socket.recv() {
            Ok((payload, meta)) => deliver.push((payload.to_vec(), meta.endpoint.into())),
            Err(_) => break,
        }
    }
    if !deliver.is_empty() {
        let closed = {
            let mut q = ctl.rx_queue.lock().unwrap();
            for item in deliver {
                if q.packets.len() >= UDP_APP_QUEUE {
                    q.packets.pop_front();
                }
                q.packets.push_back(item);
            }
            q.closed
        };
        if !closed {
            ctl.rx_waker.wake();
        }
    }
}

fn reap_tcp(
    sockets: &mut SocketSet,
    tcp_map: &mut HashMap<SocketHandle, Arc<TcpStreamHandle>>,
    pending_connect: &mut HashMap<SocketHandle, oneshot::Sender<io::Result<()>>>,
    ports: &StdMutex<PortAlloc>,
) {
    tcp_map.retain(|h, ctl| {
        let socket = sockets.get_mut::<tcp::Socket>(*h);

        // abort（dial 超时等）：立即 RST，不排空。
        if ctl.abort_requested.load(Ordering::Acquire) {
            socket.abort();
            sockets.remove(*h);
            finish_tcp(ctl, h, pending_connect, ports);
            return false;
        }

        // 应用侧已 drop：排空 send_buffer 后发 FIN（reflex 同款 drain-then-close，
        // 避免丢掉 smoltcp tx ring 里未发出的数据）。
        if ctl.socket_dropped.load(Ordering::Acquire) {
            while socket.can_send() && !ctl.send_buffer.is_empty() {
                let Ok(_) = socket.send(|buf| {
                    let n = ctl.send_buffer.dequeue_slice(buf);
                    (n, n)
                }) else {
                    break;
                };
            }
            if ctl.send_buffer.is_empty() {
                socket.close();
            }
        }

        if socket.is_active() {
            true
        } else {
            sockets.remove(*h);
            finish_tcp(ctl, h, pending_connect, ports);
            false
        }
    });
}

/// socket 出册后的统一收尾：关标志、唤醒应用、归还端口、上报 dial 失败。
fn finish_tcp(
    ctl: &TcpStreamHandle,
    h: SocketHandle,
    pending_connect: &mut HashMap<SocketHandle, oneshot::Sender<io::Result<()>>>,
    ports: &StdMutex<PortAlloc>,
) {
    ctl.socket_closed.store(true, Ordering::Release);
    ctl.read_closed.store(true, Ordering::Release);
    ctl.write_closed.store(true, Ordering::Release);
    ctl.set_connect_status(CONN_FAILED);
    ctl.recv_waker.wake();
    ctl.send_waker.wake();
    ports.lock().unwrap().free(ctl.local_port);
    pending_connect.remove(&h);
}

// ── 应用侧 TCP 流（实现 AsyncRead/AsyncWrite，供 BoxedStream 使用）───────────

pub(crate) struct WgTcpStream {
    local: SocketAddr,
    remote: SocketAddr,
    pub(crate) handle: Arc<TcpStreamHandle>,
    stack: StackHandle,
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        self.handle.socket_dropped.store(true, Ordering::Release);
        self.handle.read_closed.store(true, Ordering::Release);
        self.handle.write_closed.store(true, Ordering::Release);
        self.handle.recv_waker.wake();
        self.handle.send_waker.wake();
        self.stack.send_cmd(StackCmd::Nudge);
    }
}

impl std::fmt::Debug for WgTcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgTcpStream")
            .field("local", &self.local)
            .field("remote", &self.remote)
            .finish()
    }
}

impl tokio::io::AsyncRead for WgTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let read_buf = &self.handle.recv_buffer;
        if read_buf.is_empty() {
            self.handle.recv_waker.register(cx.waker());
            if read_buf.is_empty() {
                if self.handle.socket_closed.load(Ordering::Acquire)
                    || self.handle.read_closed.load(Ordering::Acquire)
                {
                    return Poll::Ready(Ok(())); // EOF
                }
                return Poll::Pending;
            }
        }

        // ReadBuf 未初始化内存桥接：对齐 reflex netstack（已审计写法）。
        let unfilled = unsafe {
            std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(buf.unfilled_mut())
        };
        let n = read_buf.dequeue_slice(unfilled);
        buf.advance(n);

        // 有空间了，让 poll task 继续 recv。
        self.stack.send_cmd(StackCmd::Nudge);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for WgTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.handle.write_closed.load(Ordering::Acquire)
            || self.handle.write_shutdown.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "wg tcp stream write half closed",
            )));
        }

        let send_buf = &self.handle.send_buffer;
        if send_buf.is_full() {
            self.handle.send_waker.register(cx.waker());
            if send_buf.is_full() {
                return Poll::Pending;
            }
        }

        let n = send_buf.enqueue_slice(buf);
        self.stack.send_cmd(StackCmd::Nudge);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stack.send_cmd(StackCmd::Nudge);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 半关闭：write_shutdown 置位后由 poll task 在 send_buffer 排空时发 FIN。
        this.handle.write_shutdown.store(true, Ordering::Release);
        this.handle.send_waker.wake();
        this.stack.send_cmd(StackCmd::Nudge);
        let _ = cx;
        Poll::Ready(Ok(()))
    }
}

// ── 应用侧 UDP 会话（实现 outbound::UdpSession）──────────────────────────────

pub(crate) struct WgUdpSession {
    stack: StackHandle,
    handle: Arc<UdpHandle>,
}

impl Drop for WgUdpSession {
    fn drop(&mut self) {
        {
            let mut q = self.handle.rx_queue.lock().unwrap();
            q.closed = true;
        }
        self.handle.rx_waker.wake();
        self.stack.send_cmd(StackCmd::UdpClose(self.handle.clone()));
        self.stack.send_cmd(StackCmd::Nudge);
    }
}

#[async_trait]
impl UdpSession for WgUdpSession {
    async fn send_to(&self, data: &[u8], dst: SocketAddr, _dst_host: Option<&str>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.handle.push_tx(data.to_vec(), dst);
        self.stack.send_cmd(StackCmd::Nudge);
        Ok(())
    }

    async fn recv_from(&self) -> Result<(Vec<u8>, SocketAddr)> {
        std::future::poll_fn(|cx| {
            {
                let mut q = self.handle.rx_queue.lock().unwrap();
                if let Some(item) = q.packets.pop_front() {
                    return Poll::Ready(Ok(item));
                }
            }
            self.handle.rx_waker.register(cx.waker());
            let mut q = self.handle.rx_queue.lock().unwrap();
            if let Some(item) = q.packets.pop_front() {
                return Poll::Ready(Ok(item));
            }
            if q.closed {
                return Poll::Ready(Err(anyhow::anyhow!("wg udp session closed")));
            }
            Poll::Pending
        })
        .await
    }
}

// ── 地址辅助 ─────────────────────────────────────────────────────────────────

/// 从目标地址族选本地源地址；无对应族地址时 fail-fast（config 已要求至少一个）。
pub(crate) fn pick_local_ip(local_v4: Option<IpAddr>, local_v6: Option<IpAddr>, dst: IpAddr) -> Result<IpAddr> {
    match (dst, local_v4, local_v6) {
        (IpAddr::V4(_), Some(v4), _) => Ok(v4),
        (IpAddr::V6(_), _, Some(v6)) => Ok(v6),
        (IpAddr::V4(_), None, _) => Err(anyhow::anyhow!(
            "wireguard: no local-address for IPv4 (add e.g. 10.7.0.2/32)"
        )),
        (IpAddr::V6(_), _, None) => Err(anyhow::anyhow!(
            "wireguard: no local-address for IPv6 (add e.g. fd42::2/128)"
        )),
    }
}

/// UDP 会话的默认绑定族：优先 v4（对齐 DirectOutbound 的 "0.0.0.0:0" 行为）。
pub(crate) fn pick_default_ip(local_v4: Option<IpAddr>, local_v6: Option<IpAddr>) -> Result<IpAddr> {
    local_v4
        .or(local_v6)
        .ok_or_else(|| anyhow::anyhow!("wireguard: local-address is empty"))
}
