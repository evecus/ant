//! NativeTun: virtio_net_hdr + GSO split (read, Linux) + GRO coalesce (write).
//!
//! ## Platform notes
//! - **Linux**: kernel may set IFF_VNET_HDR; read peels virtio_net_hdr and splits GSO;
//!   write runs handle_gro and sends buffers including virtio_net_hdr.
//! - **macOS (utun)**: batch I/O via `recvmsg_x` / `sendmsg_x` (sing-tun
//!   `rawfile_darwin`). Kernel frames carry a 4-byte AF family PI header;
//!   this module strips on read / prepends on write so the stack always sees
//!   **pure IP**. No kernel GSO; GRO disabled.
//! - **Windows (WinTun)**: frames are pure IP (no virtio_net_hdr, no kernel GSO).
//!   Read is plain IP. Write still runs **userspace GRO** (handle_gro) with an
//!   internal virtio_net_hdr scratch region, then strips the 10-byte prefix
//!   before sending to WinTun — coalesced large IP packets are valid on WinTun.

use super::gso::{
    self, handle_gro, GroDisablementFlags, TcpGroTable, UdpGroTable, VirtioNetHdr,
    VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_LEN,
};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, Notify};
use tracing::warn;
#[cfg(target_os = "macos")]
use tracing::info;

/// Flush GRO pending when this many packets are queued.
const GRO_BATCH_SIZE: usize = 16;

/// Write-side batch size for macOS sendmsg_x (sing-tun style).
#[cfg(target_os = "macos")]
const DARWIN_WRITE_BATCH: usize = 32;

pub struct NativeTun {
    reader: Arc<Mutex<NativeTunReader>>,
    writer: Arc<Mutex<NativeTunWriter>>,
}

impl NativeTun {
    /// Linux / Windows / generic path via AsyncRead + AsyncWrite.
    pub fn new(
        dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        vnet_hdr: bool,
        gro_flags: GroDisablementFlags,
    ) -> Self {
        let (r, w) = tokio::io::split(dev);
        Self {
            reader: Arc::new(Mutex::new(NativeTunReader {
                #[cfg(not(target_os = "macos"))]
                inner: Some(Box::pin(r)),
                #[cfg(target_os = "macos")]
                inner: Some(Box::pin(r)),
                vnet_hdr,
                pending: VecDeque::new(),
                read_buf: vec![0u8; gso::GSO_MAX_SIZE + VIRTIO_NET_HDR_LEN],
                #[cfg(target_os = "macos")]
                darwin: None,
            })),
            writer: Arc::new(Mutex::new(NativeTunWriter {
                #[cfg(not(target_os = "macos"))]
                inner: Some(Box::pin(w)),
                #[cfg(target_os = "macos")]
                inner: Some(Box::pin(w)),
                vnet_hdr,
                gro_enabled: vnet_hdr,
                gro_flags,
                tcp_table: TcpGroTable::new(),
                udp_table: UdpGroTable::new(),
                pending: Vec::new(),
                flush_notify: Arc::new(Notify::new()),
                #[cfg(target_os = "macos")]
                darwin: None,
            })),
        }
    }

    /// macOS utun path: `recvmsg_x` / `sendmsg_x` batch I/O (sing-tun).
    ///
    /// Takes exclusive ownership of `fd` (e.g. from `Device::into_raw_fd()`).
    /// Do not also wrap the same fd in `tun::AsyncDevice` / a second `AsyncFd`.
    #[cfg(target_os = "macos")]
    #[allow(dead_code)] // wired when create path yields a raw fd
    pub fn new_macos(fd: std::os::fd::RawFd, mtu: u32, rcvbuf: i32, close_on_drop: bool) -> io::Result<Self> {
        use super::darwin_batch::{self, OwnedTunFd, WriteGate};
        use tokio::io::unix::AsyncFd;

        darwin_batch::configure_fd(fd, mtu, rcvbuf)?;

        let batch_size = darwin_batch::batch_size_for_mtu(mtu);
        let async_fd = AsyncFd::new(fd).map_err(|e| {
            io::Error::new(e.kind(), format!("AsyncFd for utun: {e}"))
        })?;

        let write_gate = Arc::new(WriteGate::new());
        let keep = Arc::new(OwnedTunFd::new(fd, close_on_drop));

        info!(
            fd,
            mtu,
            batch_size,
            rcvbuf,
            "tun: macOS batch I/O enabled (recvmsg_x / sendmsg_x)"
        );

        let reader = NativeTunReader {
            inner: None,
            vnet_hdr: false,
            pending: VecDeque::new(),
            read_buf: Vec::new(),
            darwin: Some(DarwinReader {
                async_fd,
                mtu,
                batch_size,
                _keep: keep.clone(),
            }),
        };
        let writer = NativeTunWriter {
            inner: None,
            vnet_hdr: false,
            gro_enabled: false,
            gro_flags: GroDisablementFlags::default(),
            tcp_table: TcpGroTable::new(),
            udp_table: UdpGroTable::new(),
            pending: Vec::new(),
            flush_notify: Arc::new(Notify::new()),
            darwin: Some(DarwinWriter {
                fd,
                write_gate,
                batch: Vec::with_capacity(DARWIN_WRITE_BATCH),
                _keep: keep,
            }),
        };

        Ok(Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
        })
    }

    pub fn split(self) -> (Arc<Mutex<NativeTunReader>>, Arc<Mutex<NativeTunWriter>>) {
        (self.reader, self.writer)
    }
}

#[cfg(target_os = "macos")]
struct DarwinReader {
    async_fd: tokio::io::unix::AsyncFd<std::os::fd::RawFd>,
    mtu: u32,
    batch_size: usize,
    _keep: Arc<super::darwin_batch::OwnedTunFd>,
}

#[cfg(target_os = "macos")]
struct DarwinWriter {
    fd: std::os::fd::RawFd,
    write_gate: Arc<super::darwin_batch::WriteGate>,
    batch: Vec<Vec<u8>>,
    _keep: Arc<super::darwin_batch::OwnedTunFd>,
}

pub struct NativeTunReader {
    /// AsyncRead backend (Linux / Windows). `None` on macOS batch path.
    inner: Option<Pin<Box<dyn AsyncRead + Unpin + Send>>>,
    vnet_hdr: bool,
    pending: VecDeque<Vec<u8>>,
    read_buf: Vec<u8>,
    #[cfg(target_os = "macos")]
    darwin: Option<DarwinReader>,
}

impl NativeTunReader {
    pub async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        if let Some(pkt) = self.pending.pop_front() {
            return Ok(pkt);
        }

        #[cfg(target_os = "macos")]
        if self.darwin.is_some() {
            return self.read_packet_darwin().await;
        }

        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("tun reader: no backend"))?;

        loop {
            let n = inner.read(&mut self.read_buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tun device closed",
                ));
            }
            // Windows / non-vnet_hdr: pure IP frame from WinTun.
            if !self.vnet_hdr {
                return Ok(self.read_buf[..n].to_vec());
            }
            if n < VIRTIO_NET_HDR_LEN {
                warn!("tun: short read with vnet_hdr ({n} bytes), drop");
                continue;
            }
            let hdr = match VirtioNetHdr::decode(&self.read_buf[..VIRTIO_NET_HDR_LEN]) {
                Ok(h) => h,
                Err(e) => {
                    warn!(err = %e, "tun: bad virtio_net_hdr, drop");
                    continue;
                }
            };
            let payload = &self.read_buf[VIRTIO_NET_HDR_LEN..n];
            if hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE || payload.is_empty() {
                return Ok(payload.to_vec());
            }
            let mut options = match hdr.to_gso_options() {
                Ok(o) => o,
                Err(e) => {
                    warn!(err = %e, "tun: unsupported gso, pass through");
                    return Ok(payload.to_vec());
                }
            };
            if let Err(e) = gso::correct_gso_hdr_len(&mut options, payload) {
                warn!(err = %e, "tun: correct_gso_hdr_len failed, drop");
                continue;
            }
            let max_segs = (payload.len() / options.gso_size.max(1) as usize) + 2;
            let mut out_bufs: Vec<Vec<u8>> = vec![Vec::new(); max_segs];
            let mut sizes = vec![0usize; max_segs];
            match gso::gso_split(payload, &options, &mut out_bufs, &mut sizes) {
                Ok(nsegs) => {
                    for i in 0..nsegs {
                        out_bufs[i].truncate(sizes[i]);
                        self.pending.push_back(std::mem::take(&mut out_bufs[i]));
                    }
                    if let Some(pkt) = self.pending.pop_front() {
                        return Ok(pkt);
                    }
                }
                Err(e) => {
                    warn!(err = %e, "tun: gso_split failed, pass through");
                    return Ok(payload.to_vec());
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    async fn read_packet_darwin(&mut self) -> io::Result<Vec<u8>> {
        use super::darwin_batch;
        loop {
            if let Some(pkt) = self.pending.pop_front() {
                return Ok(pkt);
            }
            let d = self.darwin.as_mut().unwrap();
            // Wait until readable, then drain a full recvmsg_x batch.
            let mut guard = d.async_fd.readable().await?;
            match darwin_batch::recv_batch(d.async_fd.as_raw_fd_inner(), d.mtu, d.batch_size, &mut self.pending)
            {
                Ok(0) => {
                    // Spurious wakeup / EAGAIN
                    guard.clear_ready();
                    continue;
                }
                Ok(_) => {
                    guard.clear_ready();
                    if let Some(pkt) = self.pending.pop_front() {
                        return Ok(pkt);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(target_os = "macos")]
trait AsyncFdRaw {
    fn as_raw_fd_inner(&self) -> std::os::fd::RawFd;
}

#[cfg(target_os = "macos")]
impl AsyncFdRaw for tokio::io::unix::AsyncFd<std::os::fd::RawFd> {
    fn as_raw_fd_inner(&self) -> std::os::fd::RawFd {
        *self.get_ref()
    }
}

pub struct NativeTunWriter {
    /// AsyncWrite backend (Linux / Windows). `None` on macOS batch path.
    inner: Option<Pin<Box<dyn AsyncWrite + Unpin + Send>>>,
    vnet_hdr: bool,
    gro_enabled: bool,
    gro_flags: GroDisablementFlags,
    tcp_table: TcpGroTable,
    udp_table: UdpGroTable,
    pending: Vec<Vec<u8>>,
    /// 事件驱动 flush 信号：首个包入队时 notify，flusher task 等 2ms 批窗口
    /// 后 flush。取代旧的 2ms 忙轮询（空闲时零唤醒）。
    flush_notify: Arc<Notify>,
    #[cfg(target_os = "macos")]
    darwin: Option<DarwinWriter>,
}

impl NativeTunWriter {
    /// 事件驱动 flush 信号（flusher task 用）。
    pub fn flush_notify(&self) -> Arc<Notify> {
        self.flush_notify.clone()
    }

    /// Queue one pure IP packet; may batch through handle_gro before writing.
    pub async fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        if self.darwin.is_some() {
            return self.write_packet_darwin(pkt).await;
        }

        if !self.gro_enabled {
            return self.write_raw_ip(pkt).await;
        }
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + pkt.len()];
        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(pkt);
        let first = self.pending.is_empty();
        self.pending.push(buf);
        if first {
            // 批窗口起点：唤醒 flusher task，2ms 后统一 flush（不足
            // GRO_BATCH_SIZE 的尾包不再依赖轮询）。
            self.flush_notify.notify_one();
        }
        if self.pending.len() >= GRO_BATCH_SIZE {
            self.flush_gro().await?;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn write_packet_darwin(&mut self, pkt: &[u8]) -> io::Result<()> {
        let d = self.darwin.as_mut().unwrap();
        let first = d.batch.is_empty();
        d.batch.push(pkt.to_vec());
        if first {
            self.flush_notify.notify_one();
        }
        if d.batch.len() >= DARWIN_WRITE_BATCH {
            self.flush_darwin().await?;
        }
        Ok(())
    }

    /// Force flush any buffered GRO / darwin packets.
    pub async fn flush_gro(&mut self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        if self.darwin.is_some() {
            return self.flush_darwin().await;
        }

        if self.pending.is_empty() {
            return Ok(());
        }
        if !self.gro_enabled {
            let batch = std::mem::take(&mut self.pending);
            for p in batch {
                self.write_raw_ip(&p).await?;
            }
            return Ok(());
        }

        let mut to_write = Vec::with_capacity(self.pending.len());
        handle_gro(
            &mut self.pending,
            VIRTIO_NET_HDR_LEN,
            &mut self.tcp_table,
            &mut self.udp_table,
            self.gro_flags,
            &mut to_write,
        )?;

        for &idx in &to_write {
            if let Some(buf) = self.pending.get(idx) {
                if self.vnet_hdr {
                    // Linux: send virtio_net_hdr + IP
                    if let Some(inner) = self.inner.as_mut() {
                        inner.write_all(buf).await?;
                    }
                } else {
                    // Windows / plain IP: strip scratch virtio_net_hdr
                    if buf.len() > VIRTIO_NET_HDR_LEN {
                        if let Some(inner) = self.inner.as_mut() {
                            inner.write_all(&buf[VIRTIO_NET_HDR_LEN..]).await?;
                        }
                    }
                }
            }
        }
        self.pending.clear();
        self.tcp_table.reset();
        self.udp_table.reset();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    async fn flush_darwin(&mut self) -> io::Result<()> {
        use super::darwin_batch;
        let d = self.darwin.as_mut().unwrap();
        if d.batch.is_empty() {
            return Ok(());
        }
        let batch = std::mem::take(&mut d.batch);
        // sendmsg_x is non-blocking; do it in spawn_blocking so we don't hold
        // the async mutex across a tight retry loop under ENOBUFS. The write
        // gate is acquired inside the blocking task: a std MutexGuard is !Send
        // and must never be held across the `.await` (breaks tokio::spawn
        // callers in stack.rs / icmp_forwarder.rs).
        let fd = d.fd;
        let gate = d.write_gate.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = gate.lock();
            darwin_batch::send_batch(fd, &batch)
        })
        .await
        .map_err(|e| io::Error::other(format!("sendmsg_x join: {e}")))??;
        Ok(())
    }

    async fn write_raw_ip(&mut self, pkt: &[u8]) -> io::Result<()> {
        let inner = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("tun writer: no backend"))?;
        if self.vnet_hdr {
            let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + pkt.len());
            buf.resize(VIRTIO_NET_HDR_LEN, 0);
            buf.extend_from_slice(pkt);
            inner.write_all(&buf).await
        } else {
            inner.write_all(pkt).await
        }
    }
}

impl Drop for NativeTunWriter {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(ref d) = self.darwin {
            if !d.batch.is_empty() {
                warn!(
                    n = d.batch.len(),
                    "tun: NativeTunWriter dropped with unflushed darwin batch"
                );
            }
        }
        if !self.pending.is_empty() {
            warn!(
                n = self.pending.len(),
                "tun: NativeTunWriter dropped with unflushed GRO packets"
            );
        }
    }
}
