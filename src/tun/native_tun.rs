//! NativeTun: virtio_net_hdr + GSO split (read, Linux) + GRO coalesce (write, all platforms).
//!
//! ## Platform notes
//! - **Linux**: kernel may set IFF_VNET_HDR; read peels virtio_net_hdr and splits GSO;
//!   write runs handle_gro and sends buffers including virtio_net_hdr.
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
use tokio::sync::Mutex;
use tracing::warn;

/// Flush GRO pending when this many packets are queued.
const GRO_BATCH_SIZE: usize = 16;

pub struct NativeTun {
    reader: Arc<Mutex<NativeTunReader>>,
    writer: Arc<Mutex<NativeTunWriter>>,
}

impl NativeTun {
    pub fn new(
        dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        vnet_hdr: bool,
        gro_flags: GroDisablementFlags,
    ) -> Self {
        let (r, w) = tokio::io::split(dev);
        Self {
            reader: Arc::new(Mutex::new(NativeTunReader {
                inner: Box::pin(r),
                vnet_hdr,
                pending: VecDeque::new(),
                read_buf: vec![0u8; gso::GSO_MAX_SIZE + VIRTIO_NET_HDR_LEN],
            })),
            writer: Arc::new(Mutex::new(NativeTunWriter {
                inner: Box::pin(w),
                vnet_hdr,
                // GRO coalescing relies on the kernel honouring virtio_net_hdr
                // (NEEDS_CSUM + GSO). WinTun has no such header: the stripped
                // coalesced packet would carry only a pseudo-header checksum
                // and may exceed MTU, so Windows drops it. sing-tun does no
                // GRO on Windows either — only enable it with vnet_hdr.
                gro_enabled: vnet_hdr,
                gro_flags,
                tcp_table: TcpGroTable::new(),
                udp_table: UdpGroTable::new(),
                pending: Vec::new(),
            })),
        }
    }

    pub fn split(self) -> (Arc<Mutex<NativeTunReader>>, Arc<Mutex<NativeTunWriter>>) {
        (self.reader, self.writer)
    }
}

pub struct NativeTunReader {
    inner: Pin<Box<dyn AsyncRead + Unpin + Send>>,
    vnet_hdr: bool,
    pending: VecDeque<Vec<u8>>,
    read_buf: Vec<u8>,
}

impl NativeTunReader {
    pub async fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        if let Some(pkt) = self.pending.pop_front() {
            return Ok(pkt);
        }
        loop {
            let n = self.inner.read(&mut self.read_buf).await?;
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
                Ok(count) => {
                    for i in 0..count {
                        let len = sizes[i];
                        let mut seg = std::mem::take(&mut out_bufs[i]);
                        if seg.len() > len {
                            seg.truncate(len);
                        }
                        self.pending.push_back(seg);
                    }
                    if let Some(pkt) = self.pending.pop_front() {
                        return Ok(pkt);
                    }
                }
                Err(e) => {
                    warn!(err = %e, "tun: gso_split failed, drop");
                }
            }
        }
    }
}

pub struct NativeTunWriter {
    inner: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
    /// When true, device expects virtio_net_hdr on every write (Linux).
    vnet_hdr: bool,
    /// Run userspace handle_gro (Linux + Windows).
    gro_enabled: bool,
    gro_flags: GroDisablementFlags,
    tcp_table: TcpGroTable,
    udp_table: UdpGroTable,
    /// Buffered packets as [virtio_hdr scratch][ip...].
    pending: Vec<Vec<u8>>,
}

impl NativeTunWriter {
    /// Queue one pure IP packet; may batch through handle_gro before writing.
    pub async fn write_packet(&mut self, pkt: &[u8]) -> io::Result<()> {
        if !self.gro_enabled {
            return self.write_raw_ip(pkt).await;
        }
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + pkt.len()];
        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(pkt);
        self.pending.push(buf);
        if self.pending.len() >= GRO_BATCH_SIZE {
            self.flush_gro().await?;
        }
        Ok(())
    }

    /// Force flush any buffered GRO packets.
    pub async fn flush_gro(&mut self) -> io::Result<()> {
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
                    self.inner.write_all(buf).await?;
                } else {
                    // Windows / plain IP: strip scratch virtio_net_hdr
                    if buf.len() > VIRTIO_NET_HDR_LEN {
                        self.inner.write_all(&buf[VIRTIO_NET_HDR_LEN..]).await?;
                    }
                }
            }
        }
        self.pending.clear();
        self.tcp_table.reset();
        self.udp_table.reset();
        Ok(())
    }

    async fn write_raw_ip(&mut self, pkt: &[u8]) -> io::Result<()> {
        if self.vnet_hdr {
            let mut buf = Vec::with_capacity(VIRTIO_NET_HDR_LEN + pkt.len());
            buf.resize(VIRTIO_NET_HDR_LEN, 0);
            buf.extend_from_slice(pkt);
            self.inner.write_all(&buf).await
        } else {
            self.inner.write_all(pkt).await
        }
    }
}

impl Drop for NativeTunWriter {
    fn drop(&mut self) {
        if !self.pending.is_empty() {
            warn!(
                n = self.pending.len(),
                "tun: NativeTunWriter dropped with unflushed GRO packets"
            );
        }
    }
}
