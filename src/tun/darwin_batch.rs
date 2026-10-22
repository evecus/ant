//! macOS utun batch I/O via `recvmsg_x` / `sendmsg_x` (sing-tun `rawfile_darwin`).
//!
//! Kernel frames always carry a 4-byte PI header (`00 00 00 AF_INET[6]`). This
//! module strips it on read and prepends it on write so callers see pure IP,
//! matching the `tun` crate `packet_information=true` contract.
//!
//! ## Syscalls (XNU)
//! - `SYS_RECVMSG_X` = 480 — batch receive into `msghdr_x[]`
//! - `SYS_SENDMSG_X` = 481 — batch send from `msghdr_x[]` (MSG_DONTWAIT)
//! - Fallback write path: `writev` with PI + IP iovecs when sendmsg_x is disabled

#![allow(non_camel_case_types)]

use std::collections::VecDeque;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::ptr;
use std::sync::Mutex;
use tracing::{debug, warn};

/// 4-byte family header on every utun frame (sing-tun `PacketOffset`).
pub const PACKET_OFFSET: usize = 4;

/// Default max packets per recvmsg_x / sendmsg_x call.
/// sing-tun: `((512 * 1024) / MTU) + 1`, capped reasonably.
pub fn batch_size_for_mtu(mtu: u32) -> usize {
    let n = ((512 * 1024) / mtu.max(576) as usize) + 1;
    n.clamp(8, 128)
}

/// utun control option (sys/kern_control.h style, level = SYSPROTO_CONTROL = 2).
const SYSPROTO_CONTROL: libc::c_int = 2;
const UTUN_OPT_MAX_PENDING_PACKETS: libc::c_int = 16;
const UTUN_MAX_PENDING_PACKETS: i32 = 64;

const SYS_RECVMSG_X: libc::c_int = 480;
const SYS_SENDMSG_X: libc::c_int = 481;

#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec {
    iov_base: *mut libc::c_void,
    iov_len: libc::size_t,
}

#[repr(C)]
struct Msghdr {
    msg_name: *mut libc::c_void,
    msg_namelen: libc::socklen_t,
    msg_iov: *mut Iovec,
    msg_iovlen: i32,
    msg_control: *mut libc::c_void,
    msg_controllen: libc::socklen_t,
    msg_flags: i32,
}

/// XNU `struct msghdr_x`.
#[repr(C)]
struct MsgHdrX {
    msg: Msghdr,
    data_len: u32,
}

fn af_header(is_v6: bool) -> [u8; 4] {
    let af = if is_v6 {
        libc::AF_INET6 as u32
    } else {
        libc::AF_INET as u32
    };
    af.to_be_bytes()
}

fn is_ipv6(pkt: &[u8]) -> bool {
    !pkt.is_empty() && (pkt[0] >> 4) == 6
}

/// Configure utun fd: non-blocking + SO_RCVBUF + UTUN_OPT_MAX_PENDING_PACKETS.
pub fn configure_fd(fd: RawFd, mtu: u32, rcvbuf: i32) -> io::Result<()> {
    // Non-blocking (async path relies on EAGAIN).
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // SO_RCVBUF (already tuned by macos::tune_recv_buffer; re-apply if needed).
    if rcvbuf > 0 {
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf as *const _ as *const libc::c_void,
                mem::size_of_val(&rcvbuf) as libc::socklen_t,
            )
        };
    }

    // UTUN_OPT_MAX_PENDING_PACKETS — sing-tun configure().
    let pending = {
        let rb = if rcvbuf > 0 { rcvbuf } else { 512 << 10 };
        let mut p = (rb as usize / 8 * 7) / (mtu as usize + PACKET_OFFSET);
        if p > UTUN_MAX_PENDING_PACKETS as usize {
            p = UTUN_MAX_PENDING_PACKETS as usize;
        }
        if p < 1 {
            p = 1;
        }
        p as i32
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            SYSPROTO_CONTROL,
            UTUN_OPT_MAX_PENDING_PACKETS,
            &pending as *const _ as *const libc::c_void,
            mem::size_of_val(&pending) as libc::socklen_t,
        )
    };
    if rc != 0 {
        // Non-fatal: older kernels / external FDs may reject this opt.
        warn!(
            err = %io::Error::last_os_error(),
            pending,
            "tun: UTUN_OPT_MAX_PENDING_PACKETS failed (continuing)"
        );
    } else {
        debug!(pending, "tun: UTUN_OPT_MAX_PENDING_PACKETS set");
    }
    Ok(())
}

/// Non-blocking `recvmsg_x` — returns pure-IP packets (PI stripped).
///
/// Returns `Ok(0)` on EAGAIN / no packets. `Ok(n)` with n packets appended to `out`.
pub fn recv_batch(fd: RawFd, mtu: u32, batch_size: usize, out: &mut VecDeque<Vec<u8>>) -> io::Result<usize> {
    let pkt_cap = mtu as usize + PACKET_OFFSET;
    // Own buffers for the duration of the syscall.
    let mut bufs: Vec<Vec<u8>> = (0..batch_size).map(|_| vec![0u8; pkt_cap]).collect();
    let mut iovecs: Vec<Iovec> = bufs
        .iter_mut()
        .map(|b| Iovec {
            iov_base: b.as_mut_ptr() as *mut libc::c_void,
            iov_len: b.len(),
        })
        .collect();
    let mut hdrs: Vec<MsgHdrX> = iovecs
        .iter_mut()
        .map(|iov| MsgHdrX {
            msg: Msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iov as *mut Iovec,
                msg_iovlen: 1,
                msg_control: ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            data_len: 0,
        })
        .collect();

    let n = unsafe {
        libc::syscall(
            SYS_RECVMSG_X,
            fd as libc::c_int,
            hdrs.as_mut_ptr() as *mut libc::c_void,
            batch_size as libc::c_int,
            0 as libc::c_int, // flags
        )
    };

    if n < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(0);
        }
        // ENOTSOCK / EBADF → closed
        if err.raw_os_error() == Some(libc::ENOTSOCK) || err.raw_os_error() == Some(libc::EBADF) {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "utun closed"));
        }
        return Err(err);
    }

    let n = n as usize;
    let mut got = 0usize;
    for i in 0..n {
        let len = hdrs[i].data_len as usize;
        if len <= PACKET_OFFSET {
            continue;
        }
        // Strip 4-byte PI → pure IP
        let ip = bufs[i][PACKET_OFFSET..len].to_vec();
        out.push_back(ip);
        got += 1;
    }
    Ok(got)
}

/// Non-blocking `sendmsg_x` for a batch of pure-IP packets (PI prepended).
///
/// Returns number of messages successfully queued. Partial sends loop until done
/// or error (same as sing-tun BatchWrite).
pub fn send_batch(fd: RawFd, packets: &[Vec<u8>]) -> io::Result<()> {
    if packets.is_empty() {
        return Ok(());
    }

    // Prepend PI headers into owned buffers so iov bases stay valid.
    let mut frames: Vec<Vec<u8>> = packets
        .iter()
        .map(|pkt| {
            let mut f = Vec::with_capacity(PACKET_OFFSET + pkt.len());
            f.extend_from_slice(&af_header(is_ipv6(pkt)));
            f.extend_from_slice(pkt);
            f
        })
        .collect();

    let mut iovecs: Vec<Iovec> = frames
        .iter_mut()
        .map(|f| Iovec {
            iov_base: f.as_mut_ptr() as *mut libc::c_void,
            iov_len: f.len(),
        })
        .collect();

    let mut hdrs: Vec<MsgHdrX> = iovecs
        .iter_mut()
        .map(|iov| MsgHdrX {
            msg: Msghdr {
                msg_name: ptr::null_mut(),
                msg_namelen: 0,
                msg_iov: iov as *mut Iovec,
                msg_iovlen: 1,
                msg_control: ptr::null_mut(),
                msg_controllen: 0,
                msg_flags: 0,
            },
            data_len: 0,
        })
        .collect();

    let mut sent = 0usize;
    while sent < packets.len() {
        let n = unsafe {
            libc::syscall(
                SYS_SENDMSG_X,
                fd as libc::c_int,
                hdrs[sent..].as_mut_ptr() as *mut libc::c_void,
                (packets.len() - sent) as libc::c_int,
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                // Brief yield then retry remaining — keeps ENOBUFS from being fatal.
                std::thread::yield_now();
                continue;
            }
            if err.raw_os_error() == Some(libc::ENOTSOCK) || err.raw_os_error() == Some(libc::EBADF)
            {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "utun closed"));
            }
            return Err(err);
        }
        if n == 0 {
            std::thread::yield_now();
            continue;
        }
        sent += n as usize;
    }
    Ok(())
}

/// Fallback: single-packet `writev` with PI header (when batch is size 1).
#[allow(dead_code)]
pub fn write_one(fd: RawFd, pkt: &[u8]) -> io::Result<()> {
    let hdr = af_header(is_ipv6(pkt));
    let iov = [
        libc::iovec {
            iov_base: hdr.as_ptr() as *mut libc::c_void,
            iov_len: PACKET_OFFSET,
        },
        libc::iovec {
            iov_base: pkt.as_ptr() as *mut libc::c_void,
            iov_len: pkt.len(),
        },
    ];
    let n = unsafe { libc::writev(fd, iov.as_ptr(), 2) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Shared write serialisation (sing-tun `writeAccess`).
/// sendmsg_x uses MSG_DONTWAIT; concurrent writers holding SB_LOCK can make the
/// kernel free a whole batch yet report it fully sent.
pub struct WriteGate {
    inner: Mutex<()>,
}

impl WriteGate {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(()),
        }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Default for WriteGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Owns a utun file descriptor for batch I/O.
///
/// Constructed from a raw fd (e.g. after `Device::into_raw_fd()`). Do **not**
/// also keep an `AsyncDevice` on the same fd — dual `AsyncFd` registration is
/// undefined behaviour.
pub struct OwnedTunFd {
    fd: RawFd,
    close_on_drop: bool,
}

// RawFd is a plain integer; safe to share across threads for syscall use.
unsafe impl Send for OwnedTunFd {}
unsafe impl Sync for OwnedTunFd {}

impl OwnedTunFd {
    pub fn new(fd: RawFd, close_on_drop: bool) -> Self {
        Self { fd, close_on_drop }
    }
}

impl Drop for OwnedTunFd {
    fn drop(&mut self) {
        if self.close_on_drop && self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}
