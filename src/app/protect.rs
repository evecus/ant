//! Android `VpnService.protect(fd)` bridge.
//!
//! An unprivileged Android app cannot set `SO_MARK`, so dialer sockets cannot
//! be exempted from the VPN's routing that way. Instead the host app
//! (`AntVpnService`) listens on a unix socket whose path is passed in the env
//! var `ANT_PROTECT_SOCK`. For every outbound socket we:
//!
//!   1. connect to that unix socket,
//!   2. send one byte carrying the socket fd via `SCM_RIGHTS`,
//!   3. wait for a one-byte ack (`1` = protected, anything else = failure).
//!
//! The app then calls `VpnService.protect()` on its duplicate of the fd. The
//! protection is a property of the underlying socket, so it applies to our fd
//! too. Must be done **before** `connect()` / first send.
//!
//! When the env var is unset the bridge is disabled and every call is a no-op
//! (desktop Linux keeps using SO_MARK / SO_BINDTODEVICE).

use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::time::Duration;

const ENV_PROTECT_SOCK: &str = "ANT_PROTECT_SOCK";
const IO_TIMEOUT: Duration = Duration::from_secs(2);

static PROTECT_PATH: OnceLock<Option<String>> = OnceLock::new();

fn protect_path() -> Option<&'static str> {
    PROTECT_PATH
        .get_or_init(|| {
            let p = std::env::var(ENV_PROTECT_SOCK)
                .ok()
                .filter(|s| !s.is_empty());
            if let Some(p) = &p {
                tracing::info!("protect: VpnService.protect bridge enabled path={p}");
            }
            p
        })
        .as_deref()
}

/// True when a host app provided a protect socket.
pub fn enabled() -> bool {
    protect_path().is_some()
}

/// Ask the host app to `VpnService.protect()` this socket. No-op (Ok) when the
/// bridge is disabled. The caller must keep `fd` open until this returns.
pub async fn protect(fd: RawFd) -> io::Result<()> {
    let Some(path) = protect_path() else {
        return Ok(());
    };
    // Blocking local IPC with a short timeout; keep it off the async workers.
    tokio::task::spawn_blocking(move || protect_blocking(path, fd))
        .await
        .map_err(io::Error::other)?
}

fn protect_blocking(path: &str, fd: RawFd) -> io::Result<()> {
    let mut s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(IO_TIMEOUT))?;
    s.set_write_timeout(Some(IO_TIMEOUT))?;
    send_fd(s.as_raw_fd(), fd)?;
    let mut ack = [0u8; 1];
    s.read_exact(&mut ack)?;
    if ack[0] == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "VpnService.protect() returned false",
        ))
    }
}

/// Send `fd` over the unix socket `sock` as SCM_RIGHTS with a 1-byte payload.
fn send_fd(sock: RawFd, fd: RawFd) -> io::Result<()> {
    use std::mem;

    let payload = [1u8];
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };

    // u64 backing keeps the buffer aligned for `cmsghdr`.
    let mut cmsg_buf = [0u64; 8];
    let space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    debug_assert!(space <= mem::size_of_val(&cmsg_buf));

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            mem::size_of::<RawFd>(),
        );
    }

    loop {
        let n = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixListener;

    /// Fake host app: receive one fd via SCM_RIGHTS, check it is a live
    /// socket, ack with `ack`.
    fn serve_once(listener: UnixListener, ack: u8) -> std::thread::JoinHandle<bool> {
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut byte = [0u8; 1];
            let mut iov = libc::iovec {
                iov_base: byte.as_mut_ptr() as *mut libc::c_void,
                iov_len: 1,
            };
            let mut cbuf = [0u64; 8];
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
            let n = unsafe { libc::recvmsg(conn.as_raw_fd(), &mut msg, 0) };
            assert_eq!(n, 1);
            let got = unsafe {
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                assert!(!cmsg.is_null());
                assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
                let mut fd: RawFd = -1;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    &mut fd as *mut RawFd as *mut u8,
                    std::mem::size_of::<RawFd>(),
                );
                fd
            };
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let is_sock = unsafe { libc::fstat(got, &mut st) } == 0
                && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK;
            unsafe { libc::close(got) };
            conn.write_all(&[ack]).unwrap();
            is_sock
        })
    }

    fn temp_sock(name: &str) -> String {
        let p = std::env::temp_dir().join(format!("ant-protect-{}-{name}.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn fd_is_delivered_and_ack_ok() {
        let path = temp_sock("ok");
        let h = serve_once(UnixListener::bind(&path).unwrap(), 1);
        let victim = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        protect_blocking(&path, victim.as_raw_fd()).unwrap();
        assert!(h.join().unwrap(), "peer did not receive a socket fd");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn nack_is_an_error() {
        let path = temp_sock("nack");
        let h = serve_once(UnixListener::bind(&path).unwrap(), 0);
        let victim = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let err = protect_blocking(&path, victim.as_raw_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        h.join().unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_server_is_an_error() {
        let path = temp_sock("none");
        let victim = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(protect_blocking(&path, victim.as_raw_fd()).is_err());
    }
}
