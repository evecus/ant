use super::{stack::IfaceEvent, tcp_listener::TcpStreamHandle};
use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::{atomic::Ordering, Arc},
    task::{ready, Context, Poll},
};
use tracing::{error, trace};

pub struct TcpStream {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,

    pub(crate) handle: Arc<TcpStreamHandle>,
    pub(crate) stack_notifier: tokio::sync::mpsc::UnboundedSender<IfaceEvent<'static>>,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        trace!(
            "TcpStream dropped: {} <-> {}",
            self.local_addr,
            self.remote_addr
        );

        // socket_dropped tells poll_sockets to drain send_buffer and issue FIN.
        // read_closed / write_closed unblock any concurrent poll_read / poll_write.
        self.handle.socket_dropped.store(true, Ordering::Release);
        self.handle.read_closed.store(true, Ordering::Release);
        self.handle.write_closed.store(true, Ordering::Release);
        self.handle.recv_waker.wake();
        self.handle.send_waker.wake();
        if let Err(e) = self.stack_notifier.send(IfaceEvent::TcpSocketClosed) {
            error!("Failed to notify TCP socket closed: {e}");
        }
    }
}

impl TcpStream {
    /// 客户端（TUN 内应用）地址。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 目标地址（连接的目标）。
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// 请求立即中止连接：poll_sockets 将对 smoltcp socket 调用 abort()
    /// 并发送 RST（对齐 sing-tun NAT 失败时 Close() 的 RST 语义），
    /// 而不是走 Drop 的 drain-then-FIN 路径。dial 失败 / 规则拒绝时使用，
    /// 避免客户端误以为优雅关闭。
    pub(crate) fn abort(&self) {
        self.handle.abort_requested.store(true, Ordering::Release);
        self.handle.read_closed.store(true, Ordering::Release);
        self.handle.write_closed.store(true, Ordering::Release);
        self.handle.recv_waker.wake();
        self.handle.send_waker.wake();
        if let Err(e) = self.stack_notifier.send(IfaceEvent::TcpSocketClosed) {
            error!("Failed to notify TCP socket closed: {e}");
        }
    }

    fn notify_tcp_socket_ready(&self) {
        if let Err(e) = self.stack_notifier.send(IfaceEvent::TcpSocketReady) {
            error!("Failed to notify TCP socket ready: {e}");
        }
    }
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish()
    }
}

impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let read_buf = &self.handle.recv_buffer;

        if read_buf.is_empty() {
            // Register waker FIRST, then re-check to close the TOCTOU window.
            // If poll_sockets enqueues data between is_empty() and register(),
            // wake() is a no-op (no waker stored). The re-check below detects
            // the buffer is now non-empty and falls through to read it.
            self.handle.recv_waker.register(cx.waker());
            if read_buf.is_empty() {
                // Return EOF when smoltcp is done (socket removed) OR when the
                // read half was explicitly closed (peer FIN / local drop).
                if self
                    .handle
                    .socket_closed
                    .load(std::sync::atomic::Ordering::Acquire)
                    || self.handle.read_closed.load(Ordering::Acquire)
                {
                    return std::task::Poll::Ready(Ok(()));
                }
                return std::task::Poll::Pending;
            }
        }

        buf.initialize_unfilled();
        let recv_buf = unsafe {
            std::mem::transmute::<&mut [std::mem::MaybeUninit<u8>], &mut [u8]>(buf.unfilled_mut())
        };
        let n = read_buf.dequeue_slice(recv_buf);
        buf.advance(n);

        self.notify_tcp_socket_ready();

        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.handle.write_closed.load(Ordering::Acquire)
            || self.handle.write_shutdown.load(Ordering::Acquire)
        {
            return Poll::Ready(Err(Error::new(
                ErrorKind::BrokenPipe,
                "TCP stream write half closed",
            )));
        }

        let send_buf = &self.handle.send_buffer;

        if send_buf.is_full() {
            // Register waker FIRST, then re-check to close the TOCTOU window.
            // If poll_sockets drains the buffer between is_full() and register(),
            // wake() is a no-op (no waker stored). The re-check below detects
            // the buffer is now non-full and falls through to enqueue data.
            self.handle.send_waker.register(cx.waker());
            if send_buf.is_full() {
                self.notify_tcp_socket_ready();
                return std::task::Poll::Pending;
            }
        }

        let n = send_buf.enqueue_slice(buf);

        self.notify_tcp_socket_ready();

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.notify_tcp_socket_ready();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        self.handle.write_shutdown.store(true, Ordering::Release);
        self.handle.send_waker.wake();
        Poll::Ready(Ok(()))
    }
}
