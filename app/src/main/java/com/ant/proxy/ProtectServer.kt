package com.ant.proxy

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.Os
import android.util.Log
import java.io.File
import java.io.FileDescriptor
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Bridges `VpnService.protect(fd)` to the standalone `ant` process.
 *
 * `ant` runs as a child process, so it cannot call [VpnService.protect] itself and an
 * unprivileged app cannot set SO_MARK. Instead, for every outbound socket `ant` does:
 *
 *   1. connect to the unix socket at [socketPath] (passed via env ANT_PROTECT_SOCK),
 *   2. send 1 byte carrying the socket fd as SCM_RIGHTS ancillary data,
 *   3. read a 1-byte ack: 1 = protected, 0 = failed.
 *
 * A connection may carry several requests back to back; each is answered in order.
 *
 * The socket lives in the app's private files dir with mode 0600, and each client's UID is
 * checked, so only this app's own processes can use it. (An abstract-namespace socket would be
 * reachable by any app, which could then exempt its own sockets from the VPN.)
 */
class ProtectServer(
    private val vpn: VpnService,
    val socketPath: File,
    private val onLog: (String) -> Unit
) {
    companion object {
        private const val TAG = "ProtectServer"
        private const val CLIENT_READ_TIMEOUT_MS = 30_000
    }

    @Volatile
    private var running = false
    private var bindSocket: LocalSocket? = null
    private var server: LocalServerSocket? = null
    private var acceptThread: Thread? = null

    private val workerId = AtomicInteger(0)
    private val pool = Executors.newCachedThreadPool { r ->
        Thread(r, "ant-protect-${workerId.incrementAndGet()}").apply { isDaemon = true }
    }

    private val okCount = AtomicInteger(0)
    private val failCount = AtomicInteger(0)

    @Synchronized
    fun start(): Boolean {
        stop()
        return try {
            socketPath.delete()
            val ls = LocalSocket(LocalSocket.SOCKET_STREAM)
            ls.bind(
                LocalSocketAddress(socketPath.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM)
            )
            Os.chmod(socketPath.absolutePath, 0b110_000_000) // 0600
            // LocalServerSocket(FileDescriptor) calls listen() on the already-bound socket.
            val srv = LocalServerSocket(ls.fileDescriptor)
            bindSocket = ls
            server = srv
            running = true
            acceptThread = Thread({ acceptLoop(srv) }, "ant-protect-accept").apply {
                isDaemon = true
                start()
            }
            Log.i(TAG, "listening on ${socketPath.absolutePath}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "start failed", e)
            onLog("错误：protect 服务启动失败：${e.message}")
            stop()
            false
        }
    }

    @Synchronized
    fun stop() {
        running = false
        try {
            server?.close() // unblocks accept()
        } catch (_: Exception) {
        }
        try {
            bindSocket?.close()
        } catch (_: Exception) {
        }
        server = null
        bindSocket = null
        acceptThread = null
        socketPath.delete()
    }

    private fun acceptLoop(srv: LocalServerSocket) {
        while (running) {
            val client = try {
                srv.accept()
            } catch (e: Exception) {
                if (running) Log.w(TAG, "accept: ${e.message}")
                break
            }
            try {
                pool.execute { handle(client) }
            } catch (e: Exception) {
                // pool rejected (shutting down)
                try {
                    client.close()
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun handle(client: LocalSocket) {
        client.use { c ->
            try {
                if (c.peerCredentials.uid != Process.myUid()) {
                    Log.w(TAG, "rejecting client uid=${c.peerCredentials.uid}")
                    return
                }
                c.soTimeout = CLIENT_READ_TIMEOUT_MS
                val input = c.inputStream
                val output = c.outputStream
                while (running) {
                    if (input.read() < 0) break // EOF: client done
                    // Ancillary fds belong to the most recent read; null if none were sent.
                    val fds = c.ancillaryFileDescriptors
                    val ok = fds != null && fds.size == 1 && protectFd(fds[0])
                    fds?.forEach { closeQuietly(it) }
                    output.write(if (ok) 1 else 0)
                    output.flush()
                    if (ok) {
                        if (okCount.incrementAndGet() == 1) onLog("protect：首个套接字保护成功")
                    } else {
                        val n = failCount.incrementAndGet()
                        // Log the first few failures only, to avoid flooding the UI log.
                        if (n <= 5) onLog("警告：VpnService.protect 失败（第 $n 次）")
                    }
                }
            } catch (e: Exception) {
                // Client vanished / timed out mid-request; nothing to do.
                Log.d(TAG, "client ended: ${e.message}")
            }
        }
    }

    /**
     * Protection is a property of the underlying socket, so protecting a dup of the received fd
     * protects the socket `ant` is about to connect.
     */
    private fun protectFd(fd: FileDescriptor): Boolean {
        return try {
            ParcelFileDescriptor.dup(fd).use { vpn.protect(it.fd) }
        } catch (e: Exception) {
            Log.w(TAG, "protect: ${e.message}")
            false
        }
    }

    private fun closeQuietly(fd: FileDescriptor) {
        try {
            Os.close(fd)
        } catch (_: Exception) {
        }
    }
}
