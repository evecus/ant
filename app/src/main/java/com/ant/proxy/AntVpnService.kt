package com.ant.proxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VpnService that owns the TUN interface and launches the standalone `ant` binary.
 *
 * Lifecycle:
 *  start → Builder.establish() → get FD → AntProcessManager.start(fd)
 *  stop  → AntProcessManager.stop() → close PFD → stopForeground
 */
class AntVpnService : VpnService() {

    companion object {
        private const val TAG = "AntVpnService"
        const val ACTION_START = "com.ant.proxy.START"
        const val ACTION_STOP = "com.ant.proxy.STOP"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "ant_vpn"
        private const val PROTECT_SOCK_NAME = "protect.sock"

        /**
         * Keep this app (and its `ant` child, same UID) out of the VPN at the routing level.
         *
         * Off by default: outbound sockets are exempted individually via
         * VpnService.protect() (see ProtectServer). Excluding the whole UID also removes the
         * `ant` process from tun0 routing, which can break replies from the system-stack TCP
         * listener on the TUN address. Only enable as a fallback with an `ant` binary that
         * does not support ANT_PROTECT_SOCK.
         */
        private const val EXCLUDE_SELF_FROM_VPN = false

        @Volatile
        var isRunning: Boolean = false
            private set

        private val logBuffer = StringBuilder()
        private const val MAX_LOG_CHARS = 32_000

        fun consumeLogs(): String = synchronized(logBuffer) {
            val s = logBuffer.toString()
            logBuffer.clear()
            s
        }

        fun snapshotLogs(): String = synchronized(logBuffer) { logBuffer.toString() }

        private fun appendLog(line: String) {
            synchronized(logBuffer) {
                logBuffer.append(line).append('\n')
                if (logBuffer.length > MAX_LOG_CHARS) {
                    logBuffer.delete(0, logBuffer.length - MAX_LOG_CHARS)
                }
            }
        }
    }

    private var tunPfd: ParcelFileDescriptor? = null
    private var processManager: AntProcessManager? = null
    private var protectServer: ProtectServer? = null
    private val starting = AtomicBoolean(false)

    override fun onCreate() {
        super.onCreate()
        processManager = AntProcessManager(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_START, null -> {
                if (!isRunning && starting.compareAndSet(false, true)) {
                    startVpn()
                }
            }
        }
        return START_STICKY
    }

    private fun startVpn() {
        try {
            startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.status_starting)))

            val builder = Builder()
                .setSession(getString(R.string.vpn_session))
                .setMtu(
                    getSharedPreferences(AntProcessManager.SETTINGS_NAME, MODE_PRIVATE)
                        .getInt(AntProcessManager.KEY_MTU, AntProcessManager.TUN_MTU)
                )
                .addAddress(AntProcessManager.TUN_ADDRESS, AntProcessManager.TUN_PREFIX)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setBlocking(false)

            if (EXCLUDE_SELF_FROM_VPN) {
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (e: Exception) {
                    Log.w(TAG, "addDisallowedApplication: ${e.message}")
                }
            }

            val pfd = builder.establish()
            if (pfd == null) {
                appendLog("错误：VpnService.Builder.establish() 返回 null（权限被撤销？）")
                starting.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
            tunPfd = pfd
            appendLog("TUN 接口已建立 fd=${pfd.fd}")

            // The protect server must be listening before `ant` dials its first socket.
            val protect = ProtectServer(this, File(filesDir, PROTECT_SOCK_NAME)) { appendLog(it) }
            if (!protect.start()) {
                appendLog("错误：protect 服务启动失败，出站流量可能回环进入 TUN")
                stopVpn()
                return
            }
            protectServer = protect

            val ok = processManager?.start(pfd, protect.socketPath.absolutePath) { line ->
                appendLog(line)
            } == true

            if (!ok) {
                appendLog("错误：ant 进程启动失败")
                stopVpn()
                return
            }

            isRunning = true
            starting.set(false)
            startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.notification_running)))
            appendLog("VPN 已运行")
            sendStatusBroadcast()
        } catch (e: Exception) {
            Log.e(TAG, "startVpn", e)
            appendLog("错误：${e.message}")
            starting.set(false)
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning = false
        starting.set(false)
        processManager?.stop()
        protectServer?.stop()
        protectServer = null
        try {
            tunPfd?.close()
        } catch (_: Exception) {
        }
        tunPfd = null
        appendLog("VPN 已停止")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        sendStatusBroadcast()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        appendLog("系统已撤销 VPN 权限")
        stopVpn()
        super.onRevoke()
    }

    private fun sendStatusBroadcast() {
        sendBroadcast(Intent("com.ant.proxy.STATUS").setPackage(packageName).apply {
            putExtra("running", isRunning)
        })
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel),
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(content: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, AntVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(open)
            .addAction(0, getString(R.string.btn_stop), stop)
            .setOngoing(true)
            .build()
    }
}
