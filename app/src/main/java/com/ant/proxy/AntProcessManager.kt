package com.ant.proxy

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Manages the standalone `ant` binary as a child process.
 *
 * Android ProcessBuilder closes all FDs except 0/1/2, so a TUN fd number
 * passed via ANT_TUN_FD is always EBADF in the child. We spawn via JNI
 * fork+exec after clearing FD_CLOEXEC so the TUN fd is inherited at the
 * same number.
 *
 * Binary path: nativeLibraryDir/libant.so (jniLibs).
 */
class AntProcessManager(private val context: Context) {

    companion object {
        private const val TAG = "AntProcess"
        private const val NATIVE_LIB_NAME = "libant.so"
        private const val ASSETS_NAME = "ant"
        private const val LOG_NAME = "ant.log"
        const val CONFIG_NAME = "config.yaml"

        const val TUN_ADDRESS = "172.19.0.1"
        const val TUN_PREFIX = 30
        const val TUN_MTU = 1500
        const val API_ADDR = "127.0.0.1:9095"

        // 托管设置（设置页写入，启动 VPN 时应用到配置文件）
        const val SETTINGS_NAME = "settings"
        const val KEY_STACK = "tun_stack"
        const val KEY_MTU = "tun_mtu"
        const val KEY_DNS_HIJACK = "tun_dns_hijack"
        const val KEY_LOG_LEVEL = "log_level"
        const val DEFAULT_STACK = "gvisor"

        init {
            try {
                System.loadLibrary("ant_spawn")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "loadLibrary ant_spawn failed", e)
            }
        }

        @JvmStatic
        external fun nativeSpawn(
            path: String,
            argv: Array<String>,
            envp: Array<String>,
            tunFd: Int,
            logPath: String
        ): Int

        @JvmStatic
        external fun nativeKill(pid: Int, sig: Int): Int

        @JvmStatic
        external fun nativeWaitPid(pid: Int, block: Boolean): Int
    }

    private val pidRef = AtomicInteger(-1)
    private val logThreadRef = AtomicReference<Thread?>(null)

    val isRunning: Boolean
        get() {
            val pid = pidRef.get()
            if (pid <= 0) return false
            return try {
                nativeWaitPid(pid, false) == 0
            } catch (_: Throwable) {
                false
            }
        }

    fun ensureBinary(): File {
        val nativeDir = context.applicationInfo.nativeLibraryDir
        if (nativeDir != null) {
            val lib = File(nativeDir, NATIVE_LIB_NAME)
            if (lib.exists()) {
                try {
                    Os.chmod(lib.absolutePath, 0b111_101_101)
                } catch (_: Exception) {
                }
                if (lib.canExecute() || lib.exists()) {
                    Log.i(TAG, "Using native lib: ${lib.absolutePath} (${lib.length()} bytes)")
                    return lib
                }
            }
        }

        val cacheDir = context.codeCacheDir ?: context.cacheDir
        val dest = File(cacheDir, ASSETS_NAME)
        context.assets.open(ASSETS_NAME).use { input ->
            FileOutputStream(dest).use { output -> input.copyTo(output) }
        }
        try {
            Os.chmod(dest.absolutePath, 0b111_000_000)
        } catch (_: Exception) {
            dest.setExecutable(true, true)
        }
        Log.i(TAG, "Extracted ant → ${dest.absolutePath} exec=${dest.canExecute()}")
        return dest
    }

    fun writeDefaultConfigIfNeeded() {
        val cfg = File(context.filesDir, CONFIG_NAME)
        if (cfg.exists() && cfg.length() > 0) return

        val yaml = """
            |log-level: info
            |api: "$API_ADDR"
            |mixed-port: 7890
            |
            |tun:
            |  enable: true
            |  close-fd-on-drop: false
            |  address:
            |    - $TUN_ADDRESS/$TUN_PREFIX
            |  mtu: $TUN_MTU
            |  dns-hijack:
            |    - any:53
            |  auto-route: false
            |  auto-detect-interface: true
            |
            |dns:
            |  enable: true
            |  listen: 0.0.0.0:1053
            |  enhanced-mode: fake-ip
            |  nameserver:
            |    - 8.8.8.8
            |    - 1.1.1.1
            |
            |proxies: []
            |
            |proxy-groups:
            |  - name: PROXY
            |    type: select
            |    proxies:
            |      - DIRECT
            |
            |route:
            |  - MATCH,PROXY
            |
        """.trimMargin()

        cfg.writeText(yaml)
        Log.i(TAG, "Wrote default config → ${cfg.absolutePath}")
    }

    /**
     * TUN 完全由应用托管：启动前剥离配置文件中的顶层 tun 段与 log-level，
     * 按设置页参数重写后写回。这样无论导入什么配置，TUN 参数始终以应用为准。
     */
    fun applyManagedConfig(onLog: (String) -> Unit) {
        val cfg = File(context.filesDir, CONFIG_NAME)
        if (!cfg.exists() || cfg.length() == 0L) return

        val prefs = context.getSharedPreferences(SETTINGS_NAME, Context.MODE_PRIVATE)
        val stack = prefs.getString(KEY_STACK, DEFAULT_STACK) ?: DEFAULT_STACK
        val mtu = prefs.getInt(KEY_MTU, TUN_MTU)
        val dnsHijack = prefs.getBoolean(KEY_DNS_HIJACK, true)
        val logLevel = prefs.getString(KEY_LOG_LEVEL, "info") ?: "info"

        val out = StringBuilder()
        var inTun = false
        var logLevelWritten = false

        for (line in cfg.readText().lines()) {
            val isTop = line.isNotBlank() && !line[0].isWhitespace()
            if (inTun) {
                // tun 块内的行全部丢弃，直到遇到下一个顶层键
                if (isTop) inTun = false else continue
            }
            if (isTop && line.startsWith("tun:")) {
                // 整个顶层 tun 块由应用接管（含行内 {…} 写法）
                if (!line.contains("{")) inTun = true
                continue
            }
            if (isTop && line.startsWith("log-level:")) {
                if (!logLevelWritten) {
                    out.append("log-level: ").append(logLevel).append('\n')
                    logLevelWritten = true
                }
                continue
            }
            out.append(line).append('\n')
        }
        if (!logLevelWritten) out.insert(0, "log-level: $logLevel\n")

        out.append('\n')
        out.append("# --- TUN 由 AFA 应用统一管理（启动时覆盖导入配置中的 tun 段）---\n")
        out.append("tun:\n")
        out.append("  enable: true\n")
        out.append("  stack: $stack\n")
        out.append("  close-fd-on-drop: false\n")
        out.append("  address:\n")
        out.append("    - $TUN_ADDRESS/$TUN_PREFIX\n")
        out.append("  mtu: $mtu\n")
        if (dnsHijack) {
            out.append("  dns-hijack:\n")
            out.append("    - any:53\n")
        }
        out.append("  auto-route: false\n")
        out.append("  auto-detect-interface: true\n")

        cfg.writeText(out.toString())
        onLog("已应用托管 TUN 配置：stack=$stack mtu=$mtu dns-hijack=$dnsHijack log-level=$logLevel")
    }

    /**
     * @param protectSockPath unix socket served by [ProtectServer]; exported to `ant` as
     *   ANT_PROTECT_SOCK so it can have each outbound socket VpnService.protect()-ed.
     */
    fun start(
        tunPfd: ParcelFileDescriptor,
        protectSockPath: String?,
        onLog: (String) -> Unit
    ): Boolean {
        stop()

        val binary = try {
            ensureBinary()
        } catch (e: Exception) {
            onLog("错误：找不到 ant 可执行文件：${e.message}")
            Log.e(TAG, "ensureBinary", e)
            return false
        }

        writeDefaultConfigIfNeeded()
        // TUN 参数由应用统一管理：每次启动都覆盖配置文件中的 tun 段
        applyManagedConfig(onLog)
        val configFile = File(context.filesDir, CONFIG_NAME)
        val logFile = File(context.filesDir, LOG_NAME)
        logFile.writeText("")

        val tunFd = tunPfd.fd
        try {
            // Clear FD_CLOEXEC so fork+exec inherits the TUN fd.
            // Os.fcntlInt takes FileDescriptor; arg 0 clears all flags including CLOEXEC.
            val fdObj = tunPfd.fileDescriptor
            Os.fcntlInt(fdObj, OsConstants.F_SETFD, 0)
            Log.i(TAG, "Cleared CLOEXEC on tun fd=$tunFd")
        } catch (e: Exception) {
            onLog("警告：fcntl 清除 CLOEXEC 失败：${e.message}")
            Log.w(TAG, "fcntl CLOEXEC", e)
        }

        val argv = arrayOf(
            binary.absolutePath,
            "-c", configFile.absolutePath
        )

        val envMap = LinkedHashMap<String, String>()
        System.getenv().forEach { (k, v) -> envMap[k] = v }
        envMap["ANT_TUN_FD"] = tunFd.toString()
        if (!protectSockPath.isNullOrEmpty()) {
            envMap["ANT_PROTECT_SOCK"] = protectSockPath
        }
        envMap["RUST_LOG"] = "info"
        envMap["HOME"] = context.filesDir.absolutePath
        envMap["TMPDIR"] = context.cacheDir.absolutePath
        val libDir = context.applicationInfo.nativeLibraryDir
        if (!libDir.isNullOrEmpty()) {
            val prev = envMap["LD_LIBRARY_PATH"]
            envMap["LD_LIBRARY_PATH"] =
                if (prev.isNullOrEmpty()) libDir else "$libDir:$prev"
        }

        val envp = envMap.map { "${it.key}=${it.value}" }.toTypedArray()

        return try {
            val pid = nativeSpawn(
                binary.absolutePath,
                argv,
                envp,
                tunFd,
                logFile.absolutePath
            )
            if (pid <= 0) {
                onLog("错误：nativeSpawn 失败 code=$pid")
                Log.e(TAG, "nativeSpawn failed: $pid")
                return false
            }
            pidRef.set(pid)
            onLog("ant 已启动 pid=$pid path=${binary.absolutePath} ANT_TUN_FD=$tunFd ANT_PROTECT_SOCK=$protectSockPath")
            Log.i(TAG, "ant spawned pid=$pid fd=$tunFd")

            val t = Thread {
                try {
                    var pos = 0L
                    while (pidRef.get() == pid) {
                        if (logFile.exists() && logFile.length() > pos) {
                            FileInputStream(logFile).use { fis ->
                                fis.skip(pos)
                                BufferedReader(InputStreamReader(fis)).use { reader ->
                                    var line: String?
                                    while (reader.readLine().also { line = it } != null) {
                                        val msg = line ?: continue
                                        Log.d(TAG, msg)
                                        onLog(msg)
                                    }
                                }
                                pos = logFile.length()
                            }
                        }
                        val st = nativeWaitPid(pid, false)
                        if (st != 0) {
                            onLog("ant 进程已退出 code=$st")
                            pidRef.compareAndSet(pid, -1)
                            break
                        }
                        Thread.sleep(200)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "log tail ended: ${e.message}")
                }
            }.also {
                it.isDaemon = true
                it.name = "ant-log"
                it.start()
            }
            logThreadRef.set(t)
            true
        } catch (e: Exception) {
            onLog("错误：启动失败：${e.message}")
            Log.e(TAG, "start process", e)
            false
        }
    }

    fun stop() {
        val pid = pidRef.getAndSet(-1)
        if (pid <= 0) return
        try {
            nativeKill(pid, 15)
            var waited = 0
            while (waited < 20) {
                val st = nativeWaitPid(pid, false)
                if (st != 0) break
                Thread.sleep(100)
                waited++
            }
            if (nativeWaitPid(pid, false) == 0) {
                nativeKill(pid, 9)
                nativeWaitPid(pid, true)
            }
            Log.i(TAG, "ant process stopped pid=$pid")
        } catch (e: Exception) {
            Log.w(TAG, "stop: ${e.message}")
        }
        logThreadRef.set(null)
    }
}
