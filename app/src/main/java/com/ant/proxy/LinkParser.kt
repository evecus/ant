package com.ant.proxy

import android.util.Base64
import org.json.JSONObject
import java.io.ByteArrayOutputStream

/** 参数名归一化：忽略下划线与连字符差异（allow_insecure == allowInsecure == allow-insecure）。 */
private fun normalizeParamKey(s: String): String = s.lowercase().replace(Regex("[_-]"), "")

/**
 * 分享链接 → 结构化节点。
 *
 * 覆盖 ant link.rs 支持的全部 scheme（vless / vmess / ss / trojan /
 * hysteria2+hy2 / tuic / anytls / socks5 / naive / shadowquic+sq / spectre），
 * 参数名与 ant 保持一致：
 * sni|peer, alpn, fp, insecure|allowInsecure, path, host, mode,
 * security=reality + pbk/sid, flow, obfs, up/down, congestion-control 等。
 *
 * 也支持整段 base64 订阅 blob（标准 / URL-safe / 无 padding / 带换行）。
 * 无法识别的行会被跳过而不是让整批导入失败（对齐 ant 的容错策略）。
 */
object LinkParser {

    data class Result(val nodes: List<ProxyNode>, val skipped: Int)

    private data class Uri(
        val scheme: String,
        val user: String?,
        val host: String,
        val port: Int,
        val rawHostPort: String,
        val query: Map<String, String>,
        val fragment: String
    ) {
        fun q(vararg keys: String): String =
            keys.firstNotNullOfOrNull { query[normalizeParamKey(it)]?.takeIf { v -> v.isNotEmpty() } }.orEmpty()

        fun flag(vararg keys: String): Boolean = keys.any {
            (query[normalizeParamKey(it)] ?: "").lowercase() in setOf("1", "true", "yes", "on")
        }
    }

    fun parse(raw: String): Result {
        var text = raw.trim()
        if (text.isEmpty()) return Result(emptyList(), 0)
        // 整段 base64 订阅：解码后按行拆分
        if (!text.contains("://")) text = decodeBase64(text) ?: text

        val nodes = mutableListOf<ProxyNode>()
        val seen = HashSet<String>()
        var skipped = 0
        for (line in text.lines().map { it.trim() }.filter { it.isNotEmpty() }) {
            val uri = parseUri(line)
            if (uri == null) {
                skipped++
                continue
            }
            val fields = when (uri.scheme) {
                "vless" -> vless(uri)
                "vmess" -> vmess(uri, line)
                "ss", "shadowsocks" -> shadowsocks(uri, line)
                "trojan" -> trojan(uri)
                "hysteria2", "hy2" -> hysteria2(uri)
                "tuic" -> tuic(uri)
                "anytls" -> anytls(uri)
                "socks", "socks5", "socks5h" -> socks5(uri)
                "naive" -> naive(uri)
                "shadowquic", "sq" -> shadowquic(uri)
                "spectre" -> spectre(uri)
                else -> null
            }
            if (fields == null || fields[K_SERVER].isNullOrBlank()) {
                skipped++
                continue
            }
            val key = fields.entries.sortedBy { it.key }.joinToString("|") { "${it.key}=${it.value}" }
            if (!seen.add(key)) continue
            nodes += ProxyNode(fields = fields)
        }
        return Result(nodes, skipped)
    }

    // ── URI ────────────────────────────────────────────────────────────────

    private fun parseUri(line: String): Uri? {
        val idx = line.indexOf("://")
        if (idx <= 0) return null
        val scheme = line.substring(0, idx).lowercase()
        var rest = line.substring(idx + 3)

        val fragment = pctDecode(rest.substringAfter('#', ""))
        rest = rest.substringBefore('#')
        val queryString = rest.substringAfter('?', "")
        rest = rest.substringBefore('?')

        val query = LinkedHashMap<String, String>()
        if (queryString.isNotEmpty()) {
            queryString.split('&').forEach { pair ->
                val k = normalizeParamKey(pair.substringBefore('='))
                if (k.isNotEmpty()) query[k] = pctDecode(pair.substringAfter('=', ""))
            }
        }

        val at = rest.lastIndexOf('@')
        val user = if (at >= 0) pctDecode(rest.substring(0, at)) else null
        val rawHostPort = if (at >= 0) rest.substring(at + 1) else rest
        val (host, port) = splitHostPort(rawHostPort, scheme)
        if (host.isEmpty()) return null
        return Uri(scheme, user, host, port, rawHostPort, query, fragment)
    }

    private fun splitHostPort(s: String, scheme: String): Pair<String, Int> {
        val defaultPort = when (scheme) {
            "socks", "socks5", "socks5h", "socks4", "socks4a" -> 1080
            else -> 443
        }
        if (s.startsWith("[")) {
            val end = s.indexOf(']')
            if (end > 0) {
                val host = s.substring(1, end)
                val tail = s.substring(end + 1).removePrefix(":")
                val port = tail.substringBefore("-").substringBefore(",").toIntOrNull()
                return host to (port ?: defaultPort)
            }
        }
        val colon = s.lastIndexOf(':')
        if (colon > 0) {
            val host = s.substring(0, colon)
            val port = s.substring(colon + 1)
                .substringBefore("-").substringBefore(",").toIntOrNull()
            if (port != null) return host to port
        }
        return s to defaultPort
    }

    private fun pctDecode(s: String): String {
        if (s.indexOf('%') < 0 && s.all { it.code < 128 }) return s
        val out = ByteArrayOutputStream()
        var i = 0
        while (i < s.length) {
            if (s[i] == '%' && i + 2 < s.length) {
                val v = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (v != null) {
                    out.write(v)
                    i += 3
                    continue
                }
            }
            val chars = Character.toChars(s.codePointAt(i))
            out.write(String(chars).toByteArray(Charsets.UTF_8))
            i += chars.size
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }

    private fun decodeBase64(s: String): String? {
        val cleaned = s.replace(Regex("\\s+"), "")
        if (cleaned.isEmpty()) return null
        if (!cleaned.all { it.isLetterOrDigit() || it == '+' || it == '/' || it == '-' || it == '_' || it == '=' }) {
            return null
        }
        val std = cleaned.trimEnd('=').replace('-', '+').replace('_', '/')
        if (std.length < 4) return null
        val padded = std + "=".repeat((4 - std.length % 4) % 4)
        return try {
            val bytes = Base64.decode(padded, Base64.DEFAULT)
            val text = String(bytes, Charsets.UTF_8)
            text.takeIf { it.isNotEmpty() && !it.contains('\uFFFD') }
        } catch (_: Exception) {
            null
        }
    }

    // ── 各协议 ─────────────────────────────────────────────────────────────

    private fun newMap(type: String, u: Uri): MutableMap<String, String> = linkedMapOf(
        K_TYPE to type,
        K_SERVER to u.host,
        K_PORT to u.port.toString(),
        K_NAME to u.fragment.ifBlank { u.q("remarks", "remark").ifBlank { "${u.host}:${u.port}" } }
    )

    /** naive / shadowquic / spectre 的 userinfo 均为 `username:password`。 */
    private fun credentials(u: Uri): Pair<String, String>? {
        val cred = u.user ?: return null
        val colon = cred.indexOf(':')
        if (colon <= 0) return null
        return cred.substring(0, colon) to cred.substring(colon + 1)
    }

    private fun networkOf(u: Uri): String = when (val t = u.q("type").lowercase()) {
        "ws", "xhttp", "tcp" -> t
        "httpupgrade" -> "ws"
        else -> "tcp"
    }

    private fun putTlsCommon(m: MutableMap<String, String>, u: Uri, withSwitch: Boolean = true) {
        if (withSwitch) m[K_TLS] = "true"
        u.q("sni", "peer").takeIf { it.isNotEmpty() }?.let { m[K_SNI] = it }
        u.q("alpn").takeIf { it.isNotEmpty() }?.let { m[K_ALPN] = it }
        u.q("fp").takeIf { it.isNotEmpty() }?.let { m[K_CLIENT_FP] = it }
        u.q("pcs", "pinsha256").takeIf { it.isNotEmpty() }?.let { m[K_FINGERPRINT] = it }
        if (u.flag("insecure", "allowinsecure", "skip-cert-verify")) m[K_SKIP_CERT] = "true"
    }

    private fun putTransport(m: MutableMap<String, String>, u: Uri) {
        val net = networkOf(u)
        m[K_NETWORK] = net
        val path = u.q("path")
        val host = u.q("host")
        when (net) {
            "ws" -> {
                if (path.isNotEmpty()) m[K_WS_PATH] = path
                if (host.isNotEmpty()) m[K_WS_HOST] = host
            }
            "xhttp" -> {
                if (path.isNotEmpty()) m[K_XHTTP_PATH] = path
                if (host.isNotEmpty()) m[K_XHTTP_HOST] = host
                u.q("mode").takeIf { it.isNotEmpty() }?.let { m[K_XHTTP_MODE] = it }
            }
        }
    }

    private fun vless(u: Uri): MutableMap<String, String>? {
        val uuid = u.user ?: return null
        val m = newMap("vless", u)
        m[K_UUID] = uuid
        val security = u.q("security").lowercase()
        m[K_TLS] = if (security in setOf("none", "")) "false" else "true"
        putTlsCommon(m, u, withSwitch = false)
        putTransport(m, u)
        u.q("flow").takeIf { it.isNotEmpty() }?.let { m[K_FLOW] = it }
        if (security == "reality") {
            u.q("pbk").takeIf { it.isNotEmpty() }?.let { m[K_REALITY_PBK] = it }
            u.q("sid").takeIf { it.isNotEmpty() }?.let { m[K_REALITY_SID] = it }
        }
        return m
    }

    private fun vmess(u: Uri, line: String): MutableMap<String, String>? {
        val blob = line.substringAfter("://").substringBefore('#')
        val json = decodeBase64(blob) ?: return null
        return try {
            val o = JSONObject(pctDecode(json))
            val server = o.optString("add")
            val uuid = o.optString("id")
            if (server.isBlank() || uuid.isBlank()) return null
            val port = o.optString("port", "443").ifBlank { "443" }
            val m = linkedMapOf(
                K_TYPE to "vmess",
                K_SERVER to server,
                K_PORT to port,
                K_NAME to o.optString("ps").ifBlank {
                    u.fragment.ifBlank { "$server:$port" }
                },
                K_UUID to uuid,
                K_ALTER_ID to o.optString("aid", "0").ifBlank { "0" },
                K_CIPHER to o.optString("scy", "auto").ifBlank { "auto" }
            )
            val net = when (val n = o.optString("net", "tcp").lowercase()) {
                "ws", "xhttp", "tcp" -> n
                "h2" -> "xhttp"
                else -> "tcp"
            }
            m[K_NETWORK] = net
            m[K_TLS] = if (o.optString("tls").lowercase() in setOf("tls", "true", "1")) "true" else "false"
            o.optString("sni").ifBlank { o.optString("peer") }
                .takeIf { it.isNotEmpty() }?.let { m[K_SNI] = it }
            o.optString("alpn").takeIf { it.isNotEmpty() }?.let { m[K_ALPN] = it }
            o.optString("fp").takeIf { it.isNotEmpty() }?.let { m[K_CLIENT_FP] = it }
            val insecure = o.optBoolean("allowInsecure", false) ||
                o.optString("allowInsecure").lowercase() in setOf("true", "1")
            if (insecure) m[K_SKIP_CERT] = "true"
            val path = o.optString("path")
            val host = o.optString("host")
            when (net) {
                "ws" -> {
                    if (path.isNotEmpty()) m[K_WS_PATH] = path
                    if (host.isNotEmpty()) m[K_WS_HOST] = host
                }
                "xhttp" -> {
                    if (path.isNotEmpty()) m[K_XHTTP_PATH] = path
                    if (host.isNotEmpty()) m[K_XHTTP_HOST] = host
                }
            }
            m
        } catch (_: Exception) {
            null
        }
    }

    private fun shadowsocks(u: Uri, line: String): MutableMap<String, String>? {
        val rest = line.substringAfter("://").substringBefore('#')
        val methodPass: String
        val hostPort: String
        if (u.user != null) {
            // SIP002：userinfo = base64(method:password)
            val decoded = decodeBase64(u.user!!) ?: u.user!!
            if (!decoded.contains(':')) return null
            methodPass = decoded
            hostPort = u.rawHostPort
        } else {
            // legacy：整段 base64(method:password@host:port)
            val decoded = decodeBase64(rest) ?: return null
            val at = decoded.lastIndexOf('@')
            if (at < 0) return null
            methodPass = decoded.substring(0, at)
            hostPort = decoded.substring(at + 1).substringBefore('/')
        }
        val colon = methodPass.indexOf(':')
        if (colon <= 0) return null
        val (host, port) = splitHostPort(hostPort, "ss")
        val m = newMap("shadowsocks", u)
        m[K_SERVER] = host
        m[K_PORT] = port.toString()
        m[K_CIPHER] = methodPass.substring(0, colon)
        m[K_PASSWORD] = methodPass.substring(colon + 1)
        m[K_TLS] = "false"
        m[K_NETWORK] = "tcp"

        val plugin = u.q("plugin")
        if (plugin.contains("obfs=websocket") || plugin.contains("v2ray-plugin")) {
            m[K_NETWORK] = "ws"
            plugin.split(';').forEach { part ->
                val k = part.substringBefore('=').lowercase()
                val v = part.substringAfter('=', "")
                when (k) {
                    "path", "obfs-path" -> if (v.isNotEmpty()) m[K_WS_PATH] = v
                    "host", "obfs-host" -> if (v.isNotEmpty()) m[K_WS_HOST] = v
                }
            }
        }
        u.q("sni", "peer").takeIf { it.isNotEmpty() }?.let {
            m[K_SNI] = it
            m[K_TLS] = "true"
        }
        if (u.flag("insecure", "allowinsecure", "skip-cert-verify")) m[K_SKIP_CERT] = "true"
        return m
    }

    private fun trojan(u: Uri): MutableMap<String, String>? {
        val password = u.user ?: return null
        val m = newMap("trojan", u)
        m[K_PASSWORD] = password
        putTlsCommon(m, u)
        putTransport(m, u)
        return m
    }

    private fun hysteria2(u: Uri): MutableMap<String, String>? {
        val password = u.user ?: return null
        val m = newMap("hysteria2", u)
        m[K_PASSWORD] = password
        putTlsCommon(m, u, withSwitch = false)
        u.q("obfs").takeIf { it.isNotEmpty() }?.let { m[K_OBFS] = it }
        u.q("obfs-password", "obfs_password", "obfs-pwd")
            .takeIf { it.isNotEmpty() }?.let { m[K_OBFS_PASSWORD] = it }
        u.q("up").takeIf { it.isNotEmpty() }?.let { m[K_UP] = it }
        u.q("down").takeIf { it.isNotEmpty() }?.let { m[K_DOWN] = it }
        u.q("ports", "mport").takeIf { it.isNotEmpty() }?.let { m[K_PORTS] = it }
        // host:1000-2000,3000 形式的内嵌端口跳跃
        if (!m.containsKey(K_PORTS)) {
            val tail = u.rawHostPort.substringAfter(':', "")
            if (tail.contains('-') || tail.contains(',')) m[K_PORTS] = tail
        }
        return m
    }

    private fun tuic(u: Uri): MutableMap<String, String>? {
        val credentials = u.user ?: return null
        val colon = credentials.indexOf(':')
        if (colon <= 0) return null // 仅 TUIC v5 (uuid:password)
        val m = newMap("tuic", u)
        m[K_UUID] = credentials.substring(0, colon)
        m[K_PASSWORD] = credentials.substring(colon + 1)
        putTlsCommon(m, u, withSwitch = false)
        u.q("congestion-control", "congestion_controller")
            .takeIf { it.isNotEmpty() }?.let { m[K_CONGESTION] = it }
        u.q("heartbeat").takeIf { it.isNotEmpty() }?.let { m[K_HEARTBEAT] = it }
        return m
    }

    private fun anytls(u: Uri): MutableMap<String, String>? {
        val password = u.user ?: return null
        val m = newMap("anytls", u)
        m[K_PASSWORD] = password
        putTlsCommon(m, u, withSwitch = false)
        return m
    }

    private fun socks5(u: Uri): MutableMap<String, String>? {
        val m = newMap("socks5", u)
        val credentials = u.user
        if (!credentials.isNullOrEmpty() && credentials.contains(':')) {
            m[K_USERNAME] = credentials.substringBefore(':')
            m[K_PASSWORD] = credentials.substringAfter(':')
        }
        return m
    }

    /**
     * `naive://user:pass@host:port?sni=&insecure=&fp=&pcs=#name`
     * NaiveProxy 恒为 TLS + HTTP/2 CONNECT，ant 强制 ALPN=h2，故不解析 alpn。
     */
    private fun naive(u: Uri): MutableMap<String, String>? {
        val (user, pass) = credentials(u) ?: return null
        val m = newMap("naive", u)
        m[K_USERNAME] = user
        m[K_PASSWORD] = pass
        u.q("sni", "peer").takeIf { it.isNotEmpty() }?.let { m[K_SNI] = it }
        u.q("fp").takeIf { it.isNotEmpty() }?.let { m[K_CLIENT_FP] = it }
        u.q("pcs", "pinsha256").takeIf { it.isNotEmpty() }?.let { m[K_FINGERPRINT] = it }
        if (u.flag("insecure", "allowinsecure", "skip-cert-verify")) m[K_SKIP_CERT] = "true"
        return m
    }

    /**
     * `shadowquic://user:pass@host:port?sni=<必填>&alpn=h3&over-stream=1&disable-zero-rtt=1&initial-mtu=&min-mtu=`
     * ant link.rs 用 `disable-zero-rtt` 反向表达 0-RTT（默认开启），这里转成正向的 `zero-rtt`。
     * `congestion-control` / `heartbeat` 是 YAML 支持字段，作为扩展一并接受。
     */
    private fun shadowquic(u: Uri): MutableMap<String, String>? {
        val (user, pass) = credentials(u) ?: return null
        val sni = u.q("sni", "peer")
        if (sni.isEmpty()) return null // ant 严格要求 SNI 匹配 jls-upstream 域名
        val m = newMap("shadowquic", u)
        m[K_USERNAME] = user
        m[K_PASSWORD] = pass
        m[K_SNI] = sni
        u.q("alpn").takeIf { it.isNotEmpty() }?.let { m[K_ALPN] = it }
        if (u.flag("insecure", "allowinsecure", "skip-cert-verify")) m[K_SKIP_CERT] = "true"
        m[K_ZERO_RTT] = (!u.flag("disable-zero-rtt")).toString()
        m[K_OVER_STREAM] = u.flag("over-stream").toString()
        u.q("initial-mtu").takeIf { it.isNotEmpty() }?.let { m[K_INITIAL_MTU] = it }
        u.q("min-mtu").takeIf { it.isNotEmpty() }?.let { m[K_MIN_MTU] = it }
        u.q("congestion-control", "congestion_controller")
            .takeIf { it.isNotEmpty() }?.let { m[K_CONGESTION] = it }
        u.q("heartbeat").takeIf { it.isNotEmpty() }?.let { m[K_HEARTBEAT] = it }
        return m
    }

    /** `spectre://user:pass@host:port?sni=<必填>&up=&down=#name`（JLS + Brutal 速率）。 */
    private fun spectre(u: Uri): MutableMap<String, String>? {
        val (user, pass) = credentials(u) ?: return null
        val sni = u.q("sni", "peer")
        if (sni.isEmpty()) return null // ant 严格要求 SNI 匹配伪装域名
        val m = newMap("spectre", u)
        m[K_USERNAME] = user
        m[K_PASSWORD] = pass
        m[K_SNI] = sni
        u.q("up").takeIf { it.isNotEmpty() }?.let { m[K_UP] = it }
        u.q("down").takeIf { it.isNotEmpty() }?.let { m[K_DOWN] = it }
        return m
    }
}
