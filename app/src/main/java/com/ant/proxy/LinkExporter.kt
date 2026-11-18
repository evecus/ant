package com.ant.proxy

import android.util.Base64
import org.json.JSONObject

/**
 * 结构化节点 → 分享链接（用于卡片上的分享按钮 / 批量导出）。
 * 与 [LinkParser] 互为逆运算，保证「导入 → 编辑 → 分享 → 再导入」字段不丢失。
 */
object LinkExporter {

    private val HEX = "0123456789ABCDEF"

    fun export(node: ProxyNode): String = when (node.type) {
        "vless" -> vless(node)
        "vmess" -> vmess(node)
        "shadowsocks" -> shadowsocks(node)
        "trojan" -> trojan(node)
        "hysteria2" -> hysteria2(node)
        "tuic" -> tuic(node)
        "anytls" -> anytls(node)
        "socks5" -> socks5(node)
        "naive" -> naive(node)
        "shadowquic" -> shadowquic(node)
        "spectre" -> spectre(node)
        else -> "# ${node.name}\n${NodeSchema.renderProxies(node)}"
    }

    fun exportAll(nodes: List<ProxyNode>): String = nodes.joinToString("\n") { export(it) }

    /** 生成标准 base64 订阅 blob（可被本 App 或其它客户端导入）。 */
    fun exportSubscription(nodes: List<ProxyNode>): String =
        Base64.encodeToString(exportAll(nodes).toByteArray(Charsets.UTF_8), Base64.NO_WRAP)

    private class Query {
        private val pairs = mutableListOf<Pair<String, String>>()
        fun add(key: String, value: String) {
            if (value.isNotBlank()) pairs += key to value
        }
        fun build(): String = if (pairs.isEmpty()) "" else
            "?" + pairs.joinToString("&") { "${enc(it.first)}=${enc(it.second)}" }
    }

    private fun enc(s: String): String {
        val sb = StringBuilder()
        for (b in s.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            val ch = c.toChar()
            val asciiSafe = (c in 0x41..0x5A) || (c in 0x61..0x7A) || (c in 0x30..0x39)
            if (asciiSafe || ch in "-._~/") {
                sb.append(ch)
            } else {
                sb.append('%').append(HEX[c ushr 4]).append(HEX[c and 15])
            }
        }
        return sb.toString()
    }

    private fun hostPort(node: ProxyNode): String {
        val host = node.get(K_SERVER)
        val h = if (host.contains(':') && !host.startsWith("[")) "[$host]" else host
        return "$h:${node.get(K_PORT)}"
    }

    private fun fragment(node: ProxyNode): String =
        if (node.name.isBlank()) "" else "#" + enc(node.name)

    /** naive / shadowquic / spectre 的 `username:password@` 前缀。 */
    private fun userPass(node: ProxyNode): String =
        "${enc(node.get(K_USERNAME))}:${enc(node.get(K_PASSWORD))}@"

    private fun Query.putTls(node: ProxyNode) {
        add("sni", node.get(K_SNI))
        add("alpn", node.get(K_ALPN))
        add("fp", node.get(K_CLIENT_FP))
        add("pcs", node.get(K_FINGERPRINT))
        if (node.flag(K_SKIP_CERT)) add("insecure", "1")
    }

    private fun Query.putTransport(node: ProxyNode) {
        when (val net = node.get(K_NETWORK)) {
            "ws" -> {
                add("type", "ws")
                add("path", node.get(K_WS_PATH))
                add("host", node.get(K_WS_HOST))
            }
            "xhttp" -> {
                add("type", "xhttp")
                add("path", node.get(K_XHTTP_PATH))
                add("host", node.get(K_XHTTP_HOST))
                add("mode", node.get(K_XHTTP_MODE))
            }
            else -> if (net.isNotBlank() && net != "tcp") add("type", net)
        }
    }

    private fun vless(node: ProxyNode): String {
        val q = Query()
        val reality = node.get(K_REALITY_PBK).isNotBlank()
        q.add("security", when {
            reality -> "reality"
            node.flag(K_TLS) -> "tls"
            else -> "none"
        })
        q.putTls(node)
        q.putTransport(node)
        q.add("flow", node.get(K_FLOW))
        q.add("pbk", node.get(K_REALITY_PBK))
        q.add("sid", node.get(K_REALITY_SID))
        return "vless://${enc(node.get(K_UUID))}@${hostPort(node)}${q.build()}${fragment(node)}"
    }

    private fun vmess(node: ProxyNode): String {
        val net = node.get(K_NETWORK).ifBlank { "tcp" }
        val o = JSONObject()
            .put("v", "2")
            .put("ps", node.name)
            .put("add", node.get(K_SERVER))
            .put("port", node.get(K_PORT))
            .put("id", node.get(K_UUID))
            .put("aid", node.get(K_ALTER_ID).ifBlank { "0" })
            .put("scy", node.get(K_CIPHER).ifBlank { "auto" })
            .put("net", net)
            .put("type", "none")
            .put("tls", if (node.flag(K_TLS)) "tls" else "")
            .put("sni", node.get(K_SNI))
            .put("alpn", node.get(K_ALPN))
            .put("fp", node.get(K_CLIENT_FP))
            .put("allowInsecure", node.flag(K_SKIP_CERT))
        if (net == "ws") {
            o.put("path", node.get(K_WS_PATH)).put("host", node.get(K_WS_HOST))
        } else if (net == "xhttp") {
            o.put("path", node.get(K_XHTTP_PATH)).put("host", node.get(K_XHTTP_HOST))
        }
        val b64 = Base64.encodeToString(o.toString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
        return "vmess://$b64"
    }

    private fun shadowsocks(node: ProxyNode): String {
        val userinfo = Base64.encodeToString(
            "${node.get(K_CIPHER)}:${node.get(K_PASSWORD)}".toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP or Base64.URL_SAFE
        ).trimEnd('=')
        val q = Query()
        if (node.get(K_NETWORK) == "ws") {
            q.add(
                "plugin", buildString {
                    append("v2ray-plugin;obfs=websocket")
                    val path = node.get(K_WS_PATH)
                    val host = node.get(K_WS_HOST)
                    if (path.isNotBlank()) append(";path=").append(path)
                    if (host.isNotBlank()) append(";host=").append(host)
                }
            )
        }
        q.add("sni", node.get(K_SNI))
        if (node.flag(K_SKIP_CERT)) q.add("insecure", "1")
        return "ss://$userinfo@${hostPort(node)}${q.build()}${fragment(node)}"
    }

    private fun trojan(node: ProxyNode): String {
        val q = Query()
        q.putTls(node)
        q.putTransport(node)
        return "trojan://${enc(node.get(K_PASSWORD))}@${hostPort(node)}${q.build()}${fragment(node)}"
    }

    private fun hysteria2(node: ProxyNode): String {
        val q = Query()
        q.putTls(node)
        q.add("obfs", node.get(K_OBFS))
        q.add("obfs-password", node.get(K_OBFS_PASSWORD))
        q.add("up", node.get(K_UP))
        q.add("down", node.get(K_DOWN))
        q.add("ports", node.get(K_PORTS))
        return "hysteria2://${enc(node.get(K_PASSWORD))}@${hostPort(node)}${q.build()}${fragment(node)}"
    }

    private fun tuic(node: ProxyNode): String {
        val q = Query()
        q.putTls(node)
        q.add("congestion-control", node.get(K_CONGESTION))
        q.add("heartbeat", node.get(K_HEARTBEAT))
        return "tuic://${enc(node.get(K_UUID))}:${enc(node.get(K_PASSWORD))}@${hostPort(node)}${q.build()}${fragment(node)}"
    }

    private fun anytls(node: ProxyNode): String {
        val q = Query()
        q.putTls(node)
        return "anytls://${enc(node.get(K_PASSWORD))}@${hostPort(node)}${q.build()}${fragment(node)}"
    }

    private fun socks5(node: ProxyNode): String {
        val user = node.get(K_USERNAME)
        val pass = node.get(K_PASSWORD)
        val auth = if (user.isBlank() && pass.isBlank()) "" else "${enc(user)}:${enc(pass)}@"
        return "socks5://$auth${hostPort(node)}${fragment(node)}"
    }

    /** NaiveProxy 恒为 TLS+h2，ant 忽略 alpn 参数，故不导出。 */
    private fun naive(node: ProxyNode): String {
        val q = Query()
        q.add("sni", node.get(K_SNI))
        q.add("fp", node.get(K_CLIENT_FP))
        q.add("pcs", node.get(K_FINGERPRINT))
        if (node.flag(K_SKIP_CERT)) q.add("insecure", "1")
        return "naive://${userPass(node)}${hostPort(node)}${q.build()}${fragment(node)}"
    }

    /**
     * ant link.rs 用 `disable-zero-rtt=1` 表达关闭 0-RTT（默认开启），
     * 因此仅在显式 false 时输出该参数，保证解析回来仍是 false。
     */
    private fun shadowquic(node: ProxyNode): String {
        val q = Query()
        q.add("sni", node.get(K_SNI))
        q.add("alpn", node.get(K_ALPN))
        if (node.flag(K_SKIP_CERT)) q.add("insecure", "1")
        if (node.get(K_ZERO_RTT).equals("false", ignoreCase = true)) q.add("disable-zero-rtt", "1")
        if (node.flag(K_OVER_STREAM)) q.add("over-stream", "1")
        q.add("initial-mtu", node.get(K_INITIAL_MTU))
        q.add("min-mtu", node.get(K_MIN_MTU))
        q.add("congestion-control", node.get(K_CONGESTION))
        q.add("heartbeat", node.get(K_HEARTBEAT))
        return "shadowquic://${userPass(node)}${hostPort(node)}${q.build()}${fragment(node)}"
    }

    private fun spectre(node: ProxyNode): String {
        val q = Query()
        q.add("sni", node.get(K_SNI))
        q.add("up", node.get(K_UP))
        q.add("down", node.get(K_DOWN))
        return "spectre://${userPass(node)}${hostPort(node)}${q.build()}${fragment(node)}"
    }
}
