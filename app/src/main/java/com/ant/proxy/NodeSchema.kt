package com.ant.proxy

/**
 * 节点数据模型与协议 schema。
 *
 * 设计要点：节点的每个字段直接以 ant 的 YAML key 存储（如 `ws-path`、`skip-cert-verify`），
 * 因此「存储 → 编辑表单 → config.yaml」三者共用同一套 key，不需要任何转换层。
 * 字段顺序由 [NodeSchema.fieldsFor] 决定，渲染与表单都按它走。
 */
data class ProxyNode(
    val id: String = java.util.UUID.randomUUID().toString(),
    val fields: Map<String, String> = emptyMap()
) {
    val name: String get() = fields[K_NAME].orEmpty()
    val type: String get() = fields[K_TYPE].orEmpty()
    val server: String get() = fields[K_SERVER].orEmpty()
    val port: String get() = fields[K_PORT].orEmpty()

    fun get(key: String): String = fields[key].orEmpty()
    fun flag(key: String): Boolean = fields[key] == "true"
    fun with(key: String, value: String): ProxyNode = copy(fields = fields + (key to value))
    fun withAll(patch: Map<String, String>): ProxyNode = copy(fields = fields + patch)
}

// ── YAML 字段 key（与 ant src/config.rs ProxyConfig 对齐）──────────────────
const val K_NAME = "name"
const val K_TYPE = "type"
const val K_SERVER = "server"
const val K_PORT = "port"
const val K_UUID = "uuid"
const val K_PASSWORD = "password"
const val K_USERNAME = "username"
const val K_CIPHER = "cipher"
const val K_ALTER_ID = "alter-id"
const val K_TLS = "tls"
const val K_SNI = "sni"
const val K_ALPN = "alpn"
const val K_SKIP_CERT = "skip-cert-verify"
const val K_FINGERPRINT = "fingerprint"
const val K_CLIENT_FP = "client-fingerprint"
const val K_NETWORK = "network"
const val K_WS_PATH = "ws-path"
const val K_WS_HOST = "ws-host"
const val K_XHTTP_PATH = "xhttp-path"
const val K_XHTTP_HOST = "xhttp-host"
const val K_XHTTP_MODE = "xhttp-mode"
const val K_FLOW = "flow"
const val K_REALITY_PBK = "reality-public-key"
const val K_REALITY_SID = "reality-short-id"
const val K_OBFS = "obfs"
const val K_OBFS_PASSWORD = "obfs-password"
const val K_UP = "up"
const val K_DOWN = "down"
const val K_PORTS = "ports"
const val K_CONGESTION = "congestion-control"
const val K_HEARTBEAT = "heartbeat"
// shadowquic 专用
const val K_OVER_STREAM = "over-stream"
const val K_ZERO_RTT = "zero-rtt"
const val K_INITIAL_MTU = "initial-mtu"
const val K_MIN_MTU = "min-mtu"

// ── 表单分组 ──────────────────────────────────────────────────────────────
const val G_BASIC = "基本"
const val G_AUTH = "认证"
const val G_TRANSPORT = "传输"
const val G_TLS = "TLS"
const val G_ADV = "高级"

enum class FieldKind { TEXT, NUMBER, SECRET, TOGGLE, SELECT }

data class FieldSpec(
    val key: String,
    val label: String,
    val kind: FieldKind = FieldKind.TEXT,
    val group: String = G_BASIC,
    val hint: String = "",
    val options: List<String> = emptyList(),
    val required: Boolean = false,
    /** 条件显示，例如 network=ws 时才出现 ws-path */
    val showIf: (Map<String, String>) -> Boolean = { true }
)

data class ProtocolInfo(val key: String, val display: String)

/** App 支持编辑的 11 种协议（ant 默认编译范围内）。 */
val PROTOCOLS = listOf(
    ProtocolInfo("vless", "VLESS"),
    ProtocolInfo("vmess", "VMess"),
    ProtocolInfo("trojan", "Trojan"),
    ProtocolInfo("shadowsocks", "Shadowsocks"),
    ProtocolInfo("hysteria2", "Hysteria2"),
    ProtocolInfo("tuic", "TUIC"),
    ProtocolInfo("anytls", "AnyTLS"),
    ProtocolInfo("socks5", "SOCKS5"),
    ProtocolInfo("naive", "NaiveProxy"),
    ProtocolInfo("shadowquic", "ShadowQUIC"),
    ProtocolInfo("spectre", "Spectre")
)

fun protocolDisplay(type: String): String =
    PROTOCOLS.firstOrNull { it.key == type }?.display ?: type.uppercase()

private val SS_CIPHERS = listOf(
    "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "none"
)
private val VMESS_CIPHERS = listOf("auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero")
private val UTLS_FPS = listOf("", "chrome", "firefox", "safari", "edge", "ios", "android", "360", "qq", "random", "none")
private val NETWORKS = listOf("tcp", "ws", "xhttp")
private val XHTTP_MODES = listOf("", "auto", "stream-one", "packet-up", "stream-up")
/** tuic / shadowquic 共用（quinn 无独立 new_reno 实现，会降级为 cubic）。 */
private val CONGESTION_MODES = listOf("cubic", "bbr", "new_reno")

object NodeSchema {

    private val basic = listOf(
        FieldSpec(K_NAME, "节点名称", required = true, hint = "例如 HK-01", group = G_BASIC),
        FieldSpec(K_SERVER, "服务器地址", required = true, hint = "域名或 IP", group = G_BASIC),
        FieldSpec(K_PORT, "端口", FieldKind.NUMBER, required = true, hint = "443", group = G_BASIC)
    )

    private fun auth(type: String): List<FieldSpec> = when (type) {
        "vless" -> listOf(
            FieldSpec(K_UUID, "UUID", required = true, group = G_AUTH)
        )
        "vmess" -> listOf(
            FieldSpec(K_UUID, "UUID", required = true, group = G_AUTH),
            FieldSpec(K_CIPHER, "加密方式", FieldKind.SELECT, options = VMESS_CIPHERS, group = G_AUTH),
            FieldSpec(K_ALTER_ID, "alterId", FieldKind.NUMBER, group = G_AUTH, hint = "0")
        )
        "trojan" -> listOf(
            FieldSpec(K_PASSWORD, "密码", FieldKind.SECRET, required = true, group = G_AUTH)
        )
        "shadowsocks" -> listOf(
            FieldSpec(K_PASSWORD, "密码", FieldKind.SECRET, required = true, group = G_AUTH),
            FieldSpec(K_CIPHER, "加密方式", FieldKind.SELECT, options = SS_CIPHERS, required = true, group = G_AUTH)
        )
        "hysteria2" -> listOf(
            FieldSpec(K_PASSWORD, "密码", FieldKind.SECRET, required = true, group = G_AUTH)
        )
        "tuic" -> listOf(
            FieldSpec(K_UUID, "UUID", required = true, group = G_AUTH),
            FieldSpec(K_PASSWORD, "密码", FieldKind.SECRET, required = true, group = G_AUTH)
        )
        "anytls" -> listOf(
            FieldSpec(K_PASSWORD, "密码", FieldKind.SECRET, required = true, group = G_AUTH)
        )
        "socks5" -> listOf(
            FieldSpec(K_USERNAME, "用户名", group = G_AUTH, hint = "可留空"),
            FieldSpec(K_PASSWORD, "密码", FieldKind.SECRET, group = G_AUTH, hint = "可留空")
        )
        "naive" -> listOf(
            FieldSpec(K_USERNAME, "用户名", required = true, group = G_AUTH),
            FieldSpec(K_PASSWORD, "密码", FieldKind.SECRET, required = true, group = G_AUTH)
        )
        "shadowquic", "spectre" -> listOf(
            FieldSpec(K_USERNAME, "用户名 (JLS user iv)", required = true, group = G_AUTH),
            FieldSpec(K_PASSWORD, "密码 (JLS password)", FieldKind.SECRET, required = true, group = G_AUTH)
        )
        else -> emptyList()
    }

    private val transport = listOf(
        FieldSpec(K_NETWORK, "传输协议", FieldKind.SELECT, options = NETWORKS, group = G_TRANSPORT),
        FieldSpec(K_WS_PATH, "WebSocket 路径", group = G_TRANSPORT, hint = "/path",
            showIf = { it[K_NETWORK] == "ws" }),
        FieldSpec(K_WS_HOST, "WebSocket Host", group = G_TRANSPORT,
            showIf = { it[K_NETWORK] == "ws" }),
        FieldSpec(K_XHTTP_PATH, "XHTTP 路径", group = G_TRANSPORT, hint = "/xhttp",
            showIf = { it[K_NETWORK] == "xhttp" }),
        FieldSpec(K_XHTTP_HOST, "XHTTP Host", group = G_TRANSPORT,
            showIf = { it[K_NETWORK] == "xhttp" }),
        FieldSpec(K_XHTTP_MODE, "XHTTP 模式", FieldKind.SELECT, options = XHTTP_MODES,
            group = G_TRANSPORT, showIf = { it[K_NETWORK] == "xhttp" })
    )

    private fun tlsFields(type: String): List<FieldSpec> {
        // vless/vmess/trojan/shadowsocks 有 TLS 开关；其余协议 ant 默认 tls=true
        //（naive 更是强制 TLS、shadowquic / spectre 走 QUIC + JLS），不输出该字段。
        val withTlsSwitch = type in listOf("vless", "vmess", "trojan", "shadowsocks")
        val list = mutableListOf<FieldSpec>()
        if (withTlsSwitch) {
            list += FieldSpec(K_TLS, "启用 TLS", FieldKind.TOGGLE, group = G_TLS)
        }
        when (type) {
            "naive" -> {
                // ALPN 由 ant 强制 h2（HTTP/2 CONNECT），不暴露给用户。
                list += FieldSpec(K_SNI, "SNI / 服务器名", group = G_TLS)
                list += FieldSpec(K_SKIP_CERT, "跳过证书验证", FieldKind.TOGGLE, group = G_TLS)
                list += FieldSpec(K_CLIENT_FP, "uTLS 指纹", FieldKind.SELECT, options = UTLS_FPS, group = G_TLS)
                list += FieldSpec(K_FINGERPRINT, "证书指纹 pinSHA256", group = G_TLS)
            }
            "shadowquic" -> {
                list += FieldSpec(K_SNI, "SNI（须匹配 jls-upstream 域名）", required = true,
                    group = G_TLS, hint = "必填，不能是 IP")
                list += FieldSpec(K_ALPN, "ALPN", group = G_TLS, hint = "逗号分隔，默认 h3")
                list += FieldSpec(K_SKIP_CERT, "跳过证书验证", FieldKind.TOGGLE, group = G_TLS)
            }
            "spectre" -> {
                list += FieldSpec(K_SNI, "SNI（须匹配伪装域名）", required = true,
                    group = G_TLS, hint = "必填，不能是 IP")
            }
            else -> {
                list += FieldSpec(K_SNI, "SNI / 服务器名", group = G_TLS)
                list += FieldSpec(K_ALPN, "ALPN", group = G_TLS, hint = "逗号分隔，如 h3,h2")
                list += FieldSpec(K_SKIP_CERT, "跳过证书验证", FieldKind.TOGGLE, group = G_TLS)
                list += FieldSpec(K_CLIENT_FP, "uTLS 指纹", FieldKind.SELECT, options = UTLS_FPS, group = G_TLS)
                list += FieldSpec(K_FINGERPRINT, "证书指纹 pinSHA256", group = G_TLS)
            }
        }
        return list
    }

    private fun advanced(type: String): List<FieldSpec> = when (type) {
        "vless" -> listOf(
            FieldSpec(K_FLOW, "Flow", FieldKind.SELECT,
                options = listOf("", "xtls-rprx-vision"), group = G_ADV),
            FieldSpec(K_REALITY_PBK, "REALITY 公钥 pbk", group = G_ADV),
            FieldSpec(K_REALITY_SID, "REALITY shortId", group = G_ADV)
        )
        "hysteria2" -> listOf(
            FieldSpec(K_OBFS, "混淆类型", FieldKind.SELECT,
                options = listOf("", "salamander"), group = G_ADV),
            FieldSpec(K_OBFS_PASSWORD, "混淆密码", FieldKind.SECRET, group = G_ADV),
            FieldSpec(K_UP, "上行带宽 up", group = G_ADV, hint = "如 100 Mbps"),
            FieldSpec(K_DOWN, "下行带宽 down", group = G_ADV, hint = "如 300 Mbps"),
            FieldSpec(K_PORTS, "端口跳跃", group = G_ADV, hint = "如 1000-2000,3000")
        )
        "tuic" -> listOf(
            FieldSpec(K_CONGESTION, "拥塞控制", FieldKind.SELECT,
                options = CONGESTION_MODES, group = G_ADV),
            FieldSpec(K_HEARTBEAT, "心跳间隔", group = G_ADV, hint = "如 10s")
        )
        "shadowquic" -> listOf(
            FieldSpec(K_CONGESTION, "拥塞控制", FieldKind.SELECT,
                options = CONGESTION_MODES, group = G_ADV, hint = "默认 bbr"),
            FieldSpec(K_HEARTBEAT, "QUIC keep-alive", group = G_ADV, hint = "如 10s；off / 0 关闭"),
            FieldSpec(K_OVER_STREAM, "UDP 走 QUIC stream", FieldKind.TOGGLE, group = G_ADV,
                hint = "默认关（datagram）；代理 HTTP/3 时保持关闭"),
            FieldSpec(K_ZERO_RTT, "0-RTT 握手", FieldKind.TOGGLE, group = G_ADV),
            FieldSpec(K_INITIAL_MTU, "初始 MTU", FieldKind.NUMBER, group = G_ADV, hint = "默认 1300，≥1200"),
            FieldSpec(K_MIN_MTU, "最小 MTU", FieldKind.NUMBER, group = G_ADV, hint = "默认 1290，≥1200")
        )
        "spectre" -> listOf(
            FieldSpec(K_UP, "上行速率 up", group = G_ADV, hint = "如 50mbps / 12500000（字节/秒）"),
            FieldSpec(K_DOWN, "下行速率 down", group = G_ADV, hint = "如 200mbps / 25000000")
        )
        else -> emptyList()
    }

    /** 该协议的完整字段顺序（渲染与表单共用）。 */
    fun fieldsFor(type: String): List<FieldSpec> = buildList {
        addAll(basic)
        addAll(auth(type))
        if (type in listOf("vless", "vmess", "trojan", "shadowsocks")) addAll(transport)
        if (type != "socks5") addAll(tlsFields(type))
        addAll(advanced(type))
    }

    /** 新建节点时的默认值。 */
    fun defaults(type: String): Map<String, String> = buildMap {
        put(K_TYPE, type)
        put(K_PORT, if (type == "socks5") "1080" else "443")
        if (type in listOf("vless", "vmess", "trojan", "shadowsocks")) put(K_NETWORK, "tcp")
        when (type) {
            "vless", "trojan" -> put(K_TLS, "true")
            "vmess" -> {
                put(K_TLS, "true")
                put(K_CIPHER, "auto")
            }
            "shadowsocks" -> {
                put(K_TLS, "false")
                put(K_CIPHER, "aes-256-gcm")
            }
            "tuic" -> put(K_CONGESTION, "cubic")
            // ant link.rs apply_tls 对 naive 默认 uTLS=chrome
            "naive" -> put(K_CLIENT_FP, "chrome")
            "shadowquic" -> {
                put(K_ALPN, "h3")
                put(K_CONGESTION, "bbr")
                put(K_ZERO_RTT, "true")
                put(K_OVER_STREAM, "false")
            }
        }
    }

    /** 校验，返回错误文案，null 表示通过。 */
    fun validate(node: ProxyNode): String? {
        val f = node.fields
        if (f[K_NAME].isNullOrBlank()) return "请填写节点名称"
        if (f[K_TYPE].isNullOrBlank()) return "请选择协议"
        if (f[K_SERVER].isNullOrBlank()) return "请填写服务器地址"
        val port = f[K_PORT]?.toIntOrNull()
        if (port == null || port !in 1..65535) return "端口需为 1 – 65535 的数字"
        for (spec in fieldsFor(f[K_TYPE].orEmpty())) {
            if (spec.required && f[spec.key].isNullOrBlank() && spec.showIf(f)) {
                return "请填写「${spec.label}」"
            }
        }
        return null
    }

    /**
     * 生成 config.yaml 的 `proxies:` 段（只输出非空且当前条件可见的字段）。
     * @param nameOverride 非空时作为写进配置的 `name`（节点本身的名称不变）。
     */
    fun renderProxies(node: ProxyNode, nameOverride: String? = null): String {
        val f = node.fields
        val sb = StringBuilder()
        sb.append("proxies:\n")
        sb.append("  - ").append(K_NAME).append(": ").append(yamlScalar(nameOverride ?: f[K_NAME].orEmpty())).append('\n')
        sb.append("    ").append(K_TYPE).append(": ").append(f[K_TYPE].orEmpty()).append('\n')
        sb.append("    ").append(K_SERVER).append(": ").append(yamlScalar(f[K_SERVER].orEmpty())).append('\n')
        sb.append("    ").append(K_PORT).append(": ").append(f[K_PORT]?.toIntOrNull() ?: 443).append('\n')
        // name / type / server / port 已在上面按固定顺序输出，避免 YAML 重复键
        val alreadyWritten = setOf(K_NAME, K_TYPE, K_SERVER, K_PORT)
        for (spec in fieldsFor(f[K_TYPE].orEmpty())) {
            if (spec.key in alreadyWritten) continue
            val value = f[spec.key].orEmpty()
            if (value.isBlank() || !spec.showIf(f)) continue
            val rendered = when {
                spec.kind == FieldKind.TOGGLE -> (value == "true").toString()
                spec.kind == FieldKind.NUMBER -> (value.toIntOrNull() ?: 0).toString()
                spec.key == K_ALPN -> value.split(',', '，')
                    .map { it.trim() }.filter { it.isNotEmpty() }
                    .joinToString(", ", prefix = "[", postfix = "]") { yamlScalar(it) }
                else -> yamlScalar(value)
            }
            sb.append("    ").append(spec.key).append(": ").append(rendered).append('\n')
        }
        return sb.toString()
    }

    /** YAML 双引号标量，转义反斜杠、双引号与换行，避免密码/URL 里的特殊字符破坏语法。 */
    fun yamlScalar(value: String): String {
        val escaped = value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        return "\"$escaped\""
    }
}
