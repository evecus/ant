package com.ant.proxy

/**
 * 设置页的「网络 / DNS / API」配置（纯 Kotlin，不依赖 Android，便于 JVM 验证）。
 *
 * 对应 config-template.yaml 的 `# @GLOBAL@` / `# @DNS@` 两个注入标记：模板里
 * 不再写死 `api:` 与 `dns:`，启动时由 [ConfigManager] 读取 [SettingsStore] 后
 * 用这里渲染的内容替换——设置页所见即生效配置。
 *
 * 字段名与 ant 的 config.yaml 严格对齐（已核对 src/config.rs 与 config.example.yaml）：
 *   - 顶层 `ipv6`（GlobalConfig，默认 true，afa 默认关闭）
 *   - 顶层 `api`（非空才启动 API 面板，main.rs 判断 trim().is_empty()；地址语法见 [parseApiAddress]）
 *   - `dns.mode`：redir-host | fakeip
 *   - `dns.direct-nameserver` / `dns.proxy-nameserver`：单个字符串，rule-follow-route=true 时必填
 *   - `dns.fakeip-range` / `fakeip6-range` / `fakeip-filter-mode` / `fakeip-filter`：fakeip 模式的强校验项
 *
 * fakeip 过滤的语义来自 ant `src/app/router.rs::use_fakeip`：
 *   - `fakeip-filter` 是 **rule-provider id 列表**（不是域名列表），运行时对每个域名调 rs.match_domain()
 *   - `blacklist`（默认）：命中规则集 → 真实 IP，未命中 → fake-ip
 *   - `whitelist`：命中规则集 → fake-ip，未命中 → 真实 IP
 *   - ant 校验（config.rs:2241-2247 / 2380-2393）：mode 必须是 blacklist/whitelist，
 *     whitelist 要求 filter 非空，且 filter 引用的规则集必须是 domain / classical 类型。
 */
data class AppSettings(
    val ipv6: Boolean = DEFAULT_IPV6,
    val dnsMode: String = DEFAULT_DNS_MODE,
    val directDns: String = DEFAULT_DIRECT_DNS,
    val proxyDns: String = DEFAULT_PROXY_DNS,
    val apiEnabled: Boolean = DEFAULT_API_ENABLED,
    /** API 面板监听地址（语法同 ant 的 `api:`）。仅 [apiEnabled] 时生效。 */
    val apiAddress: String = DEFAULT_API_ADDRESS,
    /** fakeip 过滤模式：blacklist | whitelist。仅 [dnsMode] == fakeip 时生效。 */
    val fakeipFilterMode: String = DEFAULT_FAKEIP_FILTER_MODE,
    /** fakeip 过滤引用的 rule-provider id 列表。仅 [dnsMode] == fakeip 时生效。 */
    val fakeipFilter: List<String> = DEFAULT_FAKEIP_FILTER
) {
    companion object {
        // SharedPreferences key（与 MTU / DNS_HIJACK / LOG_LEVEL 等历史 key 并存）
        const val KEY_IPV6 = "ipv6"
        const val KEY_DNS_MODE = "dns_mode"
        const val KEY_DIRECT_DNS = "direct_dns"
        const val KEY_PROXY_DNS = "proxy_dns"
        const val KEY_API_ENABLED = "api_enabled"
        const val KEY_API_ADDRESS = "api_address"
        const val KEY_FAKEIP_FILTER_MODE = "fakeip_filter_mode"
        /** 逗号分隔的 rule-provider id；空串表示「一个都没勾」，与 key 缺失（回落默认）区分。 */
        const val KEY_FAKEIP_FILTER = "fakeip_filter"

        /** 默认关闭：afa 的 VpnService 原本只建 IPv4 TUN，关闭时内核与 App 行为一致。 */
        const val DEFAULT_IPV6 = false
        const val DEFAULT_DNS_MODE = "redir-host"
        const val DEFAULT_DIRECT_DNS = "223.5.5.5:53"
        const val DEFAULT_PROXY_DNS = "https://1.1.1.1/dns-query"
        /** 默认启用，保持原有 127.0.0.1:9095 面板与规则集热更新可用。 */
        const val DEFAULT_API_ENABLED = true

        val DNS_MODES = listOf("redir-host", "fakeip")
        val FAKEIP_FILTER_MODES = listOf("blacklist", "whitelist")
        const val DEFAULT_FAKEIP_FILTER_MODE = "blacklist"
        /** 默认 blacklist + geosite-cn：国内域名返回真实 IP，其余返回 fake-ip。 */
        val DEFAULT_FAKEIP_FILTER = listOf(BUILTIN_GEOSITE_CN)

        /** API 面板默认监听地址；设置页可改，[RuleSetManager] 通过 [ApiEndpoint.baseUrl] 跟随。 */
        const val DEFAULT_API_ADDRESS = "127.0.0.1:9095"

        /**
         * 解析 API 监听地址，语法与 ant `app::api::parse_listen` 对齐：
         * `IPv4:port` / `[IPv6]:port` / `:port` / `port`（后两种默认 127.0.0.1）。
         * ant 不解析主机名，所以这里同样只接受 IP 字面量。非法返回 null。
         */
        fun parseApiAddress(raw: String): ApiEndpoint? {
            val s = raw.trim()
            if (s.isEmpty() || s.any { it.isWhitespace() }) return null
            fun port(t: String): Int? = t.takeIf { it.isNotEmpty() && it.all(Char::isDigit) && it.length <= 5 }
                ?.toIntOrNull()?.takeIf { it in 1..65535 }
            port(s)?.let { return ApiEndpoint("127.0.0.1", it) }
            if (s.startsWith(":")) return port(s.substring(1))?.let { ApiEndpoint("127.0.0.1", it) }
            if (s.startsWith("[")) {
                val end = s.indexOf("]:")
                if (end < 0) return null
                val host = s.substring(1, end)
                val p = port(s.substring(end + 2)) ?: return null
                // 含 ':' 的字符串按字面量解析，不会触发 DNS 查询
                if (!host.contains(':') || host.contains('%')) return null
                return try {
                    java.net.InetAddress.getByName(host)
                    ApiEndpoint(host, p)
                } catch (_: Exception) { null }
            }
            val idx = s.lastIndexOf(':')
            if (idx <= 0) return null
            val host = s.substring(0, idx)
            val p = port(s.substring(idx + 1)) ?: return null
            val octets = host.split('.')
            val ok = octets.size == 4 && octets.all { o ->
                o.isNotEmpty() && o.length <= 3 && o.all(Char::isDigit) && o.toInt() in 0..255
            }
            return if (ok) ApiEndpoint(host, p) else null
        }

        /** IPv6 TUN 地址：取 ant/sing-tun 默认值，必须与 VpnService.Builder 配的完全相同。 */
        const val TUN_V6_ADDRESS = "fdfe:dcba:9876::1"
        const val TUN_V6_PREFIX = 126

        /**
         * DNS bootstrap（必须纯 IP），固定不暴露给用户。
         * 不配置 `dns.port`：ant 进入「仅劫持」模式，只通过 tun.dns-hijack 在 TUN 内应答，
         * 不监听任何本地 DNS 端口（纯 VPN 场景下没有进程会去连它）。
         */
        const val DEFAULT_NAMESERVER = "223.5.5.5:53"
        const val FAKEIP_RANGE = "198.18.0.0/15"
        const val FAKEIP6_RANGE = "fc00::/18"

        private val NAMESERVER_SCHEMES = setOf("udp", "tcp", "tls", "https")
    }

    /**
     * 启动前 / 保存前的 fail-fast 校验，返回错误文案；null 表示通过。
     *
     * @param ruleSets 路由页当前的规则集列表，用于核对 fakeip-filter 引用的 id
     *                 确实存在且是 domain / classical 类型（ant 对 IP 类直接拒绝启动）。
     *                 redir-host 时 fakeip-filter 不会写进配置，故跳过这部分校验，
     *                 避免切回 redir-host 后被历史引用卡住无法保存。
     */
    fun validate(ruleSets: List<RuleSetItem>): String? {
        if (dnsMode !in DNS_MODES) return "DNS 模式只能是 redir-host 或 fakeip"
        val direct = directDns.trim()
        val proxy = proxyDns.trim()
        if (direct.isEmpty()) return "直连 DNS 不能为空（rule-follow-route=true 时必填）"
        if (proxy.isEmpty()) return "代理 DNS 不能为空（rule-follow-route=true 时必填）"
        validateNameserver("直连 DNS", direct)?.let { return it }
        validateNameserver("代理 DNS", proxy)?.let { return it }

        if (apiEnabled && parseApiAddress(apiAddress) == null) {
            return "API 地址格式无效：应为 IPv4:端口（如 127.0.0.1:9095）、[IPv6]:端口、:端口 或 端口；不支持主机名"
        }

        if (dnsMode != "fakeip") return null

        if (fakeipFilterMode !in FAKEIP_FILTER_MODES) {
            return "fakeip 过滤模式只能是 blacklist 或 whitelist"
        }
        if (fakeipFilterMode == "whitelist" && fakeipFilter.isEmpty()) {
            return "白名单模式必须至少勾选一个规则集（ant 会拒绝空的 fakeip-filter）"
        }
        for (id in fakeipFilter) {
            if (id.isBlank() || id.any { it.isWhitespace() } || id.contains(',') ||
                id.contains('\n') || id.contains('\r')
            ) {
                return "fakeip 过滤引用了非法规则集标识「$id」"
            }
            val rs = ruleSets.firstOrNull { it.id == id }
                ?: return "fakeip 过滤引用的规则集「$id」不存在，请到设置页取消勾选"
            if (rs.behavior == RuleSetBehavior.IP) {
                return "规则集「${rs.name}」是 IP 类，ant 只允许 domain / classical 用于 fakeip 过滤"
            }
        }
        return null
    }

    private fun validateNameserver(label: String, raw: String): String? {
        if (raw.any { it.isWhitespace() } || raw.contains(',') || raw.contains('\n')) {
            return "$label 不能包含空白、逗号或换行"
        }
        if (raw.contains("://")) {
            val scheme = raw.substringBefore("://").lowercase()
            if (scheme !in NAMESERVER_SCHEMES) {
                return "$label 只支持 udp / tcp / tls / https 协议"
            }
            if (raw.substringAfter("://").isBlank()) return "$label 缺少服务器地址"
        }
        return null
    }

    /** 渲染顶层 `ipv6:` 与 `api:`（关闭时省略 api 行，ant 默认空串即不启动）。 */
    fun renderGlobal(): String = buildString {
        append("ipv6: ").append(ipv6).append('\n')
        if (apiEnabled) {
            // validate() 已保证可解析；规范化后写入，`:port` / `port` 统一成 127.0.0.1:port
            val ep = parseApiAddress(apiAddress) ?: parseApiAddress(DEFAULT_API_ADDRESS)!!
            append("api: ").append(NodeSchema.yamlScalar(ep.listen)).append('\n')
        }
    }.trimEnd('\n')

    /** 渲染整个 `dns:` 段。 */
    fun renderDns(): String = buildString {
        append("dns:\n")
        append("  default-nameserver: ").append(NodeSchema.yamlScalar(DEFAULT_NAMESERVER)).append('\n')
        append("  rule-follow-route: true\n")
        append("  direct-nameserver: ").append(NodeSchema.yamlScalar(directDns.trim())).append('\n')
        append("  proxy-nameserver: ").append(NodeSchema.yamlScalar(proxyDns.trim())).append('\n')
        append("  mode: ").append(dnsMode).append('\n')
        // 单一 ipv6 开关同时控制 DNS AAAA，避免两个开关语义打架
        append("  ipv6: ").append(ipv6).append('\n')
        if (dnsMode == "fakeip") {
            // ant 校验：fakeip 必须提供 range，且 fakeip-filter-mode 默认空串会直接 fail-fast
            append("  fakeip-range: ").append(NodeSchema.yamlScalar(FAKEIP_RANGE)).append('\n')
            if (ipv6) {
                append("  fakeip6-range: ").append(NodeSchema.yamlScalar(FAKEIP6_RANGE)).append('\n')
            }
            append("  fakeip-filter-mode: ").append(fakeipFilterMode).append('\n')
            // ant 的 fakeip_filter 是 Vec<String>，写 YAML 序列，元素是 rule-provider id。
            // 空列表不写该行：ant 默认空 Vec，等价于「不引用任何规则集」。
            if (fakeipFilter.isNotEmpty()) {
                append("  fakeip-filter:\n")
                for (id in fakeipFilter) {
                    append("    - ").append(NodeSchema.yamlScalar(id)).append('\n')
                }
            }
        }
    }.trimEnd('\n')
}

/** 解析后的 API 监听端点。 */
data class ApiEndpoint(val host: String, val port: Int) {
    private val isV6 get() = host.contains(':')

    /** 写进 config.yaml 的 `api:` 值（IPv6 带方括号）。 */
    val listen: String get() = if (isV6) "[$host]:$port" else "$host:$port"

    /**
     * App 侧访问用的 base URL。监听在通配地址（0.0.0.0 / ::）时回环地址一定可达，
     * 所以客户端改连 127.0.0.1 / [::1]。
     */
    val baseUrl: String
        get() {
            val h = when (host) {
                "0.0.0.0" -> "127.0.0.1"
                "::", "0:0:0:0:0:0:0:0" -> "::1"
                else -> host
            }
            return if (h.contains(':')) "http://[$h]:$port" else "http://$h:$port"
        }
}
