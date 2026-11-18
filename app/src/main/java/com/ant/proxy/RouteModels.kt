package com.ant.proxy

import java.util.UUID

/**
 * 路由页的数据模型（纯 Kotlin，不依赖 Android）。
 *
 * 设计约束：
 *  1. 条件类型严格限定为 ant `src/config.rs::parse_rule_line` 支持的 7 种 + MATCH 兜底，
 *     不暴露端口 / network / 按应用等内核不支持的字段。
 *  2. 动作只有「代理 / 绕过 / 屏蔽」三选一，分别映射到 PROXY（proxies 里选中节点的固定 name）/ DIRECT / BLOCK。
 *  3. `config.yaml` 的 route: 与 rule-providers: 两段完全由本模型渲染，
 *     模板里不再写死任何规则——路由页上看到的几条，就是生效的几条。
 */

/** 兜底规则的固定 id：不可删除、不可关闭、不可移动，只能改名称与动作。 */
const val FINAL_RULE_ID = "match"
const val BUILTIN_GEOSITE_CN = "geosite-cn"
const val BUILTIN_GEOIP_CN = "geoip-cn"

/** 规则集存放目录（应用 filesDir 下），assets 释放、导入、生成 path 共用。 */
const val RULES_DIR_NAME = "rules"

/** 匹配条件类型。`wire` 即写进 route: 行的关键字。 */
enum class RouteMatchType(val wire: String, val label: String, val hint: String) {
    DOMAIN("DOMAIN", "域名精确", "example.com"),
    DOMAIN_SUFFIX("DOMAIN-SUFFIX", "域名后缀", "google.com"),
    DOMAIN_KEYWORD("DOMAIN-KEYWORD", "域名关键字", "ads"),
    DOMAIN_REGEX("DOMAIN-REGEX", "域名正则", "^.*\\.cn$"),
    IP_CIDR("IP-CIDR", "目标 IP / CIDR", "10.0.0.0/8"),
    SRC_IP_CIDR("SRC-IP-CIDR", "源 IP / CIDR", "192.168.1.0/24"),
    RULE_SET("RULE-SET", "规则集", "从已添加的规则集中选择"),
    MATCH("MATCH", "兜底（全部流量）", "无需填写");

    /** 该类型是否可以追加 `,no-resolve`（仅 IP 类规则有意义）。 */
    val supportsNoResolve: Boolean
        get() = this == IP_CIDR || this == SRC_IP_CIDR || this == RULE_SET
}

/** 动作。`wire` 即 ant route 行的出站名；PROXY 是 ConfigManager 写进 proxies 的固定节点名。 */
enum class RouteAction(val wire: String, val label: String) {
    PROXY("PROXY", "代理"),
    DIRECT("DIRECT", "绕过"),
    BLOCK("BLOCK", "屏蔽")
}

data class RouteRule(
    val id: String = UUID.randomUUID().toString(),
    val name: String = "",
    val enabled: Boolean = true,
    val type: RouteMatchType = RouteMatchType.RULE_SET,
    val value: String = "",
    val action: RouteAction = RouteAction.PROXY,
    val noResolve: Boolean = false
) {
    val isFinal: Boolean get() = type == RouteMatchType.MATCH

    /** 列表/卡片上的条件摘要；RULE-SET 显示规则集名称而不是内部 id。 */
    fun conditionText(ruleSets: List<RuleSetItem>): String = when (type) {
        RouteMatchType.MATCH -> "MATCH（未命中以上规则的全部流量）"
        RouteMatchType.RULE_SET -> {
            val display = ruleSets.firstOrNull { it.id == value }?.name ?: value
            "${type.wire},$value  ·  $display"
        }
        else -> "${type.wire},$value"
    }
}

/** 规则集 behavior，与 ant `rule-providers.behavior` 对齐。 */
enum class RuleSetBehavior(val wire: String, val label: String) {
    DOMAIN("domain", "域名"),
    IP("ip", "IP / CIDR"),
    CLASSICAL("classical", "混合（classical）")
}

/** 规则集来源。BUILTIN / FILE 生成 `type: file`，URL 生成 `type: http`。 */
enum class RuleSetSource(val label: String) {
    BUILTIN("内置"),
    FILE("本地文件"),
    URL("URL 订阅")
}

/** 可选 format；空串表示不写 format，交给 ant 按内容/扩展名自动识别。 */
val RULESET_FORMATS = listOf("", "ars", "yaml", "json", "text")

data class RuleSetItem(
    val id: String = "rs-" + UUID.randomUUID().toString().take(8),
    val name: String = "",
    val behavior: RuleSetBehavior = RuleSetBehavior.DOMAIN,
    val source: RuleSetSource = RuleSetSource.FILE,
    val url: String = "",
    val format: String = "",
    /** `update-interval`，单位小时；0 = 不自动更新，仅手动刷新。 */
    val updateInterval: Int = 24,
    /** files/rules/ 下的文件名，内置项与 assets 一致。 */
    val fileName: String = "",
    val builtin: Boolean = false
) {
    val isRemote: Boolean get() = source == RuleSetSource.URL
}

/** afa 原有「绕过大陆」模板的 3 条规则，作为默认规则。 */
fun defaultFinalRule(): RouteRule = RouteRule(
    id = FINAL_RULE_ID,
    name = "兜底：其余走代理",
    type = RouteMatchType.MATCH,
    value = "",
    action = RouteAction.PROXY
)

fun defaultRules(): List<RouteRule> = listOf(
    RouteRule(
        id = "default-cn-domain",
        name = "国内域名直连",
        type = RouteMatchType.RULE_SET,
        value = BUILTIN_GEOSITE_CN,
        action = RouteAction.DIRECT
    ),
    RouteRule(
        id = "default-cn-ip",
        name = "国内 IP 直连",
        type = RouteMatchType.RULE_SET,
        value = BUILTIN_GEOIP_CN,
        action = RouteAction.DIRECT,
        noResolve = true
    ),
    defaultFinalRule()
)

fun builtinRuleSets(): List<RuleSetItem> = listOf(
    RuleSetItem(
        id = BUILTIN_GEOSITE_CN,
        name = "中国域名规则集",
        behavior = RuleSetBehavior.DOMAIN,
        source = RuleSetSource.BUILTIN,
        format = "ars",
        fileName = "geosite-cn.ars",
        builtin = true
    ),
    RuleSetItem(
        id = BUILTIN_GEOIP_CN,
        name = "中国 IP 规则集",
        behavior = RuleSetBehavior.IP,
        source = RuleSetSource.BUILTIN,
        format = "ars",
        fileName = "geoip-cn.ars",
        builtin = true
    )
)

/**
 * 路由页的完整状态：规则列表 + 规则集列表，统一存 routes.json。
 * [normalized] 保证不变量：有且仅有一条 MATCH 且在最后、内置规则集始终存在。
 */
data class RouteState(
    val rules: List<RouteRule> = defaultRules(),
    val ruleSets: List<RuleSetItem> = builtinRuleSets()
) {
    val finalRule: RouteRule
        get() = rules.lastOrNull { it.isFinal } ?: defaultFinalRule()

    fun normalized(): RouteState {
        val others = rules.filterNot { it.isFinal }
        val final = (rules.firstOrNull { it.isFinal } ?: defaultFinalRule())
            .copy(enabled = true, value = "", type = RouteMatchType.MATCH)
        val restored = builtinRuleSets().filter { b -> ruleSets.none { it.id == b.id } }
        return RouteState(others + final, ruleSets + restored)
    }
}
