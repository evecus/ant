package com.ant.proxy

import org.json.JSONArray
import org.json.JSONObject

/**
 * routes.json 编解码（纯 Kotlin + Android 平台内置的 org.json，零新增依赖）。
 * 与 NodeStore 一致：解析失败或字段缺失时回落到默认状态，再由 [RouteState.normalized]
 * 补齐兜底规则与内置规则集。
 */
object RouteJson {

    private const val K_VERSION = "version"
    private const val K_RULES = "rules"
    private const val K_RULE_SETS = "ruleSets"

    private const val R_ID = "id"
    private const val R_NAME = "name"
    private const val R_ENABLED = "enabled"
    private const val R_TYPE = "type"
    private const val R_VALUE = "value"
    private const val R_ACTION = "action"
    private const val R_NO_RESOLVE = "noResolve"

    private const val S_ID = "id"
    private const val S_NAME = "name"
    private const val S_BEHAVIOR = "behavior"
    private const val S_SOURCE = "source"
    private const val S_URL = "url"
    private const val S_FORMAT = "format"
    private const val S_INTERVAL = "updateInterval"
    private const val S_FILE = "fileName"
    private const val S_BUILTIN = "builtin"

    fun encode(state: RouteState): String {
        val rules = JSONArray()
        state.rules.forEach { r ->
            rules.put(
                JSONObject()
                    .put(R_ID, r.id)
                    .put(R_NAME, r.name)
                    .put(R_ENABLED, r.enabled)
                    .put(R_TYPE, r.type.wire)
                    .put(R_VALUE, r.value)
                    .put(R_ACTION, r.action.wire)
                    .put(R_NO_RESOLVE, r.noResolve)
            )
        }
        val sets = JSONArray()
        state.ruleSets.forEach { s ->
            sets.put(
                JSONObject()
                    .put(S_ID, s.id)
                    .put(S_NAME, s.name)
                    .put(S_BEHAVIOR, s.behavior.wire)
                    .put(S_SOURCE, s.source.name)
                    .put(S_URL, s.url)
                    .put(S_FORMAT, s.format)
                    .put(S_INTERVAL, s.updateInterval)
                    .put(S_FILE, s.fileName)
                    .put(S_BUILTIN, s.builtin)
            )
        }
        return JSONObject()
            .put(K_VERSION, 1)
            .put(K_RULES, rules)
            .put(K_RULE_SETS, sets)
            .toString()
    }

    fun decode(text: String): RouteState = try {
        val root = JSONObject(text)
        val rulesArr = root.optJSONArray(K_RULES)
        val setsArr = root.optJSONArray(K_RULE_SETS)
        // 两个数组都缺失视为首次运行 / 空文件 → 默认状态
        if (rulesArr == null && setsArr == null) {
            RouteState()
        } else {
            val rules = (0 until (rulesArr?.length() ?: 0)).mapNotNull { i ->
                val o = rulesArr?.optJSONObject(i) ?: return@mapNotNull null
                val id = o.optString(R_ID).ifBlank { return@mapNotNull null }
                RouteRule(
                    id = id,
                    name = o.optString(R_NAME),
                    enabled = o.optBoolean(R_ENABLED, true),
                    type = RouteMatchType.entries.firstOrNull { it.wire == o.optString(R_TYPE) }
                        ?: RouteMatchType.RULE_SET,
                    value = o.optString(R_VALUE),
                    action = RouteAction.entries.firstOrNull { it.wire == o.optString(R_ACTION) }
                        ?: RouteAction.PROXY,
                    noResolve = o.optBoolean(R_NO_RESOLVE, false)
                )
            }
            val sets = (0 until (setsArr?.length() ?: 0)).mapNotNull { i ->
                val o = setsArr?.optJSONObject(i) ?: return@mapNotNull null
                val id = o.optString(S_ID).ifBlank { return@mapNotNull null }
                RuleSetItem(
                    id = id,
                    name = o.optString(S_NAME),
                    behavior = RuleSetBehavior.entries.firstOrNull {
                        it.wire == o.optString(S_BEHAVIOR)
                    } ?: RuleSetBehavior.DOMAIN,
                    source = RuleSetSource.entries.firstOrNull { it.name == o.optString(S_SOURCE) }
                        ?: RuleSetSource.FILE,
                    url = o.optString(S_URL),
                    format = o.optString(S_FORMAT),
                    updateInterval = o.optInt(S_INTERVAL, 24),
                    fileName = o.optString(S_FILE),
                    builtin = o.optBoolean(S_BUILTIN, false)
                )
            }
            RouteState(rules, sets).normalized()
        }
    } catch (_: Exception) {
        RouteState()
    }
}
