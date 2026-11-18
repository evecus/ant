package com.ant.proxy

import java.io.File

/**
 * `config.yaml` 的 route: / rule-providers: 两段渲染器（纯 Kotlin）。
 *
 * 与旧模板的区别：模板里不再有任何写死的规则，两段完全由路由页的 [RouteState]
 * 生成。渲染前先 [validate] 做 fail-fast 校验，避免把 ant 启动时才会报错的
 * 配置写出去（MATCH 缺失、引用不存在的规则集、值里带逗号等）。
 */
object RouteConfigRenderer {

    /**
     * 启动前校验，返回错误文案；null 表示通过。
     * @param filesDir 应用私有目录，用于确认本地规则集文件已就绪。
     */
    fun validate(state: RouteState, filesDir: String): String? {
        val rules = state.rules
        val matchCount = rules.count { it.isFinal }
        if (matchCount == 0) return "缺少兜底规则（MATCH），ant 会拒绝启动"
        if (matchCount > 1) return "只能有一条兜底规则（MATCH）"
        if (!rules.last().isFinal) return "兜底规则（MATCH）必须是最后一条"
        if (!rules.last().enabled) return "兜底规则不能关闭"

        val setIds = state.ruleSets.map { it.id }.toSet()
        if (setIds.size != state.ruleSets.size) return "规则集标识（id）重复"
        if (state.ruleSets.any { it.id.isBlank() }) return "存在未命名（空 id）的规则集"

        for ((i, r) in rules.withIndex()) {
            if (r.isFinal) continue
            if (r.name.isBlank()) return "第 ${i + 1} 条规则未填写名称"
            if (r.value.isBlank()) return "「${r.name}」未填写匹配值"
            if (r.value.contains(',') || r.value.contains('\n') || r.value.contains('\r')) {
                return "「${r.name}」的匹配值不能包含逗号或换行（ant 按逗号分隔规则字段）"
            }
            if (r.type == RouteMatchType.RULE_SET && r.value !in setIds) {
                return "「${r.name}」引用的规则集「${r.value}」不存在，请先删除该规则或重新添加规则集"
            }
        }

        for (s in state.ruleSets) {
            if (s.isRemote) {
                if (!s.url.startsWith("http://") && !s.url.startsWith("https://")) {
                    return "规则集「${s.name}」的订阅地址必须以 http:// 或 https:// 开头"
                }
                if (s.updateInterval < 0) return "规则集「${s.name}」的更新间隔不能为负数"
            } else {
                if (s.fileName.isBlank()) return "规则集「${s.name}」缺少本地文件"
                val f = File(File(filesDir, RULES_DIR_NAME), s.fileName)
                if (!f.isFile()) {
                    return "规则集「${s.name}」的文件缺失（${f.name}），请重新导入或重启应用"
                }
            }
        }
        return null
    }

    /** 生成 rule-providers: 段。所有 path 都写成应用私有目录的绝对路径。 */
    fun renderRuleProviders(state: RouteState, filesDir: String): String {
        if (state.ruleSets.isEmpty()) return "rule-providers: {}"
        val sb = StringBuilder("rule-providers:\n")
        for (s in state.ruleSets) {
            val path = File(File(filesDir, RULES_DIR_NAME), s.fileName).absolutePath
            sb.append("  ").append(NodeSchema.yamlScalar(s.id)).append(":\n")
            sb.append("    type: ").append(if (s.isRemote) "http" else "file").append('\n')
            sb.append("    behavior: ").append(s.behavior.wire).append('\n')
            sb.append("    path: ").append(NodeSchema.yamlScalar(path)).append('\n')
            if (s.isRemote) {
                sb.append("    url: ").append(NodeSchema.yamlScalar(s.url)).append('\n')
                if (s.updateInterval > 0) {
                    sb.append("    update-interval: ").append(s.updateInterval).append('\n')
                }
            }
            if (s.format.isNotBlank()) {
                sb.append("    format: ").append(s.format).append('\n')
            }
        }
        return sb.toString().trimEnd('\n')
    }

    /**
     * 生成 route: 段。只输出启用的规则，MATCH 兜底永远输出且永远在最后。
     * 「代理」动作写成 `PROXY`：ConfigManager 把选中节点在 proxies 里的 name 固定为
     * [RouteAction.PROXY].wire，所以这里不需要 proxy-group，也不依赖用户起的节点名。
     * 整行用双引号标量包住，避免值里的 `#` / `:` 破坏 YAML。
     */
    fun renderRoute(state: RouteState): String {
        val sb = StringBuilder("route:\n")
        for (r in state.rules) {
            if (!r.enabled && !r.isFinal) continue
            val line = if (r.isFinal) {
                "MATCH,${r.action.wire}"
            } else {
                buildString {
                    append(r.type.wire).append(',').append(r.value).append(',').append(r.action.wire)
                    if (r.noResolve && r.type.supportsNoResolve) append(",no-resolve")
                }
            }
            sb.append("  - ").append(NodeSchema.yamlScalar(line)).append('\n')
        }
        return sb.toString().trimEnd('\n')
    }
}
