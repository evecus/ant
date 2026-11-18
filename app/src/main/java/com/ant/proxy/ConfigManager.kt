package com.ant.proxy

import android.content.Context
import android.util.Log
import java.io.File

/**
 * 内置配置 / 规则集管理。
 *
 * 与旧版的区别：节点不再以分享链接形式写入 nodes.txt 交给 ant 的
 * proxy-provider 解析。App 自己持有结构化节点（[NodeStore]），启动 VPN 时
 * 只取「当前选中的 1 个节点」，直接渲染成顶层 `proxies:` 段写入 config.yaml。
 *
 * `rule-providers:` 与 `route:` 两段不再写在模板里，而是由路由页的 [RouteStore]
 * 状态经 [RouteConfigRenderer] 渲染后注入——页面上看到的规则就是生效的规则。
 * assets/rules 下的内置规则集（geosite-cn / geoip-cn）仍由 [ensureAssets] 释放。
 */
object ConfigManager {

    private const val TAG = "ConfigManager"

    const val TEMPLATE_NAME = "config-template.yaml"
    const val RULES_ASSET_DIR = "rules"

    /** 资源版本：内置模板 / 规则集更新后 +1，触发重新释放 */
    private const val ASSETS_VERSION = 1
    private const val PREFS_NAME = "config_assets"
    private const val KEY_ASSETS_VERSION = "assets_version"

    fun rulesDir(context: Context): File = File(context.filesDir, RULES_DIR_NAME)

    /**
     * 释放内置规则集到 files/rules（版本变化时覆盖）。
     * @return 规则文件是否就绪
     */
    fun ensureAssets(context: Context, onLog: (String) -> Unit): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val applied = prefs.getInt(KEY_ASSETS_VERSION, 0)
        val dir = rulesDir(context)
        if (applied == ASSETS_VERSION && dir.listFiles()?.isNotEmpty() == true) return true

        return try {
            dir.mkdirs()
            val names = context.assets.list(RULES_ASSET_DIR) ?: emptyArray()
            for (name in names) {
                context.assets.open("$RULES_ASSET_DIR/$name").use { input ->
                    File(dir, name).outputStream().use { output -> input.copyTo(output) }
                }
                onLog("已释放内置规则集：$name")
            }
            prefs.edit().putInt(KEY_ASSETS_VERSION, ASSETS_VERSION).apply()
            true
        } catch (e: Exception) {
            Log.e(TAG, "extract rules failed", e)
            onLog("错误：释放内置规则集失败：${e.message}")
            false
        }
    }

    /**
     * 从内置模板生成 config.yaml（每次启动都重新生成，保证与 App 内选中节点、
     * 路由页规则一致）。不再生成 proxy-groups：选中节点写进 `proxies:` 时 name 固定为 `PROXY`，
     * 路由里的「代理」动作直接引用它，因此节点名里有逗号 / 空白 / 与 DIRECT 重名都不影响配置。
     * 没有节点时 proxies 为空，路由里的 PROXY 无出站（此时 App 会阻止启动）。
     *
     * 路由配置先做 fail-fast 校验：不合法就不写配置、不启动，避免把错误留到
     * ant 进程里才暴露。
     */
    fun regenerateConfig(context: Context, onLog: (String) -> Unit): Boolean {
        val filesDir = context.filesDir.absolutePath
        val routeState = RouteStore.load(context)
        val appSettings = SettingsStore.load(context)

        // fail-fast：设置 / 路由任一不合法就不写 config.yaml、不启动，
        // 避免把 ant 启动时才会报的错留到进程里暴露
        // fakeip-filter 引用的规则集必须存在且为域名类，故把路由页的规则集一并传入校验
        val settingsError = appSettings.validate(routeState.ruleSets)
        if (settingsError != null) {
            onLog("错误：设置无效：$settingsError")
            return false
        }
        val routeError = RouteConfigRenderer.validate(routeState, filesDir)
        if (routeError != null) {
            onLog("错误：路由配置无效：$routeError")
            return false
        }

        return try {
            val template = context.assets.open(TEMPLATE_NAME).bufferedReader().use { it.readText() }
            val node = NodeStore.load(context).selected

            val proxiesBlock = node?.let { NodeSchema.renderProxies(it, RouteAction.PROXY.wire).trimEnd('\n') }.orEmpty()
            // 注入标记必须唯一：模板注释里若出现这些字符串，替换会把说明文字拼进 YAML
            val yaml = template
                .replace("# @GLOBAL@", appSettings.renderGlobal())
                .replace("# @DNS@", appSettings.renderDns())
                .replace("# @PROXIES@", proxiesBlock)
                .replace(
                    "# @RULE_PROVIDERS@",
                    RouteConfigRenderer.renderRuleProviders(routeState, filesDir)
                )
                .replace("# @ROUTE@", RouteConfigRenderer.renderRoute(routeState))

            File(context.filesDir, AntProcessManager.CONFIG_NAME).writeText(yaml)
            val enabled = routeState.rules.count { it.enabled && !it.isFinal }
            onLog(
                (if (node != null) "已生成配置：${node.name}（${protocolDisplay(node.type)}）"
                 else "警告：未选择节点，路由中的 PROXY 无对应出站") +
                    " · 路由规则 ${enabled + 1} 条（含兜底）· 规则集 ${routeState.ruleSets.size} 个"
            )
            true
        } catch (e: Exception) {
            Log.e(TAG, "regenerate config failed", e)
            onLog("错误：生成配置失败：${e.message}")
            false
        }
    }
}
