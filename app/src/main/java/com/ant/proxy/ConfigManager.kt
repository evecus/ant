package com.ant.proxy

import android.content.Context
import android.util.Base64
import android.util.Log
import java.io.File

/**
 * 内置配置 / 规则集管理。
 *
 * 应用完全接管 config.yaml 的生成：
 *  1. assets/config-template.yaml（绕过大陆模板，geosite-cn / geoip-cn 直连，其余走 PROXY 组）
 *  2. assets/rules 下的 .ars 规则集（版本变化时释放到 files/rules）
 *  3. 用户只导入节点分享链接（vless:// 等），写入 files/providers/nodes.txt，
 *     作为 type: file 的 proxy-provider 引用。
 */
object ConfigManager {

    private const val TAG = "ConfigManager"

    const val TEMPLATE_NAME = "config-template.yaml"
    const val RULES_ASSET_DIR = "rules"
    const val RULES_DIR = "rules"
    const val PROVIDERS_DIR = "providers"
    const val NODES_NAME = "nodes.txt"

    /** 资源版本：内置模板 / 规则集更新后 +1，触发重新释放 */
    private const val ASSETS_VERSION = 1
    private const val PREFS_NAME = "config_assets"
    private const val KEY_ASSETS_VERSION = "assets_version"

    /** ant 可识别的节点分享链接 scheme */
    private val NODE_SCHEMES = listOf(
        "vless://", "vmess://", "ss://", "trojan://",
        "hysteria2://", "hy2://", "tuic://", "anytls://",
        "naive://", "shadowquic://", "spectre://", "wireguard://",
        "socks5://", "socks4://", "socks://"
    )

    fun nodesFile(context: Context): File =
        File(File(context.filesDir, PROVIDERS_DIR).apply { mkdirs() }, NODES_NAME)

    fun rulesDir(context: Context): File =
        File(context.filesDir, RULES_DIR)

    // ---------------------------------------------------------------- nodes

    /** 当前已导入的节点条数 */
    fun nodeCount(context: Context): Int {
        val f = nodesFile(context)
        if (!f.exists()) return 0
        return f.readText().lineSequence().count { it.isNotBlank() }
    }

    /**
     * 导入节点分享链接（覆盖模式）。
     * 支持多行粘贴；若一行都没有有效 scheme，会尝试整体 base64 解码后重新识别
     * （兼容经典订阅 blob）。返回成功写入的节点条数。
     */
    fun importNodeLinks(context: Context, raw: String): Int {
        var links = extractLinks(raw)
        if (links.isEmpty()) {
            links = tryBase64Decode(raw)?.let { extractLinks(it) } ?: emptyList()
        }
        if (links.isEmpty()) return 0
        nodesFile(context).writeText(links.joinToString("\n", postfix = "\n"))
        Log.i(TAG, "imported ${links.size} node links")
        return links.size
    }

    /** 清空已导入节点 */
    fun clearNodes(context: Context) {
        nodesFile(context).delete()
    }

    private fun extractLinks(text: String): List<String> =
        text.lineSequence()
            .map { it.trim() }
            .filter { line -> NODE_SCHEMES.any { line.startsWith(it, ignoreCase = true) } }
            .distinct()
            .toList()

    private fun tryBase64Decode(text: String): String? = try {
        val cleaned = text.replace("\n", "").replace("\r", "").replace(" ", "")
        if (cleaned.isEmpty()) null
        else String(Base64.decode(cleaned, Base64.DEFAULT))
    } catch (_: Exception) {
        null
    }

    // ---------------------------------------------------------------- assets

    /**
     * 释放内置规则集到 files/rules（版本变化时覆盖）。
     * @return 规则文件是否就绪
     */
    fun ensureAssets(context: Context, onLog: (String) -> Unit): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val applied = prefs.getInt(KEY_ASSETS_VERSION, 0)
        val rulesDir = rulesDir(context)
        if (applied == ASSETS_VERSION && rulesDir.listFiles()?.isNotEmpty() == true) return true

        try {
            rulesDir.mkdirs()
            val names = context.assets.list(RULES_ASSET_DIR) ?: emptyArray()
            for (name in names) {
                context.assets.open("$RULES_ASSET_DIR/$name").use { input ->
                    File(rulesDir, name).outputStream().use { output -> input.copyTo(output) }
                }
                onLog("已释放内置规则集：$name")
            }
            prefs.edit().putInt(KEY_ASSETS_VERSION, ASSETS_VERSION).apply()
            return true
        } catch (e: Exception) {
            Log.e(TAG, "extract rules failed", e)
            onLog("错误：释放内置规则集失败：${e.message}")
            return false
        }
    }

    // ---------------------------------------------------------------- config

    /**
     * 从内置模板生成 config.yaml（每次启动都重新生成，保证与应用状态一致）。
     * 有节点 → 注入 proxy-providers 与 PROXY 组的 use: [nodes]；
     * 无节点 → PROXY 组回落为 DIRECT。
     */
    fun regenerateConfig(context: Context, onLog: (String) -> Unit): Boolean {
        return try {
            val template = context.assets.open(TEMPLATE_NAME).bufferedReader().use { it.readText() }

            val count = nodeCount(context)
            val hasNodes = count > 0

            var yaml = template
                .replace("__FILES_DIR__", context.filesDir.absolutePath)
                .replace("    # __USE_NODES__\n", if (hasNodes) "    use:\n      - nodes\n" else "")
                .replace("# __PROXY_PROVIDER__\n", if (hasNodes) providerBlock(context) else "")

            File(context.filesDir, AntProcessManager.CONFIG_NAME).writeText(yaml)
            onLog(if (hasNodes) "已生成配置：绕过大陆（$count 个节点，geosite-cn/geoip-cn 直连）"
                  else "已生成配置：绕过大陆（未导入节点，全部 DIRECT）")
            true
        } catch (e: Exception) {
            Log.e(TAG, "regenerate config failed", e)
            onLog("错误：生成配置失败：${e.message}")
            false
        }
    }

    private fun providerBlock(context: Context): String =
        "proxy-providers:\n" +
        "  nodes:\n" +
        "    type: file\n" +
        "    path: ${nodesFile(context).absolutePath}\n"
}
