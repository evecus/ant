package com.ant.proxy

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * 规则集文件操作：内置释放、本地文件导入、URL 订阅刷新、删除与状态查询。
 *
 * URL 订阅不在 App 里下载：配置生成 `type: http` + 绝对 path，由 ant 在启动时
 * （或按 update-interval）拉取。运行中「刷新」走 ant 的
 * `PUT /providers/rules/{name}` 热更新；未运行时删掉缓存，下次启动重新下载。
 */
object RuleSetManager {

    fun rulesDir(context: Context): File = File(context.filesDir, RULES_DIR_NAME)

    fun fileOf(context: Context, item: RuleSetItem): File =
        File(rulesDir(context), item.fileName)

    fun newId(): String = "rs-" + java.util.UUID.randomUUID().toString().take(8)

    /** 从文件名 / URL 路径取扩展名，未知一律按 text 处理。 */
    fun extOf(nameOrUrl: String): String {
        val path = nameOrUrl.substringBefore('?').substringBefore('#')
        val raw = path.substringAfterLast('.', "").lowercase()
        return when (raw) {
            "ars" -> "ars"
            "yaml", "yml" -> "yaml"
            "json" -> "json"
            "txt", "list", "conf" -> "txt"
            else -> "txt"
        }
    }

    /** ant rule-providers.format 的可选值；空串表示不写、由内核自动识别。 */
    fun formatOf(ext: String): String = when (ext) {
        "ars" -> "ars"
        "yaml" -> "yaml"
        "json" -> "json"
        else -> "text"
    }

    fun fileNameFor(id: String, ext: String): String = "$id.$ext"

    fun displayNameOf(context: Context, uri: Uri): String = try {
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        } ?: "ruleset.txt"
    } catch (_: Exception) {
        "ruleset.txt"
    }

    /** 把 SAF 选择的文件复制进 files/rules/。成功返回 null，失败返回错误说明。 */
    fun importFile(context: Context, uri: Uri, item: RuleSetItem): String? {
        val dir = rulesDir(context)
        dir.mkdirs()
        val dest = fileOf(context, item)
        return try {
            val input = context.contentResolver.openInputStream(uri)
            if (input == null) {
                "无法读取所选文件"
            } else {
                input.use { source ->
                    dest.outputStream().use { output -> source.copyTo(output) }
                }
                if (dest.length() == 0L) {
                    dest.delete()
                    "所选文件为空"
                } else {
                    null
                }
            }
        } catch (e: Exception) {
            "导入失败：${e.message}"
        }
    }

    fun deleteFile(context: Context, item: RuleSetItem) {
        if (item.builtin) return
        runCatching { fileOf(context, item).delete() }
    }

    /** 管理页显示的文件状态。 */
    fun status(context: Context, item: RuleSetItem): String {
        val f = fileOf(context, item)
        if (f.isFile()) return "已就绪 · ${"%.1f".format(f.length() / 1024.0)} KB"
        return if (item.isRemote) "待下载 · 启动 VPN 后拉取" else "文件缺失 · 请重新导入"
    }

    /**
     * 刷新 URL 订阅：运行中调用 ant API 立即重新下载并热更新；
     * 未运行或 API 不可用时删除本地缓存，下次启动重新下载。
     */
    suspend fun refresh(context: Context, item: RuleSetItem): String = withContext(Dispatchers.IO) {
        if (!item.isRemote) return@withContext "本地文件规则集无需刷新"
        // API 关闭时没有热更新接口，不做无谓的 HTTP 请求，直接退回下次启动重下
        if (!SettingsStore.apiEnabled(context)) {
            runCatching { fileOf(context, item).delete() }
            return@withContext "API 未启用：「${item.name}」将在下次启动 VPN 时重新下载"
        }
        if (AntVpnService.isRunning) {
            val endpoint = "${SettingsStore.apiBaseUrl(context)}/providers/rules/${URLEncoder.encode(item.id, "UTF-8")}"
            try {
                val conn = URL(endpoint).openConnection() as HttpURLConnection
                conn.requestMethod = "PUT"
                conn.connectTimeout = 3000
                conn.readTimeout = 15000
                val code = conn.responseCode
                conn.disconnect()
                if (code in 200..299) {
                    return@withContext "已刷新「${item.name}」（运行中热更新）"
                }
            } catch (_: Exception) {
                // 落到下面的「删缓存、下次启动重新下载」
            }
        }
        runCatching { fileOf(context, item).delete() }
        "「${item.name}」将在下次启动 VPN 时重新下载"
    }
}
