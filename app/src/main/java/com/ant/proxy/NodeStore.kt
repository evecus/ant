package com.ant.proxy

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * 节点持久化：应用私有目录 nodes.json，零新增依赖（org.json 为 Android 平台内置）。
 * 节点数据完全由 App 持有，ant 不再通过 proxy-provider 解析任何分享链接。
 */
object NodeStore {

    private const val TAG = "NodeStore"
    private const val FILE_NAME = "nodes.json"
    private const val K_VERSION = "version"
    private const val K_SELECTED = "selected"
    private const val K_NODES = "nodes"
    private const val K_ID = "id"
    private const val K_FIELDS = "fields"

    data class State(
        val nodes: List<ProxyNode> = emptyList(),
        val selectedId: String? = null
    ) {
        val selected: ProxyNode?
            get() = nodes.firstOrNull { it.id == selectedId } ?: nodes.firstOrNull()
    }

    private fun file(context: Context): File = File(context.filesDir, FILE_NAME)

    fun load(context: Context): State {
        val f = file(context)
        if (!f.exists()) return State()
        return try {
            val root = JSONObject(f.readText())
            val arr = root.optJSONArray(K_NODES) ?: JSONArray()
            val nodes = (0 until arr.length()).mapNotNull { i ->
                val obj = arr.optJSONObject(i) ?: return@mapNotNull null
                val id = obj.optString(K_ID).ifBlank { return@mapNotNull null }
                val fieldsObj = obj.optJSONObject(K_FIELDS) ?: JSONObject()
                val fields = LinkedHashMap<String, String>()
                fieldsObj.keys().forEach { key -> fields[key] = fieldsObj.optString(key) }
                ProxyNode(id, fields)
            }
            State(nodes, root.optString(K_SELECTED).takeIf { it.isNotBlank() })
        } catch (e: Exception) {
            Log.e(TAG, "load nodes failed", e)
            State()
        }
    }

    fun save(context: Context, state: State) {
        try {
            val arr = JSONArray()
            state.nodes.forEach { node ->
                val fieldsObj = JSONObject()
                node.fields.forEach { (k, v) -> fieldsObj.put(k, v) }
                arr.put(JSONObject().put(K_ID, node.id).put(K_FIELDS, fieldsObj))
            }
            val root = JSONObject()
                .put(K_VERSION, 1)
                .put(K_SELECTED, state.selectedId ?: "")
                .put(K_NODES, arr)
            // 原子写：先写临时文件再 rename，避免中途被杀导致节点丢失
            val target = file(context)
            val tmp = File(target.parentFile, "$FILE_NAME.tmp")
            tmp.writeText(root.toString())
            if (!tmp.renameTo(target)) {
                target.writeText(root.toString())
                tmp.delete()
            }
        } catch (e: Exception) {
            Log.e(TAG, "save nodes failed", e)
        }
    }

    fun upsert(context: Context, node: ProxyNode): State {
        val state = load(context)
        val exists = state.nodes.any { it.id == node.id }
        val nodes = if (exists) state.nodes.map { if (it.id == node.id) node else it }
                    else state.nodes + node
        val selected = state.selectedId?.takeIf { id -> nodes.any { it.id == id } }
            ?: nodes.firstOrNull()?.id
        val next = State(nodes, selected)
        save(context, next)
        return next
    }

    fun addAll(context: Context, newNodes: List<ProxyNode>): State {
        val state = load(context)
        val nodes = state.nodes + newNodes
        val selected = state.selectedId?.takeIf { id -> nodes.any { it.id == id } }
            ?: nodes.firstOrNull()?.id
        val next = State(nodes, selected)
        save(context, next)
        return next
    }

    fun delete(context: Context, id: String): State {
        val state = load(context)
        val nodes = state.nodes.filterNot { it.id == id }
        val selected = state.selectedId?.takeIf { it != id && nodes.any { n -> n.id == it } }
            ?: nodes.firstOrNull()?.id
        val next = State(nodes, selected)
        save(context, next)
        return next
    }

    fun select(context: Context, id: String): State {
        val state = load(context)
        val next = state.copy(selectedId = id)
        save(context, next)
        return next
    }

    fun clear(context: Context): State {
        val next = State()
        save(context, next)
        return next
    }
}
