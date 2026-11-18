package com.ant.proxy

import android.content.Context
import android.util.Log
import java.io.File

/**
 * 路由页状态持久化：应用私有目录 routes.json。
 * 规则与规则集放在同一个文件里，读写/重置默认都只需一次 IO。
 */
object RouteStore {

    private const val TAG = "RouteStore"
    const val FILE_NAME = "routes.json"

    fun file(context: Context): File = File(context.filesDir, FILE_NAME)

    fun load(context: Context): RouteState {
        val f = file(context)
        if (!f.exists()) return RouteState()
        return try {
            RouteJson.decode(f.readText())
        } catch (e: Exception) {
            Log.e(TAG, "load routes failed", e)
            RouteState()
        }
    }

    /** 原子写：先写临时文件再 rename，避免中途被杀导致配置损坏。 */
    fun save(context: Context, state: RouteState): RouteState {
        val next = state.normalized()
        return try {
            val target = file(context)
            val tmp = File(target.parentFile, "$FILE_NAME.tmp")
            tmp.writeText(RouteJson.encode(next))
            if (!tmp.renameTo(target)) {
                target.writeText(RouteJson.encode(next))
                tmp.delete()
            }
            next
        } catch (e: Exception) {
            Log.e(TAG, "save routes failed", e)
            next
        }
    }

    /** 恢复成 afa 默认的「国内域名 / 国内 IP 直连 + 兜底代理」。 */
    fun reset(context: Context): RouteState = save(context, RouteState())
}
