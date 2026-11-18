package com.ant.proxy

import android.content.Context

/** [PerAppSettings] 的 SharedPreferences 持久化，与其它设置共用 `settings` 表。 */
object PerAppStore {

    private fun prefs(context: Context) =
        context.getSharedPreferences(AntProcessManager.SETTINGS_NAME, Context.MODE_PRIVATE)

    fun load(context: Context): PerAppSettings {
        val p = prefs(context)
        val packages = p.getString(PerAppSettings.KEY_PACKAGES, null)
            ?.split(',')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.toSet()
            ?: emptySet()
        return PerAppSettings(
            mode = PerAppMode.fromKey(p.getString(PerAppSettings.KEY_MODE, null)),
            packages = packages
        )
    }

    fun save(context: Context, s: PerAppSettings) {
        prefs(context).edit()
            .putString(PerAppSettings.KEY_MODE, s.mode.key)
            .putString(PerAppSettings.KEY_PACKAGES, s.packages.sorted().joinToString(","))
            .apply()
    }
}
