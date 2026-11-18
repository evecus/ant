package com.ant.proxy

import android.content.Context

/**
 * [AppSettings] 的 SharedPreferences 持久化，与 MTU / DNS 劫持 / 日志级别共用
 * 同一个 `settings` 表（key 互不冲突）。
 */
object SettingsStore {

    private fun prefs(context: Context) =
        context.getSharedPreferences(AntProcessManager.SETTINGS_NAME, Context.MODE_PRIVATE)

    fun load(context: Context): AppSettings {
        val p = prefs(context)
        // key 缺失 → 回落默认（blacklist + geosite-cn）；key 存在但为空串 → 用户主动清空了勾选。
        val filter = p.getString(AppSettings.KEY_FAKEIP_FILTER, null)
            ?.split(',')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.distinct()
            ?: AppSettings.DEFAULT_FAKEIP_FILTER
        return AppSettings(
            ipv6 = p.getBoolean(AppSettings.KEY_IPV6, AppSettings.DEFAULT_IPV6),
            dnsMode = p.getString(AppSettings.KEY_DNS_MODE, AppSettings.DEFAULT_DNS_MODE)
                ?: AppSettings.DEFAULT_DNS_MODE,
            directDns = p.getString(AppSettings.KEY_DIRECT_DNS, AppSettings.DEFAULT_DIRECT_DNS)
                ?: AppSettings.DEFAULT_DIRECT_DNS,
            proxyDns = p.getString(AppSettings.KEY_PROXY_DNS, AppSettings.DEFAULT_PROXY_DNS)
                ?: AppSettings.DEFAULT_PROXY_DNS,
            apiEnabled = p.getBoolean(
                AppSettings.KEY_API_ENABLED, AppSettings.DEFAULT_API_ENABLED
            ),
            apiAddress = p.getString(AppSettings.KEY_API_ADDRESS, AppSettings.DEFAULT_API_ADDRESS)
                ?: AppSettings.DEFAULT_API_ADDRESS,
            fakeipFilterMode = p.getString(
                AppSettings.KEY_FAKEIP_FILTER_MODE, AppSettings.DEFAULT_FAKEIP_FILTER_MODE
            ) ?: AppSettings.DEFAULT_FAKEIP_FILTER_MODE,
            fakeipFilter = filter
        )
    }

    fun save(context: Context, settings: AppSettings) {
        prefs(context).edit()
            .putBoolean(AppSettings.KEY_IPV6, settings.ipv6)
            .putString(AppSettings.KEY_DNS_MODE, settings.dnsMode)
            .putString(AppSettings.KEY_DIRECT_DNS, settings.directDns.trim())
            .putString(AppSettings.KEY_PROXY_DNS, settings.proxyDns.trim())
            .putBoolean(AppSettings.KEY_API_ENABLED, settings.apiEnabled)
            .putString(AppSettings.KEY_API_ADDRESS, settings.apiAddress.trim())
            .putString(AppSettings.KEY_FAKEIP_FILTER_MODE, settings.fakeipFilterMode)
            .putString(
                AppSettings.KEY_FAKEIP_FILTER,
                settings.fakeipFilter.distinct().joinToString(",")
            )
            .apply()
    }

    /** 供 VpnService / 进程管理等非设置页调用点读取单个开关。 */
    fun apiEnabled(context: Context): Boolean =
        prefs(context).getBoolean(AppSettings.KEY_API_ENABLED, AppSettings.DEFAULT_API_ENABLED)

    /** App 访问 ant API 的 base URL（跟随设置页的监听地址；地址非法时回落默认值）。 */
    fun apiBaseUrl(context: Context): String {
        val raw = prefs(context)
            .getString(AppSettings.KEY_API_ADDRESS, AppSettings.DEFAULT_API_ADDRESS)
            .orEmpty()
        return (AppSettings.parseApiAddress(raw)
            ?: AppSettings.parseApiAddress(AppSettings.DEFAULT_API_ADDRESS)!!).baseUrl
    }
}
