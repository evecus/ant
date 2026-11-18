package com.ant.proxy

/**
 * 分应用代理（纯 Kotlin，不依赖 Android，便于 JVM 验证）。
 *
 * 落到 VpnService.Builder 上只有两种互斥的系统接口：
 *   - ALLOW    → addAllowedApplication：只有名单内的应用进 TUN（白名单）
 *   - DISALLOW → addDisallowedApplication：名单内的应用不进 TUN（黑名单）
 * 两者混用系统会抛异常，所以这里是单选模式。
 *
 * **本 App 必须始终留在 VPN 内**（见 AntVpnService.EXCLUDE_SELF_FROM_VPN 的说明）：
 * ant 子进程与本 App 同 UID，其 system-stack 的 TCP 监听回包要走 tun0；
 * UID 被排除出 VPN 会让这些回包绕出 TUN。出站 socket 的防回环由 ProtectServer 负责。
 *   - ALLOW 模式：自动把本 App 加进白名单（[allowedPackages]）
 *   - DISALLOW 模式：自动忽略名单里的本 App（[disallowedPackages]）
 */
enum class PerAppMode(val key: String) {
    /** 不分应用：所有应用走代理（原有行为，默认）。 */
    OFF("off"),
    ALLOW("allow"),
    DISALLOW("disallow");

    companion object {
        fun fromKey(key: String?): PerAppMode = values().firstOrNull { it.key == key } ?: OFF
    }
}

data class PerAppSettings(
    val mode: PerAppMode = PerAppMode.OFF,
    val packages: Set<String> = emptySet()
) {
    /** 启动前校验，返回错误文案；null 表示通过。 */
    fun validate(selfPackage: String): String? {
        if (mode == PerAppMode.ALLOW && packages.none { it != selfPackage }) {
            // 白名单只剩本 App 时没有任何应用被代理，几乎一定是忘了勾选
            return "分应用代理为「只代理选中的应用」但未选择任何应用"
        }
        return null
    }

    fun allowedPackages(selfPackage: String): List<String> =
        (listOf(selfPackage) + packages).distinct()

    fun disallowedPackages(selfPackage: String): List<String> =
        packages.filter { it != selfPackage }

    companion object {
        const val KEY_MODE = "perapp_mode"
        /** 逗号分隔的包名（包名不含逗号）。 */
        const val KEY_PACKAGES = "perapp_packages"
    }
}
