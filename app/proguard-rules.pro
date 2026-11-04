# ── JNI：spawn_fd.c 通过 RegisterNatives 绑定 ────────────────
# AntProcessManager 里的 external fun（nativeSpawn / nativeKill / nativeWaitPid）
# 编译为 native 方法，按名字绑定，不能被 R8 改名
-keepclasseswithmembernames class com.ant.proxy.** { native <methods>; }

# AntVpnService 由系统 VpnService 反射/隐式调用，Manifest 引用类 R8 自动保留
# libant.so 为独立可执行文件（运行时从 nativeLibraryDir 解包），与 R8 无关
-dontwarn com.ant.proxy.**
