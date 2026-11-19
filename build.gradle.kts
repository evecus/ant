plugins {
    id("com.android.application") version "8.7.2" apply false
    id("org.jetbrains.kotlin.android") version "2.1.21" apply false
    // Kotlin 2.0+ 起 Compose Compiler 与 Kotlin 版本绑定，由该插件提供
    id("org.jetbrains.kotlin.plugin.compose") version "2.1.21" apply false
}
