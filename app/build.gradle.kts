import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ── 发布签名 ──────────────────────────────────────────────────────────
// 凭据只从环境变量或 Gradle 属性（如 ~/.gradle/gradle.properties）读取，不进仓库。
// 前三项必填、齐全才启用签名（密钥密码可省略）；缺任一必填项时 release 仍可构建，但产物是未签名 APK（无法安装）。
//   ANT_KEYSTORE_FILE      keystore 路径（绝对路径，或相对 app/ 目录）
//   ANT_KEYSTORE_PASSWORD  keystore 密码
//   ANT_KEY_ALIAS          密钥别名
//   ANT_KEY_PASSWORD       密钥密码（省略则与 keystore 密码相同）
fun signingProp(name: String): String? =
    providers.environmentVariable(name).orNull?.takeIf { it.isNotBlank() }
        ?: providers.gradleProperty(name).orNull?.takeIf { it.isNotBlank() }

val releaseStoreFile = signingProp("ANT_KEYSTORE_FILE")
val releaseStorePassword = signingProp("ANT_KEYSTORE_PASSWORD")
val releaseKeyAlias = signingProp("ANT_KEY_ALIAS")
val releaseKeyPassword = signingProp("ANT_KEY_PASSWORD") ?: releaseStorePassword
val hasReleaseSigning =
    releaseStoreFile != null && releaseStorePassword != null && releaseKeyAlias != null

android {
    namespace = "com.ant.proxy"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.ant.proxy"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(releaseStoreFile!!)
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        release {
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            } else {
                logger.warn("WARNING: 未配置发布签名（ANT_KEYSTORE_*），release 将产出未签名 APK")
            }
            // R8 压缩（11.6MB 的 libant.so 是 Rust 静态核心，不受 R8 影响）
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }

    // 不再编译 C：libant_spawn.so / libant.so 都以预编译产物放在 src/main/jniLibs/arm64-v8a/。
    // spawn_fd.c 与 CMakeLists.txt 仅作为源码保留在 src/main/cpp/，改动后需手动重新编译并替换 .so。

    packaging {
        jniLibs {
            // libant.so 需要在 nativeLibraryDir 中以可执行文件形式解包
            useLegacyPackaging = true
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.5")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
}

// Kotlin 2.x 起 jvmTarget 通过顶层 compilerOptions 配置（kotlinOptions 已废弃）
kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}
