package com.ant.proxy

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.view.WindowCompat
import com.ant.proxy.ui.AfaApp
import com.ant.proxy.ui.AfaTheme

/**
 * Compose 版入口：单 Activity 承载全部界面（Home / Route / RuleSets / Logs / Settings）。
 * VPN 权限、状态广播、节点导入等交互全部下沉到 HomeScreen 的 composable 中。
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // targetSdk 35 强制 edge-to-edge，Scaffold 通过 contentWindowInsets 避开系统栏
        enableEdgeToEdge()
        // 顶部工具栏是亮蓝色，状态栏图标改为浅色以保证对比度
        WindowCompat.getInsetsController(window, window.decorView)
            .isAppearanceLightStatusBars = false
        setContent {
            AfaTheme {
                AfaApp()
            }
        }
    }
}
