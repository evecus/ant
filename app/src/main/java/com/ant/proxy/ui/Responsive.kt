package com.ant.proxy.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.DrawerState
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.PermanentNavigationDrawer
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * 平板 / 大屏适配基础设施。
 *
 * 设计要点：
 * - 依据「当前窗口宽度」而非设备类型区分档位：分屏、多窗口、折叠屏展开时
 *   BoxWithConstraints 的可用宽度会随之变化，布局能实时响应重组。
 * - 断点沿用 Material 3 规范：Compact < 600dp，Medium 600–840dp，Expanded ≥ 840dp。
 * - 通过 CompositionLocal 下发档位，各页面无需层层传参即可自适应。
 */

enum class WindowClass { COMPACT, MEDIUM, EXPANDED }

/** 当前窗口宽度档位。 */
val LocalWindowClass = compositionLocalOf { WindowClass.COMPACT }

/** 宽屏下抽屉常驻，顶部栏不再需要汉堡按钮。 */
val LocalShowNavIcon = compositionLocalOf { true }

/**
 * 窗口档位判定。
 * 用 BoxWithConstraints 提供的 maxWidth（Dp）判断，稳定 API 且随窗口尺寸变化重组，
 * 手机横竖屏切换、分屏、折叠屏展开都能实时响应。
 */
fun windowClassForWidth(width: Dp): WindowClass = when {
    width >= 840.dp -> WindowClass.EXPANDED
    width >= 600.dp -> WindowClass.MEDIUM
    else -> WindowClass.COMPACT
}

/** 在根 Composable 注入窗口档位，供整棵 UI 树读取。 */
@Composable
fun ProvideWindowClass(content: @Composable () -> Unit) {
    BoxWithConstraints {
        val windowClass = windowClassForWidth(maxWidth)
        CompositionLocalProvider(LocalWindowClass provides windowClass, content = content)
    }
}

/** 列表网格列数：手机单列，平板 / 大屏双列，避免卡片被拉得过宽。 */
fun gridColumns(windowClass: WindowClass): Int = when (windowClass) {
    WindowClass.COMPACT -> 1
    WindowClass.MEDIUM -> 2
    WindowClass.EXPANDED -> 2
}

/** 宽屏下限制内容最大宽度，手机 / 中等屏保持满宽。 */
@Composable
fun Modifier.adaptiveMaxWidth(maxWidth: Dp = 720.dp): Modifier =
    if (LocalWindowClass.current == WindowClass.EXPANDED) this.widthIn(max = maxWidth) else this

/**
 * 页面主体容器：宽屏下把内容限制在 [maxWidth] 内并水平居中，
 * 避免内容被无限拉伸导致单行过长、留白失衡。
 */
@Composable
fun AdaptiveContentBox(
    modifier: Modifier = Modifier,
    maxWidth: Dp = 720.dp,
    content: @Composable ColumnScope.() -> Unit
) {
    Box(modifier = modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier.fillMaxSize().adaptiveMaxWidth(maxWidth),
            content = content
        )
    }
}

/**
 * 自适应导航容器：
 * - Expanded（平板横屏 / 大屏）：左侧抽屉常驻，内容与抽屉并排；
 * - Compact / Medium：保持 ModalNavigationDrawer，点击汉堡弹出。
 *
 * [drawerState] 仅在 Modal 模式使用；常驻模式下传入的 state 会被忽略，
 * AfaApp 里的 openDrawer/closeDrawer 调用对常驻模式无副作用。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdaptiveNavigationDrawer(
    drawerState: DrawerState,
    drawerContent: @Composable () -> Unit,
    content: @Composable () -> Unit
) {
    if (LocalWindowClass.current == WindowClass.EXPANDED) {
        PermanentNavigationDrawer(drawerContent = drawerContent, content = content)
    } else {
        ModalNavigationDrawer(
            drawerState = drawerState,
            drawerContent = drawerContent,
            content = content
        )
    }
}
