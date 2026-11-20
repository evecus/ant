package com.ant.proxy.ui

import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.ant.proxy.ConfigManager
import com.ant.proxy.NodeStore
import com.ant.proxy.R
import com.ant.proxy.RouteStore
import kotlinx.coroutines.launch

internal object Routes {
    const val HOME = "home"
    const val LOGS = "logs"
    const val SETTINGS = "settings"
    const val PERAPP = "perapp"
    const val ROUTE = "route"
    const val RULESETS = "rulesets"
    const val EDIT = "edit/{nodeId}"
    const val ROUTE_EDIT = "route_edit/{routeId}"
    fun edit(nodeId: String?) = "edit/${nodeId ?: "new"}"
    fun routeEdit(ruleId: String?) = "route_edit/${ruleId ?: "new"}"
}

/**
 * 单 Activity + Navigation Compose。
 * - 左侧抽屉提升到 NavHost 外层：配置 / 路由 / 设置 / 日志四个主页面共用同一个抽屉，
 *   左上角统一为汉堡图标（面包屑）打开它；二级页面（编辑 / 规则集 / 分应用）仍是返回箭头。
 * - 节点状态与路由状态提升到 NavHost 之外：编辑页保存 / 列表增删后统一刷新，
 *   返回列表页时不会出现数据不更新的问题。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AfaApp() {
    val context = LocalContext.current
    val navController = rememberNavController()
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val windowClass = LocalWindowClass.current
    var nodeState by remember(context) { mutableStateOf(NodeStore.load(context)) }
    var routeState by remember(context) { mutableStateOf(RouteStore.load(context)) }
    var showAbout by remember { mutableStateOf(false) }

    // 当前主路由，用于抽屉高亮
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    fun openDrawer() {
        scope.launch { drawerState.open() }
    }

    fun closeDrawer() {
        scope.launch { drawerState.close() }
    }

    fun reloadNodes() {
        nodeState = NodeStore.load(context)
    }

    fun reloadRoutes() {
        routeState = RouteStore.load(context)
    }

    fun navigateTop(route: String) {
        closeDrawer()
        if (route != currentRoute) navController.navigate(route)
    }

    // 内置规则集不再只在启动 VPN 时释放：一进 App 就就绪，规则集管理页
    // 才能正确显示文件状态，路由配置校验也不会误报「文件缺失」。
    LaunchedEffect(Unit) {
        ConfigManager.ensureAssets(context) { }
    }

    // 宽屏抽屉常驻时隐藏各页面顶部栏的汉堡图标；窄屏保留。
    CompositionLocalProvider(LocalShowNavIcon provides (windowClass != WindowClass.EXPANDED)) {
    AdaptiveNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            AfaDrawerSheet(
                configSelected = currentRoute == Routes.HOME,
                routeSelected = currentRoute == Routes.ROUTE,
                settingsSelected = currentRoute == Routes.SETTINGS,
                logsSelected = currentRoute == Routes.LOGS,
                onConfig = { navigateTop(Routes.HOME) },
                onRoute = { navigateTop(Routes.ROUTE) },
                onSettings = { navigateTop(Routes.SETTINGS) },
                onLogs = { navigateTop(Routes.LOGS) },
                onAbout = { closeDrawer(); showAbout = true }
            )
        }
    ) {
        NavHost(navController = navController, startDestination = Routes.HOME) {
            composable(Routes.HOME) {
                HomeScreen(
                    nodeState = nodeState,
                    onNodesChanged = { nodeState = it },
                    onOpenDrawer = { openDrawer() },
                    onOpenEdit = { id -> navController.navigate(Routes.edit(id)) }
                )
            }
            composable(Routes.LOGS) {
                LogsScreen(onOpenDrawer = { openDrawer() })
            }
            composable(Routes.SETTINGS) {
                SettingsScreen(
                    onOpenDrawer = { openDrawer() },
                    onBack = { navController.popBackStack() },
                    onOpenPerApp = { navController.navigate(Routes.PERAPP) }
                )
            }
            composable(Routes.PERAPP) {
                PerAppScreen(onBack = { navController.popBackStack() })
            }
            composable(
                route = Routes.EDIT,
                arguments = listOf(navArgument("nodeId") { type = NavType.StringType })
            ) { entry ->
                val raw = entry.arguments?.getString("nodeId")
                NodeEditScreen(
                    nodeId = raw?.takeIf { it != "new" },
                    onSaved = { reloadNodes() },
                    onBack = { navController.popBackStack() }
                )
            }
            composable(Routes.ROUTE) {
                RouteScreen(
                    state = routeState,
                    onStateChanged = { routeState = it },
                    onOpenEdit = { id -> navController.navigate(Routes.routeEdit(id)) },
                    onOpenRuleSets = { navController.navigate(Routes.RULESETS) },
                    onOpenDrawer = { openDrawer() }
                )
            }
            composable(Routes.RULESETS) {
                RuleSetScreen(
                    state = routeState,
                    onStateChanged = { routeState = it },
                    onBack = { navController.popBackStack() }
                )
            }
            composable(
                route = Routes.ROUTE_EDIT,
                arguments = listOf(navArgument("routeId") { type = NavType.StringType })
            ) { entry ->
                val raw = entry.arguments?.getString("routeId")
                RouteEditScreen(
                    ruleId = raw?.takeIf { it != "new" },
                    state = routeState,
                    onSaved = { reloadRoutes() },
                    onBack = { navController.popBackStack() }
                )
            }
        }
    }
    } // CompositionLocalProvider(LocalShowNavIcon)

    if (showAbout) {
        AlertDialog(
            onDismissRequest = { showAbout = false },
            title = { Text(stringResource(R.string.drawer_about)) },
            text = {
                Text(
                    stringResource(R.string.about_text),
                    modifier = Modifier.widthIn(max = 420.dp)
                )
            },
            confirmButton = {
                TextButton(onClick = { showAbout = false }) {
                    Text(stringResource(android.R.string.ok))
                }
            }
        )
    }
}
