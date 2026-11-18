package com.ant.proxy.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.ant.proxy.ConfigManager
import com.ant.proxy.NodeStore
import com.ant.proxy.RouteStore

private object Routes {
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
 * 节点状态与路由状态都提升到 NavHost 之外：编辑页保存 / 列表增删后统一刷新，
 * 返回列表页时不会出现数据不更新的问题。
 */
@Composable
fun AfaApp() {
    val context = LocalContext.current
    val navController = rememberNavController()
    var nodeState by remember(context) { mutableStateOf(NodeStore.load(context)) }
    var routeState by remember(context) { mutableStateOf(RouteStore.load(context)) }

    fun reloadNodes() {
        nodeState = NodeStore.load(context)
    }

    fun reloadRoutes() {
        routeState = RouteStore.load(context)
    }

    // 内置规则集不再只在启动 VPN 时释放：一进 App 就就绪，规则集管理页
    // 才能正确显示文件状态，路由配置校验也不会误报「文件缺失」。
    LaunchedEffect(Unit) {
        ConfigManager.ensureAssets(context) { }
    }

    NavHost(navController = navController, startDestination = Routes.HOME) {
        composable(Routes.HOME) {
            HomeScreen(
                nodeState = nodeState,
                onNodesChanged = { nodeState = it },
                onOpenLogs = { navController.navigate(Routes.LOGS) },
                onOpenSettings = { navController.navigate(Routes.SETTINGS) },
                onOpenRoute = { navController.navigate(Routes.ROUTE) },
                onOpenEdit = { id -> navController.navigate(Routes.edit(id)) }
            )
        }
        composable(Routes.LOGS) {
            LogsScreen(onBack = { navController.popBackStack() })
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(
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
                onBack = { navController.popBackStack() }
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
