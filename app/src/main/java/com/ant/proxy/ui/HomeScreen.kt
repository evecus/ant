package com.ant.proxy.ui

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.SwapHoriz
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FabPosition
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.NavigationDrawerItemDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.ant.proxy.AntVpnService
import com.ant.proxy.LinkExporter
import com.ant.proxy.LinkParser
import com.ant.proxy.NodeStore
import com.ant.proxy.ProxyNode
import com.ant.proxy.R
import com.ant.proxy.protocolDisplay
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private val BrandBlue = Color(0xFF0E9CE6)
private val BrandBlueContainer = Color(0xFFD3EDFB)
private val DeepBlue = Color(0xFF0B2A5B)
private val CardSelected = Color(0xFFF0F8FE)
private val TextDark = Color(0xFF202124)
private val TextGrey = Color(0xFF9AA0A6)
private val RunningGreen = Color(0xFF2E7D32)
private val StartingOrange = Color(0xFFEF8C1A)

/**
 * NekoBox 风格首页：
 *  - 顶部蓝色工具栏：汉堡（左侧边栏）/ 搜索 / 导入 / 更多
 *  - 左侧抽屉：配置（首页）、路由、设置、日志、关于
 *  - 节点卡片列表：点击选中、编辑、分享、删除
 *  - 底部中央飞机 FAB：唯一启停入口，仅以颜色表达状态
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(
    nodeState: NodeStore.State,
    onNodesChanged: (NodeStore.State) -> Unit,
    onOpenDrawer: () -> Unit,
    onOpenEdit: (String?) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current

    var running by remember { mutableStateOf(AntVpnService.isRunning) }
    var starting by remember { mutableStateOf(false) }
    var showImport by remember { mutableStateOf(false) }
    var showMenu by remember { mutableStateOf(false) }
    var searchActive by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var deleteTarget by remember { mutableStateOf<ProxyNode?>(null) }
    var showClearConfirm by remember { mutableStateOf(false) }

    DisposableEffect(context) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context?, i: Intent?) {
                running = AntVpnService.isRunning
            }
        }
        ContextCompat.registerReceiver(
            context, receiver,
            IntentFilter("com.ant.proxy.STATUS"),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        onDispose { runCatching { context.unregisterReceiver(receiver) } }
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        running = AntVpnService.isRunning
    }

    LaunchedEffect(starting) {
        if (starting) {
            delay(600)
            running = AntVpnService.isRunning
            starting = false
        }
    }

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            ContextCompat.startForegroundService(
                context,
                Intent(context, AntVpnService::class.java).setAction(AntVpnService.ACTION_START)
            )
            starting = true
        } else {
            Toast.makeText(context, R.string.vpn_permission_denied, Toast.LENGTH_SHORT).show()
            starting = false
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* 通知为可选权限，拒绝不影响 VPN */ }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    fun startVpn() {
        if (nodeState.selected == null) {
            Toast.makeText(context, R.string.node_required, Toast.LENGTH_SHORT).show()
            return
        }
        val prepare = VpnService.prepare(context)
        if (prepare != null) {
            vpnPermissionLauncher.launch(prepare)
        } else {
            ContextCompat.startForegroundService(
                context,
                Intent(context, AntVpnService::class.java).setAction(AntVpnService.ACTION_START)
            )
            starting = true
        }
    }

    fun toggleVpn() {
        if (AntVpnService.isRunning) {
            context.startService(
                Intent(context, AntVpnService::class.java).setAction(AntVpnService.ACTION_STOP)
            )
            running = AntVpnService.isRunning
        } else {
            startVpn()
        }
    }

    fun shareText(text: String) {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(Intent.createChooser(send, context.getString(R.string.share_title)))
    }

    fun importNodes(raw: String) {
        val text = raw.ifBlank { readClipboard(context) }
        if (text.isBlank()) {
            Toast.makeText(context, R.string.node_import_none, Toast.LENGTH_SHORT).show()
            return
        }
        val result = LinkParser.parse(text)
        if (result.nodes.isEmpty()) {
            Toast.makeText(context, R.string.node_import_none, Toast.LENGTH_LONG).show()
            return
        }
        onNodesChanged(NodeStore.addAll(context, result.nodes))
        showImport = false
        Toast.makeText(
            context,
            context.getString(R.string.node_import_ok, result.nodes.size, result.skipped),
            Toast.LENGTH_LONG
        ).show()
    }

    fun selectNode(node: ProxyNode) {
        onNodesChanged(NodeStore.select(context, node.id))
        if (running) {
            Toast.makeText(context, R.string.node_switched, Toast.LENGTH_SHORT).show()
        }
    }

    val filtered = remember(nodeState, query) {
        if (query.isBlank()) nodeState.nodes
        else nodeState.nodes.filter {
            it.name.contains(query, true) || it.server.contains(query, true) ||
                protocolDisplay(it.type).contains(query, true)
        }
    }

    Scaffold(
        modifier = modifier,
        topBar = {
                TopAppBar(
                    title = { Text(stringResource(R.string.app_name)) },
                    navigationIcon = {
                        IconButton(onClick = onOpenDrawer) {
                            Icon(Icons.Filled.Menu, stringResource(R.string.drawer_open))
                        }
                    },
                    actions = {
                        IconButton(onClick = {
                            searchActive = !searchActive
                            if (!searchActive) query = ""
                        }) {
                            Icon(Icons.Filled.Search, stringResource(R.string.action_search))
                        }
                        IconButton(onClick = { showImport = true }) {
                            Icon(Icons.Filled.ContentPaste, stringResource(R.string.btn_import))
                        }
                        Box {
                            IconButton(onClick = { showMenu = true }) {
                                Icon(Icons.Filled.MoreVert, stringResource(R.string.action_more))
                            }
                            DropdownMenu(
                                expanded = showMenu,
                                onDismissRequest = { showMenu = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.menu_new_node)) },
                                    leadingIcon = { Icon(Icons.Filled.Add, null) },
                                    onClick = { showMenu = false; onOpenEdit(null) }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.menu_export_all)) },
                                    leadingIcon = { Icon(Icons.Filled.Share, null) },
                                    onClick = {
                                        showMenu = false
                                        if (nodeState.nodes.isEmpty()) {
                                            Toast.makeText(context, R.string.no_nodes, Toast.LENGTH_SHORT).show()
                                        } else {
                                            shareText(LinkExporter.exportAll(nodeState.nodes))
                                        }
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.menu_clear_all)) },
                                    leadingIcon = { Icon(Icons.Filled.Delete, null) },
                                    onClick = { showMenu = false; showClearConfirm = true }
                                )
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = BrandBlue,
                        titleContentColor = Color.White,
                        navigationIconContentColor = Color.White,
                        actionIconContentColor = Color.White
                    )
                )
            },
            floatingActionButtonPosition = FabPosition.Center,
            floatingActionButton = {
                FloatingActionButton(
                    onClick = { toggleVpn() },
                    shape = CircleShape,
                    containerColor = when {
                        starting -> StartingOrange
                        running -> RunningGreen
                        else -> BrandBlue
                    },
                    contentColor = Color.White,
                    elevation = FloatingActionButtonDefaults.elevation(6.dp),
                    modifier = Modifier.size(64.dp)
                ) {
                    Icon(
                        imageVector = Icons.AutoMirrored.Filled.Send,
                        contentDescription = stringResource(
                            if (running) R.string.btn_stop else R.string.btn_start
                        ),
                        modifier = Modifier.size(28.dp)
                    )
                }
            }
        ) { innerPadding ->
            Column(
                modifier = Modifier
                    .padding(innerPadding)
                    .fillMaxSize()
            ) {
                if (searchActive) {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        placeholder = { Text(stringResource(R.string.search_hint)) },
                        singleLine = true,
                        trailingIcon = {
                            if (query.isNotEmpty()) {
                                IconButton(onClick = { query = "" }) {
                                    Icon(Icons.Filled.Close, null)
                                }
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp)
                    )
                }

                if (filtered.isEmpty()) {
                    Box(
                        modifier = Modifier.weight(1f).fillMaxWidth(),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(
                                Icons.Filled.Description,
                                contentDescription = null,
                                tint = TextGrey.copy(alpha = 0.5f),
                                modifier = Modifier.size(56.dp)
                            )
                            Spacer(Modifier.height(12.dp))
                            Text(
                                text = stringResource(
                                    if (nodeState.nodes.isEmpty()) R.string.empty_nodes
                                    else R.string.empty_search
                                ),
                                color = TextGrey,
                                fontSize = 14.sp
                            )
                        }
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(start = 12.dp, end = 12.dp, top = 12.dp, bottom = 96.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(filtered, key = { it.id }) { node ->
                            NodeCard(
                                node = node,
                                selected = node.id == nodeState.selected?.id,
                                onSelect = { selectNode(node) },
                                onEdit = { onOpenEdit(node.id) },
                                onShare = { shareText(LinkExporter.export(node)) },
                                onDelete = { deleteTarget = node }
                            )
                        }
                    }
                }
            }
        }

    if (showImport) {
        ImportDialog(
            onDismiss = { showImport = false },
            onImport = { importNodes(it) },
            onPaste = { readClipboard(context) }
        )
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.delete_title)) },
            text = { Text(stringResource(R.string.delete_message, target.name)) },
            confirmButton = {
                TextButton(onClick = {
                    onNodesChanged(NodeStore.delete(context, target.id))
                    deleteTarget = null
                }) { Text(stringResource(R.string.btn_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(android.R.string.cancel))
                }
            }
        )
    }

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            title = { Text(stringResource(R.string.clear_all_title)) },
            text = { Text(stringResource(R.string.clear_all_message)) },
            confirmButton = {
                TextButton(onClick = {
                    onNodesChanged(NodeStore.clear(context))
                    showClearConfirm = false
                }) { Text(stringResource(R.string.btn_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) {
                    Text(stringResource(android.R.string.cancel))
                }
            }
        )
    }

}

/**
 * 全局左侧导航抽屉，由 AfaApp 提升到 NavHost 外层，四个主页面共用。
 * 选中态颜色显式指定为蓝色系，不依赖 Material3 默认的淡紫 secondaryContainer。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun AfaDrawerSheet(
    configSelected: Boolean,
    routeSelected: Boolean,
    settingsSelected: Boolean,
    logsSelected: Boolean,
    onConfig: () -> Unit,
    onRoute: () -> Unit,
    onSettings: () -> Unit,
    onLogs: () -> Unit,
    onAbout: () -> Unit
) {
    val selectedColors = NavigationDrawerItemDefaults.colors(
        selectedContainerColor = BrandBlueContainer,
        selectedTextColor = DeepBlue,
        selectedIconColor = BrandBlue,
        unselectedContainerColor = Color.Transparent,
        unselectedTextColor = TextDark,
        unselectedIconColor = TextGrey
    )
    ModalDrawerSheet(modifier = Modifier.width(300.dp)) {
        Column(Modifier.padding(vertical = 20.dp)) {
            Text(
                text = stringResource(R.string.app_name),
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
                color = BrandBlue,
                modifier = Modifier.padding(horizontal = 28.dp)
            )
            Text(
                text = stringResource(R.string.drawer_subtitle),
                fontSize = 12.sp,
                color = TextGrey,
                modifier = Modifier.padding(horizontal = 28.dp)
            )
        }
        NavigationDrawerItem(
            label = { Text(stringResource(R.string.drawer_config)) },
            icon = { Icon(Icons.Filled.Description, null) },
            selected = configSelected,
            onClick = onConfig,
            colors = selectedColors,
            modifier = Modifier.padding(horizontal = 12.dp)
        )
        NavigationDrawerItem(
            label = { Text(stringResource(R.string.drawer_route)) },
            icon = { Icon(Icons.Filled.SwapHoriz, null) },
            selected = routeSelected,
            onClick = onRoute,
            colors = selectedColors,
            modifier = Modifier.padding(horizontal = 12.dp)
        )
        NavigationDrawerItem(
            label = { Text(stringResource(R.string.drawer_settings)) },
            icon = { Icon(Icons.Filled.Settings, null) },
            selected = settingsSelected,
            onClick = onSettings,
            colors = selectedColors,
            modifier = Modifier.padding(horizontal = 12.dp)
        )
        NavigationDrawerItem(
            label = { Text(stringResource(R.string.drawer_logs)) },
            icon = { Icon(Icons.Filled.List, null) },
            selected = logsSelected,
            onClick = onLogs,
            colors = selectedColors,
            modifier = Modifier.padding(horizontal = 12.dp)
        )
        HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
        NavigationDrawerItem(
            label = { Text(stringResource(R.string.drawer_about)) },
            icon = { Icon(Icons.Filled.Info, null) },
            selected = false,
            onClick = onAbout,
            colors = selectedColors,
            modifier = Modifier.padding(horizontal = 12.dp)
        )
    }
}

@Composable
private fun NodeCard(
    node: ProxyNode,
    selected: Boolean,
    onSelect: () -> Unit,
    onEdit: () -> Unit,
    onShare: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onSelect),
        shape = RoundedCornerShape(6.dp),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) CardSelected else MaterialTheme.colorScheme.surface
        )
    ) {
        Row(modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
            Box(
                modifier = Modifier
                    .width(4.dp)
                    .fillMaxHeight()
                    .background(if (selected) BrandBlue else Color.Transparent)
            )
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(start = 12.dp, top = 14.dp, bottom = 14.dp)
            ) {
                Text(node.name, fontSize = 17.sp, color = TextDark)
                Spacer(Modifier.height(8.dp))
                Text(protocolDisplay(node.type), fontSize = 14.sp, color = BrandBlue)
                Spacer(Modifier.height(2.dp))
                Text("${node.server}:${node.port}", fontSize = 12.sp, color = TextGrey)
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(end = 2.dp)
            ) {
                IconButton(onClick = onEdit) {
                    Icon(Icons.Filled.Edit, stringResource(R.string.action_edit), tint = TextGrey)
                }
                IconButton(onClick = onShare) {
                    Icon(Icons.Filled.Share, stringResource(R.string.action_share), tint = TextGrey)
                }
                IconButton(onClick = onDelete) {
                    Icon(Icons.Filled.Delete, stringResource(R.string.action_delete), tint = TextGrey)
                }
            }
        }
    }
}

@Composable
private fun ImportDialog(
    onDismiss: () -> Unit,
    onImport: (String) -> Unit,
    onPaste: () -> String
) {
    var text by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.btn_import)) },
        text = {
            Column {
                Text(
                    text = stringResource(R.string.import_hint),
                    fontSize = 12.sp,
                    color = TextGrey
                )
                Spacer(Modifier.height(10.dp))
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    placeholder = { Text(stringResource(R.string.hint_node_links), fontSize = 12.sp) },
                    minLines = 5,
                    maxLines = 10,
                    modifier = Modifier.fillMaxWidth()
                )
                TextButton(onClick = { text = onPaste() }) {
                    Text(stringResource(R.string.btn_paste))
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onImport(text) }) {
                Text(stringResource(R.string.node_import_btn))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(android.R.string.cancel))
            }
        }
    )
}

/** 留空输入框时直接读取剪贴板（兼容订阅 blob / 多行链接）。 */
private fun readClipboard(context: Context): String =
    (context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager)
        ?.primaryClip
        ?.takeIf { it.itemCount > 0 }
        ?.getItemAt(0)
        ?.text
        ?.toString()
        .orEmpty()
