package com.ant.proxy.ui

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ant.proxy.R
import com.ant.proxy.RouteAction
import com.ant.proxy.RouteState
import com.ant.proxy.RouteStore
import com.ant.proxy.RouteRule

private val RouteBlue = Color(0xFF0E9CE6)
private val RouteGreen = Color(0xFF2E7D32)
private val RouteRed = Color(0xFFC62828)
private val RouteGrey = Color(0xFF9AA0A6)

private fun actionColor(action: RouteAction): Color = when (action) {
    RouteAction.PROXY -> RouteBlue
    RouteAction.DIRECT -> RouteGreen
    RouteAction.BLOCK -> RouteRed
}

/**
 * 路由页：afa 唯一的路由配置入口。
 * 列表里的每一条（含固定的 MATCH 兜底）就是启动时要写进 config.yaml 的
 * route: 段，模板里不再有隐藏规则。支持开关、编辑、新增、删除、上下排序。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RouteScreen(
    state: RouteState,
    onStateChanged: (RouteState) -> Unit,
    onOpenEdit: (String?) -> Unit,
    onOpenRuleSets: () -> Unit,
    onOpenDrawer: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    var showMenu by remember { mutableStateOf(false) }
    var showReset by remember { mutableStateOf(false) }
    var deleteTarget by remember { mutableStateOf<RouteRule?>(null) }

    fun commit(next: RouteState) {
        val saved = RouteStore.save(context, next)
        onStateChanged(saved)
        Toast.makeText(context, R.string.route_restart_hint, Toast.LENGTH_SHORT).show()
    }

    fun move(index: Int, delta: Int) {
        val rules = state.rules
        val target = index + delta
        // 最后一条永远是 MATCH 兜底，普通规则不能越过它
        if (target < 0 || target >= rules.lastIndex) return
        val list = rules.toMutableList()
        val item = list.removeAt(index)
        list.add(target, item)
        commit(state.copy(rules = list))
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.title_route)) },
                navigationIcon = {
                    if (LocalShowNavIcon.current) {
                        IconButton(onClick = onOpenDrawer) {
                            Icon(
                                Icons.Filled.Menu,
                                stringResource(R.string.drawer_open)
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = onOpenRuleSets) {
                        Icon(Icons.Filled.Folder, stringResource(R.string.route_ruleset_entry))
                    }
                    IconButton(onClick = { showMenu = true }) {
                        Icon(Icons.Filled.MoreVert, stringResource(R.string.action_more))
                    }
                    DropdownMenu(
                        expanded = showMenu,
                        onDismissRequest = { showMenu = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.route_reset)) },
                            onClick = { showMenu = false; showReset = true }
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = RouteBlue,
                    titleContentColor = Color.White,
                    navigationIconContentColor = Color.White,
                    actionIconContentColor = Color.White
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { onOpenEdit(null) },
                containerColor = RouteBlue,
                contentColor = Color.White
            ) {
                Icon(Icons.Filled.Add, stringResource(R.string.route_add))
            }
        }
    ) { innerPadding ->
        AdaptiveContentBox(modifier = Modifier.padding(innerPadding), maxWidth = 960.dp) {
        Column(
            modifier = Modifier
                .fillMaxSize()
        ) {
            Text(
                text = stringResource(R.string.route_note),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp)
            )

            LazyVerticalGrid(
                columns = GridCells.Fixed(gridColumns(LocalWindowClass.current)),
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(
                    start = 12.dp, end = 12.dp, bottom = 88.dp
                ),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                itemsIndexed(state.rules, key = { _, r -> r.id }) { index, rule ->
                    RouteCard(
                        rule = rule,
                        state = state,
                        canMoveUp = index > 0,
                        canMoveDown = index < state.rules.lastIndex - 1,
                        onToggle = { checked ->
                            val next = state.rules.map {
                                if (it.id == rule.id) it.copy(enabled = checked) else it
                            }
                            commit(state.copy(rules = next))
                        },
                        onEdit = { onOpenEdit(rule.id) },
                        onDelete = { deleteTarget = rule },
                        onMoveUp = { move(index, -1) },
                        onMoveDown = { move(index, 1) }
                    )
                }
            }
        }
        }
    }

    if (showReset) {
        AlertDialog(
            onDismissRequest = { showReset = false },
            title = { Text(stringResource(R.string.route_reset_title)) },
            text = {
                Text(
                    stringResource(R.string.route_reset_message),
                    modifier = Modifier.widthIn(max = 440.dp)
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    onStateChanged(RouteStore.reset(context))
                    showReset = false
                    Toast.makeText(context, R.string.route_restart_hint, Toast.LENGTH_SHORT).show()
                }) { Text(stringResource(R.string.btn_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { showReset = false }) {
                    Text(stringResource(R.string.btn_cancel))
                }
            }
        )
    }

    deleteTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.route_delete_title)) },
            text = { Text(stringResource(R.string.route_delete_message, target.name)) },
            confirmButton = {
                TextButton(onClick = {
                    commit(state.copy(rules = state.rules.filterNot { it.id == target.id }))
                    deleteTarget = null
                }) { Text(stringResource(R.string.btn_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { deleteTarget = null }) {
                    Text(stringResource(R.string.btn_cancel))
                }
            }
        )
    }
}

@Composable
private fun RouteCard(
    rule: RouteRule,
    state: RouteState,
    canMoveUp: Boolean,
    canMoveDown: Boolean,
    onToggle: (Boolean) -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onMoveUp: () -> Unit,
    onMoveDown: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .alpha(if (rule.enabled || rule.isFinal) 1f else 0.55f),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        text = rule.name.ifBlank { rule.type.wire },
                        fontSize = 15.sp,
                        fontWeight = FontWeight.Bold
                    )
                    Spacer(Modifier.height(3.dp))
                    Text(
                        text = rule.conditionText(state.ruleSets),
                        fontSize = 12.sp,
                        color = RouteGrey
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = rule.action.label,
                            fontSize = 12.sp,
                            color = Color.White,
                            modifier = Modifier
                                .background(
                                    actionColor(rule.action),
                                    RoundedCornerShape(4.dp)
                                )
                                .padding(horizontal = 8.dp, vertical = 3.dp)
                        )
                        if (rule.noResolve && !rule.isFinal) {
                            Spacer(Modifier.size(8.dp))
                            Text(
                                text = stringResource(R.string.route_no_resolve_tag),
                                fontSize = 11.sp,
                                color = RouteGrey
                            )
                        }
                    }
                }
                if (rule.isFinal) {
                    Text(
                        text = stringResource(R.string.route_final_fixed),
                        fontSize = 12.sp,
                        color = RouteGrey
                    )
                } else {
                    Switch(checked = rule.enabled, onCheckedChange = onToggle)
                }
            }

            HorizontalDivider(modifier = Modifier.padding(vertical = 6.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End,
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (!rule.isFinal) {
                    IconButton(onClick = onMoveUp, enabled = canMoveUp, modifier = Modifier.size(36.dp)) {
                        Icon(Icons.Filled.KeyboardArrowUp, null)
                    }
                    IconButton(onClick = onMoveDown, enabled = canMoveDown, modifier = Modifier.size(36.dp)) {
                        Icon(Icons.Filled.KeyboardArrowDown, null)
                    }
                } else {
                    Text(
                        text = stringResource(R.string.route_final_note),
                        fontSize = 11.sp,
                        color = RouteGrey,
                        modifier = Modifier.weight(1f)
                    )
                }
                Spacer(Modifier.weight(1f))
                IconButton(onClick = onEdit, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.Filled.Edit, stringResource(R.string.action_edit))
                }
                if (!rule.isFinal) {
                    IconButton(onClick = onDelete, modifier = Modifier.size(36.dp)) {
                        Icon(Icons.Filled.Delete, stringResource(R.string.action_delete))
                    }
                }
            }
        }
    }
}
