package com.ant.proxy.ui

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ant.proxy.R
import com.ant.proxy.RULESET_FORMATS
import com.ant.proxy.RuleSetBehavior
import com.ant.proxy.RuleSetItem
import com.ant.proxy.RuleSetManager
import com.ant.proxy.RuleSetSource
import com.ant.proxy.RouteMatchType
import com.ant.proxy.RouteState
import com.ant.proxy.RouteStore
import com.ant.proxy.SettingsStore
import kotlinx.coroutines.launch

private val SetBlue = Color(0xFF0E9CE6)
private val SetGrey = Color(0xFF9AA0A6)

/**
 * 规则集管理：内置两个 .ars、本地文件导入、URL 订阅、刷新与删除。
 * 删除前检查是否被路由规则或 fakeip 过滤引用，避免生成 ant 会拒绝的配置。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleSetScreen(
    state: RouteState,
    onStateChanged: (RouteState) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var showUrlDialog by remember { mutableStateOf(false) }
    var pendingUri by remember { mutableStateOf<Uri?>(null) }
    var deleteTarget by remember { mutableStateOf<RuleSetItem?>(null) }
    var refreshingId by remember { mutableStateOf<String?>(null) }

    val importLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> pendingUri = uri }

    fun commit(next: RouteState) {
        val saved = RouteStore.save(context, next)
        onStateChanged(saved)
        Toast.makeText(context, R.string.route_restart_hint, Toast.LENGTH_SHORT).show()
    }

    fun addItem(item: RuleSetItem) {
        commit(state.copy(ruleSets = state.ruleSets + item))
        Toast.makeText(context, R.string.ruleset_added, Toast.LENGTH_SHORT).show()
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.title_rulesets)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.action_back))
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = SetBlue,
                    titleContentColor = Color.White,
                    navigationIconContentColor = Color.White
                )
            )
        }
    ) { innerPadding ->
        AdaptiveContentBox(modifier = Modifier.padding(innerPadding), maxWidth = 960.dp) {
        Column(
            modifier = Modifier
                .fillMaxSize()
        ) {
            Text(
                text = stringResource(R.string.ruleset_note),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 10.dp)
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Button(
                    onClick = { showUrlDialog = true },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Filled.Link, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.size(6.dp))
                    Text(stringResource(R.string.ruleset_add_url))
                }
                Button(
                    onClick = { importLauncher.launch(arrayOf("*/*")) },
                    modifier = Modifier.weight(1f)
                ) {
                    Icon(Icons.Filled.AttachFile, null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.size(6.dp))
                    Text(stringResource(R.string.ruleset_import_file))
                }
            }

            Spacer(Modifier.height(12.dp))
            LazyVerticalGrid(
                columns = GridCells.Fixed(gridColumns(LocalWindowClass.current)),
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(
                    start = 12.dp, end = 12.dp, bottom = 24.dp
                ),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(state.ruleSets, key = { it.id }) { item ->
                    RuleSetCard(
                        item = item,
                        status = RuleSetManager.status(context, item),
                        refreshing = refreshingId == item.id,
                        onRefresh = {
                            refreshingId = item.id
                            scope.launch {
                                val msg = RuleSetManager.refresh(context, item)
                                refreshingId = null
                                Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                            }
                        },
                        onDelete = { deleteTarget = item }
                    )
                }
            }
        }
        }
    }

    if (showUrlDialog) {
        AddUrlDialog(
            onDismiss = { showUrlDialog = false },
            onConfirm = { name, url, behavior, format, interval ->
                val id = RuleSetManager.newId()
                val ext = RuleSetManager.extOf(url)
                addItem(
                    RuleSetItem(
                        id = id,
                        name = name,
                        behavior = behavior,
                        source = RuleSetSource.URL,
                        url = url,
                        format = format,
                        updateInterval = interval,
                        fileName = RuleSetManager.fileNameFor(id, ext)
                    )
                )
                showUrlDialog = false
            }
        )
    }

    val pendingDisplayName = pendingUri?.let { RuleSetManager.displayNameOf(context, it) }
    pendingUri?.let { uri ->
        val displayName = pendingDisplayName ?: "ruleset.txt"
        ImportFileDialog(
            defaultName = displayName,
            onDismiss = { pendingUri = null },
            onConfirm = { name, behavior ->
                val id = RuleSetManager.newId()
                val ext = RuleSetManager.extOf(displayName)
                val item = RuleSetItem(
                    id = id,
                    name = name,
                    behavior = behavior,
                    source = RuleSetSource.FILE,
                    format = RuleSetManager.formatOf(ext),
                    fileName = RuleSetManager.fileNameFor(id, ext)
                )
                val error = RuleSetManager.importFile(context, uri, item)
                if (error != null) {
                    Toast.makeText(context, error, Toast.LENGTH_LONG).show()
                } else {
                    addItem(item)
                    Toast.makeText(
                        context,
                        context.getString(R.string.ruleset_import_ok, item.name),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                pendingUri = null
            }
        )
    }

    deleteTarget?.let { item ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text(stringResource(R.string.ruleset_delete_title)) },
            text = { Text(stringResource(R.string.ruleset_delete_message, item.name)) },
            confirmButton = {
                TextButton(onClick = {
                    val refs = state.rules.count {
                        it.type == RouteMatchType.RULE_SET && it.value == item.id
                    }
                    // fakeip-filter 也是规则集引用，删掉会让 config.yaml 启动 fail-fast
                    val filterRefs = SettingsStore.load(context).fakeipFilter.count { it == item.id }
                    when {
                        refs > 0 -> Toast.makeText(
                            context,
                            context.getString(R.string.ruleset_delete_blocked, item.name, refs),
                            Toast.LENGTH_LONG
                        ).show()
                        filterRefs > 0 -> Toast.makeText(
                            context,
                            context.getString(R.string.ruleset_delete_blocked_filter, item.name),
                            Toast.LENGTH_LONG
                        ).show()
                        else -> {
                            RuleSetManager.deleteFile(context, item)
                            commit(state.copy(ruleSets = state.ruleSets.filterNot { it.id == item.id }))
                        }
                    }
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
private fun RuleSetCard(
    item: RuleSetItem,
    status: String,
    refreshing: Boolean,
    onRefresh: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(item.name.ifBlank { item.id }, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(3.dp))
                    Text(
                        "${item.id}  ·  ${item.behavior.wire}  ·  ${item.source.label}",
                        fontSize = 12.sp,
                        color = SetGrey
                    )
                }
                if (item.builtin) {
                    Text(
                        stringResource(R.string.ruleset_builtin_tag),
                        fontSize = 11.sp,
                        color = Color.White,
                        modifier = Modifier
                            .background(SetBlue, RoundedCornerShape(4.dp))
                            .padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }
            if (item.isRemote) {
                Spacer(Modifier.height(6.dp))
                Text(item.url, fontSize = 12.sp, color = SetGrey)
                Text(
                    if (item.updateInterval > 0) "自动更新：每 ${item.updateInterval} 小时"
                    else "自动更新：关闭",
                    fontSize = 11.sp,
                    color = SetGrey
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(status, fontSize = 12.sp, color = if (status.contains("缺失")) Color(0xFFC62828) else SetGrey)

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                if (item.isRemote) {
                    TextButton(onClick = onRefresh, enabled = !refreshing) {
                        Icon(Icons.Filled.Refresh, null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.size(4.dp))
                        Text(
                            if (refreshing) stringResource(R.string.ruleset_refreshing)
                            else stringResource(R.string.ruleset_refresh)
                        )
                    }
                }
                if (!item.builtin) {
                    IconButton(onClick = onDelete, modifier = Modifier.size(36.dp)) {
                        Icon(Icons.Filled.Delete, stringResource(R.string.action_delete))
                    }
                }
            }
        }
    }
}

/** URL 订阅表单。URL 与名称必填，format 留空交给 ant 自动识别。 */
@Composable
private fun AddUrlDialog(
    onDismiss: () -> Unit,
    onConfirm: (String, String, RuleSetBehavior, String, Int) -> Unit
) {
    val context = LocalContext.current
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var behavior by remember { mutableStateOf(RuleSetBehavior.DOMAIN) }
    var format by remember { mutableStateOf("") }
    var formatMenu by remember { mutableStateOf(false) }
    var interval by remember { mutableStateOf("24") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.ruleset_dialog_url_title)) },
        text = {
            Column(
                Modifier
                    .fillMaxWidth()
                    .widthIn(max = 520.dp)
                    .verticalScroll(rememberScrollState())
            ) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.ruleset_name_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text(stringResource(R.string.ruleset_url_label)) },
                    placeholder = { Text("https://example.com/ads.yaml") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(10.dp))
                Text(stringResource(R.string.ruleset_behavior), fontSize = 12.sp, color = SetGrey)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RuleSetBehavior.entries.forEach { b ->
                        RadioButton(selected = behavior == b, onClick = { behavior = b })
                        Text(b.label, fontSize = 12.sp)
                    }
                }
                Spacer(Modifier.height(6.dp))
                OutlinedButton(onClick = { formatMenu = true }, modifier = Modifier.fillMaxWidth()) {
                    Text(
                        if (format.isBlank()) stringResource(R.string.ruleset_format) else format,
                        modifier = Modifier.weight(1f)
                    )
                    Icon(Icons.Filled.ArrowDropDown, null)
                }
                DropdownMenu(expanded = formatMenu, onDismissRequest = { formatMenu = false }) {
                    RULESET_FORMATS.forEach { f ->
                        DropdownMenuItem(
                            text = { Text(f.ifBlank { stringResource(R.string.ruleset_format) }) },
                            onClick = { format = f; formatMenu = false }
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = interval,
                    onValueChange = { interval = it },
                    label = { Text(stringResource(R.string.ruleset_interval)) },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val trimmedName = name.trim()
                val trimmedUrl = url.trim()
                val hours = interval.toIntOrNull()
                when {
                    trimmedName.isBlank() ->
                        Toast.makeText(context, R.string.ruleset_err_name, Toast.LENGTH_SHORT).show()
                    !trimmedUrl.startsWith("http://") && !trimmedUrl.startsWith("https://") ->
                        Toast.makeText(context, R.string.ruleset_err_url, Toast.LENGTH_SHORT).show()
                    hours == null || hours < 0 ->
                        Toast.makeText(context, R.string.ruleset_err_interval, Toast.LENGTH_SHORT).show()
                    else -> onConfirm(trimmedName, trimmedUrl, behavior, format, hours)
                }
            }) { Text(stringResource(R.string.btn_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.btn_cancel)) }
        }
    )
}

/** 本地文件导入表单：文件已在 SAF 回调里选定，这里只补名称与规则类型。 */
@Composable
private fun ImportFileDialog(
    defaultName: String,
    onDismiss: () -> Unit,
    onConfirm: (String, RuleSetBehavior) -> Unit
) {
    val context = LocalContext.current
    var name by remember { mutableStateOf(defaultName.substringBeforeLast('.', defaultName)) }
    var behavior by remember { mutableStateOf(RuleSetBehavior.DOMAIN) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.ruleset_dialog_file_title)) },
        text = {
            Column(Modifier.fillMaxWidth().widthIn(max = 480.dp)) {
                Text(defaultName, fontSize = 12.sp, color = SetGrey)
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.ruleset_name_label)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(10.dp))
                Text(stringResource(R.string.ruleset_behavior), fontSize = 12.sp, color = SetGrey)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RuleSetBehavior.entries.forEach { b ->
                        RadioButton(selected = behavior == b, onClick = { behavior = b })
                        Text(b.label, fontSize = 12.sp)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val trimmed = name.trim()
                if (trimmed.isBlank()) {
                    Toast.makeText(context, R.string.ruleset_err_name, Toast.LENGTH_SHORT).show()
                } else {
                    onConfirm(trimmed, behavior)
                }
            }) { Text(stringResource(R.string.btn_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.btn_cancel)) }
        }
    )
}
