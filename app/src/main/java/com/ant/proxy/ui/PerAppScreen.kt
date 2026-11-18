package com.ant.proxy.ui

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.graphics.drawable.toBitmap
import com.ant.proxy.AntVpnService
import com.ant.proxy.PerAppMode
import com.ant.proxy.PerAppSettings
import com.ant.proxy.PerAppStore
import com.ant.proxy.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private class AppEntry(
    val label: String,
    val pkg: String,
    val isSystem: Boolean,
    val icon: ImageBitmap?
)

private fun loadApps(context: Context, preselected: Set<String>): List<AppEntry> {
    val pm = context.packageManager
    return pm.getInstalledApplications(0)
        .filter { it.packageName != context.packageName }   // 本 App 始终留在 VPN 内，不可选
        .map { info ->
            val isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0 &&
                (info.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
            val icon = try {
                info.loadIcon(pm).toBitmap(72, 72).asImageBitmap()
            } catch (_: Exception) {
                null
            }
            AppEntry(info.loadLabel(pm).toString(), info.packageName, isSystem, icon)
        }
        // 进入页面时已选中的置顶；之后勾选不重排，避免点一下列表就跳
        .sortedWith(
            compareByDescending<AppEntry> { it.pkg in preselected }
                .thenBy { it.label.lowercase() }
        )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PerAppScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    val context = LocalContext.current
    var settings by remember { mutableStateOf(PerAppStore.load(context)) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }
    var apps by remember { mutableStateOf<List<AppEntry>?>(null) }

    LaunchedEffect(Unit) {
        val pre = settings.packages
        apps = withContext(Dispatchers.IO) { loadApps(context, pre) }
    }

    // 改动即时落盘；下次（重新）启动 VPN 时才由 AntVpnService 读取
    fun update(next: PerAppSettings) {
        settings = next
        PerAppStore.save(context, next)
    }

    val visible by remember {
        derivedStateOf {
            val q = query.trim().lowercase()
            apps.orEmpty().filter { a ->
                (showSystem || !a.isSystem || a.pkg in settings.packages) &&
                    (q.isEmpty() || a.label.lowercase().contains(q) || a.pkg.lowercase().contains(q))
            }
        }
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.perapp_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back)
                        )
                    }
                },
                actions = {
                    TextButton(
                        onClick = { update(settings.copy(packages = emptySet())) },
                        enabled = settings.packages.isNotEmpty()
                    ) { Text(stringResource(R.string.perapp_clear)) }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .padding(horizontal = 16.dp)
        ) {
            val modes = listOf(
                PerAppMode.OFF to R.string.perapp_mode_off,
                PerAppMode.ALLOW to R.string.perapp_mode_allow,
                PerAppMode.DISALLOW to R.string.perapp_mode_disallow
            )
            modes.forEach { (m, label) ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { update(settings.copy(mode = m)) },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RadioButton(selected = settings.mode == m, onClick = { update(settings.copy(mode = m)) })
                    Text(stringResource(label))
                }
            }
            Text(
                text = stringResource(
                    when (settings.mode) {
                        PerAppMode.OFF -> R.string.perapp_note_off
                        PerAppMode.ALLOW -> R.string.perapp_note_allow
                        PerAppMode.DISALLOW -> R.string.perapp_note_disallow
                    }
                ),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            if (AntVpnService.isRunning) {
                Spacer(Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.perapp_restart_hint),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.error
                )
            }

            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text(stringResource(R.string.perapp_search_hint)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    stringResource(R.string.perapp_selected_count, settings.packages.size),
                    fontSize = 13.sp
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.perapp_show_system), fontSize = 13.sp)
                    Spacer(Modifier.size(8.dp))
                    Switch(checked = showSystem, onCheckedChange = { showSystem = it })
                }
            }

            val loaded = apps
            when {
                loaded == null -> Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(24.dp),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.size(12.dp))
                    Text(stringResource(R.string.perapp_loading))
                }
                visible.isEmpty() -> Text(
                    stringResource(R.string.perapp_empty),
                    modifier = Modifier.padding(24.dp),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                    items(visible, key = { it.pkg }) { app ->
                        val checked = app.pkg in settings.packages
                        val toggle = {
                            update(
                                settings.copy(
                                    packages = if (checked) settings.packages - app.pkg
                                    else settings.packages + app.pkg
                                )
                            )
                        }
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { toggle() }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Checkbox(checked = checked, onCheckedChange = { toggle() })
                            if (app.icon != null) {
                                Image(
                                    bitmap = app.icon,
                                    contentDescription = null,
                                    modifier = Modifier.size(36.dp)
                                )
                            } else {
                                Spacer(Modifier.size(36.dp))
                            }
                            Spacer(Modifier.size(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(app.label, fontSize = 14.sp, maxLines = 1)
                                Text(
                                    app.pkg,
                                    fontSize = 11.sp,
                                    maxLines = 1,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
