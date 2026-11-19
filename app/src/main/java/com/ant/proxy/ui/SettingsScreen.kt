package com.ant.proxy.ui

import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ant.proxy.AntProcessManager
import com.ant.proxy.AppSettings
import com.ant.proxy.PerAppMode
import com.ant.proxy.PerAppStore
import com.ant.proxy.R
import com.ant.proxy.RuleSetBehavior
import com.ant.proxy.RouteStore
import com.ant.proxy.SettingsStore

private val LOG_LEVELS = listOf("debug", "info", "warn", "error")

@Composable
private fun SectionTitle(text: String) {
    Spacer(Modifier.height(22.dp))
    Text(
        text = text,
        fontSize = 15.sp,
        fontWeight = FontWeight.Bold,
        color = MaterialTheme.colorScheme.primary
    )
    Spacer(Modifier.height(8.dp))
}

@Composable
private fun SwitchRow(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(text = label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun SettingNote(text: String) {
    Spacer(Modifier.height(6.dp))
    Text(
        text = text,
        fontSize = 12.sp,
        color = MaterialTheme.colorScheme.onSurfaceVariant
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onOpenDrawer: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenPerApp: () -> Unit = {}
) {
    val context = LocalContext.current
    val prefs = remember {
        context.getSharedPreferences(AntProcessManager.SETTINGS_NAME, Context.MODE_PRIVATE)
    }
    val saved = remember { SettingsStore.load(context) }
    // fakeip-filter 引用的是规则集 id，这里取路由页当前的规则集做展示与校验
    val ruleSets = remember { RouteStore.load(context).ruleSets }

    var mtu by remember {
        mutableStateOf(
            prefs.getInt(AntProcessManager.KEY_MTU, AntProcessManager.TUN_MTU).toString()
        )
    }
    var logLevel by remember {
        mutableStateOf(prefs.getString(AntProcessManager.KEY_LOG_LEVEL, "info") ?: "info")
    }
    var ipv6 by remember { mutableStateOf(saved.ipv6) }
    var dnsMode by remember { mutableStateOf(saved.dnsMode) }
    var directDns by remember { mutableStateOf(saved.directDns) }
    var proxyDns by remember { mutableStateOf(saved.proxyDns) }
    var apiEnabled by remember { mutableStateOf(saved.apiEnabled) }
    var apiAddress by remember { mutableStateOf(saved.apiAddress) }
    var fakeipFilterMode by remember { mutableStateOf(saved.fakeipFilterMode) }
    // 丢弃已被删除或改成 IP 类的历史引用，避免用户卡在无法保存的状态
    var fakeipFilter by remember {
        mutableStateOf(
            saved.fakeipFilter.filter { id ->
                ruleSets.any { it.id == id && it.behavior != RuleSetBehavior.IP }
            }
        )
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.title_settings)) },
                navigationIcon = {
                    IconButton(onClick = onOpenDrawer) {
                        Icon(
                            Icons.Filled.Menu,
                            contentDescription = stringResource(R.string.drawer_open)
                        )
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
        ) {
            SectionTitle(stringResource(R.string.perapp_title))
            val perApp = remember { PerAppStore.load(context) }
            OutlinedButton(onClick = onOpenPerApp, modifier = Modifier.fillMaxWidth()) {
                Text(
                    when (perApp.mode) {
                        PerAppMode.OFF -> stringResource(R.string.perapp_summary_off)
                        PerAppMode.ALLOW ->
                            stringResource(R.string.perapp_summary_allow, perApp.packages.size)
                        PerAppMode.DISALLOW ->
                            stringResource(R.string.perapp_summary_disallow, perApp.packages.size)
                    }
                )
            }

            SectionTitle(stringResource(R.string.settings_section_basic))

            OutlinedTextField(
                value = mtu,
                onValueChange = { mtu = it },
                label = { Text(stringResource(R.string.settings_mtu_label)) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            SectionTitle(stringResource(R.string.settings_loglevel_label))
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                LOG_LEVELS.forEach { level ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        RadioButton(
                            selected = logLevel == level,
                            onClick = { logLevel = level }
                        )
                        Text(level, fontSize = 12.sp)
                    }
                }
            }

            SectionTitle(stringResource(R.string.settings_section_network))
            SwitchRow(
                label = stringResource(R.string.settings_ipv6),
                checked = ipv6,
                onCheckedChange = { ipv6 = it }
            )
            SettingNote(stringResource(R.string.settings_ipv6_note))

            SectionTitle(stringResource(R.string.settings_section_dns))
            Text(stringResource(R.string.settings_dns_mode_label), fontSize = 14.sp)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                AppSettings.DNS_MODES.forEach { mode ->
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        RadioButton(
                            selected = dnsMode == mode,
                            onClick = { dnsMode = mode }
                        )
                        Text(mode, fontSize = 12.sp)
                    }
                }
            }
            SettingNote(stringResource(R.string.settings_dns_mode_note))

            // fakeip 专属：过滤模式 + 引用规则集。redir-host 时整块隐藏。
            if (dnsMode == "fakeip") {
                Spacer(Modifier.height(16.dp))
                Text(
                    stringResource(R.string.settings_fakeip_filter_mode_label),
                    fontSize = 14.sp
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    AppSettings.FAKEIP_FILTER_MODES.forEach { mode ->
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            RadioButton(
                                selected = fakeipFilterMode == mode,
                                onClick = { fakeipFilterMode = mode }
                            )
                            Text(
                                text = if (mode == "blacklist")
                                    stringResource(R.string.settings_fakeip_blacklist)
                                else stringResource(R.string.settings_fakeip_whitelist),
                                fontSize = 12.sp
                            )
                        }
                    }
                }
                SettingNote(stringResource(R.string.settings_fakeip_filter_mode_note))

                Spacer(Modifier.height(14.dp))
                Text(stringResource(R.string.settings_fakeip_filter_label), fontSize = 14.sp)
                Spacer(Modifier.height(4.dp))
                ruleSets.forEach { rs ->
                    // ant 只允许 domain / classical 参与 fakeip 过滤；IP 类列出但禁用
                    val selectable = rs.behavior != RuleSetBehavior.IP
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Checkbox(
                            checked = fakeipFilter.contains(rs.id),
                            onCheckedChange = { on ->
                                fakeipFilter = if (on) (fakeipFilter + rs.id).distinct()
                                else fakeipFilter - rs.id
                            },
                            enabled = selectable
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = rs.name.ifBlank { rs.id },
                                fontSize = 13.sp,
                                color = if (selectable) MaterialTheme.colorScheme.onSurface
                                else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Text(
                                text = if (selectable) rs.id
                                else stringResource(R.string.settings_fakeip_ip_disabled),
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                SettingNote(stringResource(R.string.settings_fakeip_filter_note))
            }

            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = directDns,
                onValueChange = { directDns = it },
                label = { Text(stringResource(R.string.settings_direct_dns_label)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                value = proxyDns,
                onValueChange = { proxyDns = it },
                label = { Text(stringResource(R.string.settings_proxy_dns_label)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            SettingNote(stringResource(R.string.settings_dns_hint))

            SectionTitle(stringResource(R.string.settings_section_api))
            SwitchRow(
                label = stringResource(R.string.settings_api_enabled),
                checked = apiEnabled,
                onCheckedChange = { apiEnabled = it }
            )
            if (apiEnabled) {
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = apiAddress,
                    onValueChange = { apiAddress = it },
                    label = { Text(stringResource(R.string.settings_api_address_label)) },
                    placeholder = { Text(AppSettings.DEFAULT_API_ADDRESS) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                SettingNote(stringResource(R.string.settings_api_address_note))
            }
            SettingNote(stringResource(R.string.settings_api_note))

            Spacer(Modifier.height(32.dp))
            Button(
                onClick = {
                    val value = mtu.toIntOrNull()
                    val candidate = AppSettings(
                        ipv6 = ipv6,
                        dnsMode = dnsMode,
                        directDns = directDns,
                        proxyDns = proxyDns,
                        apiEnabled = apiEnabled,
                        apiAddress = apiAddress,
                        fakeipFilterMode = fakeipFilterMode,
                        fakeipFilter = fakeipFilter
                    )
                    val dnsError = candidate.validate(ruleSets)
                    when {
                        value == null || value < 576 || value > 10000 ->
                            Toast.makeText(
                                context,
                                R.string.settings_mtu_invalid,
                                Toast.LENGTH_SHORT
                            ).show()
                        dnsError != null ->
                            Toast.makeText(context, dnsError, Toast.LENGTH_SHORT).show()
                        else -> {
                            prefs.edit()
                                .putInt(AntProcessManager.KEY_MTU, value)
                                .putString(AntProcessManager.KEY_LOG_LEVEL, logLevel)
                                .apply()
                            SettingsStore.save(context, candidate)
                            Toast.makeText(context, R.string.settings_saved, Toast.LENGTH_SHORT)
                                .show()
                            onBack()
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(stringResource(R.string.btn_save))
            }

            Spacer(Modifier.height(16.dp))
            Text(
                text = stringResource(R.string.settings_note),
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
