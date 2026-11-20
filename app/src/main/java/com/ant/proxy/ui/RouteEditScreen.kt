package com.ant.proxy.ui

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ant.proxy.R
import com.ant.proxy.RouteAction
import com.ant.proxy.RouteMatchType
import com.ant.proxy.RouteRule
import com.ant.proxy.RouteState
import com.ant.proxy.RouteStore

private val EditBlue = Color(0xFF0E9CE6)
private val EditGrey = Color(0xFF9AA0A6)

/** 新增 / 编辑单条路由规则。字段只包含 ant 真正支持的匹配方式与三种动作。 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RouteEditScreen(
    ruleId: String?,
    state: RouteState,
    onSaved: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val existing = remember(ruleId, state) {
        ruleId?.let { id -> state.rules.firstOrNull { it.id == id } }
    }
    val isFinal = existing?.isFinal == true

    var name by remember { mutableStateOf(existing?.name.orEmpty()) }
    var type by remember {
        mutableStateOf(existing?.type ?: RouteMatchType.DOMAIN_SUFFIX)
    }
    var value by remember { mutableStateOf(existing?.value.orEmpty()) }
    var action by remember { mutableStateOf(existing?.action ?: RouteAction.PROXY) }
    var noResolve by remember { mutableStateOf(existing?.noResolve ?: false) }
    var typeMenu by remember { mutableStateOf(false) }
    var setMenu by remember { mutableStateOf(false) }

    fun save() {
        if (name.isBlank()) {
            Toast.makeText(context, R.string.route_err_name, Toast.LENGTH_SHORT).show()
            return
        }
        if (!isFinal) {
            if (value.isBlank()) {
                Toast.makeText(context, R.string.route_err_value, Toast.LENGTH_SHORT).show()
                return
            }
            if (value.contains(',') || value.contains('\n') || value.contains('\r')) {
                Toast.makeText(context, R.string.route_err_comma, Toast.LENGTH_SHORT).show()
                return
            }
            if (type == RouteMatchType.RULE_SET &&
                state.ruleSets.none { it.id == value }
            ) {
                Toast.makeText(context, R.string.route_err_ruleset, Toast.LENGTH_SHORT).show()
                return
            }
        }
        val rule = (existing ?: RouteRule()).copy(
            name = name.trim(),
            type = if (isFinal) RouteMatchType.MATCH else type,
            value = if (isFinal) "" else value.trim(),
            action = action,
            noResolve = !isFinal && noResolve && type.supportsNoResolve,
            enabled = true
        )
        val nextRules = if (existing != null) {
            state.rules.map { if (it.id == existing.id) rule else it }
        } else {
            // 新规则插到 MATCH 兜底之前
            val list = state.rules.toMutableList()
            list.add(list.lastIndex, rule)
            list
        }
        RouteStore.save(context, state.copy(rules = nextRules))
        onSaved()
        Toast.makeText(context, R.string.route_saved, Toast.LENGTH_SHORT).show()
        onBack()
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        stringResource(
                            if (existing == null) R.string.title_new_route
                            else R.string.title_edit_route
                        )
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.action_back))
                    }
                },
                actions = {
                    TextButton(onClick = { save() }) {
                        Text(stringResource(R.string.btn_save), color = Color.White)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = EditBlue,
                    titleContentColor = Color.White,
                    navigationIconContentColor = Color.White,
                    actionIconContentColor = Color.White
                )
            )
        }
    ) { innerPadding ->
        AdaptiveContentBox(modifier = Modifier.padding(innerPadding), maxWidth = 680.dp) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 12.dp)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
            ) {
                Column(Modifier.padding(14.dp)) {
                    OutlinedTextField(
                        value = name,
                        onValueChange = { name = it },
                        label = { Text(stringResource(R.string.route_name_label)) },
                        placeholder = { Text(stringResource(R.string.route_name_hint)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(Modifier.height(16.dp))
                    Text(
                        stringResource(R.string.route_match_type),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = EditBlue
                    )
                    Spacer(Modifier.height(4.dp))
                    if (isFinal) {
                        Text(
                            text = RouteMatchType.MATCH.label,
                            fontSize = 15.sp,
                            modifier = Modifier.padding(vertical = 8.dp)
                        )
                    } else {
                        OutlinedButton(onClick = { typeMenu = true }, modifier = Modifier.fillMaxWidth()) {
                            Text(type.label, modifier = Modifier.weight(1f))
                            Icon(Icons.Filled.ArrowDropDown, null)
                        }
                        DropdownMenu(
                            expanded = typeMenu,
                            onDismissRequest = { typeMenu = false }
                        ) {
                            RouteMatchType.entries
                                .filter { it != RouteMatchType.MATCH }
                                .forEach { t ->
                                    DropdownMenuItem(
                                        text = { Text("${t.label}  ·  ${t.wire}") },
                                        onClick = {
                                            type = t
                                            if (t == RouteMatchType.RULE_SET &&
                                                state.ruleSets.none { it.id == value }
                                            ) {
                                                value = ""
                                            }
                                            typeMenu = false
                                        }
                                    )
                                }
                        }
                    }

                    Spacer(Modifier.height(16.dp))
                    if (type == RouteMatchType.RULE_SET && !isFinal) {
                        Text(
                            stringResource(R.string.route_ruleset_label),
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Bold,
                            color = EditBlue
                        )
                        Spacer(Modifier.height(4.dp))
                        val chosen = state.ruleSets.firstOrNull { it.id == value }
                        OutlinedButton(onClick = { setMenu = true }, modifier = Modifier.fillMaxWidth()) {
                            Text(
                                chosen?.name ?: stringResource(R.string.route_ruleset_label),
                                modifier = Modifier.weight(1f)
                            )
                            Icon(Icons.Filled.ArrowDropDown, null)
                        }
                        DropdownMenu(expanded = setMenu, onDismissRequest = { setMenu = false }) {
                            state.ruleSets.forEach { s ->
                                DropdownMenuItem(
                                    text = { Text("${s.name}  ·  ${s.id}") },
                                    onClick = { value = s.id; setMenu = false }
                                )
                            }
                        }
                    } else if (!isFinal) {
                        OutlinedTextField(
                            value = value,
                            onValueChange = { value = it },
                            label = { Text(stringResource(R.string.route_value_label)) },
                            placeholder = { Text(type.hint) },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }

                    if (type.supportsNoResolve && !isFinal) {
                        Spacer(Modifier.height(12.dp))
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(stringResource(R.string.route_no_resolve), fontSize = 13.sp)
                                Text(
                                    stringResource(R.string.route_no_resolve_note),
                                    fontSize = 11.sp,
                                    color = EditGrey
                                )
                            }
                            Switch(checked = noResolve, onCheckedChange = { noResolve = it })
                        }
                    }
                }
            }

            Spacer(Modifier.height(14.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
            ) {
                Column(Modifier.padding(14.dp)) {
                    Text(
                        stringResource(R.string.route_action_title),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Bold,
                        color = EditBlue
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        RouteAction.entries.forEach { a ->
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                RadioButton(
                                    selected = action == a,
                                    onClick = { action = a }
                                )
                                Spacer(Modifier.width(2.dp))
                                Text(a.label, fontSize = 14.sp)
                            }
                        }
                    }
                }
            }

            if (isFinal) {
                Spacer(Modifier.height(14.dp))
                Text(
                    stringResource(R.string.route_final_note),
                    fontSize = 12.sp,
                    color = EditGrey
                )
            }
        }
        }
    }
}

