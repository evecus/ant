package com.ant.proxy.ui

import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ant.proxy.applyFieldChange
import com.ant.proxy.FieldKind
import com.ant.proxy.FieldSpec
import com.ant.proxy.G_ADV
import com.ant.proxy.G_AUTH
import com.ant.proxy.G_BASIC
import com.ant.proxy.G_TLS
import com.ant.proxy.G_TRANSPORT
import com.ant.proxy.K_NAME
import com.ant.proxy.K_PORT
import com.ant.proxy.K_SECURITY_MODE
import com.ant.proxy.K_SERVER
import com.ant.proxy.K_TYPE
import com.ant.proxy.NodeSchema
import com.ant.proxy.NodeStore
import com.ant.proxy.PROTOCOLS
import com.ant.proxy.ProxyNode
import com.ant.proxy.R
import com.ant.proxy.protocolDisplay
import com.ant.proxy.securityMode

private val AccentBlue = Color(0xFF0E9CE6)
private val HintGrey = Color(0xFF9AA0A6)

/** 切换协议时保留的通用字段（其余按新协议默认值重置）。 */
private val KEEP_ON_TYPE_CHANGE = setOf(
    K_NAME, K_SERVER,
    "uuid", "password", "sni", "alpn", "skip-cert-verify",
    "fingerprint", "client-fingerprint", "network",
    "ws-path", "ws-host", "xhttp-path", "xhttp-host", "xhttp-mode",
    "flow", "reality-public-key", "reality-short-id", "ech-config",
    K_SECURITY_MODE
)

/**
 * 新增 / 编辑节点。表单由 [NodeSchema.fieldsFor] 数据驱动：
 * 选中协议后自动生成对应字段，改动协议无需改 UI 代码。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeEditScreen(
    nodeId: String?,
    onSaved: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val existing = remember(nodeId) {
        nodeId?.let { id -> NodeStore.load(context).nodes.firstOrNull { it.id == id } }
    }
    var fields by remember {
        val initial = (existing?.fields ?: NodeSchema.defaults("vless")).toMutableMap()
        // 老节点（链接/订阅导入）无 security-mode：按 tls/reality key 推断补齐，
        // 让「安全配置」下拉正确显示当前模式并参与互斥显隐。
        if (!initial.containsKey(K_SECURITY_MODE)) {
            initial[K_SECURITY_MODE] = securityMode(initial)
        }
        mutableStateOf(initial.toMap())
    }
    val type = fields[K_TYPE].orEmpty().ifBlank { "vless" }

    fun update(key: String, value: String) {
        fields = applyFieldChange(fields, key, value)
    }

    fun changeType(newType: String) {
        val next = fields.filterKeys { it in KEEP_ON_TYPE_CHANGE }.toMutableMap()
        next.putAll(NodeSchema.defaults(newType))
        fields = next
    }

    fun save() {
        val node = (existing ?: ProxyNode()).copy(fields = fields)
        val error = NodeSchema.validate(node)
        if (error != null) {
            Toast.makeText(context, error, Toast.LENGTH_SHORT).show()
            return
        }
        NodeStore.upsert(context, node)
        onSaved()
        Toast.makeText(context, R.string.node_saved, Toast.LENGTH_SHORT).show()
        onBack()
    }

    val visibleSpecs = NodeSchema.fieldsFor(type).filter { it.showIf(fields) }
    val groupOrder = listOf(G_BASIC, G_AUTH, G_TRANSPORT, G_TLS, G_ADV)

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        stringResource(
                            if (existing == null) R.string.title_new_node else R.string.title_edit_node
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
                    containerColor = AccentBlue,
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
                .padding(horizontal = 14.dp, vertical = 10.dp)
        ) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
            ) {
                Column(Modifier.padding(14.dp)) {
                    Text(
                        stringResource(R.string.label_protocol),
                        fontWeight = FontWeight.Bold,
                        color = AccentBlue,
                        fontSize = 13.sp
                    )
                    Spacer(Modifier.height(10.dp))
                    SelectBox(
                        value = protocolDisplay(type),
                        options = PROTOCOLS.map { it.display },
                        onSelect = { display ->
                            PROTOCOLS.firstOrNull { it.display == display }?.let { changeType(it.key) }
                        },
                        label = stringResource(R.string.label_protocol)
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        stringResource(R.string.protocol_hint),
                        fontSize = 11.sp,
                        color = HintGrey
                    )
                }
            }

            groupOrder.forEach { group ->
                val specs = visibleSpecs.filter { it.group == group }
                if (specs.isEmpty()) return@forEach
                SectionCard(title = group) {
                    specs.forEach { spec ->
                        FieldRow(
                            spec = spec,
                            value = fields[spec.key].orEmpty(),
                            onChange = { update(spec.key, it) }
                        )
                        Spacer(Modifier.height(8.dp))
                    }
                }
            }
            Spacer(Modifier.height(80.dp))
        }
        }
    }
}

@Composable
private fun SectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.padding(14.dp)) {
            Text(title, fontWeight = FontWeight.Bold, color = AccentBlue, fontSize = 13.sp)
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
private fun FieldRow(
    spec: FieldSpec,
    value: String,
    onChange: (String) -> Unit
) {
    var showPassword by remember { mutableStateOf(false) }
    val isSecret = spec.kind == FieldKind.SECRET

    // 显式声明 composable lambda 类型，避免 if/else + null 时的类型推断歧义
    val placeholderContent: (@Composable () -> Unit)? =
        if (spec.hint.isNotEmpty()) {
            { Text(spec.hint, fontSize = 11.sp) }
        } else null
    val trailingContent: (@Composable () -> Unit)? =
        if (isSecret) {
            {
                IconButton(onClick = { showPassword = !showPassword }) {
                    Icon(
                        if (showPassword) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = null
                    )
                }
            }
        } else null

    when (spec.kind) {
        FieldKind.TOGGLE -> {
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(spec.label, fontSize = 14.sp)
                    if (spec.hint.isNotEmpty()) {
                        Text(spec.hint, fontSize = 11.sp, color = HintGrey)
                    }
                }
                Switch(checked = value == "true", onCheckedChange = { onChange(it.toString()) })
            }
        }
        FieldKind.SELECT -> {
            SelectBox(
                value = value,
                options = spec.options,
                onSelect = onChange,
                label = spec.label
            )
        }
        else -> {
            OutlinedTextField(
                value = value,
                onValueChange = onChange,
                label = {
                    Text(if (spec.required) "${spec.label} *" else spec.label, fontSize = 13.sp)
                },
                placeholder = placeholderContent,
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = when (spec.kind) {
                        FieldKind.NUMBER -> KeyboardType.Number
                        FieldKind.SECRET -> KeyboardType.Password
                        else -> KeyboardType.Text
                    }
                ),
                visualTransformation = if (isSecret && !showPassword) {
                    PasswordVisualTransformation()
                } else VisualTransformation.None,
                trailingIcon = trailingContent,
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

/** 轻量下拉选择：用透明覆盖层捕获点击，避免依赖 ExposedDropdownMenuBox 的版本差异。 */
@Composable
private fun SelectBox(
    value: String,
    options: List<String>,
    onSelect: (String) -> Unit,
    label: String
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = Modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            label = { Text(label, fontSize = 13.sp) },
            trailingIcon = { Icon(Icons.Filled.ArrowDropDown, null) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
        )
        Box(
            modifier = Modifier
                .matchParentSize()
                .clickable { expanded = true }
        )
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(if (option.isEmpty()) "（默认）" else option) },
                    onClick = { onSelect(option); expanded = false }
                )
            }
        }
    }
}
