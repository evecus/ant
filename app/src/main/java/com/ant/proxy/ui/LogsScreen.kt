package com.ant.proxy.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ant.proxy.AntVpnService
import com.ant.proxy.R
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(onBack: () -> Unit, modifier: Modifier = Modifier) {
    var logText by remember { mutableStateOf(AntVpnService.snapshotLogs()) }
    val scrollState = rememberScrollState()

    // 与原 LogsActivity 一致：每 500ms 拉取新增日志并追加（最多保留 32k 字符）
    LaunchedEffect(Unit) {
        while (true) {
            delay(500)
            val newLogs = AntVpnService.consumeLogs()
            if (newLogs.isNotEmpty()) {
                logText = (logText + newLogs).takeLast(32_000)
            }
        }
    }

    // 新日志到达后自动滚到底部；等一帧确保 maxValue 已随文本更新
    LaunchedEffect(logText) {
        withFrameNanos { }
        scrollState.scrollTo(scrollState.maxValue)
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.title_logs)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back)
                        )
                    }
                },
                actions = {
                    TextButton(onClick = { logText = "" }) {
                        Text(stringResource(R.string.btn_clear))
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .fillMaxSize()
                .verticalScroll(scrollState)
                .padding(horizontal = 12.dp, vertical = 8.dp)
        ) {
            if (logText.isEmpty()) {
                Text(
                    text = stringResource(R.string.logs_empty),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    fontSize = 12.sp
                )
            } else {
                SelectionContainer {
                    Text(
                        text = logText,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}
