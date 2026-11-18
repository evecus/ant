package com.ant.proxy.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// 与 NekoBox 参考界面一致的亮蓝主色
private val BrandBlue = Color(0xFF0E9CE6)
private val BrandBlueContainer = Color(0xFFD3EDFB)
private val DeepBlue = Color(0xFF0B2A5B)

/** 与原 Theme.Material3.DayNight 主色一致，改为纯 Compose Material3 配色。 */
private val LightColors = lightColorScheme(
    primary = BrandBlue,
    onPrimary = Color.White,
    primaryContainer = BrandBlueContainer,
    onPrimaryContainer = DeepBlue,
    background = Color(0xFFF7F9FC),
    onBackground = Color(0xFF1A1C1E),
    surface = Color.White,
    onSurface = Color(0xFF1A1C1E)
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF90CAF9),
    onPrimary = DeepBlue,
    primaryContainer = DeepBlue,
    onPrimaryContainer = BrandBlueContainer,
    background = Color(0xFF121418),
    onBackground = Color(0xFFE3E6EA),
    surface = Color(0xFF1A1E24),
    onSurface = Color(0xFFE3E6EA)
)

@Composable
fun AfaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content
    )
}
