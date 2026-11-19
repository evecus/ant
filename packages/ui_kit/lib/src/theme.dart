/// 浅色主题（Material 3）— 对齐 Go 版 React 前端的视觉基调
/// （index.css :root 浅色令牌）。
library;

import 'package:flutter/material.dart';

import 'palette.dart';

/// 构建 ant GUI 桌面浅色主题。
ThemeData buildAntTheme() {
  const scheme = ColorScheme.light(
    primary: AntPalette.accent,
    onPrimary: Colors.white,
    surface: AntPalette.bgPanel,
    onSurface: AntPalette.text,
    surfaceContainerHighest: AntPalette.bgInput,
    outline: AntPalette.border,
    error: AntPalette.red,
  );
  return ThemeData(
    useMaterial3: true,
    colorScheme: scheme,
    scaffoldBackgroundColor: AntPalette.bg,
    canvasColor: AntPalette.bgPanel,
    fontFamily: 'Microsoft YaHei UI',
    textTheme: const TextTheme(
      bodyMedium: TextStyle(color: AntPalette.text, fontSize: 13),
      bodySmall: TextStyle(color: AntPalette.textMid, fontSize: 12),
      titleMedium: TextStyle(color: AntPalette.text, fontSize: 14),
    ),
    dividerColor: AntPalette.border,
    splashFactory: InkSparkle.splashFactory,
    dropdownMenuTheme: DropdownMenuThemeData(
      menuStyle: MenuStyle(
        backgroundColor: const WidgetStatePropertyAll(AntPalette.bgPanel),
        surfaceTintColor: const WidgetStatePropertyAll(Colors.transparent),
        side: const WidgetStatePropertyAll(
          BorderSide(color: AntPalette.border),
        ),
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: AntPalette.bgInput,
      hintStyle: const TextStyle(color: AntPalette.textFaint),
      contentPadding:
          const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AntPalette.border),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AntPalette.border),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(8),
        borderSide: const BorderSide(color: AntPalette.accent),
      ),
      isDense: true,
    ),
    menuButtonTheme: MenuButtonThemeData(
      style: MenuItemButton.styleFrom(
        foregroundColor: AntPalette.text,
        minimumSize: const Size(140, 34),
        textStyle: const TextStyle(fontSize: 13),
      ),
    ),
    switchTheme: SwitchThemeData(
      trackColor: WidgetStateProperty.resolveWith(
        (s) => s.contains(WidgetState.selected)
            ? AntPalette.accent
            : AntPalette.bgHover,
      ),
      thumbColor: WidgetStateProperty.resolveWith(
        (s) => s.contains(WidgetState.selected)
            ? Colors.white
            : AntPalette.textDim,
      ),
    ),
    checkboxTheme: CheckboxThemeData(
      fillColor: WidgetStateProperty.resolveWith(
        (s) => s.contains(WidgetState.selected)
            ? AntPalette.accent
            : Colors.transparent,
      ),
      side: const BorderSide(color: AntPalette.textDim),
    ),
    tooltipTheme: const TooltipThemeData(
      decoration: BoxDecoration(color: AntPalette.text),
      textStyle: TextStyle(color: AntPalette.bgPanel, fontSize: 12),
      waitDuration: Duration(milliseconds: 400),
    ),
    dialogTheme: const DialogThemeData(
      backgroundColor: AntPalette.bgPanel,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.all(Radius.circular(14)),
        side: BorderSide(color: AntPalette.border),
      ),
    ),
    popupMenuTheme: const PopupMenuThemeData(
      color: AntPalette.bgPanel,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.all(Radius.circular(12)),
        side: BorderSide(color: AntPalette.border),
      ),
    ),
  );
}
