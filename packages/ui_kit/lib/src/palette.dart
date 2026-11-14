/// 调色板 — 对齐 Go 版 React 前端 App.css（index.css）的浅色设计令牌
/// （浅色为默认主题，:root 变量值一一对应）。
library;

import 'package:flutter/material.dart';

/// ant GUI 浅色调色板（对应 Go 版 index.css 的 :root）。
abstract final class AntPalette {
  /// 主背景（--bg-0，窗口底色）。
  static const bg = Color(0xFFf7f8fc);

  /// 顶栏 / 底栏 / 卡片（--bg-1）。
  static const bgPanel = Color(0xFFffffff);

  /// 次级面板 / 弹窗体 / 输入框（--bg-2）。
  static const bgInput = Color(0xFFf1f2f9);

  /// hover / 嵌入块（--bg-3）。
  static const bgHover = Color(0xFFe7e9f4);

  /// 边框（--border）。
  static const border = Color(0xFFe4e6f1);

  /// 强边框（--border-light）。
  static const borderLight = Color(0xFFd2d6e8);

  /// 主文字（--text-0）。
  static const text = Color(0xFF191c2b);

  /// 次级文字（--text-1）。
  static const textMid = Color(0xFF4c5270);

  /// 弱文字（--text-2）。
  static const textDim = Color(0xFF878da9);

  /// 占位/最弱文字（--text-3）。
  static const textFaint = Color(0xFFc3c7dd);

  /// 主题强调色（--accent）。
  static const accent = Color(0xFF5b7cfa);

  /// 强调色浅底（--accent-dim）。
  static const accentDim = Color(0x1C5b7cfa); // 11% alpha

  /// 成功/绿色（--green）。
  static const green = Color(0xFF1fb76a);

  /// 绿色浅底（--green-dim）。
  static const greenDim = Color(0x1F1fb76a); // 12% alpha

  /// 危险/红色（--red）。
  static const red = Color(0xFFe5484d);

  /// 红色浅底（--red-dim）。
  static const redDim = Color(0x1Fe5484d); // 12% alpha

  /// 警告/黄色（--yellow）。
  static const yellow = Color(0xFFc98a04);

  /// 黄色浅底（--yellow-dim）。
  static const yellowDim = Color(0x24de9a06); // 14% alpha

  /// 橙色。
  static const orange = Color(0xFFf97316);

  /// 青色。
  static const cyan = Color(0xFF22d3ee);
}
