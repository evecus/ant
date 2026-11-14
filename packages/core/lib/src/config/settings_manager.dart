/// 设置文件读写管理 — 移植自 Go: backend/config/manager.go（Manager / NewManager /
/// Load / Save，settingsAlias 的 bool 字段存在性探测在 Settings.fromJson 内完成）。
library;

import 'dart:convert';
import 'dart:io';

import '../parsing/common.dart';
import 'settings.dart';

/// SettingsManager 负责把 [Settings] 读写到 settings.json。
class SettingsManager {
  /// 配置文件绝对路径。
  final String path;

  /// 当前设置（Load 前为全零值，与 Go 零值 struct 行为一致）。
  Settings settings;

  SettingsManager(this.path) : settings = Settings();

  /// Load 读取设置文件。
  /// 文件不存在时使用全新默认设置（对应 Go 的 os.IsNotExist 分支）；
  /// JSON 非法或读取失败抛 [ParseException]。
  void load() {
    late final String data;
    try {
      data = File(path).readAsStringSync();
    } on FileSystemException catch (e) {
      if (e.osError?.errorCode == 2) {
        // ENOENT — 文件不存在：双保险补齐任何缺省段
        settings = Settings.defaults();
        settings.applyDefaults();
        return;
      }
      throw ParseException('读取设置失败: ${e.message}');
    }
    dynamic decoded;
    try {
      decoded = jsonDecode(data);
    } on FormatException {
      throw ParseException('settings.json 解析失败: invalid json');
    }
    if (decoded is! Map) {
      throw ParseException('settings.json 解析失败: invalid json');
    }
    settings = Settings.fromJson(decoded.cast<String, dynamic>());
    settings.applyDefaults();
  }

  /// Save 校验并写盘（JSON 缩进两空格，与 Go 的 MarshalIndent 一致）。
  /// 校验失败抛 [ParseException]（不写盘）。
  void save() {
    settings.validate();
    final data = const JsonEncoder.withIndent('  ').convert(settings.toJson());
    try {
      File(path).writeAsStringSync(data, flush: true);
    } on FileSystemException catch (e) {
      throw ParseException('写入设置失败: ${e.message}');
    }
  }
}
