/// Windows 系统能力 — 移植自 Go: backend/winutil/winutil_windows.go
///
/// 管理员检测（IsUserAnAdmin FFI）、UAC 提权重启（PowerShell Start-Process
/// runas，替代 Go 的 ShellExecute）、开机自启（注册表 Run 键 / 计划任务）。
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

class WinUtilException implements Exception {
  final String message;
  WinUtilException(this.message);

  @override
  String toString() => message;
}

final DynamicLibrary _shell32 = DynamicLibrary.open('shell32.dll');

/// BOOL IsUserAnAdmin(void); —— Vista 后标记 deprecated 但一直可用。
final int Function() _isUserAnAdmin = _shell32
    .lookupFunction<Int32 Function(), int Function()>('IsUserAnAdmin');

/// 报告当前进程是否以管理员（UAC 提权）身份运行。
bool isAdmin() {
  if (!Platform.isWindows) return false;
  try {
    return _isUserAnAdmin() != 0;
  } catch (_) {
    return false;
  }
}

/// 以管理员身份启动 exe（触发 UAC 授权框），等待用户响应。
/// 用户取消授权 / 启动失败时抛 [WinUtilException]。
Future<void> launchElevated(String exe) async {
  if (!Platform.isWindows) {
    throw WinUtilException('当前平台不支持提权重启');
  }
  // PowerShell Start-Process -Verb RunAs：用户取消 UAC 时退出码非 0。
  // 命令体走 -EncodedCommand（UTF-16LE base64），规避引号/空格转义问题。
  final ps = "Start-Process -FilePath '$exe' -Verb RunAs";
  final encoded = base64Encode(utf16LeBytes(ps));
  final r = await Process.run('powershell', [
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    encoded,
  ]).timeout(const Duration(minutes: 5), onTimeout: () {
    throw WinUtilException('等待 UAC 授权超时');
  });
  if (r.exitCode != 0) {
    throw WinUtilException('提权启动失败或授权被取消');
  }
}

List<int> utf16LeBytes(String s) {
  final out = <int>[];
  for (final unit in s.codeUnits) {
    out.add(unit & 0xff);
    out.add((unit >> 8) & 0xff);
  }
  return out;
}

// ─── 开机自启动 ───────────────────────────────────────────────────────────────

const String _runKeyPath =
    r'HKCU\Software\Microsoft\Windows\CurrentVersion\Run';
const String _taskName = 'ant GUI';
const String _silentArg = '--silent';

String _silentSuffix(bool silent) => silent ? ' $_silentArg' : '';

/// 写入当前用户注册表 Run 自启动项（普通权限路径）。
Future<void> setRegistryRun(String exe, bool silent) async {
  final r = await Process.run('reg', [
    'add',
    _runKeyPath,
    '/v',
    _taskName,
    '/t',
    'REG_SZ',
    '/d',
    '"$exe"${_silentSuffix(silent)}',
    '/f',
  ]);
  if (r.exitCode != 0) {
    throw WinUtilException('写入注册表 Run 键失败: ${r.stderr}');
  }
}

/// 删除注册表 Run 自启动项（不存在视为成功）。
Future<void> deleteRegistryRun() async {
  try {
    await Process.run('reg', ['delete', _runKeyPath, '/v', _taskName, '/f']);
  } catch (_) {
    // 不存在等情况一律视为已删除
  }
}

/// 用计划任务注册开机自启动（/RL HIGHEST，开机后仍以管理员最高权限运行——
/// 参考 v2rayN 对管理员自启动的做法）。
Future<void> createScheduledTask(String exe, bool silent) async {
  final r = await Process.run('schtasks', [
    '/Create',
    '/F',
    '/TN',
    _taskName,
    '/SC',
    'ONLOGON',
    '/RL',
    'HIGHEST',
    '/TR',
    '"$exe"${_silentSuffix(silent)}',
  ]);
  if (r.exitCode != 0) {
    throw WinUtilException('创建计划任务失败: ${r.stderr}'.trim());
  }
}

/// 删除自启动计划任务（不存在视为成功）。
Future<void> deleteScheduledTask() async {
  try {
    final r = await Process.run(
        'schtasks', ['/Delete', '/F', '/TN', _taskName]);
    if (r.exitCode != 0) {
      final out = r.stdout.toString();
      if (out.contains('does not exist') || out.contains('不存在')) return;
    }
  } catch (_) {
    // 不存在等情况一律视为已删除
  }
}
