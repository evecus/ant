/// Windows 系统代理 — 移植自 Go: backend/sysproxy/windows.go
///
/// 用 reg.exe 读写注册表（免 FFI 依赖），InternetSetOption（wininet.dll）
/// 通过 dart:ffi 通知系统代理变更（对应 Go 的 notify_windows.go）。
library;

import 'dart:ffi';
import 'dart:io';

/// 非 Windows 平台抛出此异常。
class SysProxyUnsupported implements Exception {
  final String message;
  SysProxyUnsupported([this.message = '当前平台不支持系统代理']);

  @override
  String toString() => message;
}

const String _regPath =
    r'Software\Microsoft\Windows\CurrentVersion\Internet Settings';

/// bypass list: 常见 LAN/回环/内网网段
const String _defaultBypass = 'localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;'
    '172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;'
    '172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>';

/// 通知 WinInet 代理设置已变更（对应 Go 的 notifyProxyChange）。
void _notifyProxyChange() {
  // BOOL InternetSetOption(HWND, DWORD dwOption, LPVOID, DWORD);
  // INTERNET_OPTION_SETTINGS_CHANGED = 39, INTERNET_OPTION_REFRESH = 37
  final wininet = DynamicLibrary.open('wininet.dll');
  final internetSetOption = wininet.lookupFunction<
      Int32 Function(Pointer<Void>, Uint32, Pointer<Void>, Uint32),
      int Function(Pointer<Void>, int, Pointer<Void>, int)>('InternetSetOptionW');
  internetSetOption(nullptr, 39, nullptr, 0);
  internetSetOption(nullptr, 37, nullptr, 0);
}

Future<void> _regAdd(String valueName, String type, String data) async {
  final r = await Process.run('reg', [
    'add',
    'HKCU\\$_regPath',
    '/v',
    valueName,
    '/t',
    type,
    '/d',
    data,
    '/f',
  ]);
  if (r.exitCode != 0) {
    throw StateError('写入注册表失败: ${r.stderr}');
  }
}

/// Windows 系统代理管理器。
class SysProxyManager {
  /// 开启系统代理：ProxyEnable=1, ProxyServer=host:port, 写入默认 bypass。
  Future<void> enable(String host, int port) async {
    if (!Platform.isWindows) throw SysProxyUnsupported();
    await _regAdd('ProxyEnable', 'REG_DWORD', '1');
    await _regAdd('ProxyServer', 'REG_SZ', '$host:$port');
    await _regAdd('ProxyOverride', 'REG_SZ', _defaultBypass);
    _notifyProxyChange();
  }

  /// 关闭系统代理：ProxyEnable=0。
  Future<void> disable() async {
    if (!Platform.isWindows) throw SysProxyUnsupported();
    await _regAdd('ProxyEnable', 'REG_DWORD', '0');
    _notifyProxyChange();
  }

  /// 读取注册表判断系统代理当前是否开启。
  Future<bool> isEnabled() async {
    if (!Platform.isWindows) return false;
    final r = await Process.run('reg', [
      'query',
      'HKCU\\$_regPath',
      '/v',
      'ProxyEnable',
    ]);
    if (r.exitCode != 0) return false;
    final m = RegExp(r'ProxyEnable\s+REG_DWORD\s+(\S+)')
        .firstMatch(r.stdout.toString());
    if (m == null) return false;
    final v = int.tryParse(m.group(1)!.replaceAll('0x', ''), radix: 16) ??
        int.tryParse(m.group(1)!) ??
        0;
    return v != 0;
  }
}
