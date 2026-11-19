/// 内核子进程管理 — 移植自 Go: backend/singbox/process.go + proc_windows.go
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// 内核进程状态。
class ProcessStatus {
  final bool running;
  final int pid;
  final String error;

  const ProcessStatus({
    this.running = false,
    this.pid = 0,
    this.error = '',
  });

  Map<String, dynamic> toJson() => {
        'running': running,
        'pid': pid,
        if (error.isNotEmpty) 'error': error,
      };
}

final RegExp _ansiEscape = RegExp(r'\x1b\[[0-9;]*[a-zA-Z]');

String _stripAnsi(String s) => s.replaceAll(_ansiEscape, '');

String _now() {
  final t = DateTime.now();
  String two(int v) => v.toString().padLeft(2, '0');
  return '${two(t.hour)}:${two(t.minute)}:${two(t.second)}';
}

/// 管理一个内核子进程：启动/停止、日志环形缓冲、状态流。
/// 移植自 Go 的 singbox.Process；Go 的 mutex 在 Dart VM 单线程下天然互斥。
class CoreProcess {
  Process? _process;
  String _label = '';
  ProcessStatus _status = const ProcessStatus();
  final List<String> _log = [];
  int _maxLog;

  final _logController = StreamController<String>.broadcast();
  final _statusController = StreamController<ProcessStatus>.broadcast();

  CoreProcess({int maxLog = 500}) : _maxLog = maxLog < 1 ? 500 : maxLog;

  /// 内核日志行（增量）。
  Stream<String> get logLines => _logController.stream;

  /// 进程状态变化。
  Stream<ProcessStatus> get statusChanges => _statusController.stream;

  /// 更新日志保留行数并按需裁剪已有日志。
  void setMaxLog(int maxLog) {
    if (maxLog <= 0) maxLog = 500;
    _maxLog = maxLog;
    if (_log.length > _maxLog) {
      _log.removeRange(0, _log.length - _maxLog);
    }
  }

  /// 启动内核进程。
  /// binPath 为内核二进制路径；args 为完整启动参数（含配置文件路径）。
  /// label 仅用于日志显示（如 "sing-box" / "mihomo"）。
  Future<void> start(String binPath, List<String> args,
      {String label = ''}) async {
    if (_process != null) {
      throw StateError('核心已在运行');
    }
    _label = label.isEmpty ? '核心' : label;

    Process process;
    try {
      process = await Process.start(binPath, args,
          mode: ProcessStartMode.normal); // GUI 宿主下无控制台窗口
    } catch (e) {
      throw StateError('启动失败: $e');
    }
    _process = process;
    _log.clear();
    _status = ProcessStatus(running: true, pid: process.pid);
    _statusController.add(_status);
    _appendLog('[${_now()}] $_label 已启动 PID=${process.pid} 参数=$args');

    // capture stdout+stderr
    _pumpStream(process.stdout);
    _pumpStream(process.stderr);

    // watch process：防止旧进程 watcher 在快速重启后覆盖新进程状态
    // （Dart 中通过比较 _process 是否仍是自己实现）
    unawaited(() async {
      final code = await process.exitCode;
      if (!identical(_process, process)) return;
      if (code != 0) {
        _appendLog('[${_now()}] $_label 退出: exit code $code');
        _status = ProcessStatus(running: false, error: 'exit code $code');
      } else {
        _appendLog('[${_now()}] $_label 正常退出');
        _status = const ProcessStatus(running: false);
      }
      _process = null;
      _statusController.add(_status);
    }());
  }

  void _pumpStream(Stream<List<int>> stream) {
    stream
        .transform(const SystemEncoding().decoder)
        .transform(const LineSplitter())
        .listen(_appendLog, onError: (Object e) {/* 进程退出时管道关闭，忽略 */});
  }

  /// 停止内核进程并等待其真正退出（超时 3 秒）。
  /// 保证 Stop 返回后端口/TUN 已释放，紧接的 Start 不会绑端口失败。
  Future<void> stop() async {
    final p = _process;
    if (p == null) {
      _status = const ProcessStatus(running: false);
      _statusController.add(_status);
      return;
    }
    _process = null;
    _status = const ProcessStatus(running: false);
    _statusController.add(_status);
    // Windows 上 kill() 即 TerminateProcess（对应 Go 的 Process.Kill）
    try {
      p.kill();
    } catch (e) {
      throw StateError('停止失败: $e');
    }
    try {
      await p.exitCode.timeout(const Duration(seconds: 3));
    } on TimeoutException {
      throw StateError('等待核心退出超时，进程可能仍在运行');
    }
    _appendLog('[${_now()}] $_label 已停止');
  }

  ProcessStatus getStatus() => _status;

  List<String> getLog() => List<String>.unmodifiable(_log);

  void _appendLog(String line) {
    line = _stripAnsi(line);
    _log.add(line);
    if (_log.length > _maxLog) {
      _log.removeRange(0, _log.length - _maxLog);
    }
    _logController.add(line);
  }
}
