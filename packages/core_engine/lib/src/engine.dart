/// 引擎控制抽象 — 按「启动收配置内容与路径参数」设计：
/// 桌面端 = 拉起 ant 子进程；内核只有 ant 一种，不再有分支。
library;

import 'core_process.dart';

/// 内核标识（单内核 ant，与 settings.dart 的 coreAnt 常量一致）。
abstract final class CoreTypes {
  static const ant = 'ant';
}

/// 引擎启动参数。
class EngineRunConfig {
  /// 内核类型（恒为 "ant"，保留字段供日志/校验，不再有内核选择）。
  final String core;

  /// 内核可执行文件路径（bin/ant.exe）。
  final String binPath;

  /// 运行目录（存放配置与规则文件的目录，桌面端为 <exe>/run）。
  final String runDir;

  /// 已写好的配置文件路径（run/config.yaml）。
  final String configPath;

  const EngineRunConfig({
    required this.core,
    required this.binPath,
    required this.runDir,
    required this.configPath,
  });
}

/// 引擎控制接口。桌面端 = 子进程。
abstract interface class Engine {
  Future<void> start(EngineRunConfig config);
  Future<void> stop();
  ProcessStatus get status;
  Stream<String> get logLines;
  Stream<ProcessStatus> get statusChanges;
  List<String> get logSnapshot;

  /// 更新日志保留行数（对齐 Go: sbProcess.SetMaxLog，设置保存后立即生效）。
  void setMaxLog(int maxLog);
}

/// 桌面端引擎实现：拉起 ant 子进程。
/// 内核参数对齐 ant 的 CLI：`ant -c <configPath>`。
/// ant 的 -c/--config 与 -d/--dir 互斥；配置里的 rule-provider 路径、
/// cache-file 全部写成绝对路径，因此不需要 -d 的目录解析。
class DesktopEngine implements Engine {
  final CoreProcess _process;

  DesktopEngine({int maxLog = 500}) : _process = CoreProcess(maxLog: maxLog);

  @override
  Future<void> start(EngineRunConfig config) {
    if (config.core != CoreTypes.ant) {
      throw ArgumentError('未知内核类型: ${config.core}');
    }
    final args = ['-c', config.configPath];
    return _process.start(config.binPath, args, label: config.core);
  }

  @override
  Future<void> stop() => _process.stop();

  @override
  ProcessStatus get status => _process.getStatus();

  @override
  Stream<String> get logLines => _process.logLines;

  @override
  Stream<ProcessStatus> get statusChanges => _process.statusChanges;

  @override
  List<String> get logSnapshot => _process.getLog();

  @override
  void setMaxLog(int maxLog) => _process.setMaxLog(maxLog);
}
