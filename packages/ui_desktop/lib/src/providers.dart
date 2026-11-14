/// Riverpod 状态层 — AntApp 单例 + 节点/分组/配置文件 AsyncNotifier +
/// 内核状态 StreamProvider + 日志 Notifier。
library;

import 'dart:async';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ant_engine/ant_engine.dart';

/// AntApp 单例 provider。
/// 必须在 ProviderScope overrides 中注入（AntApp 在 main() 中
/// 完成 init 与规则集释放后再传下来）。
final antAppProvider = Provider<AntApp>((ref) {
  throw UnimplementedError('antAppProvider 必须在应用启动时注入');
});

// ─── 设置 ────────────────────────────────────────────────────────────────────

/// 设置版本号：Settings 是可变对象，字段变化后 bump 触发依赖刷新。
/// bump 时同步读取最新的 appliedNodeID，让 appliedIdProvider 能即时刷新。
class SettingsVersion extends Notifier<int> {
  @override
  int build() => 0;

  void bump() => state++;
}

final settingsVersionProvider =
    NotifierProvider<SettingsVersion, int>(SettingsVersion.new);

/// 当前设置（读取 + 版本联动）。
/// 注意：Settings 是可变对象，ref.watch(settingsProvider) 的引用不变，
/// 下游若直接比较对象引用则不会感知字段变化。
/// 对于需要即时刷新的字段（如 appliedNodeID），请使用各自独立的派生 Provider。
final settingsProvider = Provider<Settings>((ref) {
  ref.watch(settingsVersionProvider);
  return ref.watch(antAppProvider).settings;
});

/// 当前应用的节点 ID（直接暴露为字符串值，而非从可变 Settings 对象派生）。
/// Riverpod 对 String 做值相等比较，bump 后能正确触发 UI 刷新。
final appliedIdProvider = Provider<String>((ref) {
  // 必须 watch settingsVersionProvider，使 bump() 能让本 Provider 重建；
  // 返回的是 String 值，Riverpod 通过 == 判断是否真的变化，会正确通知下游。
  ref.watch(settingsVersionProvider);
  return ref.watch(antAppProvider).settings.appliedNodeID;
});

// ─── 节点 / 分组 / 配置文件 ─────────────────────────────────────────────────

class NodesNotifier extends AsyncNotifier<List<Node>> {
  @override
  Future<List<Node>> build() async => ref.watch(antAppProvider).allNodes();

  /// 变更后刷新。
  Future<void> reload() async {
    state = await AsyncValue.guard(() async => ref.read(antAppProvider).allNodes());
  }
}

final nodesProvider =
    AsyncNotifierProvider<NodesNotifier, List<Node>>(NodesNotifier.new);

class GroupsNotifier extends AsyncNotifier<List<Group>> {
  @override
  Future<List<Group>> build() async => ref.watch(antAppProvider).allGroups();

  Future<void> reload() async {
    state =
        await AsyncValue.guard(() async => ref.read(antAppProvider).allGroups());
  }
}

final groupsProvider =
    AsyncNotifierProvider<GroupsNotifier, List<Group>>(GroupsNotifier.new);

class ConfigFilesNotifier extends AsyncNotifier<List<String>> {
  @override
  Future<List<String>> build() async =>
      ref.watch(antAppProvider).listConfigFiles();

  Future<void> reload() async {
    state = await AsyncValue.guard(
        () => ref.read(antAppProvider).listConfigFiles());
  }
}

final configFilesProvider =
    AsyncNotifierProvider<ConfigFilesNotifier, List<String>>(
        ConfigFilesNotifier.new);

/// 当前选中的分组 ID（对齐 React 版 App.jsx 的 activeGroupId：
/// 启动时显示「默认」分组；订阅拉取成功后切到新分组）。
class ActiveGroupId extends Notifier<String> {
  @override
  String build() => defaultGroupID;

  void set(String id) => state = id;
}

final activeGroupIdProvider =
    NotifierProvider<ActiveGroupId, String>(ActiveGroupId.new);

// ─── 内核状态 / 日志 ─────────────────────────────────────────────────────────

/// 内核状态流：先吐当前状态，再跟随状态变化。
final coreStatusProvider = StreamProvider<ProcessStatus>((ref) async* {
  final app = ref.watch(antAppProvider);
  yield app.coreStatus;
  await for (final s in app.coreStatusChanges) {
    yield s;
  }
});

/// 内核内部重启编排状态流：应用节点/保存设置/切换配置/TUN 与系统代理
/// 切换等动作会在内部先停核心再拉起，true 表示正处于这类编排中。
final coreRestartingProvider = StreamProvider<bool>((ref) async* {
  final app = ref.watch(antAppProvider);
  yield app.coreRestarting;
  await for (final v in app.coreRestartingChanges) {
    yield v;
  }
});

/// "启动核心"开关的显示状态：核心在跑，或正处于内部重启编排中。
/// 重启编排期间状态流会短暂经过 stopped，这里保持"运行中"外观，
/// 避免开关在视觉上关闭再开启。
final coreSwitchOnProvider = Provider<bool>((ref) {
  final running = ref.watch(coreStatusProvider).valueOrNull?.running ?? false;
  final restarting = ref.watch(coreRestartingProvider).valueOrNull ?? false;
  return running || restarting;
});

/// 日志列表：初始为快照，之后增量追加。
class LogController extends Notifier<List<String>> {
  StreamSubscription<String>? _sub;

  @override
  List<String> build() {
    final app = ref.watch(antAppProvider);
    _sub?.cancel();
    _sub = app.coreLogLines.listen(_append);
    ref.onDispose(() => _sub?.cancel());
    return List.of(app.coreLogSnapshot);
  }

  void _append(String line) {
    state = [...state, line];
  }

  /// 界面「清空」按钮：只清显示缓冲。
  void clear() => state = const [];
}

final logProvider = NotifierProvider<LogController, List<String>>(
    LogController.new);

// ─── 系统代理 / TUN ──────────────────────────────────────────────────────────

class SysProxyNotifier extends AsyncNotifier<bool> {
  @override
  Future<bool> build() => ref.watch(antAppProvider).sysProxyEnabled();

  Future<void> reload() async {
    state = await AsyncValue.guard(
        () => ref.read(antAppProvider).sysProxyEnabled());
  }
}

final sysProxyProvider =
    AsyncNotifierProvider<SysProxyNotifier, bool>(SysProxyNotifier.new);

/// TUN 开关（读自 settings.tunEnabled，与设置版本联动）。
final tunEnabledProvider = Provider<bool>(
    (ref) => ref.watch(settingsProvider).tunEnabled);

/// 当前应用的节点对象（可能为 null）。
final appliedNodeProvider = Provider<Node?>((ref) {
  final id = ref.watch(appliedIdProvider);
  if (id.isEmpty) return null;
  final nodes = ref.watch(nodesProvider).value;
  if (nodes == null) return null;
  for (final n in nodes) {
    if (n.id == id) return n;
  }
  return null;
});
