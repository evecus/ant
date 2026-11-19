/// 顶部配置栏 — 对齐 Go 版 ConfigBar.jsx：
/// 配置文件下拉（真实文件 + 内置路由配置分组）+ 刷新/打开目录 +
/// 导入节点 / 订阅 / 清空 + 节点计数。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

import '../actions.dart';
import '../providers.dart';

class ConfigBar extends ConsumerWidget {
  final VoidCallback onImport;
  final VoidCallback onSubscription;

  const ConfigBar({
    super.key,
    required this.onImport,
    required this.onSubscription,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(settingsProvider);
    final configFiles =
        ref.watch(configFilesProvider).valueOrNull ?? const <String>[];
    final nodes = ref.watch(nodesProvider).valueOrNull ?? const [];
    const core = coreAnt;
    const extHint = 'yaml';

    final activePath = settings.activeConfigPath();
    final activeBuiltin =
        isBuiltinMode(settings.routingMode) ? settings.routingMode : '';
    final builtinItems = builtinDisplayNames();
    final realFiles =
        configFiles.where((f) => parseBuiltinName(f) == null).toList();

    // 内置模式激活时回显对应的内置配置项；否则回显选中的真实配置文件
    final selectedName = activeBuiltin.isNotEmpty
        ? (builtinDisplayName(activeBuiltin) ?? '')
        : activePath;
    final value =
        configFiles.contains(selectedName) ? selectedName : '';

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
      decoration: const BoxDecoration(
        color: AntPalette.bgPanel,
        border: Border(bottom: BorderSide(color: AntPalette.border)),
      ),
      child: Row(
        children: [
          // ── 配置文件区域 ──
          Expanded(
            child: Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
              decoration: BoxDecoration(
                color: AntPalette.bgInput,
                border: Border.all(color: AntPalette.border),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  const Icon(Icons.settings_ethernet,
                      size: 14, color: AntPalette.accent),
                  const SizedBox(width: 8),
                  Expanded(
                    child: DropdownButtonFormField<String>(
                      initialValue: value.isEmpty ? null : value,
                      isDense: true,
                      isExpanded: true,
                      icon: const Icon(Icons.keyboard_arrow_down,
                          size: 18, color: AntPalette.textDim),
                      decoration: const InputDecoration(
                        filled: false,
                        border: InputBorder.none,
                        enabledBorder: InputBorder.none,
                        focusedBorder: InputBorder.none,
                        contentPadding: EdgeInsets.zero,
                        isCollapsed: true,
                      ),
                      hint: Text(
                        configFiles.isEmpty
                            ? 'configs 目录为空，请放入 $extHint 配置…'
                            : (value.isEmpty
                                ? '— 选择 $core 配置文件 —'
                                : value),
                        style: TextStyle(
                          color: value.isEmpty
                              ? AntPalette.textDim
                              : AntPalette.text,
                          fontSize: 12,
                          fontFamily: 'Consolas',
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                      items: [
                        for (final f in realFiles)
                          DropdownMenuItem(
                            value: f,
                            child: Text(f,
                                style: const TextStyle(
                                    color: AntPalette.text,
                                    fontSize: 12,
                                    fontFamily: 'Consolas'),
                                overflow: TextOverflow.ellipsis),
                          ),
                        // 内置路由配置分组（对齐 Go 的 optgroup）
                        for (final b in builtinItems)
                          DropdownMenuItem(
                            value: b,
                            child: Text(b,
                                style: const TextStyle(
                                    color: AntPalette.textMid,
                                    fontSize: 12),
                                overflow: TextOverflow.ellipsis),
                          ),
                      ],
                      onChanged: (v) => _selectConfig(context, ref, v),
                    ),
                  ),
                  _MiniBtn(
                    icon: Icons.refresh,
                    tooltip: '重新扫描 configs 目录',
                    onTap: () =>
                        ref.read(configFilesProvider.notifier).reload(),
                  ),
                  _MiniBtn(
                    icon: Icons.home_outlined,
                    tooltip: '打开 configs 目录',
                    onTap: () async {
                      final app = ref.read(antAppProvider);
                      try {
                        await app.openConfigsDir();
                      } catch (_) {/* ignore */}
                    },
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 10),
          // ── 动作按钮 ──
          _ActionBtn(
            label: '导入节点',
            icon: Icons.add_circle_outline,
            tooltip: '从剪贴板或文本导入节点链接',
            onTap: onImport,
          ),
          _ActionBtn(
            label: '订阅',
            icon: Icons.sync,
            tooltip: '拉取/管理订阅',
            onTap: onSubscription,
          ),
          _ActionBtn(
            label: '清空',
            icon: Icons.do_not_disturb_on_outlined,
            tooltip: '清空所有节点',
            danger: true,
            onTap: () => _clearNodes(context, ref),
          ),
          const SizedBox(width: 6),
          Text('${nodes.length} 个节点',
              style: const TextStyle(
                  color: AntPalette.textDim,
                  fontSize: 11,
                  fontFamily: 'Consolas')),
        ],
      ),
    );
  }

  Future<void> _selectConfig(
      BuildContext context, WidgetRef ref, String? name) async {
    if (name == null || name.isEmpty) return;
    final app = ref.read(antAppProvider);
    await runAction(context, () => app.selectConfigFile(name),
        successMsg: '已切换配置: $name', failurePrefix: '切换配置失败');
    ref.read(settingsVersionProvider.notifier).bump();
    ref.read(configFilesProvider.notifier).reload();
  }

  Future<void> _clearNodes(BuildContext context, WidgetRef ref) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('确认'),
        content: const Text('确认清空所有节点？'),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('确认'),
          ),
        ],
      ),
    );
    if (confirmed != true || !context.mounted) return;
    final app = ref.read(antAppProvider);
    await runAction(context, () async => app.clearAllNodes(),
        successMsg: '已清空所有节点', failurePrefix: '清空失败');
    await ref.read(nodesProvider.notifier).reload();
  }
}

/// 下拉旁的小圆钮（刷新 / 打开目录）。
class _MiniBtn extends StatelessWidget {
  final IconData icon;
  final String tooltip;
  final VoidCallback onTap;

  const _MiniBtn({required this.icon, required this.tooltip, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: tooltip,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(6),
        child: Container(
          width: 26,
          height: 26,
          margin: const EdgeInsets.only(left: 2),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: Colors.transparent),
          ),
          child: Icon(icon, size: 15, color: AntPalette.textDim),
        ),
      ),
    );
  }
}

/// 动作按钮（导入 / 订阅 / 清空）。
class _ActionBtn extends StatelessWidget {
  final String label;
  final IconData icon;
  final String tooltip;
  final bool danger;
  final VoidCallback onTap;

  const _ActionBtn({
    required this.label,
    required this.icon,
    required this.tooltip,
    required this.onTap,
    this.danger = false,
  });

  @override
  Widget build(BuildContext context) {
    final color = danger ? AntPalette.red : AntPalette.text;
    return Padding(
      padding: const EdgeInsets.only(left: 6),
      child: Tooltip(
        message: tooltip,
        child: OutlinedButton.icon(
          onPressed: onTap,
          icon: Icon(icon, size: 15),
          label: Text(label),
          style: OutlinedButton.styleFrom(
            foregroundColor: color,
            side: const BorderSide(color: AntPalette.border),
            backgroundColor: AntPalette.bgInput,
            padding:
                const EdgeInsets.symmetric(horizontal: 13, vertical: 9),
            textStyle:
                const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
          ),
        ),
      ),
    );
  }
}
