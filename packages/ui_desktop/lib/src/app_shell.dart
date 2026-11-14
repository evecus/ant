/// 应用主壳 — 对齐 Go 版 React 版 App.jsx：
/// 标题栏（节点列表 / 运行日志 / ⚙设置 Tab + 内核状态灯）→
/// ConfigBar（仅节点页）→ 内容区 → BottomBar。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ant_engine/ant_engine.dart';
import 'package:ui_kit/ui_kit.dart';

import 'modals/edit_node_modal.dart';
import 'modals/import_modal.dart';
import 'modals/subscription_modal.dart';
import 'providers.dart';
import 'widgets/bottom_bar.dart';
import 'widgets/config_bar.dart';
import 'widgets/log_panel.dart';
import 'widgets/node_list.dart';
import 'settings_panel.dart';

/// 主窗口内容（不含 MaterialApp，由 apps/desktop 提供）。
class AntDesktopApp extends ConsumerStatefulWidget {
  const AntDesktopApp({super.key});

  @override
  ConsumerState<AntDesktopApp> createState() => _AntDesktopAppState();
}

class _AntDesktopAppState extends ConsumerState<AntDesktopApp> {
  String _tab = 'nodes'; // nodes | log | settings

  void _openImport() {
    AppModal.show<void>(
      context,
      title: '导入节点',
      width: 560,
      builder: (_) => const ImportModal(),
    );
  }

  void _openSubscription() {
    AppModal.show<void>(
      context,
      title: '订阅管理',
      width: 540,
      builder: (_) => const SubscriptionModal(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final status =
        ref.watch(coreStatusProvider).valueOrNull ?? const ProcessStatus();
    // 内部重启编排期间保持"运行中"外观，避免指示灯/开关视觉上熄灭再点亮
    final running = ref.watch(coreSwitchOnProvider);

    return Scaffold(
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // ── 标题栏 ──
          _TitleBar(
            tab: _tab,
            onTab: (t) => setState(() => _tab = t),
            running: running,
            pid: status.pid,
          ),
          // ── 配置栏（仅节点列表页）──
          if (_tab == 'nodes')
            ConfigBar(
              onImport: _openImport,
              onSubscription: _openSubscription,
            ),
          // ── 主内容 ──
          Expanded(
            child: switch (_tab) {
              'log' => const LogPanel(),
              'settings' => const SettingsPanel(),
              _ => const NodeList(),
            },
          ),
          // ── 底部栏 ──
          const BottomBar(),
        ],
      ),
    );
  }
}

class _TitleBar extends StatelessWidget {
  final String tab;
  final ValueChanged<String> onTab;
  final bool running;
  final int pid;

  const _TitleBar({
    required this.tab,
    required this.onTab,
    required this.running,
    required this.pid,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 44,
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: const BoxDecoration(
        color: AntPalette.bgPanel,
        border: Border(bottom: BorderSide(color: AntPalette.border)),
      ),
      child: Row(
        children: [
          // Tab 胶囊组
          if (tab == 'nodes') ...[
            const _AddNodeButton(),
            const SizedBox(width: 8),
          ],
          Container(
            padding: const EdgeInsets.all(3),
            decoration: BoxDecoration(
              color: AntPalette.bgInput,
              borderRadius: BorderRadius.circular(10),
            ),
            child: Row(
              children: [
                _TabButton(
                  label: '节点列表',
                  active: tab == 'nodes',
                  onTap: () => onTab('nodes'),
                ),
                _TabButton(
                  label: '运行日志',
                  active: tab == 'log',
                  badge: running,
                  onTap: () => onTab('log'),
                ),
                _TabButton(
                  label: '⚙ 设置',
                  active: tab == 'settings',
                  onTap: () => onTab('settings'),
                ),
              ],
            ),
          ),
          const Spacer(),
          // 状态胶囊
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            decoration: BoxDecoration(
              color: AntPalette.bgInput,
              borderRadius: BorderRadius.circular(20),
            ),
            child: Row(
              children: [
                Container(
                  width: 7,
                  height: 7,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: running ? AntPalette.green : AntPalette.textFaint,
                    boxShadow: running
                        ? [
                            BoxShadow(
                              color: AntPalette.green.withValues(alpha: 0.35),
                              blurRadius: 4,
                              spreadRadius: 2,
                            ),
                          ]
                        : null,
                  ),
                ),
                const SizedBox(width: 7),
                Text(
                  running ? '运行中 #$pid' : '未运行',
                  style: const TextStyle(
                    color: AntPalette.textMid,
                    fontSize: 11,
                    fontFamily: 'Consolas',
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// 「添加」按钮 — 对齐 v2rayN：点击弹出协议类型菜单，选择后打开
/// 新建节点编辑弹窗（保存时入库新增，归入当前视图分组）。
class _AddNodeButton extends ConsumerWidget {
  const _AddNodeButton();

  Future<void> _showAddMenu(BuildContext context, WidgetRef ref) async {
    final box = context.findRenderObject() as RenderBox;
    // 菜单贴着按钮下缘展开
    final pos = box.localToGlobal(Offset(0, box.size.height + 4));
    final picked = await showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(pos.dx, pos.dy, pos.dx + 1, pos.dy + 1),
      color: AntPalette.bgPanel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: AntPalette.border),
      ),
      items: [
        for (final p in addableProtocols)
          PopupMenuItem<String>(
            value: p,
            height: 34,
            child: Text(
              '添加 [${protocolDisplayName(p)}]',
              style: const TextStyle(
                color: AntPalette.text,
                fontSize: 12,
                fontFamily: 'Consolas',
              ),
            ),
          ),
      ],
    );
    if (picked == null || !context.mounted) return;
    // 归入当前视图分组（对齐 v2rayN：新节点进当前选中的分组）
    final groupId = ref.read(activeGroupIdProvider);
    AppModal.show<void>(
      context,
      title: '添加节点 — ${protocolDisplayName(picked)}',
      width: 620,
      builder: (_) => EditNodeModal(
        node: Node(id: '', protocol: picked, groupId: groupId),
        isNew: true,
      ),
    );
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return InkWell(
      onTap: () => _showAddMenu(context, ref),
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
        decoration: BoxDecoration(
          color: AntPalette.bgInput,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AntPalette.border),
        ),
        child: const Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.add, size: 14, color: AntPalette.accent),
            SizedBox(width: 3),
            Text(
              '添加',
              style: TextStyle(
                color: AntPalette.accent,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _TabButton extends StatelessWidget {
  final String label;
  final bool active;
  final bool badge;
  final VoidCallback onTap;

  const _TabButton({
    required this.label,
    required this.active,
    this.badge = false,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(7),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        decoration: BoxDecoration(
          color: active ? AntPalette.bgPanel : null,
          borderRadius: BorderRadius.circular(7),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              label,
              style: TextStyle(
                color: active ? AntPalette.accent : AntPalette.textMid,
                fontSize: 12,
                fontWeight: active ? FontWeight.w600 : FontWeight.w500,
              ),
            ),
            if (badge) ...[
              const SizedBox(width: 5),
              Container(
                width: 6,
                height: 6,
                decoration: const BoxDecoration(
                  shape: BoxShape.circle,
                  color: AntPalette.green,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
