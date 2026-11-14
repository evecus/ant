/// 节点列表 — 对齐 Go 版 NodeList.jsx：
/// 横向分组页签（点击切换 / 右键管理）+ 节点行（协议徽章 / 已应用 /
/// 传输层与 TLS 徽章 / 地址 / 测试结果）+ 完整右键菜单 + 空态。
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

import '../actions.dart';
import '../modals/edit_node_modal.dart';
import '../modals/group_edit_modal.dart';
import '../providers.dart';

/// 传输层显示名（对齐 Go: TRANSPORT_LABELS）。
const Map<String, String> _transportLabels = {
  'ws': 'ws',
  'http': 'h2',
  'grpc': 'grpc',
  'httpupgrade': 'upg',
  'quic': 'quic',
  'xhttp': 'xhttp',
};

/// 从节点数据中提取传输层与 TLS 信息
/// （对齐 Go: getNodeMeta，兼容结构化配置与 raw 出站数据）。
class _NodeMeta {
  final String transport;
  final bool tls;
  final bool reality;
  final bool ech;
  final bool utls;
  const _NodeMeta({
    required this.transport,
    required this.tls,
    required this.reality,
    required this.ech,
    required this.utls,
  });

  factory _NodeMeta.of(Node node) {
    // cfg 类型各异（VMessConfig/VLESSConfig/TrojanConfig 无公共父类字段），
    // 逐类型取值后再合并（语义与 Go 版 getNodeMeta 一致）
    final vm = node.vMess;
    final vl = node.vless;
    final tr = node.trojan;
    final hasCfg = vm != null || vl != null || tr != null;
    var transport = vm?.transport?.type ??
        vl?.transport?.type ??
        tr?.transport?.type ??
        '';
    // TrojanConfig 无 tls 字段（trojan 恒为 TLS，由下方强制 TLS 列表覆盖）
    var tls = vm?.tls ?? vl?.tls ?? false;
    var reality = (vl?.publicKey.isNotEmpty ?? false);
    var ech = [
      vm?.echConfig,
      vl?.echConfig,
      tr?.echConfig,
    ].any((e) => e != null && e.isNotEmpty);
    var utls = (vm?.fingerprint.isNotEmpty ?? false) ||
        (vl?.fingerprint.isNotEmpty ?? false) ||
        (tr?.fingerprint.isNotEmpty ?? false);

    if (!hasCfg && node.rawOutbound != null) {
      final raw = node.rawOutbound!;
      transport = (raw['transport'] as Map?)?['type'] as String? ?? '';
      final t = raw['tls'] as Map?;
      tls = t?['enabled'] == true;
      reality = ((t?['reality'] as Map?)?['enabled'] == true);
      ech = ((t?['ech'] as Map?)?['enabled'] == true);
      utls = ((t?['utls'] as Map?)?['enabled'] == true);
    }
    // 这些协议强制 TLS/QUIC
    if (['hysteria', 'hysteria2', 'tuic', 'anytls', 'trojan', 'shadowtls']
        .contains(node.protocol)) {
      tls = true;
    }
    return _NodeMeta(
      transport: transport,
      tls: tls,
      reality: reality,
      ech: ech,
      utls: utls,
    );
  }
}

class NodeList extends ConsumerStatefulWidget {
  const NodeList({super.key});

  @override
  ConsumerState<NodeList> createState() => _NodeListState();
}

class _NodeListState extends ConsumerState<NodeList> {
  final Map<String, _TestState> _tests = {};

  List<Node> _nodesOf(List<Node> nodes, Group g) =>
      nodes.where((n) => (n.groupId.isEmpty ? defaultGroupID : n.groupId) == g.id).toList();

  // ─── 节点动作 ──────────────────────────────────────────────────────────────

  Future<void> _applyNode(Node node) async {
    final app = ref.read(antAppProvider);
    await runAction(context, () => app.applyNode(node.id),
        successMsg: '节点已应用到配置文件', failurePrefix: '应用节点失败');
    ref.read(settingsVersionProvider.notifier).bump();
  }

  Future<void> _unapply() async {
    final app = ref.read(antAppProvider);
    final ok = await runAction(context, () => app.unapplyNode(),
        successMsg: '已取消应用节点', failurePrefix: '取消应用失败');
    // 成功后必须 bump 版本号，settingsProvider 才会重新读取 appliedNodeID，
    // 否则节点行的绿色高亮 / 右键菜单文案不会刷新（此前误写成 !ok）。
    if (ok) {
      ref.read(settingsVersionProvider.notifier).bump();
    } else {
      ref.invalidate(settingsVersionProvider);
    }
  }

  Future<void> _deleteNode(Node node) async {
    final app = ref.read(antAppProvider);
    await runAction(context, () async => app.deleteNode(node.id),
        failurePrefix: '删除失败');
    await ref.read(nodesProvider.notifier).reload();
  }

  Future<void> _moveNode(Node node, int delta) async {
    final app = ref.read(antAppProvider);
    app.moveNode(node.id, delta); // 已在边界时返回 false，不提示
    await ref.read(nodesProvider.notifier).reload();
  }

  Future<void> _testLatency(Node node) async {
    final app = ref.read(antAppProvider);
    setState(() => _tests[node.id] = const _TestState.testing());
    final ms = await app.testLatency(node);
    if (!mounted) return;
    setState(() => _tests[node.id] =
        ms >= 0 ? _TestState.done(ms) : const _TestState.failed());
  }

  Future<void> _testSpeed(Node node) async {
    final app = ref.read(antAppProvider);
    setState(() => _tests[node.id] = const _TestState.testing());
    try {
      final mbps = await app.testSpeed(node);
      if (!mounted) return;
      setState(() => _tests[node.id] = _TestState.speed(mbps));
    } catch (e) {
      if (!mounted) return;
      setState(() => _tests[node.id] = const _TestState.failed());
    }
  }

  Future<void> _exportNode(Node node) async {
    final app = ref.read(antAppProvider);
    String uri;
    try {
      uri = app.exportNodeURI(node.id);
    } catch (e) {
      if (mounted) {
        await showDialog<void>(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Text('导出失败'),
            content: Text('$e'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('确定'),
              ),
            ],
          ),
        );
      }
      return;
    }
    await Clipboard.setData(ClipboardData(text: uri));
    if (mounted) {
      // 对齐 Go 的 alert：展示完整链接，需点确定
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('分享链接已复制到剪贴板'),
          content: Text(uri),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('确定'),
            ),
          ],
        ),
      );
    }
  }

  // ─── 分组动作 ──────────────────────────────────────────────────────────────

  Future<void> _refreshSubscription(Group group) async {
    final app = ref.read(antAppProvider);
    final ok = await runAction(context, () async {
      final count = await app.refreshGroupSubscription(group.id);
      if (mounted) {
        await showDialog<void>(
          context: context,
          builder: (ctx) => AlertDialog(
            title: const Text('订阅更新成功'),
            content: Text('分组「${group.name}」订阅更新成功，共 $count 个节点'),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('确定'),
              ),
            ],
          ),
        );
      }
    }, failurePrefix: '订阅更新失败');
    if (ok) {
      await ref.read(nodesProvider.notifier).reload();
      await ref.read(groupsProvider.notifier).reload();
    }
  }

  Future<void> _deleteGroup(Group group) async {
    if (group.isDefault) return;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('确认'),
        content: Text('确认删除分组「${group.name}」？\n该分组内的节点将移入「默认」分组。'),
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
    if (confirmed != true || !mounted) return;
    final app = ref.read(antAppProvider);
    await runAction(context, () async => app.deleteGroup(group.id),
        failurePrefix: '删除分组失败');
    await ref.read(groupsProvider.notifier).reload();
    await ref.read(nodesProvider.notifier).reload();
  }

  Future<void> _moveGroup(Group group, int delta) async {
    final app = ref.read(antAppProvider);
    await runAction(context, () async => app.moveGroup(group.id, delta),
        failurePrefix: '移动分组失败');
    await ref.read(groupsProvider.notifier).reload();
  }

  Future<void> _openGroupEdit(Group? group, String? afterID) {
    return AppModal.show<void>(
      context,
      title: group == null ? '新建分组' : (group.isDefault ? '编辑默认分组' : '编辑分组'),
      width: 560,
      builder: (_) => GroupEditModal(group: group, afterID: afterID),
    );
  }

  Future<void> _openNodeEdit(Node node) {
    return AppModal.show<void>(
      context,
      title: '编辑节点 — ${protocolDisplayName(node.protocol)}',
      width: 620,
      builder: (_) => EditNodeModal(node: node),
    );
  }

  // ─── 右键菜单 ──────────────────────────────────────────────────────────────

  void _showNodeMenu(Offset pos, Node node, bool applied, int index, int total) {
    showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(pos.dx, pos.dy, pos.dx + 1, pos.dy + 1),
      color: AntPalette.bgPanel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: AntPalette.border),
      ),
      items: [
        _headerItem(node.name),
        const PopupMenuDivider(),
        PopupMenuItem(
          value: applied ? 'unapply' : 'apply',
          child: _ctxItem(applied ? '✕' : '▶', applied ? '取消应用' : '应用',
              primary: !applied),
        ),
        PopupMenuItem(
            value: 'edit', child: _ctxItem('✎', '编辑')),
        PopupMenuItem(
            value: 'latency',
            child: _ctxItem('⏱', '测试真连接延迟')),
        PopupMenuItem(value: 'speed', child: _ctxItem('⇣', '测试速度')),
        PopupMenuItem(
            value: 'export', child: _ctxItem('⧉', '导出分享链接')),
        const PopupMenuDivider(),
        PopupMenuItem(
          value: 'up',
          enabled: index > 0,
          child: _ctxItem('↑', '上移', disabled: index <= 0),
        ),
        PopupMenuItem(
          value: 'down',
          enabled: index < total - 1,
          child: _ctxItem('↓', '下移', disabled: index >= total - 1),
        ),
        const PopupMenuDivider(),
        PopupMenuItem(
          value: 'delete',
          child: _ctxItem('⊗', '删除节点', danger: true),
        ),
      ],
    ).then((v) {
      if (v == null) return;
      switch (v) {
        case 'apply':
          _applyNode(node);
        case 'unapply':
          _unapply();
        case 'edit':
          _openNodeEdit(node);
        case 'latency':
          _testLatency(node);
        case 'speed':
          _testSpeed(node);
        case 'export':
          _exportNode(node);
        case 'up':
          _moveNode(node, -1);
        case 'down':
          _moveNode(node, 1);
        case 'delete':
          _deleteNode(node);
      }
    });
  }

  void _showGroupMenu(Offset pos, Group group, int index, int total) {
    final canMoveLeft = index >= 2; // 默认分组与其右侧第一个分组不可左移
    final canMoveRight = !group.isDefault && index < total - 1;
    showMenu<String>(
      context: context,
      position: RelativeRect.fromLTRB(pos.dx, pos.dy, pos.dx + 1, pos.dy + 1),
      color: AntPalette.bgPanel,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: AntPalette.border),
      ),
      items: [
        _headerItem('分组：${group.name}'),
        const PopupMenuDivider(),
        PopupMenuItem(value: 'create', child: _ctxItem('⊞', '新建分组', primary: true)),
        PopupMenuItem(value: 'edit', child: _ctxItem('✎', '编辑')),
        if (group.subUrl.isNotEmpty)
          PopupMenuItem(value: 'refresh', child: _ctxItem('⟳', '更新')),
        if (canMoveLeft)
          PopupMenuItem(value: 'left', child: _ctxItem('←', '左移')),
        if (canMoveRight)
          PopupMenuItem(value: 'right', child: _ctxItem('→', '右移')),
        PopupMenuItem(
          value: 'delete',
          enabled: !group.isDefault,
          child: _ctxItem('⊗', '删除分组', danger: true, disabled: group.isDefault),
        ),
      ],
    ).then((v) {
      if (v == null) return;
      switch (v) {
        case 'create':
          _openGroupEdit(null, group.id);
        case 'edit':
          _openGroupEdit(group, null);
        case 'refresh':
          _refreshSubscription(group);
        case 'left':
          _moveGroup(group, -1);
        case 'right':
          _moveGroup(group, 1);
        case 'delete':
          _deleteGroup(group);
      }
    });
  }

  PopupMenuItem<String> _headerItem(String text) => PopupMenuItem(
        enabled: false,
        child: Text(text,
            style: const TextStyle(
                color: AntPalette.textDim, fontSize: 11)),
      );

  Widget _ctxItem(String icon, String label,
      {bool primary = false, bool danger = false, bool disabled = false}) {
    var color = AntPalette.text;
    if (primary) color = AntPalette.accent;
    if (danger) color = AntPalette.red;
    if (disabled) color = AntPalette.textFaint;
    return Row(
      children: [
        SizedBox(width: 18, child: Text(icon, style: TextStyle(color: color, fontSize: 12))),
        const SizedBox(width: 6),
        Text(label, style: TextStyle(color: color, fontSize: 12)),
      ],
    );
  }

  // ─── 构建 ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final groups = ref.watch(groupsProvider).valueOrNull;
    final nodes = ref.watch(nodesProvider).valueOrNull;
    final appliedId = ref.watch(appliedIdProvider);
    final activeGroupId = ref.watch(activeGroupIdProvider);

    if (groups == null || nodes == null) {
      return const Center(
          child: CircularProgressIndicator(strokeWidth: 2));
    }
    // 当前选中分组若已被删除, 回到默认分组（对齐 React loadGroups）
    final activeGroup = groups.any((g) => g.id == activeGroupId)
        ? groups.firstWhere((g) => g.id == activeGroupId)
        : groups.firstWhere(
            (g) => g.id == defaultGroupID,
            orElse: () => groups.first,
          );
    final activeNodes = _nodesOf(nodes, activeGroup);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // ── 分组页签栏（横向）──
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: const BoxDecoration(
            color: AntPalette.bgPanel,
            border: Border(bottom: BorderSide(color: AntPalette.border)),
          ),
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                for (final g in groups)
                  _GroupTab(
                    group: g,
                    active: g.id == activeGroup.id,
                    count: _nodesOf(nodes, g).length,
                    onTap: () =>
                        ref.read(activeGroupIdProvider.notifier).set(g.id),
                    onMenu: (pos) {
                      ref.read(activeGroupIdProvider.notifier).set(g.id);
                      _showGroupMenu(pos, g, groups.indexOf(g), groups.length);
                    },
                  ),
              ],
            ),
          ),
        ),
        // ── 列表 ──
        Expanded(
          child: activeNodes.isEmpty
              ? _EmptyState(groupName: activeGroup.name)
              : SingleChildScrollView(
                  child: Column(
                    children: [
                      const SizedBox(height: 6),
                      for (final node in activeNodes)
                        _NodeRow(
                          node: node,
                          applied: node.id == appliedId,
                          test: _tests[node.id],
                          onEdit: () => _openNodeEdit(node),
                          onMenu: (pos) {
                            final idx = activeNodes.indexOf(node);
                            _showNodeMenu(pos, node, node.id == appliedId,
                                idx, activeNodes.length);
                          },
                        ),
                      const SizedBox(height: 6),
                    ],
                  ),
                ),
        ),
      ],
    );
  }
}

/// 分组页签（胶囊）。
class _GroupTab extends StatelessWidget {
  final Group group;
  final bool active;
  final int count;
  final VoidCallback onTap;
  final void Function(Offset) onMenu;

  const _GroupTab({
    required this.group,
    required this.active,
    required this.count,
    required this.onTap,
    required this.onMenu,
  });

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: group.isDefault ? '默认分组（不可删除，名称固定）' : '右键管理分组',
      child: GestureDetector(
        onSecondaryTapUp: (d) => onMenu(d.globalPosition),
        child: InkWell(
          onTap: onTap,
          hoverColor: AntPalette.bgHover,
          highlightColor: Colors.transparent,
          splashFactory: NoSplash.splashFactory,
          borderRadius: BorderRadius.circular(20),
          child: Container(
            margin: const EdgeInsets.only(right: 6),
            padding:
                const EdgeInsets.symmetric(horizontal: 13, vertical: 4),
            decoration: BoxDecoration(
              color: active ? AntPalette.accentDim : AntPalette.bgInput,
              border: Border.all(
                color: active ? AntPalette.accent : Colors.transparent,
              ),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 140),
                  child: Text(
                    group.name,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      color: active ? AntPalette.accent : AntPalette.textMid,
                      fontSize: 12,
                      fontWeight: active ? FontWeight.w600 : FontWeight.w400,
                    ),
                  ),
                ),
                if (group.subUrl.isNotEmpty) ...[
                  const SizedBox(width: 5),
                  const Text('◉',
                      style:
                          TextStyle(color: AntPalette.accent, fontSize: 9)),
                ],
                const SizedBox(width: 5),
                Container(
                  padding:
                      const EdgeInsets.symmetric(horizontal: 6, vertical: 0),
                  constraints: const BoxConstraints(minWidth: 16),
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: active ? AntPalette.accent : AntPalette.bgHover,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    '$count',
                    style: TextStyle(
                      color: active ? Colors.white : AntPalette.textDim,
                      fontSize: 10,
                      fontFamily: 'Consolas',
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

/// 空态（对齐 Go: node-list-empty）。
class _EmptyState extends StatelessWidget {
  final String groupName;
  const _EmptyState({required this.groupName});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text('◈',
              style: TextStyle(fontSize: 40, color: AntPalette.textFaint)),
          const SizedBox(height: 10),
          Text('「$groupName」分组暂无节点',
              style: const TextStyle(
                  color: AntPalette.textMid,
                  fontSize: 15,
                  fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          const Text('点击上方「导入节点」或「订阅」，获取的节点将导入当前分组',
              style: TextStyle(color: AntPalette.textDim, fontSize: 12)),
        ],
      ),
    );
  }
}

/// 延迟/测速结果。
class _TestState {
  final bool testing;
  final int? ms;
  final double? mbps;
  const _TestState.testing() : testing = true, ms = null, mbps = null;
  const _TestState.done(this.ms) : testing = false, mbps = null;
  const _TestState.speed(this.mbps) : testing = false, ms = null;
  const _TestState.failed() : testing = false, ms = null, mbps = null;
}

/// 节点行：仅已应用节点有视觉差异（绿底+绿条）；双击 → 编辑弹窗，
/// 右键 → 菜单；单击无任何高亮。
class _NodeRow extends StatelessWidget {
  final Node node;
  final bool applied;
  final _TestState? test;
  final VoidCallback onEdit;
  final void Function(Offset) onMenu;

  const _NodeRow({
    required this.node,
    required this.applied,
    required this.onEdit,
    required this.onMenu,
    this.test,
  });

  (Color, Color) _testChipColors() {
    final t = test;
    if (t == null) return (AntPalette.textDim, AntPalette.bgHover);
    if (t.testing) return (AntPalette.textDim, AntPalette.bgHover);
    if (t.mbps != null) {
      final v = t.mbps!;
      return v > 20
          ? (const Color(0xFF16a34a), const Color(0x2116a34a))
          : v > 5
              ? (const Color(0xFFd97706), const Color(0x21d97706))
              : (const Color(0xFFdc2626), const Color(0x21dc2626));
    }
    final ms = t.ms;
    if (ms == null || ms < 0) {
      return (const Color(0xFFdc2626), const Color(0x21dc2626));
    }
    return ms < 300
        ? (const Color(0xFF16a34a), const Color(0x2116a34a))
        : ms < 800
            ? (const Color(0xFFd97706), const Color(0x21d97706))
            : (const Color(0xFFdc2626), const Color(0x21dc2626));
  }

  String _testText() {
    final t = test;
    if (t == null) return '';
    if (t.testing) return '测试中…';
    if (t.mbps != null) {
      final v = t.mbps!;
      return '${v >= 1 ? v.toStringAsFixed(1) : v.toStringAsFixed(2)} Mbps';
    }
    if (t.ms != null && t.ms! >= 0) return '${t.ms} ms';
    return '失败';
  }

  @override
  Widget build(BuildContext context) {
    final meta = _NodeMeta.of(node);
    final chipColor = _testChipColors();

    return InkWell(
      // 单击不显示选中状态；双击直接打开编辑弹窗；右键菜单不变
      onDoubleTap: onEdit,
      onSecondaryTapUp: (d) => onMenu(d.globalPosition),
      // hover 用 Go 版的 --bg-2 灰，禁用 Material 默认蓝色水波纹
      hoverColor: AntPalette.bgInput,
      highlightColor: Colors.transparent,
      splashFactory: NoSplash.splashFactory,
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 8),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
        // 只有已应用节点有差异：绿底 + 3px 绿色左条
        decoration: BoxDecoration(
          color: applied ? AntPalette.greenDim : null,
          border: Border(
            left: BorderSide(
              width: 3,
              color: applied ? AntPalette.green : Colors.transparent,
            ),
          ),
          borderRadius: BorderRadius.circular(8),
        ),
        child: Row(
          children: [
            ProtocolBadge(protocol: node.protocol),
            const SizedBox(width: 10),
            Expanded(
              child: Row(
                children: [
                  Flexible(
                    child: Text(
                      node.name.isEmpty ? '未命名节点' : node.name,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                          color: AntPalette.text, fontSize: 12.5),
                    ),
                  ),
                  if (applied) ...[
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 7, vertical: 1),
                      decoration: BoxDecoration(
                        color: AntPalette.greenDim,
                        borderRadius: BorderRadius.circular(20),
                      ),
                      child: const Text('已应用',
                          style: TextStyle(
                              color: AntPalette.green,
                              fontSize: 10,
                              fontWeight: FontWeight.w600)),
                    ),
                  ],
                ],
              ),
            ),
            // 传输层 / TLS 标识
            if (meta.transport.isNotEmpty) ...[
              const SizedBox(width: 6),
              MetaBadge(
                label:
                    _transportLabels[meta.transport] ?? meta.transport,
                color: AntPalette.textDim,
              ),
            ],
            const SizedBox(width: 6),
            if (meta.reality)
              const MetaBadge(label: 'REALITY', color: AntPalette.green)
            else if (meta.tls)
              MetaBadge(
                  label: meta.ech ? 'TLS·ECH' : 'TLS',
                  color: meta.ech ? AntPalette.cyan : AntPalette.green),
            if (meta.utls && !meta.reality) ...[
              const SizedBox(width: 6),
              const MetaBadge(label: 'uTLS', color: AntPalette.accent),
            ],
            const SizedBox(width: 10),
            Text(
              '${node.address}:${node.port}',
              style: const TextStyle(
                  color: AntPalette.textDim,
                  fontSize: 11,
                  fontFamily: 'Consolas'),
            ),
            if (test != null) ...[
              const SizedBox(width: 10),
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 9, vertical: 1),
                decoration: BoxDecoration(
                  color: chipColor.$2,
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Text(_testText(),
                    style: TextStyle(
                        color: chipColor.$1,
                        fontSize: 11,
                        fontFamily: 'Consolas',
                        fontWeight: FontWeight.w500)),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
