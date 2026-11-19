/// 分组新建/编辑弹窗 — 新建与编辑共用同一完整表单
/// （名称 + 订阅链接 + 自动更新设置），不再单独显示命名弹窗。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

import '../actions.dart';
import '../providers.dart';

class GroupEditModal extends ConsumerStatefulWidget {
  /// null = 新建；非 null = 编辑。
  final Group? group;

  /// 新建时的插入位置分组 ID。
  final String? afterID;

  const GroupEditModal({super.key, this.group, this.afterID});

  @override
  ConsumerState<GroupEditModal> createState() => _GroupEditModalState();
}

class _GroupEditModalState extends ConsumerState<GroupEditModal> {
  late final Group? _group = widget.group;
  late final bool _isEdit = _group != null;
  late final bool _isDefault = _group?.isDefault ?? false;
  late final TextEditingController _name =
      TextEditingController(text: _isEdit ? _group!.name : '');
  late final TextEditingController _subUrl =
      TextEditingController(text: _isEdit ? _group!.subUrl : '');
  late bool _autoUpdate = _isEdit ? _group!.autoUpdate : false;
  late final TextEditingController _interval = TextEditingController(
      text:
          '${_isEdit && _group!.updateIntervalHours > 0 ? _group.updateIntervalHours : 24}');
  bool _saving = false;

  bool get _hasSub => _subUrl.text.trim().isNotEmpty;
  bool get _intervalEnabled => _hasSub && _autoUpdate;
  bool get _canConfirm =>
      _isEdit ? _isDefault || _name.text.trim().isNotEmpty : _name.text.trim().isNotEmpty;

  @override
  void dispose() {
    _name.dispose();
    _subUrl.dispose();
    _interval.dispose();
    super.dispose();
  }

  Future<void> _confirm() async {
    if (_saving || !_canConfirm) return;
    final app = ref.read(antAppProvider);
    setState(() => _saving = true);
    final ok = await runAction(context, () async {
      if (_isEdit) {
        app.updateGroup(Group(
          id: _group!.id,
          name: _isDefault ? _group.name : _name.text.trim(),
          isDefault: _group.isDefault,
          subUrl: _subUrl.text.trim(),
          autoUpdate: _intervalEnabled,
          updateIntervalHours:
              _intervalEnabled ? (int.tryParse(_interval.text) ?? 0) : 0,
          lastUpdate: _group.lastUpdate,
        ));
      } else {
        // 新建分组：先建组，再写入订阅设置（对齐 Go 版 AddGroup + UpdateGroup）
        final g = app.addGroup(_name.text.trim(), widget.afterID ?? '');
        app.updateGroup(Group(
          id: g.id,
          name: _name.text.trim(),
          subUrl: _subUrl.text.trim(),
          autoUpdate: _intervalEnabled,
          updateIntervalHours:
              _intervalEnabled ? (int.tryParse(_interval.text) ?? 0) : 0,
        ));
      }
    }, failurePrefix: _isEdit ? '编辑分组失败' : '新建分组失败');
    if (ok && mounted) Navigator.of(context).pop();
    if (mounted) setState(() => _saving = false);
    await ref.read(groupsProvider.notifier).reload();
    await ref.read(nodesProvider.notifier).reload();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        const ModalFieldLabel('分组名称'),
        TextField(
          controller: _name,
          enabled: !_isDefault,
          autofocus: !_isEdit,
          onChanged: (_) => setState(() {}),
          decoration: InputDecoration(
            hintText: '输入分组名称…',
            helperText: _isDefault ? '默认分组名称固定' : null,
          ),
        ),
        const ModalFieldLabel('订阅链接（可选）'),
        TextField(
          controller: _subUrl,
          onChanged: (_) => setState(() {}),
          decoration:
              const InputDecoration(hintText: '输入订阅链接 https://…'),
        ),
        const SizedBox(height: 12),
        // 自动更新订阅 + 间隔（同一行）
        Row(
          children: [
            SizedBox(
              width: 16,
              height: 16,
              child: Checkbox(
                value: _intervalEnabled,
                onChanged: _hasSub
                    ? (v) => setState(() => _autoUpdate = v ?? false)
                    : null,
              ),
            ),
            const SizedBox(width: 8),
            Text('自动更新订阅',
                style: TextStyle(
                    color: _hasSub ? AntPalette.text : AntPalette.textDim,
                    fontSize: 13)),
            const SizedBox(width: 20),
            Text('自动更新间隔（小时）',
                style: TextStyle(
                    color: _intervalEnabled
                        ? AntPalette.textDim
                        : AntPalette.textDim.withValues(alpha: 0.5),
                    fontSize: 12)),
            const SizedBox(width: 8),
            SizedBox(
              width: 90,
              child: TextField(
                controller: _interval,
                enabled: _intervalEnabled,
                keyboardType: TextInputType.number,
              ),
            ),
          ],
        ),
        if (!_hasSub)
          const Padding(
            padding: EdgeInsets.only(top: 4),
            child: Text('填写订阅链接后自动更新设置才会生效',
                style: TextStyle(color: AntPalette.textDim, fontSize: 11)),
          ),
        const SizedBox(height: 16),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            ModalButton(
              label: '取消',
              onPressed: () => Navigator.of(context).pop(),
            ),
            ModalButton(
              label: _saving ? '保存中…' : '确认',
              primary: true,
              onPressed: _canConfirm && !_saving ? _confirm : null,
            ),
          ],
        ),
      ],
    );
  }
}
