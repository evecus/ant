/// 节点编辑弹窗 — schema 驱动（数据驱动，对齐 ant-afa 的 NodeEditScreen）。
///
/// 表单字段完全由 [NodeSchema] 的 FieldSpec 表生成，本文件不含任何按协议的
/// switch-case：新增/删减协议只改 core 的 NodeSchema，UI 零改动。
/// 支持运行时切换协议（切换时保留通用字段、套用新协议默认值）与按
/// spec.required 的通用必填校验。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

import '../providers.dart';

/// 「添加节点」菜单的协议顺序（来自 schema 注册表，单一数据源）。
final List<String> addableProtocols = NodeSchema.keys;

class EditNodeModal extends ConsumerStatefulWidget {
  final Node node;

  /// true = 新建模式：保存时入库新增（自动生成 id/归组），
  /// false = 编辑模式：按原 id 更新。
  final bool isNew;

  const EditNodeModal({super.key, required this.node, this.isNew = false});

  @override
  ConsumerState<EditNodeModal> createState() => _EditNodeModalState();
}

class _EditNodeModalState extends ConsumerState<EditNodeModal> {
  /// 可编辑副本：字段访问器直接读写它；保存时整棵序列化入库。
  late final Node _draft = Node.fromJson(widget.node.toJson());

  /// 当前协议（字符串），运行时可切换。
  late String _proto = _draft.protocol;

  @override
  void initState() {
    super.initState();
    if (widget.isNew) {
      // 新建：空协议给默认值；预选协议则套用内核要求的 Config 默认值
      // （如 vmess/vless 的 tls=true、cipher=auto、transport=tcp）。
      final target = NodeSchema.supports(_proto) ? _proto : 'vless';
      _proto = target;
      NodeSchema.init(_draft, target);
    }
    // 编辑 raw 协议节点：保持只读基本信息，不做任何 Config 初始化。
  }

  bool get _supportedProto => NodeSchema.supports(_proto);

  final Map<String, TextEditingController> _c = {};
  final Map<String, Object> _st = {};
  bool _saving = false;
  String? _error;

  TextEditingController _ctl(String key, String initial) =>
      _c.putIfAbsent(key, () => TextEditingController(text: initial));

  Object _state(String key, Object? initial) =>
      _st.putIfAbsent(key, () => initial!);

  @override
  void dispose() {
    for (final c in _c.values) {
      c.dispose();
    }
    super.dispose();
  }

  /// 当前协议可见的字段（按 group 顺序渲染时再过滤分组）。
  List<FieldSpec> get _visibleSpecs =>
      NodeSchema.fieldsFor(_proto).where((s) => s.showIf(_draft)).toList();

  // ─── 协议切换 ─────────────────────────────────────────────────────────────

  void _changeType(String newType) {
    if (newType == _proto) return;
    setState(() {
      // 暂存当前表单里 controller / state 的编辑值到 draft
      _flushToDraft();
      final old = _proto;
      NodeSchema.changeType(_draft, old, newType);
      _proto = newType;
      // 协议切换后字段集合变化，清空控件缓存让它们按新值重建
      for (final c in _c.values) {
        c.dispose();
      }
      _c.clear();
      _st.clear();
      _error = null;
    });
  }

  /// 把当前 controller / state 里的编辑值写回 draft（切换/保存前调用）。
  void _flushToDraft() {
    for (final spec in _visibleSpecs) {
      switch (spec.kind) {
        case FieldKind.toggle:
          spec.set(_draft, (_state(spec.key, spec.get(_draft)) as bool).toString());
          break;
        case FieldKind.select:
          spec.set(_draft, _state(spec.key, spec.get(_draft)) as String);
          break;
        case FieldKind.number:
        case FieldKind.text:
        case FieldKind.secret:
          final c = _c[spec.key];
          if (c != null) spec.set(_draft, c.text);
          break;
      }
    }
  }

  // ─── 保存 ─────────────────────────────────────────────────────────────────

  Future<void> _save() async {
    if (_saving) return;
    _flushToDraft();

    final error = NodeSchema.validate(_draft);
    if (error != null) {
      _setError(error);
      return;
    }

    final app = ref.read(antAppProvider);
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      final out = Node.fromJson(_draft.toJson());
      out.subUrl = widget.node.subUrl;
      out.groupId = widget.node.groupId;
      // 结构化协议保存后清除 raw 透传，让编辑内容生效
      if (_supportedProto) {
        out.rawOutbound = null;
        out.rawClashProxy = null;
      }

      if (widget.isNew) {
        app.addNode(out);
      } else {
        app.updateNode(out);
      }
      if (mounted) {
        AppToast.show(context, '节点已保存', ToastType.success);
        Navigator.of(context).pop();
      }
    } catch (e) {
      _setError('保存失败: $e');
    }
    if (mounted) setState(() => _saving = false);
    await ref.read(nodesProvider.notifier).reload();
  }

  void _setError(String msg) {
    setState(() => _error = msg);
  }

  // ─── 通用字段控件（按 FieldKind 渲染，无协议判断）────────────────────────

  Widget _fieldRow(FieldSpec spec) {
    final initial = spec.get(_draft);
    // key 带协议前缀：切换协议时强制控件按新初始值重建，避免复用旧值。
    final fieldKey = ValueKey('$_proto.${spec.key}');
    Widget control;
    switch (spec.kind) {
      case FieldKind.text:
        control = TextField(
          key: fieldKey,
          controller: _ctl(spec.key, initial),
          decoration: InputDecoration(hintText: spec.hint.isEmpty ? null : spec.hint),
          style: const TextStyle(
              color: AntPalette.text, fontSize: 12, fontFamily: 'Consolas'),
        );
        break;
      case FieldKind.number:
        control = TextField(
          key: fieldKey,
          controller: _ctl(spec.key, initial),
          keyboardType: TextInputType.number,
          decoration: InputDecoration(hintText: spec.hint.isEmpty ? null : spec.hint),
          style: const TextStyle(color: AntPalette.text, fontSize: 12),
        );
        break;
      case FieldKind.secret:
        control = TextField(
          key: fieldKey,
          controller: _ctl(spec.key, initial),
          obscureText: true,
          decoration: InputDecoration(hintText: spec.hint.isEmpty ? null : spec.hint),
          style: const TextStyle(
              color: AntPalette.text, fontSize: 12, fontFamily: 'Consolas'),
        );
        break;
      case FieldKind.toggle:
        final v = _state(spec.key, initial == 'true') as bool;
        control = Align(
          key: fieldKey,
          alignment: Alignment.centerLeft,
          child: SizedBox(
            width: 20,
            height: 20,
            child: Checkbox(
              value: v,
              onChanged: (nv) {
                setState(() => _st[spec.key] = nv ?? false);
                spec.set(_draft, (nv ?? false).toString());
              },
            ),
          ),
        );
        break;
      case FieldKind.select:
        var v = _state(spec.key, initial) as String;
        // 若草稿值与选项不匹配（如来自订阅的自定义值），补进选项，避免
        // DropdownButton 断言 value not in items。
        final items = <String>[...spec.options];
        if (v.isNotEmpty && !items.contains(v)) items.insert(0, v);
        if (v.isEmpty && items.isNotEmpty && !items.contains('')) {
          items.insert(0, '');
        }
        v = items.contains(v) ? v : (items.isNotEmpty ? items.first : '');
        control = DropdownButtonFormField<String>(
          key: fieldKey,
          initialValue: v,
          isExpanded: true,
          items: [
            for (final opt in items)
              DropdownMenuItem(
                value: opt,
                child: Text(
                  opt.isEmpty ? '（默认）' : opt,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
          onChanged: (nv) {
            if (nv != null) {
              setState(() => _st[spec.key] = nv);
              spec.set(_draft, nv);
            }
          },
        );
        break;
    }
    return _formRow(spec.label + (spec.required ? ' *' : ''), control,
        hint: spec.hint);
  }

  Widget _formRow(String label, Widget child, {String? hint}) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            SizedBox(
              width: 150,
              child: Tooltip(
                message: hint ?? '',
                child: Text(label,
                    style: const TextStyle(
                        color: AntPalette.textDim, fontSize: 12)),
              ),
            ),
            Expanded(child: child),
          ],
        ),
      );

  Widget _section(String title) => Padding(
        padding: const EdgeInsets.only(top: 10, bottom: 2),
        child: Text(title,
            style: const TextStyle(
                color: AntPalette.accent,
                fontSize: 12,
                fontWeight: FontWeight.w600)),
      );

  // ─── 构建 ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final specs = _visibleSpecs;
    final protoItems = <String>[
      ...NodeSchema.keys,
      if (!NodeSchema.supports(widget.node.protocol) &&
          widget.node.protocol.isNotEmpty)
        widget.node.protocol,
    ];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (!_supportedProto)
          Container(
            padding: const EdgeInsets.all(8),
            margin: const EdgeInsets.only(bottom: 8),
            decoration: BoxDecoration(
              color: AntPalette.yellow.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              '该节点 ($_proto) 来自完整配置(raw)，仅支持编辑基本信息。可切到受支持协议以启用结构化编辑。',
              style: const TextStyle(color: AntPalette.yellow, fontSize: 12),
            ),
          ),
        if (_error != null)
          Container(
            padding: const EdgeInsets.all(8),
            margin: const EdgeInsets.only(bottom: 8),
            decoration: BoxDecoration(
              color: AntPalette.red.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(_error!,
                style: const TextStyle(color: AntPalette.red, fontSize: 12)),
          ),

        // ── 协议选择（运行时可切换）──
        _section('协议'),
        _formRow(
          '协议类型',
          DropdownButtonFormField<String>(
            key: ValueKey('protocol-selector.$_proto'),
            initialValue: protoItems.contains(_proto) ? _proto : protoItems.first,
            isExpanded: true,
            items: [
              for (final p in protoItems)
                DropdownMenuItem(
                  value: p,
                  child: Text(
                    NodeSchema.supports(p) ? '${NodeSchema.display(p)} ($p)' : '$p (raw)',
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
            ],
            onChanged: (nv) {
              if (nv != null) _changeType(nv);
            },
          ),
        ),

        // ── 按 schema 分组渲染 ──
        for (final group in NodeSchema.groupOrder) ...[
          if (specs.any((s) => s.group == group)) ...[
            _section(group),
            for (final spec in specs.where((s) => s.group == group))
              _fieldRow(spec),
          ],
        ],

        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            ModalButton(
              label: '取消',
              onPressed: () => Navigator.of(context).pop(),
            ),
            ModalButton(
              label: _saving ? '保存中…' : '保存',
              primary: true,
              onPressed: _saving ? null : _save,
            ),
          ],
        ),
      ],
    );
  }
}
