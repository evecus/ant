/// 导入节点弹窗 — 对齐 Go 版 ImportModal.jsx：
/// 粘贴 URI/base64/完整配置，导入到当前选中的分组（无分组下拉）。
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ui_kit/ui_kit.dart';

import '../actions.dart';
import '../providers.dart';

class ImportModal extends ConsumerStatefulWidget {
  const ImportModal({super.key});

  @override
  ConsumerState<ImportModal> createState() => _ImportModalState();
}

class _ImportModalState extends ConsumerState<ImportModal> {
  final _content = TextEditingController();
  bool _loading = false;

  @override
  void dispose() {
    _content.dispose();
    super.dispose();
  }

  Future<void> _paste() async {
    final text = await Clipboard.getData(Clipboard.kTextPlain);
    if (text?.text != null) {
      _content.text = text!.text!;
    }
  }

  Future<void> _import() async {
    final text = _content.text.trim();
    if (text.isEmpty || _loading) return;
    final app = ref.read(antAppProvider);
    final groupId = ref.read(activeGroupIdProvider);
    setState(() => _loading = true);
    final ok = await runAction(context, () async {
      final count = app.addNodesFromText(text, groupId, '');
      if (mounted) {
        AppToast.show(context, '成功导入 $count 个节点', ToastType.success);
      }
    }, failurePrefix: '导入失败');
    if (ok && mounted) {
      Navigator.of(context).pop();
    }
    if (mounted) setState(() => _loading = false);
    await ref.read(nodesProvider.notifier).reload();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        const Text(
          '粘贴节点链接（每行一个）或 base64 编码内容\n'
          '支持：vmess:// vless:// trojan:// ss:// hysteria2:// hysteria:// tuic://\n'
          'socks:// anytls:// wireguard:// 及 Clash / sing-box 完整配置\n'
          '（ant 无 hysteria v1 / ssr / http 出站，应用时会明确报错）',
          style: TextStyle(color: AntPalette.textDim, fontSize: 12),
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            const Text('节点内容',
                style: TextStyle(color: AntPalette.textDim, fontSize: 12)),
            const Spacer(),
            TextButton.icon(
              onPressed: _paste,
              icon: const Icon(Icons.content_paste, size: 14),
              label: const Text('从剪贴板粘贴'),
              style: TextButton.styleFrom(
                foregroundColor: AntPalette.accent,
                textStyle: const TextStyle(fontSize: 12),
              ),
            ),
          ],
        ),
        TextField(
          controller: _content,
          maxLines: 10,
          autofocus: true,
          onChanged: (_) => setState(() {}),
          style: const TextStyle(
              color: AntPalette.text, fontSize: 12, fontFamily: 'Consolas'),
          decoration: const InputDecoration(
            hintText: 'vmess://...\nvless://...\ntrojan://...',
          ),
        ),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            ModalButton(
              label: '取消',
              onPressed: _loading ? null : () => Navigator.of(context).pop(),
            ),
            ModalButton(
              label: _loading ? '导入中…' : '导入',
              primary: true,
              onPressed:
                  _content.text.trim().isEmpty || _loading ? null : _import,
            ),
          ],
        ),
      ],
    );
  }
}
