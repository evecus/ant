/// 订阅管理弹窗 — 对齐 Go 版 SubscriptionModal.jsx：
/// 已添加的订阅列表（移除）+ 拉取新订阅（成功后自动新建「订阅N」分组）。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ui_kit/ui_kit.dart';

import '../actions.dart';
import '../providers.dart';

class SubscriptionModal extends ConsumerStatefulWidget {
  const SubscriptionModal({super.key});

  @override
  ConsumerState<SubscriptionModal> createState() => _SubscriptionModalState();
}

class _SubscriptionModalState extends ConsumerState<SubscriptionModal> {
  final _url = TextEditingController();
  bool _loading = false;

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  /// 拉取订阅（成功 → 新建「订阅N」分组并切换到该分组）。
  Future<void> _fetch() async {
    final url = _url.text.trim();
    if (url.isEmpty || _loading) return;
    final app = ref.read(antAppProvider);
    setState(() => _loading = true);
    final ok = await runAction(context, () async {
      final res = await app.fetchSubscriptionAsGroup(url);
      if (mounted) {
        AppToast.show(context,
            '订阅拉取成功，新建分组「${res.$1.name}」，共 ${res.$2} 个节点',
            ToastType.success);
      }
      // 拉取成功 → 激活新建的订阅分组
      ref.read(activeGroupIdProvider.notifier).set(res.$1.id);
    }, failurePrefix: '订阅拉取失败');
    if (ok && mounted) Navigator.of(context).pop();
    if (mounted) setState(() => _loading = false);
    await ref.read(nodesProvider.notifier).reload();
    await ref.read(groupsProvider.notifier).reload();
    ref.read(settingsVersionProvider.notifier).bump();
  }

  Future<void> _remove(String subUrl) async {
    ref.read(antAppProvider).removeSubscription(subUrl);
    if (mounted) Navigator.of(context).pop();
    ref.read(settingsVersionProvider.notifier).bump();
  }

  @override
  Widget build(BuildContext context) {
    final subs =
        ref.watch(settingsProvider).subscriptions ?? const <String>[];

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (subs.isNotEmpty) ...[
          const Text('已添加的订阅',
              style: TextStyle(color: AntPalette.textDim, fontSize: 12)),
          const SizedBox(height: 6),
          for (final sub in subs)
            Container(
              margin: const EdgeInsets.only(bottom: 6),
              padding:
                  const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: AntPalette.bgInput,
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AntPalette.border),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: Text(sub,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(
                            color: AntPalette.textMid,
                            fontSize: 11,
                            fontFamily: 'Consolas')),
                  ),
                  const SizedBox(width: 8),
                  InkWell(
                    onTap: _loading ? null : () => _remove(sub),
                    borderRadius: BorderRadius.circular(4),
                    child: const Padding(
                      padding: EdgeInsets.all(2),
                      child: Icon(Icons.do_not_disturb_on_outlined,
                          size: 15, color: AntPalette.red),
                    ),
                  ),
                ],
              ),
            ),
          const SizedBox(height: 4),
        ],
        const Text('添加新订阅地址',
            style: TextStyle(color: AntPalette.textDim, fontSize: 12)),
        const SizedBox(height: 6),
        TextField(
          controller: _url,
          autofocus: true,
          onChanged: (_) => setState(() {}),
          onSubmitted: (_) => _fetch(),
          decoration: const InputDecoration(
              hintText: 'https://your-subscription-url...'),
        ),
        const SizedBox(height: 8),
        const Text(
          '拉取成功后将自动新建「订阅N」分组并放入节点；更新请使用分组右键菜单中的「更新」',
          style: TextStyle(color: AntPalette.textDim, fontSize: 11),
        ),
        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            ModalButton(
              label: '关闭',
              onPressed: _loading ? null : () => Navigator.of(context).pop(),
            ),
            ModalButton(
              label: _loading ? '拉取中…' : '拉取订阅',
              primary: true,
              onPressed: _url.text.trim().isEmpty || _loading ? null : _fetch,
            ),
          ],
        ),
      ],
    );
  }
}
