/// 通用 Modal/Dialog 骨架 — 对齐原 React 版 Modal.css：
/// 半透明遮罩 + 居中面板（标题栏 / 内容 / 底部按钮）。
library;

import 'package:flutter/material.dart';

import 'palette.dart';

/// 应用通用弹窗骨架。
///
/// [width] 控制面板宽度；[actions] 为底部按钮行（确认/取消由调用方组装）。
class AppModal extends StatelessWidget {
  final String title;
  final Widget child;
  final List<Widget> actions;
  final double width;
  final VoidCallback? onClose;

  const AppModal({
    super.key,
    required this.title,
    required this.child,
    this.actions = const [],
    this.width = 520,
    this.onClose,
  });

  /// 居中弹出该弹窗，返回 [result]。
  static Future<T?> show<T>(
    BuildContext context, {
    required String title,
    required WidgetBuilder builder,
    double width = 520,
    bool barrierDismissible = true,
  }) {
    return showDialog<T>(
      context: context,
      barrierDismissible: barrierDismissible,
      barrierColor: Colors.black54,
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        child: _ModalFrame(
          title: title,
          width: width,
          child: builder(ctx),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return _ModalFrame(
      title: title,
      width: width,
      onClose: onClose,
      actions: actions,
      child: child,
    );
  }
}

class _ModalFrame extends StatelessWidget {
  final String title;
  final Widget child;
  final List<Widget>? actions;
  final double width;
  final VoidCallback? onClose;

  const _ModalFrame({
    required this.title,
    required this.child,
    required this.width,
    this.actions,
    this.onClose,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: width,
      constraints: const BoxConstraints(maxHeight: 720),
      decoration: BoxDecoration(
        color: AntPalette.bgPanel,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: AntPalette.border),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // 标题栏
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: AntPalette.border)),
            ),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    title,
                    style: const TextStyle(
                      color: AntPalette.text,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
                IconButton(
                  visualDensity: VisualDensity.compact,
                  iconSize: 18,
                  color: AntPalette.textDim,
                  tooltip: '关闭',
                  onPressed: onClose ?? () => Navigator.of(context).maybePop(),
                  icon: const Icon(Icons.close),
                ),
              ],
            ),
          ),
          // 内容
          Flexible(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(14),
              child: child,
            ),
          ),
          // 底部按钮
          if (actions != null && actions!.isNotEmpty)
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: const BoxDecoration(
                border: Border(top: BorderSide(color: AntPalette.border)),
              ),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: actions!,
              ),
            ),
        ],
      ),
    );
  }
}

/// 弹窗底部通用按钮（取消 = 灰，确认 = 主色）。
class ModalButton extends StatelessWidget {
  final String label;
  final VoidCallback? onPressed;
  final bool primary;
  final bool danger;

  const ModalButton({
    super.key,
    required this.label,
    this.onPressed,
    this.primary = false,
    this.danger = false,
  });

  @override
  Widget build(BuildContext context) {
    final color = danger
        ? AntPalette.red
        : primary
            ? AntPalette.accent
            : AntPalette.textDim;
    return Padding(
      padding: const EdgeInsets.only(left: 8),
      child: OutlinedButton(
        onPressed: onPressed,
        style: OutlinedButton.styleFrom(
          foregroundColor: onPressed == null
              ? AntPalette.textDim.withValues(alpha: 0.5)
              : color,
          side: BorderSide(
            color: onPressed == null
                ? AntPalette.border
                : color.withValues(alpha: 0.7),
          ),
          backgroundColor: primary
              ? (onPressed == null
                  ? AntPalette.accent.withValues(alpha: 0.2)
                  : AntPalette.accent.withValues(alpha: 0.25))
              : Colors.transparent,
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 10),
        ),
        child: Text(label),
      ),
    );
  }
}

/// 弹窗表单字段标签。
class ModalFieldLabel extends StatelessWidget {
  final String text;

  const ModalFieldLabel(this.text, {super.key});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 4, top: 8),
      child: Text(
        text,
        style: const TextStyle(color: AntPalette.textDim, fontSize: 12),
      ),
    );
  }
}
