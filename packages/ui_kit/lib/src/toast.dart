/// 全局 Toast — 对齐原 React 版 Toast.jsx：
/// 顶部居中出现，2.8s 自动消失，四种类别（success/error/info/warning）。
library;

import 'dart:async';

import 'package:flutter/material.dart';

import 'palette.dart';

/// Toast 类别。
enum ToastType { success, error, info, warning }

/// Toast 显示时长。
const Duration _toastDuration = Duration(milliseconds: 2800);

/// 全局 Toast 入口：`AppToast.show(context, '消息', ToastType.success)`。
abstract final class AppToast {
  static Timer? _timer;
  static OverlayEntry? _entry;
  static int _seq = 0;

  /// 显示一条 Toast；同类消息重复调用会替换当前内容并重置计时。
  static void show(BuildContext context, String message,
      [ToastType type = ToastType.info]) {
    final overlay = Overlay.maybeOf(context, rootOverlay: true);
    if (overlay == null) return;
    final seq = ++_seq;
    _entry?.remove();
    _entry = OverlayEntry(
      builder: (_) => _ToastView(
        key: ValueKey(seq),
        message: message,
        type: type,
      ),
    );
    overlay.insert(_entry!);
    _timer?.cancel();
    _timer = Timer(_toastDuration, () {
      _entry?.remove();
      _entry = null;
    });
  }

  /// 立即移除当前 Toast（测试用）。
  static void dismiss() {
    _timer?.cancel();
    _entry?.remove();
    _entry = null;
  }
}

class _ToastView extends StatefulWidget {
  final String message;
  final ToastType type;

  const _ToastView({super.key, required this.message, required this.type});

  @override
  State<_ToastView> createState() => _ToastViewState();
}

class _ToastViewState extends State<_ToastView>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 180),
  )..forward();

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  Color get _color => switch (widget.type) {
        ToastType.success => AntPalette.green,
        ToastType.error => AntPalette.red,
        ToastType.warning => AntPalette.yellow,
        ToastType.info => AntPalette.accent,
      };

  IconData get _icon => switch (widget.type) {
        ToastType.success => Icons.check_circle_outline,
        ToastType.error => Icons.cancel_outlined,
        ToastType.warning => Icons.warning_amber_outlined,
        ToastType.info => Icons.info_outline,
      };

  @override
  Widget build(BuildContext context) {
    return Positioned(
      top: 48,
      left: 0,
      right: 0,
      child: Center(
        child: FadeTransition(
          opacity: CurvedAnimation(parent: _ctrl, curve: Curves.easeOut),
          child: Material(
            color: Colors.transparent,
            child: Container(
              constraints: const BoxConstraints(maxWidth: 560),
              padding:
                  const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              decoration: BoxDecoration(
                color: AntPalette.bgInput,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: _color.withValues(alpha: 0.6)),
                boxShadow: const [
                  BoxShadow(
                    color: Colors.black54,
                    blurRadius: 12,
                    offset: Offset(0, 4),
                  ),
                ],
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(_icon, color: _color, size: 18),
                  const SizedBox(width: 8),
                  Flexible(
                    child: Text(
                      widget.message,
                      style: const TextStyle(
                          color: AntPalette.text, fontSize: 13),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
