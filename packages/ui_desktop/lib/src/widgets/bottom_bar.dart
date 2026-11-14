/// 底部状态栏 — 对齐 Go 版 BottomBar.jsx：
/// 三个开关块（TUN 模式 ⬡ / 系统代理 ⇌ / 启动核心 ▶）+ 分隔线，
/// 每块含图标 + 标签 + 开关 + 描述行。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

import '../actions.dart';
import '../providers.dart';

class BottomBar extends ConsumerWidget {
  const BottomBar({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final app = ref.watch(antAppProvider);
    final settings = ref.watch(settingsProvider);
    final coreOn = ref.watch(coreSwitchOnProvider);
    final sysProxy = ref.watch(sysProxyProvider).valueOrNull ?? false;
    final tun = ref.watch(tunEnabledProvider);
    const coreName = coreAnt;
    final proxyAddr = '127.0.0.1:${settings.proxyPort}';

    return Container(
      height: 66,
      padding: const EdgeInsets.symmetric(horizontal: 6),
      decoration: const BoxDecoration(
        color: AntPalette.bgPanel,
        border: Border(top: BorderSide(color: AntPalette.border)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Expanded(
            child: _ToggleBlock(
              label: 'TUN 模式',
              icon: '⬡',
              enabled: tun,
              activeColor: AntPalette.green,
              desc: tun ? '虚拟网卡已启用' : '点击启用 TUN',
              onToggle: (on) =>
                  _toggleTun(context, ref, app, on),
            ),
          ),
          const _VDivider(),
          Expanded(
            child: _ToggleBlock(
              label: '系统代理',
              icon: '⇌',
              enabled: sysProxy,
              activeColor: AntPalette.accent,
              desc: sysProxy ? (proxyAddr) : '点击设置系统代理',
              onToggle: (on) => _toggleProxy(context, ref, app, on),
            ),
          ),
          const _VDivider(),
          Expanded(
            child: _ToggleBlock(
              label: '启动核心',
              icon: '▶',
              enabled: coreOn,
              activeColor: AntPalette.yellow,
              desc: coreOn ? '$coreName 运行中' : '点击启动 $coreName',
              isPrimary: true,
              onToggle: (on) => _toggleCore(context, ref, app, on),
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _toggleCore(
      BuildContext context, WidgetRef ref, AntApp app, bool on) async {
    const coreName = coreAnt;
    await runAction(
      context,
      () => on
          ? app.startCoreUserRequested()
          : app.stopCoreUserRequested(),
      successMsg: on ? '$coreName 已启动' : '$coreName 已停止',
      failurePrefix: on ? '启动失败' : '停止失败',
    );
  }

  Future<void> _toggleProxy(
      BuildContext context, WidgetRef ref, AntApp app, bool on) async {
    await runAction(
      context,
      () => on
          ? app.enableSystemProxyUserRequested()
          : app.disableSystemProxyUserRequested(),
      successMsg: on
          ? '已启用系统代理 (${app.settings.proxyListen}:${app.settings.proxyPort})'
          : '已关闭系统代理',
      failurePrefix: '系统代理操作失败',
    );
    ref.read(sysProxyProvider.notifier).reload();
  }

  Future<void> _toggleTun(
      BuildContext context, WidgetRef ref, AntApp app, bool on) async {
    await runAction(
      context,
      () => on ? app.enableTun() : app.disableTun(),
      successMsg: on ? '已启用 TUN 模式' : '已关闭 TUN 模式',
      failurePrefix: 'TUN 操作失败',
    );
    ref.read(settingsVersionProvider.notifier).bump();
  }
}

/// 竖分隔线。
class _VDivider extends StatelessWidget {
  const _VDivider();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 1,
      margin: const EdgeInsets.symmetric(vertical: 12),
      color: AntPalette.border,
    );
  }
}

/// 开关块（对齐 Go: ToggleButton）。
class _ToggleBlock extends StatelessWidget {
  final String label;
  final String icon;
  final bool enabled;
  final Color activeColor;
  final String desc;
  final bool isPrimary;
  final ValueChanged<bool> onToggle;

  const _ToggleBlock({
    required this.label,
    required this.icon,
    required this.enabled,
    required this.activeColor,
    required this.desc,
    required this.onToggle,
    this.isPrimary = false,
  });

  @override
  Widget build(BuildContext context) {
    final fg = enabled ? activeColor : AntPalette.textMid;
    return InkWell(
      onTap: () => onToggle(!enabled),
      borderRadius: BorderRadius.circular(10),
      child: Container(
        margin: const EdgeInsets.symmetric(vertical: 8, horizontal: 4),
        padding: const EdgeInsets.symmetric(horizontal: 14),
        decoration: BoxDecoration(
          color: enabled
              ? activeColor.withValues(alpha: 0.10)
              : Colors.transparent,
          borderRadius: BorderRadius.circular(10),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                SizedBox(
                  width: 18,
                  child: Text(icon,
                      textAlign: TextAlign.center,
                      style: TextStyle(
                          color: fg,
                          fontSize: 14,
                          fontFamily: 'Consolas')),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(label,
                      style: TextStyle(
                          color: fg,
                          fontSize: 13,
                          fontWeight: FontWeight.w600)),
                ),
                // 自绘开关（对齐 CSS 的 toggle-switch）
                _MiniSwitch(
                  on: enabled,
                  activeColor: activeColor,
                ),
              ],
            ),
            const SizedBox(height: 2),
            Padding(
              padding: const EdgeInsets.only(left: 26),
              child: Text(
                desc,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  color: enabled
                      ? Color.lerp(activeColor, AntPalette.textDim, 0.3)
                      : AntPalette.textDim,
                  fontSize: 10.5,
                  fontFamily: 'Consolas',
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// 开关外观（36×19 胶囊 + 滑块）。
class _MiniSwitch extends StatelessWidget {
  final bool on;
  final Color activeColor;

  const _MiniSwitch({required this.on, required this.activeColor});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 36,
      height: 19,
      decoration: BoxDecoration(
        color: on ? activeColor : AntPalette.bgHover,
        borderRadius: BorderRadius.circular(10),
        boxShadow: on
            ? [
                BoxShadow(
                  color: activeColor.withValues(alpha: 0.18),
                  blurRadius: 0,
                  spreadRadius: 3,
                ),
              ]
            : null,
      ),
      child: AnimatedAlign(
        duration: const Duration(milliseconds: 180),
        curve: Curves.easeOut,
        alignment: on ? Alignment.centerRight : Alignment.centerLeft,
        child: Container(
          width: 13,
          height: 13,
          margin: const EdgeInsets.all(2),
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            color: on ? Colors.white : AntPalette.textDim,
            boxShadow: const [
              BoxShadow(
                  color: Colors.black26,
                  offset: Offset(0, 1),
                  blurRadius: 2),
            ],
          ),
        ),
      ),
    );
  }
}
