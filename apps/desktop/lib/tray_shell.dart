/// 桌面外壳 — 窗口管理（window_manager）+ 系统托盘（tray_manager）。
///
/// 窗口：1100x750、标题 "ant GUI"（native 侧同步设置）；关闭按钮不退出，
/// 改为隐藏到托盘（首次 Toast 提示），托盘菜单「退出」才真正退出。
/// 退出流程：停核心 →（settings.exitDisableProxy 且系统代理开启时）关闭系统
/// 代理 → 销毁托盘与窗口 → 结束进程。
library;

import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/scheduler.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ant_engine/ant_engine.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:ui_desktop/ui_desktop.dart' show showActionError;
import 'package:ui_kit/ui_kit.dart';
import 'package:window_manager/window_manager.dart';

/// 窗口尺寸（与 windows/runner/main.cpp 的原生设置保持一致）。
const Size kDesktopWindowSize = Size(1100, 750);

/// 托盘菜单 key。
const String _kShowWindow = 'show_window';
const String _kStartCore = 'start_core';
const String _kStopCore = 'stop_core';
const String _kToggleSysProxy = 'toggle_sys_proxy';
const String _kExit = 'exit';

/// 窗口 + 托盘生命周期管理（main 中创建，应用退出时销毁）。
class DesktopShell with WindowListener, TrayListener {
  final AntApp _app;

  /// 用于在托盘回调里拿到 Overlay 显示 Toast。
  final GlobalKey<NavigatorState> navigatorKey;

  // Windows 下 tray_manager 用 PNG 生成 HICON 时，Shell_NotifyIcon 对小尺寸
  // 直通 alpha 图标经常合成错误，托盘区域会显示为发灰/透明的方块；
  // 改用内置多尺寸、预乘 alpha 的 .ico 可修复。其余平台仍用 .png。
  static final String _iconRunning =
      Platform.isWindows ? 'assets/tray_running.ico' : 'assets/tray_running.png';
  static final String _iconStopped =
      Platform.isWindows ? 'assets/tray_stopped.ico' : 'assets/tray_stopped.png';

  /// 关闭按钮 → 隐藏到托盘的提示只弹一次。
  bool _hideTipShown = false;

  /// 系统代理当前开关（托盘菜单勾选态）。
  bool _sysProxy = false;

  StreamSubscription<ProcessStatus>? _statusSub;
  StreamSubscription<bool>? _restartSub;

  DesktopShell({required AntApp app, required this.navigatorKey}) : _app = app;

  /// 内核有效运行态：核心在跑，或正处于内部重启编排中
  /// （应用节点/保存设置/切换配置等动作内部的停-启）。重启期间托盘图标
  /// 与菜单保持"运行中"外观，不闪烁。
  bool get _coreOn => _app.coreRunning || _app.coreRestarting;

  /// 初始化窗口与托盘。[silent] 为 true（`--silent` 自启动）时不显示主窗口。
  Future<void> init({required bool silent}) async {
    await windowManager.ensureInitialized();
    const options = WindowOptions(
      size: kDesktopWindowSize,
      title: 'ant GUI',
      center: true,
    );
    await windowManager.waitUntilReadyToShow(options, () async {
      // 关闭按钮走 onWindowClose → 隐藏到托盘，而非退出进程
      await windowManager.setPreventClose(true);
      if (!silent) {
        await windowManager.show();
        await windowManager.focus();
      } else {
        // 双保险：原生 runner 已按 --silent 跳过首帧 Show()，
        // 这里再显式隐藏一次，确保窗口不出现（仅托盘）。
        await windowManager.hide();
      }
    });
    windowManager.addListener(this);

    _sysProxy = await _safeSysProxy();
    await _applyTray();
    trayManager.addListener(this);

    // 内核状态变化 → 换托盘图标 + 刷新菜单可用态
    _statusSub = _app.coreStatusChanges.listen((_) => _refreshTray());
    // 内部重启编排起止 → 同样刷新托盘（编排结束回到真实运行态）
    _restartSub = _app.coreRestartingChanges.listen((_) => _refreshTray());
  }

  Future<void> dispose() async {
    await _statusSub?.cancel();
    await _restartSub?.cancel();
    trayManager.removeListener(this);
    windowManager.removeListener(this);
  }

  // ─── 托盘 ─────────────────────────────────────────────────────────────────

  List<MenuItem> _menuItems() => [
        MenuItem(key: _kShowWindow, label: '显示主窗口'),
        MenuItem.separator(),
        MenuItem(
          key: _kStartCore,
          label: '启动内核',
          disabled: _coreOn,
        ),
        MenuItem(
          key: _kStopCore,
          label: '停止内核',
          disabled: !_coreOn,
        ),
        MenuItem(
          key: _kToggleSysProxy,
          label: '系统代理',
          checked: _sysProxy,
        ),
        MenuItem.separator(),
        MenuItem(key: _kExit, label: '退出'),
      ];

  Future<void> _applyTray() async {
    await trayManager.setIcon(_coreOn ? _iconRunning : _iconStopped);
    await trayManager.setContextMenu(Menu(items: _menuItems()));
  }

  Future<void> _refreshTray() async {
    try {
      await _applyTray();
    } catch (_) {/* 托盘不可用时忽略 */}
  }

  Future<bool> _safeSysProxy() async {
    try {
      return await _app.sysProxyEnabled();
    } catch (_) {
      return false;
    }
  }

  @override
  void onTrayIconMouseDown() {
    _scheduleUI(_showWindow);
  }

  @override
  void onTrayIconRightMouseDown() {
    trayManager.popUpContextMenu();
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) {
    // 托盘菜单点击来自原生消息循环，调度回主 isolate 的 UI 任务队列处理
    final key = menuItem.key ?? '';
    _scheduleUI(() => _onMenu(key));
  }

  /// 原生回调可能落在帧间隙：确保下一帧被调度，再把逻辑排入 UI 任务队列。
  void _scheduleUI(VoidCallback fn) {
    SchedulerBinding.instance.ensureVisualUpdate();
    SchedulerBinding.instance.scheduleTask(fn, Priority.touch);
  }

  Future<void> _onMenu(String key) async {
    switch (key) {
      case _kShowWindow:
        await _showWindow();
      case _kStartCore:
        await _runTrayAction(
          '启动内核失败',
          _app.startCoreUserRequested,
          successMsg: '$coreAnt 已启动',
        );
      case _kStopCore:
        await _runTrayAction(
          '停止内核失败',
          _app.stopCoreUserRequested,
          successMsg: '$coreAnt 已停止',
        );
      case _kToggleSysProxy:
        await _toggleSysProxy();
      case _kExit:
        await exitApp();
    }
  }

  Future<void> _showWindow() async {
    await windowManager.show();
    await windowManager.focus();
  }

  /// 托盘动作统一包装：错误走 Toast（含提权重启退出处理），
  /// 结束后刷新托盘（图标/菜单可用态可能变化）。
  Future<void> _runTrayAction(
    String failurePrefix,
    Future<void> Function() fn, {
    String? successMsg,
  }) async {
    try {
      await fn();
      if (successMsg != null) {
        _toast(successMsg, ToastType.success);
      }
    } catch (e) {
      await showActionError(
          navigatorKey.currentContext, e, failurePrefix: failurePrefix);
    }
    await _refreshTray();
  }

  /// 在根 Overlay 上弹 Toast（窗口隐藏时 Toast 会在窗口恢复显示后可见）。
  void _toast(String message, ToastType type) {
    final ctx = navigatorKey.currentContext;
    if (ctx == null || !ctx.mounted) return;
    AppToast.show(ctx, message, type);
  }

  Future<void> _toggleSysProxy() async {
    try {
      if (_sysProxy) {
        await _app.disableSystemProxyUserRequested();
        _sysProxy = false;
        _toast('已关闭系统代理', ToastType.success);
      } else {
        await _app.enableSystemProxyUserRequested();
        _sysProxy = true;
        _toast('已启用系统代理', ToastType.success);
      }
    } catch (e) {
      _sysProxy = await _safeSysProxy();
      await showActionError(
          navigatorKey.currentContext, e, failurePrefix: '系统代理操作失败');
    }
    await _refreshTray();
  }

  // ─── 窗口 ─────────────────────────────────────────────────────────────────

  @override
  void onWindowClose() async {
    // setPreventClose(true) 拦截关闭按钮：隐藏到托盘而不是退出
    await windowManager.hide();
    if (!_hideTipShown) {
      _hideTipShown = true;
      _toast('程序已最小化到系统托盘', ToastType.info);
    }
  }

  // ─── 退出 ─────────────────────────────────────────────────────────────────

  /// 真正退出：停核心 →（设置开启且系统代理开着时）关闭系统代理 →
  /// 清理托盘与窗口 → 结束进程。每步失败都不阻断退出流程。
  Future<void> exitApp() async {
    try {
      if (_app.coreRunning) {
        await _app.stopCore();
      }
    } catch (_) {}
    if (_app.settings.exitDisableProxy) {
      try {
        if (await _app.sysProxyEnabled()) {
          await _app.disableSystemProxy();
        }
      } catch (_) {}
    }
    try {
      await trayManager.destroy();
    } catch (_) {}
    try {
      await windowManager.destroy();
    } catch (_) {}
    exit(0);
  }
}
