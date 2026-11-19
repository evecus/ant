// ant GUI 桌面端入口：初始化 AntApp（对齐 Go 版 portable 目录布局 + DesktopEngine），
// 接入窗口管理（window_manager）与系统托盘（tray_manager），
// 解析 `--silent`（自启动静默：不显示主窗口，仅托盘），注入 Riverpod 后启动主界面。
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ant_engine/ant_engine.dart';
import 'package:ui_desktop/ui_desktop.dart';
import 'package:ui_kit/ui_kit.dart';

import 'startup_args.dart';
import 'tray_shell.dart';

Future<void> main(List<String> args) async {
  WidgetsFlutterBinding.ensureInitialized();

  // 自启动静默启动：applyAutoStart 写入的自启动项带 `--silent` 参数。
  // runner 的 main.cpp 通过 DartProject.set_dart_entrypoint_arguments 把
  // 命令行参数传进来，Dart 侧只能从 main(List<String> args) 读到；
  // Platform.executableArguments 只含 VM 参数，Flutter Windows 上恒为空。
  final silent = hasSilentArg(args);

  // portable 目录布局（对齐 Go 版 getDataDir/getConfigsDir/getRunDir）：
  // exe 同级为 data/（节点与设置持久化）、configs/、run/、bin/，
  // 全部数据落在程序目录内，移动程序目录即整体搬迁。
  // 内置 .ars 规则集（run/rules/）与 bin/ 内核由 CI 打包时放入，程序不管理。
  final exeDir = File(Platform.resolvedExecutable).parent.path;
  final app = AntApp(
    dataDir: _join(exeDir, 'data'),
    appRootDir: exeDir,
    engine: DesktopEngine(maxLog: 500),
  );
  await app.init();

  // 内置 .ars 规则集：CI 打包时已复制进 run/rules/ant/；这里再用 Flutter
  // assets 兜底释放一次（缺文件时补齐，已存在且非空的不覆盖）。
  await app.ensureRuleFiles((assetPath) async {
    final key = assetPath.startsWith('assets/')
        ? assetPath
        : 'assets/$assetPath';
    try {
      final data = await rootBundle.load(key);
      return data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
    } catch (_) {
      return null;
    }
  });

  // 窗口（1100x750 / ant GUI / 关闭隐藏到托盘）与系统托盘
  final navigatorKey = GlobalKey<NavigatorState>();
  final shell = DesktopShell(app: app, navigatorKey: navigatorKey);
  await shell.init(silent: silent);

  runApp(ProviderScope(
    overrides: [antAppProvider.overrideWithValue(app)],
    child: AntDesktopApplication(navigatorKey: navigatorKey),
  ));
}

String _join(String a, String b) => a.endsWith(Platform.pathSeparator)
    ? '$a$b'
    : '$a${Platform.pathSeparator}$b';

class AntDesktopApplication extends StatelessWidget {
  final GlobalKey<NavigatorState> navigatorKey;

  const AntDesktopApplication({super.key, required this.navigatorKey});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ant GUI',
      navigatorKey: navigatorKey,
      debugShowCheckedModeBanner: false,
      theme: buildAntTheme(),
      home: const AntDesktopApp(),
    );
  }
}
