// actions.dart 提权重启判断 + 设置页保存流程（app.saveSettings）。
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ant_engine/ant_engine.dart';
import 'package:ui_desktop/src/actions.dart';
import 'package:ui_desktop/src/providers.dart';
import 'package:ui_desktop/src/settings_panel.dart';
import 'package:ui_kit/ui_kit.dart';

void main() {
  group('isElevationRestart', () {
    test('仅匹配提权重启消息', () {
      expect(
        isElevationRestart(AppException('正在以管理员身份重启程序…')),
        isTrue,
      );
      expect(isElevationRestart(AppException('未选择配置文件')), isFalse);
      expect(isElevationRestart(AppException('')), isFalse);
    });

    test('elevationRestartMessage 与 AntApp 抛出的消息一致', () {
      // 防止两侧文案漂移导致退出逻辑失效
      expect(elevationRestartMessage, '正在以管理员身份重启程序…');
    });
  });

  group('设置页保存', () {
    late Directory tempDir;
    late AntApp app;

    setUp(() async {
      tempDir = await Directory.systemTemp.createTemp('ant_gui_test_');
      app = AntApp(
        dataDir: tempDir.path,
        engine: DesktopEngine(maxLog: 100),
      );
      await app.init();
    });

    tearDown(() async {
      await app.dispose();
      await tempDir.delete(recursive: true);
      AppToast.dismiss();
    });

    Widget buildHost(WidgetTester tester) {
      // 设置页表单很高（多行表单，测试字体 Ahem 行宽/行高偏大），
      // 放大测试视口保证全部可见；忽略仅测试字体导致的溢出异常
      tester.view.physicalSize = const Size(1200, 2600);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);
      final originalOnError = FlutterError.onError;
      FlutterError.onError = (details) {
        final e = details.exception;
        if (e is FlutterError && e.message.contains('overflowed')) return;
        originalOnError?.call(details);
      };
      addTearDown(() => FlutterError.onError = originalOnError);
      return ProviderScope(
        overrides: [antAppProvider.overrideWithValue(app)],
        child: MaterialApp(
          theme: buildAntTheme(),
          home: const Scaffold(body: SettingsPanel()),
        ),
      );
    }

    testWidgets('保存成功：走 app.saveSettings 且弹「设置已保存」', (tester) async {
      await tester.pumpWidget(buildHost(tester));
      await tester.pumpAndSettle();

      // 程序视图的开关可见
      expect(find.text('开机自启动'), findsOneWidget);
      expect(find.text('静默启动'), findsOneWidget);

      // 配置视图可切换且含「退出时关闭系统代理」
      await tester.tap(find.text('配置'));
      await tester.pumpAndSettle();
      expect(find.text('退出时关闭系统代理'), findsOneWidget);

      await tester.tap(find.text('保存'));
      await tester.pumpAndSettle();

      expect(find.text('设置已保存'), findsOneWidget);
      // 设置确实通过 saveSettings 写盘
      final saved = File('${tempDir.path}/settings.json');
      expect(saved.existsSync(), isTrue);
      // 单内核版：settings.json 不再持久化内核选择字段
      expect(saved.readAsStringSync().contains('"core"'), isFalse,
          reason: 'ant 单内核不应再写出 core 字段');
      expect(app.settings.routingMode, modeCustom);
      // 推进 2.8s 让 Toast 计时器结束，避免测试结束时残留 pending timer
      await tester.pump(const Duration(seconds: 3));
    });

    testWidgets('校验失败：前端预校验弹 alert 且不写盘', (tester) async {
      await tester.pumpWidget(buildHost(tester));
      await tester.pumpAndSettle();

      // 日志行数改成非法值 30（合法范围 50-100000）→ 前端预校验 alert
      final logField =
          find.ancestor(of: find.text('500'), matching: find.byType(TextField)).first;
      await tester.enterText(logField, '30');
      await tester.tap(find.text('保存'));
      await tester.pumpAndSettle();

      expect(find.textContaining('日志行数必须是'), findsOneWidget);
      // alert 需手动关闭（对齐 Go 版 alert 行为）
      await tester.tap(find.text('确定'));
      await tester.pumpAndSettle();
      // 设置未写盘
      expect(File('${tempDir.path}/settings.json').existsSync(), isFalse);
    });
  });
}
