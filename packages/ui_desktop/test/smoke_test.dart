// ui_desktop 冒烟测试：用临时目录构造真实 AntApp，pump 主界面。
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ant_engine/ant_engine.dart';
import 'package:ui_desktop/ui_desktop.dart';
import 'package:ui_kit/ui_kit.dart';

void main() {
  late Directory tempDir;
  late AntApp app;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('ant_gui_test_');
    app = AntApp(
      dataDir: tempDir.path,
      engine: DesktopEngine(maxLog: 100),
    );
    await app.init();
    // 预置两个节点便于列表渲染
    app.addNodesFromText(
      'ss://YWVzLTI1Ni1nY206dGVzdA@1.2.3.4:8388#测试节点A\n'
      'trojan://pass@example.com:443?sni=example.com#测试节点B',
      defaultGroupID,
      '',
    );
  });

  tearDown(() async {
    await app.dispose();
    await tempDir.delete(recursive: true);
    AppToast.dismiss();
  });

  testWidgets('主界面冒烟：标题栏 / 配置栏 / 分组与节点渲染', (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [antAppProvider.overrideWithValue(app)],
        child: MaterialApp(
          theme: buildAntTheme(),
          home: const AntDesktopApp(),
        ),
      ),
    );
    await tester.pumpAndSettle(const Duration(seconds: 1));

    // 标题栏 Tab
    expect(find.text('节点列表'), findsWidgets);
    expect(find.text('运行日志'), findsOneWidget);
    // 状态灯文案
    expect(find.text('未运行'), findsOneWidget);
    // 底部栏
    expect(find.text('系统代理'), findsOneWidget);
    expect(find.text('TUN 模式'), findsOneWidget);
    // 分组与节点
    expect(find.text('默认'), findsOneWidget);
    expect(find.text('测试节点A'), findsOneWidget);
    expect(find.text('测试节点B'), findsOneWidget);
    expect(find.text('2 个节点'), findsWidgets);
  });

  testWidgets('日志 Tab 切换冒烟', (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [antAppProvider.overrideWithValue(app)],
        child: MaterialApp(
          theme: buildAntTheme(),
          home: const AntDesktopApp(),
        ),
      ),
    );
    await tester.pumpAndSettle(const Duration(seconds: 1));

    await tester.tap(find.text('运行日志'));
    await tester.pumpAndSettle();
    expect(find.text('运行日志', skipOffstage: false), findsWidgets);
    expect(find.text('0 条'), findsOneWidget);
  });
}
