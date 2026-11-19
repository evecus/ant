// ant GUI 桌面端冒烟测试：构造临时目录 AntApp，pump 主界面验证基本渲染。
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
    tempDir = await Directory.systemTemp.createTemp('ant_desktop_test_');
    app = AntApp(
      dataDir: tempDir.path,
      engine: DesktopEngine(maxLog: 100),
    );
    await app.init();
  });

  tearDown(() async {
    await app.dispose();
    await tempDir.delete(recursive: true);
  });

  testWidgets('主界面冒烟', (tester) async {
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

    expect(find.text('节点列表'), findsWidgets);
    expect(find.text('运行日志'), findsOneWidget);
    expect(find.text('系统代理'), findsOneWidget);
    expect(find.text('TUN 模式'), findsOneWidget);
    expect(find.text('默认'), findsOneWidget);
  });
}
