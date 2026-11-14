// ui_kit 基础冒烟：主题构建 + 协议徽章 + Toast。
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ui_kit/ui_kit.dart';

void main() {
  testWidgets('ProtocolBadge 渲染协议显示名与颜色', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: buildAntTheme(),
        home: const Scaffold(
          body: Center(child: ProtocolBadge(protocol: 'hysteria2')),
        ),
      ),
    );
    expect(find.text('Hy2'), findsOneWidget);
  });

  testWidgets('未知协议回退为大写原文', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: buildAntTheme(),
        home: const Scaffold(
          body: Center(child: ProtocolBadge(protocol: 'mieru')),
        ),
      ),
    );
    expect(find.text('MIERU'), findsOneWidget);
  });
}
