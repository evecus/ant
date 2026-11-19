// 启动参数解析（--silent，对齐 Go 版 winutil 的 silentArg）。
import 'package:flutter_test/flutter_test.dart';
import 'package:ant_desktop/startup_args.dart';

void main() {
  test('hasSilentArg：带 --silent 返回 true', () {
    expect(hasSilentArg(['--silent']), isTrue);
    expect(hasSilentArg(['--verbose', '--silent']), isTrue);
  });

  test('hasSilentArg：无参数 / 相似参数不误判', () {
    expect(hasSilentArg(const []), isFalse);
    expect(hasSilentArg(['--verbose']), isFalse);
    expect(hasSilentArg(['-silent']), isFalse);
    expect(hasSilentArg(['--silenta']), isFalse);
    expect(hasSilentArg(['SILENT']), isFalse);
  });
}
