/// NodeSchema 数据驱动表单的单元测试：
/// 验证字段表完整性、访问器往返、协议切换、必填校验。
library;

import 'package:ant_core/src/models/node.dart';
import 'package:ant_core/src/models/node_schema.dart';
import 'package:test/test.dart';

Node _fresh(String proto) {
  final n = Node(id: 'x', protocol: proto);
  NodeSchema.init(n, proto);
  return n;
}

void main() {
  group('schema 注册与字段表', () {
    test('覆盖全部 12 个结构化协议', () {
      expect(NodeSchema.keys, containsAll([
        'vmess', 'vless', 'ss', 'trojan', 'hysteria2', 'tuic',
        'anytls', 'socks', 'wireguard', 'naive', 'shadowquic', 'spectre',
      ]));
      expect(NodeSchema.keys.length, 12);
    });

    test('每个协议的字段 key 无重复', () {
      for (final p in NodeSchema.protocols) {
        final keys = p.fields.map((f) => f.key).toList();
        expect(keys.length, keys.toSet().length,
            reason: '${p.key} 存在重复字段 key');
      }
    });

    test('每个字段都能读写往返（不抛异常，值一致）', () {
      for (final p in NodeSchema.protocols) {
        final n = _fresh(p.key);
        for (final spec in p.fields) {
          // 用简单样例值写入再读出
          final probe = switch (spec.kind) {
            FieldKind.toggle => 'true',
            FieldKind.number => '1234',
            FieldKind.select =>
              spec.options.isEmpty ? 'probe' : spec.options.last,
            FieldKind.text || FieldKind.secret => 'probe-value',
          };
          spec.set(n, probe);
          expect(spec.get(n), probe,
              reason: '${p.key}.${spec.key} 读写往返不一致');
        }
      }
    });
  });

  group('内核默认值', () {
    test('vmess/vless 默认 tls=true 且 transport=tcp', () {
      final vm = _fresh('vmess');
      expect(vm.vMess!.tls, isTrue);
      expect(vm.vMess!.security, 'auto');
      expect(vm.vMess!.transport!.type, 'tcp');

      final vl = _fresh('vless');
      expect(vl.vless!.tls, isTrue);
      expect(vl.vless!.transport!.type, 'tcp');
    });

    test('shadowquic 默认 alpn=h3 / bbr / zeroRtt=true', () {
      final n = _fresh('shadowquic');
      expect(n.shadowquic!.alpn, ['h3']);
      expect(n.shadowquic!.congestionControl, 'bbr');
      expect(n.shadowquic!.zeroRtt, isTrue);
      expect(n.shadowquic!.overStream, isFalse);
    });

    test('naive 默认 uTLS=chrome；socks 默认 1080', () {
      expect(_fresh('naive').naive!.clientFingerprint, 'chrome');
      expect(_fresh('socks').port, 1080);
    });
  });

  group('条件显示 showIf', () {
    test('transport 子字段仅在对应 network 下可见', () {
      final n = _fresh('vmess');
      final fields = NodeSchema.fieldsFor('vmess');
      FieldSpec byKey(String k) => fields.firstWhere((f) => f.key == k);

      n.vMess!.transport!.type = 'tcp';
      expect(byKey(kWsPath).showIf(n), isFalse);
      n.vMess!.transport!.type = 'ws';
      expect(byKey(kWsPath).showIf(n), isTrue);
      expect(byKey(kXhttpPath).showIf(n), isFalse);
      n.vMess!.transport!.type = 'xhttp';
      expect(byKey(kXhttpPath).showIf(n), isTrue);
    });

    test('vless REALITY 字段仅 TLS 开启时可见', () {
      final n = _fresh('vless');
      final pbk = NodeSchema.fieldsFor('vless')
          .firstWhere((f) => f.key == kRealityPbk);
      expect(pbk.showIf(n), isTrue); // 默认 tls=true
      n.vless!.tls = false;
      expect(pbk.showIf(n), isFalse);
    });
  });

  group('协议切换 changeType', () {
    test('保留 name/address/port 与通用字段，重建目标协议', () {
      final n = _fresh('vmess');
      n.name = 'demo';
      n.address = 'example.com';
      n.port = 8443;
      n.vMess!.uuid = 'u-123';
      n.vMess!.sni = 'sni.example.com';

      NodeSchema.changeType(n, 'vmess', 'vless');

      expect(n.protocol, 'vless');
      expect(n.name, 'demo');
      expect(n.address, 'example.com');
      expect(n.port, 8443);
      expect(n.vMess, isNull, reason: '旧协议 Config 应被清除');
      expect(n.vless!.uuid, 'u-123', reason: '通用字段 uuid 应保留');
      expect(n.vless!.sni, 'sni.example.com', reason: '通用字段 sni 应保留');
      expect(n.vless!.tls, isTrue, reason: '新协议默认值应生效');
      expect(n.vless!.transport!.type, 'tcp');
    });

    test('切到无 TLS 的 ss 后不会残留 TLS 字段', () {
      final n = _fresh('vmess');
      n.vMess!.sni = 'sni.example.com';
      NodeSchema.changeType(n, 'vmess', 'ss');
      expect(n.ss, isNotNull);
      expect(n.vMess, isNull);
    });
  });

  group('必填校验 validate', () {
    test('基本信息缺失时报错', () {
      final n = _fresh('vless');
      expect(NodeSchema.validate(n), '请填写节点名称');
      n.name = 'ok';
      expect(NodeSchema.validate(n), '请填写服务器地址');
      n.address = 'example.com';
      expect(NodeSchema.validate(n), isNull);
    });

    test('端口范围校验', () {
      final n = _fresh('vless')
        ..name = 'ok'
        ..address = 'example.com'
        ..port = 70000;
      expect(NodeSchema.validate(n), contains('端口'));
    });

    test('按协议 required 字段校验（uuid / sni）', () {
      final vl = _fresh('vless')
        ..name = 'ok'
        ..address = 'example.com';
      expect(NodeSchema.validate(vl), '请填写「UUID」');
      vl.vless!.uuid = 'u-1';
      expect(NodeSchema.validate(vl), isNull);

      final sq = _fresh('shadowquic')
        ..name = 'ok'
        ..address = 'example.com';
      sq.shadowquic!.username = 'user';
      sq.shadowquic!.password = 'pwd';
      expect(NodeSchema.validate(sq), '请填写「SNI（须匹配 jls-upstream 域名）」');
      sq.shadowquic!.sni = 'jls.example.com';
      expect(NodeSchema.validate(sq), isNull);
    });

    test('raw 协议跳过结构化校验', () {
      final n = Node(id: 'x', protocol: 'ssh');
      expect(NodeSchema.validate(n), isNull);
    });
  });
}
