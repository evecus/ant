/// 配置增量编辑测试 — ant 单内核 YAML 版。
///
/// 覆盖点保持与上游原版一致（应用节点 / raw 无损回写 / 未知 transport /
/// TUN / mixed-port / 已应用节点识别 / 取消应用 / 坏配置），
/// 另覆盖 ant 特有的字段归一化（nodeToAntProxy / clashProxyToAntProxy）与
/// 不支持协议的 fail-fast。
library;

import 'dart:io';

import 'package:ant_core/src/config/ant_edit.dart';
import 'package:ant_core/src/config/editor.dart';
import 'package:ant_core/src/export/ant_write.dart';
import 'package:ant_core/src/models/node.dart';
import 'package:ant_core/src/parsing/common.dart';
import 'package:ant_core/src/parsing/content.dart';
import 'package:test/test.dart';

const antTestCfg = '''mixed-port: 7890
proxies:
  - name: proxy
    type: ss
    server: old.example.com
    port: 8388
    cipher: aes-128-gcm
    password: oldpass
route:
  - MATCH,proxy
''';

/// 在系统临时目录写测试配置文件，测试结束后清理。
String writeTempFile(String content, {String name = 'config.yaml'}) {
  final dir = Directory.systemTemp.createTempSync('ant_config_editor_test_');
  addTearDown(() {
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  });
  final p = '${dir.path}${Platform.pathSeparator}$name';
  File(p).writeAsStringSync(content);
  return p;
}

void main() {
  group('ant 配置增量编辑（移植自 mihomo_test.go）', () {
    test('应用 hysteria2 节点并替换 proxy 条目', () {
      final p = writeTempFile(antTestCfg);
      final n = Node(
        id: 'n1',
        name: 'test-hy2',
        address: '1.2.3.4',
        port: 443,
        protocol: 'hysteria2',
        hysteria2: Hysteria2Config(
          password: 'pw',
          sni: 'sni.example.com',
          upMbps: 30,
          downMbps: 200,
          insecure: true,
        ),
      );
      applyNodeToConfig(p, n);

      final cfg = loadYamlFile(p);
      final proxies = getProxies(cfg);
      expect(proxies.length, 1);
      final pr = proxies[0] as Map;
      expect(pr['name'], antProxyName);
      expect(pr['type'], 'hysteria2');
      expect(pr['server'], '1.2.3.4');
      expect(pr['port'], 443);
      expect(pr['password'], 'pw');
      expect(pr['sni'], 'sni.example.com');
      // ant 的 up/down 是 Option<String>，带单位（不是裸数字）
      expect(pr['up'], '30 Mbps');
      expect(pr['down'], '200 Mbps');
      expect(pr['skip-cert-verify'], true);
      // QUIC 系协议恒为 TLS（raw 未写 tls 时按协议补默认）
      expect(pr['tls'], true);

      // 不再生成 proxy-groups，route 直接引用节点名
      expect(cfg.containsKey('proxy-groups'), isFalse);
      expect((cfg['route'] as List).contains('MATCH,$antProxyName'), isTrue);

      // 已应用节点可被识别；其他节点不应误判
      expect(findAppliedNodeId(p, [n]), 'n1');
      final other = Node(
        id: 'n2',
        name: 'test-hy2',
        address: '1.2.3.4',
        port: 443,
        protocol: 'hysteria2',
        hysteria2: Hysteria2Config(
          password: 'different',
          sni: 'sni.example.com',
          upMbps: 30,
          downMbps: 200,
          insecure: true,
        ),
      );
      expect(findAppliedNodeId(p, [other]), '');
    });

    test('Clash YAML 导入的节点经 ant 归一化后无损回写', () {
      final p = writeTempFile(antTestCfg);
      const clashYaml = '''proxies:
  - name: raw-node
    type: vless
    server: 5.6.7.8
    port: 443
    uuid: uuid-123
    tls: true
    servername: example.com
    network: ws
    client-fingerprint: chrome
    ws-opts:
      path: /ws
      headers:
        Host: example.com
''';
      final nodes = parseContent(clashYaml);
      expect(nodes.length, 1);
      final n = nodes[0];
      expect(n.rawClashProxy, isNotNull);

      applyNodeToConfig(p, n);
      final cfg = loadYamlFile(p);
      final proxies = getProxies(cfg);
      expect(proxies.length, 1);
      final pr = proxies[0] as Map;
      expect(pr['name'], antProxyName);
      expect(pr['uuid'], 'uuid-123');
      expect(pr['servername'], 'example.com');
      expect(pr['sni'], 'example.com', reason: 'servername → sni 别名');
      expect(pr['network'], 'ws');
      expect(pr['ws-path'], '/ws', reason: '嵌套 ws-opts → 扁平 ws-path');
      expect(pr['ws-host'], 'example.com', reason: 'ws-opts.headers.Host → ws-host');
      expect(pr['client-fingerprint'], 'chrome');
      expect(pr['tls'], true);
      expect(findAppliedNodeId(p, [n]), n.id);
    });

    test('ant 不支持的 transport fail-fast（不静默降级）', () {
      final p = writeTempFile(antTestCfg);
      final n = Node(
        id: 'n9',
        name: 'vmess-splithttp',
        address: '9.9.9.9',
        port: 10086,
        protocol: 'vmess',
        vMess: VMessConfig(
          uuid: 'uuid-9',
          transport: TransportConfig(type: 'splithttp', path: '/x'),
        ),
      );
      // ant 只实现 tcp / ws / xhttp，未知 transport 直接报错
      expect(() => applyNodeToConfig(p, n), throwsA(isA<ParseException>()));
      // 失败不应污染原配置
      final cfg = loadYamlFile(p);
      expect((getProxies(cfg).single as Map)['server'], 'old.example.com');
    });

    test('TUN 开关与 ant 字段（无 stack）', () {
      final p = writeTempFile(antTestCfg);

      setTun(p, true, 8500, true);
      expect(hasTunInbound(p), isTrue);
      var cfg = loadYamlFile(p);
      final tun = cfg['tun'] as Map;
      expect(tun['enable'], true);
      expect(tun['mtu'], 8500);
      expect(tun['strict-route'], true);
      expect(tun['auto-route'], true);
      expect(tun.containsKey('auto-detect-interface'), isFalse,
          reason: 'auto-detect-interface 由内核自行处理');
      expect(tun.containsKey('address'), isFalse,
          reason: 'address 由内核自行处理');
      expect((tun['dns-hijack'] as List).single, 'any:53');
      expect(tun.containsKey('stack'), isFalse, reason: 'ant 内核 NAT 系统栈无 stack');

      // mtu <= 0 回退默认 9000
      setTun(p, true, 0, false);
      cfg = loadYamlFile(p);
      expect((cfg['tun'] as Map)['mtu'], 9000);
      expect((cfg['tun'] as Map)['strict-route'], false);

      // TUN 关闭 → 整段移除
      setTun(p, false, 0, false);
      expect(hasTunInbound(p), isFalse);
      expect(loadYamlFile(p).containsKey('tun'), isFalse);
    });

    test('mixed-port + bind-address（ant 无 allow-lan）', () {
      final p = writeTempFile(antTestCfg);

      setMixedInbound(p, true, '0.0.0.0', 2081);
      var cfg = loadYamlFile(p);
      expect(cfg['mixed-port'], 2081);
      expect(cfg['bind-address'], '0.0.0.0');
      expect(cfg.containsKey('allow-lan'), isFalse);

      // 空参数回退 127.0.0.1:2080
      setMixedInbound(p, true, '', 0);
      cfg = loadYamlFile(p);
      expect(cfg['mixed-port'], 2080);
      expect(cfg['bind-address'], '127.0.0.1');

      // 关闭 → 移除 mixed-port
      setMixedInbound(p, false, '127.0.0.1', 0);
      expect(loadYamlFile(p).containsKey('mixed-port'), isFalse);
    });

    test('应用节点不生成 proxy-groups，route 直接引用节点名', () {
      final p = writeTempFile('mixed-port: 7890\nroute:\n  - MATCH,proxy\n');
      final n = Node(
        id: 'n1',
        name: 'ss-node',
        address: '1.1.1.1',
        port: 8388,
        protocol: 'ss',
        ss: SSConfig(method: 'aes-128-gcm', password: 'pw'),
      );
      applyNodeToConfig(p, n);
      final cfg = loadYamlFile(p);
      expect(getProxies(cfg), hasLength(1));
      expect((getProxies(cfg).single as Map)['name'], antProxyName);
      expect(cfg.containsKey('proxy-groups'), isFalse,
          reason: 'route 直接按节点名引用，无需选择组');
      expect((cfg['route'] as List).contains('MATCH,$antProxyName'), isTrue);
      expect(findAppliedNodeId(p, [n]), 'n1');
    });

    test('removeNodeFromConfig：移除 proxy 节点', () {
      final p = writeTempFile(antTestCfg);
      removeNodeFromConfig(p);
      final cfg = loadYamlFile(p);
      expect(getProxies(cfg), isEmpty);
      // route 与其它段保持原样（GUI 只移除节点条目）
      expect((cfg['route'] as List).single, 'MATCH,proxy');
      // 未应用过时不动文件
      expect(() => removeNodeFromConfig(p), returnsNormally);
      expect(getProxies(loadYamlFile(p)), isEmpty);
    });

    test('loadConfig/saveConfig 兼容入口（YAML 往返）', () {
      final p = writeTempFile(antTestCfg);
      final cfg = loadConfig(p);
      cfg['log-level'] = 'warn';
      saveConfig(p, cfg);
      expect(loadConfig(p)['log-level'], 'warn');
    });

    test('坏配置/不存在文件：ParseException 与容错', () {
      final bad = writeTempFile('a: [1, b: 2\n');
      expect(
          () => applyNodeToConfig(
              bad,
              Node(
                  id: 'x',
                  protocol: 'ss',
                  ss: SSConfig(method: 'aes-128-gcm', password: 'p'))),
          throwsA(isA<ParseException>()));
      expect(() => hasTunInbound(bad), returnsNormally,
          reason: '读失败 hasTunInbound 返回 false 而非抛错');
      expect(hasTunInbound(bad), isFalse);
      expect(hasTunInbound('/nonexistent/path/config.yaml'), isFalse);
      expect(findAppliedNodeId('/nonexistent/path/config.yaml', []), '');
    });

    test('buildAntTunInbound：默认值', () {
      final tun = buildAntTunInbound(0, false);
      expect(tun['mtu'], 9000);
      expect(tun['strict-route'], false);
      expect(tun.containsKey('address'), isFalse,
          reason: 'address 由内核自行处理');
      expect(tun.containsKey('auto-detect-interface'), isFalse,
          reason: 'auto-detect-interface 由内核自行处理');
    });
  });

  group('nodeToAntProxy 代表性协议（ant 扁平字段）', () {
    test('vmess + ws + tls（alterId→alter-id、ws-opts→ws-path/ws-host）', () {
      final n = Node(
        id: 'x1',
        address: 'a.example.com',
        port: 443,
        protocol: 'vmess',
        vMess: VMessConfig(
          uuid: 'u-1',
          alterId: 0,
          security: '',
          tls: true,
          sni: 'sni.example.com',
          insecure: true,
          transport:
              TransportConfig(type: 'ws', path: '/ws', host: 'cdn.example.com'),
        ),
      );
      final ob = nodeToAntProxy(n);
      expect(ob['type'], 'vmess');
      expect(ob['uuid'], 'u-1');
      expect(ob['alter-id'], 0,
          reason: 'Clash 的 alterId 应收敛为 ant 的 alter-id');
      expect(ob['cipher'], 'auto');
      expect(ob['network'], 'ws');
      expect(ob['ws-path'], '/ws');
      expect(ob['ws-host'], 'cdn.example.com');
      expect((ob['ws-headers'] as Map)['Host'], 'cdn.example.com');
      expect(ob['tls'], true);
      expect(ob['sni'], 'sni.example.com');
      expect(ob['skip-cert-verify'], true);
    });

    test('vless + reality + flow（reality-opts → 扁平字段）', () {
      final n = Node(
        id: 'x2',
        address: 'b.example.com',
        port: 443,
        protocol: 'vless',
        vless: VLESSConfig(
          uuid: 'u-2',
          flow: 'xtls-rprx-vision',
          tls: true,
          sni: 'www.apple.com',
          publicKey: 'pbk-xyz',
          shortId: 'abcd',
        ),
      );
      final ob = nodeToAntProxy(n);
      expect(ob['type'], 'vless');
      expect(ob['flow'], 'xtls-rprx-vision');
      expect(ob['reality-public-key'], 'pbk-xyz');
      expect(ob['reality-short-id'], 'abcd');
      expect(ob['sni'], 'www.apple.com');
      expect(ob['tls'], true);
    });

    test('hysteria2（obfs + up/down 带宽字符串）', () {
      final n = Node(
        id: 'x3',
        address: 'c.example.com',
        port: 443,
        protocol: 'hysteria2',
        hysteria2: Hysteria2Config(
          password: 'pw',
          sni: 's.example.com',
          upMbps: 10,
          downMbps: 100,
          obfs: 'salamander',
          obfsPassword: 'obfspw',
          insecure: true,
        ),
      );
      final ob = nodeToAntProxy(n);
      expect(ob['type'], 'hysteria2');
      expect(ob['password'], 'pw');
      expect(ob['up'], '10 Mbps');
      expect(ob['down'], '100 Mbps');
      expect(ob['obfs'], 'salamander');
      expect(ob['obfs-password'], 'obfspw');
      expect(ob['tls'], true);
      expect(ob['skip-cert-verify'], true);
    });

    test('clashProxyToAntProxy 别名归一化（对齐 parse.rs）', () {
      final ant = clashProxyToAntProxy(<String, dynamic>{
        'name': 'raw',
        'type': 'tuic',
        'server': 's.example.com',
        'port': '443', // 字符串端口 → int
        'uuid': 'uuid-x',
        'password': 'pw',
        'congestion-controller': 'bbr', // → congestion-control
        'alpn': 'h3,h2', // 逗号串 → 列表
        'tls-fingerprint': 'fp', // → fingerprint
        'skip-cert-verify': 'true', // 字符串 → bool
      });
      expect(ant['port'], 443);
      expect(ant['congestion-control'], 'bbr');
      expect(ant['alpn'], orderedEquals(<String>['h3', 'h2']));
      expect(ant['fingerprint'], 'fp');
      expect(ant['skip-cert-verify'], true);
      expect(ant['tls'], true, reason: 'tuic 恒 TLS');
    });

    test('ant 不支持的协议/transport fail-fast', () {
      for (final type in ['hysteria', 'ssr', 'http', 'snell', 'ssh']) {
        expect(
            () => clashProxyToAntProxy(<String, dynamic>{
                  'name': 'x',
                  'type': type,
                  'server': 's',
                  'port': 1,
                }),
            throwsA(isA<ParseException>()),
            reason: '$type 无对应出站，应明确报错');
      }
      expect(
          () => clashProxyToAntProxy(<String, dynamic>{
                'name': 'x',
                'type': 'ss',
                'server': 's',
                'port': 1,
                'plugin': 'v2ray-plugin',
              }),
          throwsA(isA<ParseException>()),
          reason: 'SIP003 插件 ant 不支持');
      expect(
          () => clashProxyToAntProxy(<String, dynamic>{
                'name': 'x',
                'type': 'vless',
                'server': 's',
                'port': 1,
                'network': 'grpc',
              }),
          throwsA(isA<ParseException>()),
          reason: 'grpc transport ant 不支持');
      expect(
          () => clashProxyToAntProxy(<String, dynamic>{
                'name': 'x',
                'type': 'ss',
                'server': 's',
              }),
          throwsA(isA<ParseException>()),
          reason: '缺端口 fail-fast');
    });
  });
}
