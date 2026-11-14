/// parser_test.go 的 Dart 移植 — 用例数据原样照抄，作为移植验收标准。
library;

import 'dart:convert';

import 'package:ant_core/ant_core.dart';
import 'package:test/test.dart';

const _vmessWsTlsFp =
    'vmess://eyJ2IjoiMiIsInBzIjoi5rWL6K+VVM0yIiwiYWRkIjoiMS4yLjMuNCIsInBvcnQiOjQ0MywiaWQiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJhaWQiOjAsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInR5cGUiOiIiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiL3BhdGgiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJleGFtcGxlLmNvbSIsImFscG4iOiJodHRwLzEuMSIsImZwIjoiY2hyb21lIn0=';

const _vmessVerifyCertFalse =
    'vmess://eyJ2IjoiMiIsInBzIjoi5rWL6K+VVM0yIiwiYWRkIjoiMS4yLjMuNCIsInBvcnQiOjQ0MywiaWQiOiJhYWFhYWFhYS1iYmJiLWNjY2MtZGRkZC1lZWVlZWVlZWVlZWUiLCJhaWQiOjAsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInR5cGUiOiIiLCJob3N0IjoiZXhhbXBsZS5jb20iLCJwYXRoIjoiL3BhdGgiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJleGFtcGxlLmNvbSIsImFscG4iOiJodHRwLzEuMSIsImZwIjoiY2hyb21lIiwidmVyaWZ5X2NlcnQiOmZhbHNlfQ==';

const _ssrUri =
    'ssr://MS4yLjMuNDo0NDM6YXV0aF9zaGExX3Y0OmFlcy0yNTYtY2ZiOnRsczEuMl90aWNrZXRfYXV0aDpHdG5CM05uVUEvP29iZnNwYXJhbT0mcHJvdG9wYXJhbT0mcmVtYXJrcz1zc3ItbmlrbmFtZQ==';

String base64UrlEncode(String s) =>
    base64Url.encode(utf8.encode(s)).replaceAll('=', '');

void main() {
  group('ParseURI protocols', () {
    final cases = [
      // vmess (base64 JSON, ws + tls + fp)
      _vmessWsTlsFp,
      // vless + reality + grpc
      'vless://uuid-1234@example.com:443?type=grpc&security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=abcd&flow=xtls-rprx-vision&serviceName=grpc-svc#VLESS-Reality',
      // vless + ws + tls + insecure
      'vless://uuid-5678@example.com:443?type=ws&security=tls&sni=example.com&path=%2Fws&host=example.com&insecure=1#VLESS-WS',
      // trojan + fp + insecure
      'trojan://pass123@example.com:443?sni=example.com&fp=safari&allowInsecure=1&type=ws&path=%2Ftrojan#Trojan-Node',
      // ss SIP002 with plugin
      'ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#SS-Node',
      // hysteria2 with up/down/obfs
      'hysteria2://pass%3Aword@example.com:443?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfspass&upmbps=100&downmbps=500#HY2',
      // tuic
      'tuic://uuid-9900:password@example.com:443?sni=example.com&congestion_control=bbr&udp_relay_mode=quic&allow_insecure=1&TUIC-Node',
      // hysteria v1
      'hysteria://1.2.3.4:36712?auth=secret123&peer=example.com&insecure=1&upmbps=50&downmbps=200&obfs=xplus#HY1',
      // socks
      'socks://user:pass@1.2.3.4:1080#SOCKS-Node',
      // anytls
      'anytls://password123@example.com:8443?sni=example.com&insecure=1&fp=chrome#AnyTLS-Node',
      // ssr
      _ssrUri,
      // wireguard
      'wireguard://privKEYbase64@1.2.3.4:51820?publickey=peerKEY&presharedkey=psk&address=10.0.0.2%2F32&reserved=AQID&mtu=1420#WG-Node',
    ];

    test('all protocols parse without error', () {
      for (final uri in cases) {
        final n = parseUri(uri);
        expect(n.id, isNotEmpty, reason: uri);
        expect(n.protocol, isNotEmpty, reason: uri);
        expect(n.address, isNotEmpty, reason: uri);
        expect(n.port, greaterThan(0), reason: uri);
      }
    });

    test('unsupported protocol throws', () {
      expect(() => parseUri('http://example.com'), throwsA(isA<ParseException>()));
    });
  });

  group('ParseVMess fields', () {
    test('verify_cert=false → insecure, ws transport', () {
      final n = parseUri(_vmessVerifyCertFalse);
      expect(n.vMess, isNotNull);
      expect(n.vMess!.fingerprint, 'chrome');
      expect(n.vMess!.insecure, isTrue, reason: 'verify_cert=false → insecure');
      expect(n.vMess!.transport, isNotNull);
      expect(n.vMess!.transport!.type, 'ws');
    });
  });

  group('ParseSS plugin', () {
    test('SIP003 plugin params', () {
      final n = parseUri(
          'ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#SS');
      expect(n.ss, isNotNull);
      expect(n.ss!.plugin, 'obfs-local');
      expect(n.ss!.pluginOpts, 'obfs=http;obfs-host=example.com');
    });
  });

  group('ParseHysteria2 fields', () {
    test('password / updown / pinSHA256', () {
      final n = parseUri(
          'hysteria2://pass:word@example.com:443?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfspass&upmbps=100&downmbps=500&pinSHA256=ABCD#HY2');
      expect(n.hysteria2, isNotNull);
      expect(n.hysteria2!.password, 'pass:word');
      expect(n.hysteria2!.upMbps, 100);
      expect(n.hysteria2!.downMbps, 500);
      expect(n.hysteria2!.insecure, isTrue, reason: 'pinSHA256 → insecure');
    });
  });

  group('normalizeNetwork', () {
    test('rejects Xray-only transports', () {
      expect(() => normalizeNetwork('kcp'), throwsA(isA<ParseException>()));
    });
    test('xhttp maps to xhttp', () {
      expect(normalizeNetwork('xhttp'), 'xhttp');
    });
    test('raw maps to empty transport', () {
      expect(normalizeNetwork('raw'), '');
    });
    test('h2 maps to http', () {
      expect(normalizeNetwork('h2'), 'http');
    });
  });

  group('export round trip', () {
    // parse → export → parse again, key fields must survive the round trip
    final cases = [
      'vless://uuid-1234@example.com:443?type=grpc&security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=abcd&flow=xtls-rprx-vision&serviceName=svc#VLESS',
      'vless://uuid-5678@example.com:443?type=xhttp&security=tls&sni=example.com&path=%2Fxp&host=example.com&mode=stream-up#VLESS-XHTTP',
      'trojan://pass123@example.com:443?sni=example.com&fp=safari&allowInsecure=1&type=ws&path=%2Ftrojan#Trojan',
      'ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#SS',
      'hysteria2://pass%3Aword@example.com:443?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfspass&upmbps=100&downmbps=500#HY2',
      'tuic://uuid-9900:password@example.com:443?sni=example.com&congestion_control=bbr&udp_relay_mode=quic&allow_insecure=1#TUIC',
      'hysteria://1.2.3.4:36712?auth=secret&peer=example.com&insecure=1&upmbps=50&downmbps=200&obfs=xplus#HY1',
      'anytls://password123@example.com:8443?sni=example.com&insecure=1&fp=chrome#AnyTLS',
      _ssrUri,
      'socks://dXNlcjpwYXNzQDEuMi4zLjQ6MTA4MA==#SOCKS',
      'wireguard://privKEY@1.2.3.4:51820?publickey=peerKEY&address=10.0.0.2%2F32&reserved=1%2C2%2C3&mtu=1420#WG',
    ];

    for (final uri in cases) {
      test(uri.substring(0, 40), () {
        final n1 = parseUri(uri);
        final exported = nodeToUri(n1);
        final n2 = parseUri(exported);
        expect(n2.address, n1.address, reason: exported);
        expect(n2.port, n1.port, reason: exported);
        expect(n2.name, n1.name, reason: exported);
        expect(n2.protocol, n1.protocol, reason: exported);
      });
    }
  });

  test('export VMess round trip', () {
    final n1 = parseUri(_vmessWsTlsFp);
    final exported = nodeToUri(n1);
    final n2 = parseUri(exported);
    expect(n2.vMess, isNotNull);
    expect(n2.vMess!.uuid, n1.vMess!.uuid);
    expect(n2.vMess!.fingerprint, 'chrome');
    expect(n2.vMess!.tls, isTrue);
    expect(n2.vMess!.transport, isNotNull);
    expect(n2.vMess!.transport!.type, 'ws');
    expect(n2.vMess!.transport!.host, 'example.com');
  });

  group('ParseSingBoxJSON raw passthrough', () {
    const content = '''
{
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "selector", "tag": "sel", "outbounds": []},
    {"type": "ssh", "tag": "my-ssh", "server": "1.2.3.4", "server_port": 22, "user": "root", "password": "pw"},
    {"type": "shadowtls", "tag": "my-stls", "server": "1.2.3.4", "server_port": 443,
     "password": "pw", "tls": {"enabled": true, "server_name": "example.com",
     "utls": {"enabled": true, "fingerprint": "chrome"},
     "ech": {"enabled": true, "config": "ECHCFG"}}},
    {"type": "vless", "tag": "my-vless", "server": "5.6.7.8", "server_port": 443,
     "uuid": "uuid-x", "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "example.com", "insecure": true,
             "utls": {"enabled": true, "fingerprint": "firefox"},
             "reality": {"enabled": true, "public_key": "PBK", "short_id": "SID"}},
     "transport": {"type": "ws", "path": "/wspath", "headers": {"Host": "example.com"}}}
  ]
}''';

    test('ssh/shadowtls keep raw, vless structured', () {
      final nodes = parseContent(content);
      expect(nodes.length, 3);

      final ssh = nodes.where((n) => n.protocol == 'ssh').toList();
      expect(ssh, hasLength(1));
      expect(ssh.first.rawOutbound, isNotNull, reason: 'ssh node should keep RawOutbound');

      final stls = nodes.where((n) => n.protocol == 'shadowtls').toList();
      expect(stls, hasLength(1));
      expect(stls.first.rawOutbound, isNotNull,
          reason: 'shadowtls node should keep RawOutbound');

      final vless = nodes.where((n) => n.protocol == 'vless').toList();
      expect(vless, hasLength(1));
      final v = vless.first;
      expect(v.vless, isNotNull);
      expect(v.vless!.publicKey, 'PBK');
      expect(v.vless!.shortId, 'SID');
      expect(v.vless!.insecure, isTrue);
      expect(v.vless!.transport, isNotNull);
      expect(v.vless!.transport!.host, 'example.com');
    });
  });

  group('ParseBase64 subscription', () {
    test('base64 of URI list', () {
      final list =
          'trojan://pass@1.2.3.4:443?sni=a.com#T1\nvless://uid@1.2.3.4:443?type=ws&security=tls&sni=a.com&path=%2Fv#V1';
      final b64 = base64UrlEncode(list);
      final nodes = parseContent(b64);
      expect(nodes.length, 2);
    });
  });

  group('ParseClashYAML', () {
    const content = '''
proxies:
  - name: "hy2-yaml"
    type: hysteria2
    server: 1.2.3.4
    port: 443
    password: pw
    sni: a.com
    skip-cert-verify: true
    obfs: salamander
    obfs-password: op
    up: 100 Mbps
    down: 500 Mbps
  - name: "ssr-yaml"
    type: ssr
    server: 1.2.3.4
    port: 443
    cipher: aes-256-cfb
    password: "pass"
    protocol: auth_sha1_v4
    obfs: tls1.2_ticket_auth
  - name: "anytls-yaml"
    type: anytls
    server: 1.2.3.4
    port: 8443
    password: pw
    sni: a.com
    skip-cert-verify: true
  - name: "wg-yaml"
    type: wireguard
    server: 1.2.3.4
    port: 51820
    private-key: priv
    public-key: pub
    ip: 10.0.0.2/32
    reserved: [1, 2, 3]
    mtu: 1420
  - name: "socks-yaml"
    type: socks5
    server: 1.2.3.4
    port: 1080
    username: u
    password: p
''';

    test('all 5 proxies parsed with fields', () {
      final nodes = parseContent(content);
      expect(nodes.length, 5);

      Node byProto(String p) =>
          nodes.firstWhere((n) => n.protocol == p);

      final hy2 = byProto('hysteria2');
      expect(hy2.hysteria2!.upMbps, 100);
      expect(hy2.hysteria2!.obfsPassword, 'op');

      final ssr = byProto('ssr');
      expect(ssr.ssr!.obfs, 'tls1.2_ticket_auth');

      final at = byProto('anytls');
      expect(at.anytls!.insecure, isTrue);

      final wg = byProto('wireguard');
      expect(wg.wireGuard!.reserved, hasLength(3));
      expect(wg.wireGuard!.mtu, 1420);

      final socks = byProto('socks');
      expect(socks.socks!.username, 'u');
    });
  });

  group('Node JSON round trip', () {
    test('vmess node toJson → fromJson keeps fields', () {
      final n1 = parseUri(_vmessWsTlsFp);
      final n2 = Node.fromJson(n1.toJson());
      expect(n2.protocol, n1.protocol);
      expect(n2.vMess!.uuid, n1.vMess!.uuid);
      expect(n2.vMess!.fingerprint, 'chrome');
      expect(n2.vMess!.transport!.type, 'ws');
      expect(n2.vMess!.transport!.host, 'example.com');
      expect(n2.vMess!.alpn, ['http/1.1']);
    });

    test('raw outbound round trip is lossless', () {
      const content = '''
{"outbounds": [{"type": "shadowtls", "tag": "my-stls", "server": "1.2.3.4", "server_port": 443,
 "password": "pw", "tls": {"enabled": true, "server_name": "example.com",
 "utls": {"enabled": true, "fingerprint": "chrome"}}}]}''';
      final n1 = parseContent(content).first;
      final n2 = Node.fromJson(n1.toJson());
      expect(n2.rawOutbound, n1.rawOutbound);
      expect(n2.rawOutbound!['tls']['utls']['fingerprint'], 'chrome');
    });
  });
}
