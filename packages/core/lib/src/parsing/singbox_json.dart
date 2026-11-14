/// sing-box JSON 订阅解析 — 移植自 Go: backend/node/subscribe.go（sing-box JSON 部分）
library;

import 'dart:convert';

import '../models/node.dart';
import 'common.dart';

/// sing-box 内置非代理 outbound，绝不能成为节点。
/// 其余所有类型都接受——已知类型构建结构化配置，
/// 其他（ssh/shadowtls/shadowsocksr/mieru/tor/未来协议…）
/// 存为 RawOutbound 原样回写（与 v2rayN 相同思路）。
const Set<String> _skipOutboundTypes = {
  'direct', 'block', 'dns', 'selector', 'urltest', '',
};

/// 解析 sing-box JSON 配置中的 outbounds 为节点列表。
/// JSON 无效抛 [ParseException]；outbounds 缺失/为空返回空列表。
List<Node> parseSingBoxJson(String content) {
  content = content.trim();
  if (!content.startsWith('{')) throw ParseException('not json');
  dynamic decoded;
  try {
    decoded = jsonDecode(content);
  } on FormatException {
    throw ParseException('invalid json');
  }
  if (decoded is! Map) throw ParseException('invalid json');
  final rawOutbounds = decoded['outbounds'];
  if (rawOutbounds is! List) return [];
  final nodes = <Node>[];
  for (final raw in rawOutbounds) {
    if (raw is! Map) continue;
    final rawMap = Map<String, dynamic>.from(raw);
    final type = _str(raw['type']);
    final server = _str(raw['server']);
    final serverPort = (raw['server_port'] as num?)?.toInt() ?? 0;
    if (_skipOutboundTypes.contains(type) || server.isEmpty) continue;

    final transport = _sbTransport(raw['transport']);
    final tls = raw['tls'] is Map ? (raw['tls'] as Map).cast<String, dynamic>() : null;

    final n = Node(
      id: newUuid(),
      name: _str(raw['tag']),
      address: server,
      port: serverPort,
      protocol: type,
      rawOutbound: rawMap, // verbatim outbound — 支持所有协议与 TLS 类型
    );

    switch (type) {
      case 'vmess':
        n.vMess = VMessConfig(
          uuid: _str(raw['uuid']),
          alterId: dynToInt(raw['alter_id']),
          security: orDefault(_str(raw['security']), 'auto'),
          tls: _tlsEnabled(tls),
          sni: _tlsSni(tls),
          alpn: _tlsAlpn(tls),
          fingerprint: _tlsFingerprint(tls),
          insecure: _tlsInsecure(tls),
          echConfig: _tlsEchConfig(tls),
          transport: transport,
        );
      case 'vless':
        final cfg = VLESSConfig(
          uuid: _str(raw['uuid']),
          flow: _str(raw['flow']),
          tls: _tlsEnabled(tls),
          sni: _tlsSni(tls),
          alpn: _tlsAlpn(tls),
          fingerprint: _tlsFingerprint(tls),
          insecure: _tlsInsecure(tls),
          echConfig: _tlsEchConfig(tls),
          transport: transport,
        );
        final reality = tls == null ? null : tls['reality'];
        if (reality is Map) {
          cfg.publicKey = _str(reality['public_key']);
          cfg.shortId = _str(reality['short_id']);
        }
        n.vless = cfg;
      case 'trojan':
        n.trojan = TrojanConfig(
          password: _str(raw['password']),
          sni: _tlsSni(tls),
          alpn: _tlsAlpn(tls),
          fingerprint: _tlsFingerprint(tls),
          insecure: _tlsInsecure(tls),
          echConfig: _tlsEchConfig(tls),
          transport: transport,
        );
      case 'shadowsocks':
        n.protocol = 'ss';
        n.ss = SSConfig(
          method: _str(raw['method']),
          password: _str(raw['password']),
          plugin: _str(raw['plugin']),
          pluginOpts: _str(raw['plugin_opts']),
        );
      case 'hysteria':
        final cfg = HysteriaConfig(
          authStr: _str(raw['auth_str']),
          sni: _tlsSni(tls),
          insecure: _tlsInsecure(tls),
          alpn: _tlsAlpn(tls),
          upMbps: (raw['up_mbps'] as num?)?.toInt() ?? 0,
          downMbps: (raw['down_mbps'] as num?)?.toInt() ?? 0,
        );
        if (raw['obfs'] is String) cfg.obfs = raw['obfs'] as String;
        n.hysteria = cfg;
      case 'hysteria2':
        final cfg = Hysteria2Config(
          password: _str(raw['password']),
          sni: _tlsSni(tls),
          insecure: _tlsInsecure(tls),
          alpn: _tlsAlpn(tls),
          echConfig: _tlsEchConfig(tls),
          upMbps: (raw['up_mbps'] as num?)?.toInt() ?? 0,
          downMbps: (raw['down_mbps'] as num?)?.toInt() ?? 0,
        );
        if (raw['obfs'] is Map) {
          final m = raw['obfs'] as Map;
          cfg.obfs = _str(m['type']);
          cfg.obfsPassword = _str(m['password']);
        }
        n.hysteria2 = cfg;
      case 'tuic':
        n.tuic = TUICConfig(
          uuid: _str(raw['uuid']),
          password: _str(raw['password']),
          sni: _tlsSni(tls),
          alpn: _tlsAlpn(tls),
          insecure: _tlsInsecure(tls),
          congestionControl: orDefault(_str(raw['congestion_control']), 'cubic'),
          udpRelayMode: _str(raw['udp_relay_mode']),
        );
      case 'socks':
        n.protocol = 'socks';
        n.socks = SocksConfig(
          version: orDefault(_str(raw['version']), '5'),
          username: _str(raw['username']),
          password: _str(raw['password']),
        );
      case 'http':
        n.protocol = 'http';
        n.http = HTTPConfig(
          username: _str(raw['username']),
          password: _str(raw['password']),
          tls: _tlsEnabled(tls),
          sni: _tlsSni(tls),
          insecure: _tlsInsecure(tls),
          alpn: _tlsAlpn(tls),
        );
      case 'anytls':
        n.anytls = AnyTLSConfig(
          password: _str(raw['password']),
          sni: _tlsSni(tls),
          insecure: _tlsInsecure(tls),
          alpn: _tlsAlpn(tls),
          fingerprint: _tlsFingerprint(tls),
          echConfig: _tlsEchConfig(tls),
        );
      default:
        // ssh / shadowtls / shadowsocksr / wireguard / mieru / tor / ...
        // Node 只保留 RawOutbound —— 原样回写。
        break;
    }
    if (n.name.isEmpty) {
      n.name = '$type-$server:$serverPort';
    }
    nodes.add(n);
  }
  return nodes;
}

// ─── sing-box TLS / transport 子视图 ─────────────────────────────────────────

String _str(dynamic v) => v is String ? v : '';

bool _tlsEnabled(Map<String, dynamic>? tls) =>
    tls != null && tls['enabled'] == true;

String _tlsSni(Map<String, dynamic>? tls) =>
    tls == null ? '' : _str(tls['server_name']);

List<String>? _tlsAlpn(Map<String, dynamic>? tls) {
  if (tls == null) return null;
  final v = tls['alpn'];
  if (v is! List) return null;
  final out = v.whereType<String>().toList();
  return out.isEmpty ? null : out;
}

bool _tlsInsecure(Map<String, dynamic>? tls) =>
    tls != null && tls['insecure'] == true;

String _tlsFingerprint(Map<String, dynamic>? tls) {
  final utls = tls?['utls'];
  return utls is Map ? _str(utls['fingerprint']) : '';
}

String _tlsEchConfig(Map<String, dynamic>? tls) {
  final ech = tls?['ech'];
  if (ech is! Map) return '';
  if (ech['enabled'] != true) return '';
  return _str(ech['config']);
}

/// 将 sing-box transport 块转成我们的 TransportConfig。
TransportConfig? _sbTransport(dynamic t) {
  if (t is! Map) return null;
  final type = _str(t['type']);
  if (type.isEmpty) return null;
  final out = TransportConfig(
    type: type,
    path: _str(t['path']),
    serviceName: _str(t['service_name']),
    maxEarlyData: (t['max_early_data'] as num?)?.toInt() ?? 0,
    earlyDataHeaderName: _str(t['early_data_header_name']),
  );
  final headers = t['headers'] is Map ? (t['headers'] as Map) : null;
  String? headerHost;
  if (headers != null) {
    headerHost = headers['Host'] is String
        ? headers['Host'] as String
        : (headers['host'] is String ? headers['host'] as String : null);
  }

  switch (type) {
    case 'ws':
      // ws 的 Host 在 headers["Host"]
      out.host = headerHost ?? '';
    case 'xhttp':
      // fork 布局不一：headers["Host"]（ws 风格）或顶层 host 字符串/数组（Xray）
      if (headerHost != null && headerHost.isNotEmpty) {
        out.host = headerHost;
      } else {
        out.host = _hostFromTopLevel(t['host']);
      }
    case 'http':
      // http/h2 的 Host 是 []string 数组
      out.host = _hostFromTopLevel(t['host']);
    case 'httpupgrade':
      // Host 是顶层字符串字段
      out.host = t['host'] is String ? t['host'] as String : '';
  }
  return out;
}

String _hostFromTopLevel(dynamic host) {
  if (host is String) return host;
  if (host is List && host.isNotEmpty) return _str(host.first);
  return '';
}
