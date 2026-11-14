/// Clash YAML 订阅解析 — 移植自 Go: backend/node/subscribe.go（Clash YAML 部分）
library;

import 'package:yaml/yaml.dart';

import '../models/node.dart';
import 'common.dart';

/// 解析 Clash YAML 的 proxies 为节点列表。
/// YAML 无效抛 [ParseException]；无 proxies 抛异常（与 Go 版一致）。
List<Node> parseClashYaml(String content) {
  dynamic doc;
  try {
    doc = loadYaml(content);
  } on YamlException catch (e) {
    throw ParseException('yaml error: ${e.message}');
  }
  final proxies = doc is Map ? doc['proxies'] : null;
  if (proxies is! List || proxies.isEmpty) {
    throw ParseException('no proxies');
  }
  final nodes = <Node>[];
  for (final p in proxies) {
    if (p is! Map) continue;
    try {
      nodes.add(_clashProxyToNode(_toPlain(p)));
    } on ParseException {
      continue;
    }
  }
  return nodes;
}

/// YamlMap/YamlList → 普通 Map/List（保持插入顺序）。
dynamic _toPlain(dynamic node) {
  if (node is YamlMap) {
    return node.map((k, v) => MapEntry(k.toString(), _toPlain(v)));
  }
  if (node is YamlList) {
    return node.map(_toPlain).toList();
  }
  return node;
}

Node _clashProxyToNode(Map<String, dynamic> p) {
  final type = _str(p['type']);
  final name = _str(p['name']);
  final server = _str(p['server']);
  final port = dynToInt(p['port']);
  if (server.isEmpty || port == 0) {
    throw ParseException('invalid proxy');
  }

  final n = Node(id: newUuid(), name: name, address: server, port: port);
  // 保留原始 Clash proxies 条目，用于无损回写 mihomo 配置
  n.rawClashProxy = p;

  switch (type) {
    case 'vmess':
      final network = normalizeNetwork(_str(p['network']));
      n.protocol = 'vmess';
      n.vMess = VMessConfig(
        uuid: _str(p['uuid']),
        alterId: dynToInt(p['alterId']),
        security: orDefault(_str(p['cipher']), 'auto'),
        tls: p['tls'] == true,
        sni: _str(p['servername']),
        alpn: _clashStrSlice(p['alpn']),
        fingerprint: _str(p['client-fingerprint']),
        insecure: p['skip-cert-verify'] == true,
        transport: _clashBuildTransport(network, p),
      );

    case 'vless':
      var tls = p['tls'] == true;
      final network = normalizeNetwork(_str(p['network']));
      final transport = _clashBuildTransport(network, p);
      // Reality
      var pubKey = '', shortId = '';
      final ro = p['reality-opts'];
      if (ro is Map) {
        pubKey = _str(ro['public-key']);
        shortId = _str(ro['short-id']);
        tls = true;
      }
      n.protocol = 'vless';
      n.vless = VLESSConfig(
        uuid: _str(p['uuid']),
        flow: _str(p['flow']),
        tls: tls,
        sni: _str(p['servername']),
        alpn: _clashStrSlice(p['alpn']),
        fingerprint: _str(p['client-fingerprint']),
        publicKey: pubKey,
        shortId: shortId,
        insecure: p['skip-cert-verify'] == true,
        transport: transport,
      );

    case 'trojan':
      var sni = _str(p['sni']);
      if (sni.isEmpty) sni = _str(p['peer']);
      final network = normalizeNetwork(_str(p['network']));
      n.protocol = 'trojan';
      n.trojan = TrojanConfig(
        password: _str(p['password']),
        sni: sni,
        alpn: _clashStrSlice(p['alpn']),
        fingerprint: _str(p['client-fingerprint']),
        insecure: p['skip-cert-verify'] == true,
        transport: _clashBuildTransport(network, p),
      );

    case 'ss':
    case 'shadowsocks':
      var pluginOpts = '';
      final po = p['plugin-opts'];
      if (po is Map) {
        // map → k=v;k=v 字符串（sing-box plugin_opts 格式）
        pluginOpts =
            po.entries.map((e) => '${e.key}=${e.value ?? ''}').join(';');
      }
      n.protocol = 'ss';
      n.ss = SSConfig(
        method: _str(p['cipher']),
        password: _str(p['password']),
        plugin: _str(p['plugin']),
        pluginOpts: pluginOpts,
      );

    case 'hysteria2':
    case 'hy2':
      n.protocol = 'hysteria2';
      n.hysteria2 = Hysteria2Config(
        password: _str(p['password']),
        sni: _str(p['sni']),
        insecure: p['skip-cert-verify'] == true,
        alpn: _clashStrSlice(p['alpn']),
        upMbps: _clashFirstInt(p, ['up', 'upmbps']),
        downMbps: _clashFirstInt(p, ['down', 'downmbps']),
        obfs: _str(p['obfs']),
        obfsPassword: _str(p['obfs-password']),
      );

    case 'hysteria':
    case 'hysteria1':
      var auth = _str(p['auth-str']);
      if (auth.isEmpty) auth = _str(p['auth']);
      n.protocol = 'hysteria';
      n.hysteria = HysteriaConfig(
        authStr: auth,
        sni: _str(p['sni']),
        insecure: p['skip-cert-verify'] == true,
        alpn: _clashStrSlice(p['alpn']),
        upMbps: _clashFirstInt(p, ['up', 'upmbps']),
        downMbps: _clashFirstInt(p, ['down', 'downmbps']),
        obfs: _str(p['obfs']),
      );

    case 'tuic':
      n.protocol = 'tuic';
      n.tuic = TUICConfig(
        uuid: _str(p['uuid']),
        password: _str(p['password']),
        sni: _str(p['sni']),
        alpn: _clashStrSlice(p['alpn']),
        congestionControl: orDefault(_str(p['congestion-controller']), 'cubic'),
        udpRelayMode: _str(p['udp-relay-mode']),
        insecure: p['skip-cert-verify'] == true,
      );

    case 'socks5':
    case 'socks':
      // socks over TLS 不是 sing-box socks outbound 支持的特性；忽略 TLS 标志
      n.protocol = 'socks';
      n.socks = SocksConfig(
        version: '5',
        username: _str(p['username']),
        password: _str(p['password']),
      );

    case 'http':
      n.protocol = 'http';
      n.http = HTTPConfig(
        username: _str(p['username']),
        password: _str(p['password']),
        tls: p['tls'] == true,
        sni: _str(p['sni']),
        insecure: p['skip-cert-verify'] == true,
        alpn: _clashStrSlice(p['alpn']),
      );

    case 'anytls':
      n.protocol = 'anytls';
      n.anytls = AnyTLSConfig(
        password: _str(p['password']),
        sni: _str(p['sni']),
        insecure: p['skip-cert-verify'] == true,
        alpn: _clashStrSlice(p['alpn']),
        fingerprint: _str(p['client-fingerprint']),
      );

    case 'ssr':
      n.protocol = 'ssr';
      n.ssr = SSRConfig(
        method: _str(p['cipher']),
        password: _str(p['password']),
        protocol: _str(p['protocol']),
        protocolParam: _str(p['protocol-param']),
        obfs: _str(p['obfs']),
        obfsParam: _str(p['obfs-param']),
      );

    case 'wireguard':
      List<int>? reserved;
      final r = _clashIntSlice(p['reserved']);
      if (r != null) reserved = r;
      List<String>? localAddr;
      final ip = p['ip'];
      if (ip is String) {
        (localAddr ??= []).add(ip);
      } else if (ip is List) {
        for (final s in ip) {
          (localAddr ??= []).add(s.toString());
        }
      }
      final ipv6 = _str(p['ipv6']);
      if (ipv6.isNotEmpty) (localAddr ??= []).add(ipv6);
      List<String>? dns;
      final d = p['dns'];
      if (d is String) {
        (dns ??= []).add(d);
      } else if (d is List) {
        for (final s in d) {
          (dns ??= []).add(s.toString());
        }
      }
      n.protocol = 'wireguard';
      n.wireGuard = WireGuardConfig(
        privateKey: _str(p['private-key']),
        publicKey: _str(p['public-key']),
        presharedKey: _str(p['pre-shared-key']),
        reserved: reserved,
        localAddress: localAddr,
        mtu: _clashFirstInt(p, ['mtu']),
        dns: dns,
      );

    case 'ssh':
      // 从 Clash 字段构建原始 sing-box ssh outbound
      final m = <String, dynamic>{
        'type': 'ssh',
        'server': server,
        'server_port': port,
      };
      final username = _str(p['username']);
      if (username.isNotEmpty) m['user'] = username;
      final password = _str(p['password']);
      if (password.isNotEmpty) m['password'] = password;
      n.protocol = 'ssh';
      n.rawOutbound = m;

    default:
      throw ParseException('unsupported clash proxy type: $type');
  }
  return n;
}

/// 把 Clash proxy map 的 transport 选项解析成 TransportConfig。
/// Clash 使用按网络划分的 `*-opts` 块：
///   ws-opts:        { path, headers: {Host}, max-early-data, early-data-header-name }
///   h2-opts:        { host: `[]string`, path }
///   grpc-opts:      { grpc-service-name }
///   httpupgrade-opts: { path, host }
///   xhttp-opts:     { path, host: `[]string`, mode }
TransportConfig? _clashBuildTransport(String network, Map<String, dynamic> p) {
  if (network.isEmpty) return null;
  final t = TransportConfig(type: network);
  switch (network) {
    case 'ws':
      final opts = p['ws-opts'];
      if (opts is Map) {
        t.path = _str(opts['path']);
        final hdrs = opts['headers'];
        if (hdrs is Map) {
          t.host = _str(hdrs['Host']);
          if (t.host.isEmpty) t.host = _str(hdrs['host']);
        }
        final ed = dynToInt(opts['max-early-data']);
        if (ed > 0) {
          t.maxEarlyData = ed;
          t.earlyDataHeaderName =
              orDefault(_str(opts['early-data-header-name']), 'Sec-WebSocket-Protocol');
        }
        // path 里可能嵌 "?ed=2560"（机场 clash 订阅常见）— 统一规整
        normalizeWsEarlyData(t);
      }
    case 'http':
      final opts = p['h2-opts'];
      if (opts is Map) {
        t.path = _str(opts['path']);
        // h2-opts.host 是 []string
        final hosts = opts['host'];
        if (hosts is List && hosts.isNotEmpty) {
          t.host = _str(hosts.first);
        }
      }
    case 'grpc':
      final opts = p['grpc-opts'];
      if (opts is Map) {
        t.serviceName = _str(opts['grpc-service-name']);
      }
    case 'httpupgrade':
      final opts = p['httpupgrade-opts'];
      if (opts is Map) {
        t.path = _str(opts['path']);
        t.host = _str(opts['host']);
      }
    case 'xhttp':
      final opts = p['xhttp-opts'];
      if (opts is Map) {
        t.path = _str(opts['path']);
        // xhttp-opts.host 是 []string
        final hosts = opts['host'];
        if (hosts is List && hosts.isNotEmpty) {
          t.host = _str(hosts.first);
        }
        t.mode = _str(opts['mode']);
      }
  }
  return t;
}

// ─── Clash helpers ───────────────────────────────────────────────────────────

String _str(dynamic v) => v is String ? v : '';

int _clashFirstInt(Map<String, dynamic> p, List<String> keys) {
  for (final k in keys) {
    final v = p[k];
    if (v == null) continue;
    // 值形如 "50 mbps" / 50
    if (v is num) return v.toInt();
    if (v is String) {
      final fields = v.trim().split(RegExp(r'\s+'));
      if (fields.isNotEmpty && fields.first.isNotEmpty) {
        return int.tryParse(fields.first) ?? 0;
      }
    }
  }
  return 0;
}

/// Clash YAML 的 string 或 `[]string` 转 `List<String>`。
List<String>? _clashStrSlice(dynamic v) {
  if (v is String) return parseAlpn(v);
  if (v is List) {
    final out = <String>[];
    for (final s in v) {
      if (s is String && s.isNotEmpty) out.add(s);
    }
    return out.isEmpty ? null : out;
  }
  return null;
}

/// Clash YAML 的 int 或 `[]int` 转 `List<int>`。
List<int>? _clashIntSlice(dynamic v) {
  if (v is int) return [v];
  if (v is List) {
    final out = <int>[];
    for (final s in v) {
      out.add(dynToInt(s));
    }
    return out;
  }
  return null;
}
