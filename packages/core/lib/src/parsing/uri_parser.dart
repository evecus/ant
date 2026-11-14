/// 单条分享链接解析 — 移植自 Go: backend/node/parser.go
library;

import 'dart:convert';

import '../models/node.dart';
import 'common.dart';

/// 解析单条代理 URI 为 [Node]；失败抛 [ParseException]。
Node parseUri(String uri) {
  uri = uri.trim();
  if (uri.startsWith('vmess://')) return _parseVMess(uri);
  if (uri.startsWith('vless://')) return _parseVLESS(uri);
  if (uri.startsWith('trojan://')) return _parseTrojan(uri);
  if (uri.startsWith('ss://')) return _parseSS(uri);
  if (uri.startsWith('hysteria2://') || uri.startsWith('hy2://')) {
    return _parseHysteria2(uri);
  }
  if (uri.startsWith('tuic://')) return _parseTUIC(uri);
  if (uri.startsWith('hysteria://')) return _parseHysteria(uri);
  if (uri.startsWith('socks://')) return _parseSocks(uri);
  if (uri.startsWith('anytls://')) return _parseAnyTLS(uri);
  if (uri.startsWith('ssr://')) return _parseSSR(uri);
  if (uri.startsWith('wireguard://') || uri.startsWith('wg://')) {
    return _parseWireGuard(uri);
  }
  throw ParseException(
      'unsupported protocol: ${uri.substring(0, uri.length < 20 ? uri.length : 20)}');
}

// ─── VMess (legacy base64-JSON format) ───────────────────────────────────────

Node _parseVMess(String uri) {
  var encoded = uri.substring('vmess://'.length);
  // strip fragment
  final idx = encoded.indexOf('#');
  if (idx >= 0) encoded = encoded.substring(0, idx);

  final decoded = tryBase64Decode(encoded);
  if (decoded == null) throw ParseException('vmess decode error');

  Map<String, dynamic> v;
  try {
    final j = jsonDecode(decoded);
    if (j is! Map<String, dynamic>) throw const FormatException();
    v = j;
  } on FormatException {
    throw ParseException('vmess json error');
  }

  final network = normalizeNetwork(_jstr(v['net']));
  final transport = _buildTransportFromVMessJson(network, v);

  var insecure = false;
  final verifyCert = v['verify_cert'];
  if (verifyCert is bool) insecure = !verifyCert;
  final allowInsecure = _jstr(v['allowInsecure']);
  if (allowInsecure == '1' || allowInsecure.toLowerCase() == 'true') {
    insecure = true;
  }

  final add = _jstr(v['add']);
  final port = dynToInt(v['port']);
  var name = _jstr(v['ps']);
  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'vmess',
    address: add,
    port: port,
    vMess: VMessConfig(
      uuid: _jstr(v['id']),
      alterId: dynToInt(v['aid']),
      security: orDefault(_jstr(v['scy']), 'auto'),
      tls: _jstr(v['tls']) == 'tls',
      sni: orDefault(_jstr(v['sni']), _jstr(v['host'])),
      alpn: parseAlpn(_jstr(v['alpn'])),
      fingerprint: _jstr(v['fp']),
      insecure: insecure,
      echConfig: _jstr(v['ech']),
      transport: transport,
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'VMess-${n.address}:${n.port}';
  }
  return n;
}

TransportConfig? _buildTransportFromVMessJson(String network, Map<String, dynamic> v) {
  if (network.isEmpty) return null;
  final t = TransportConfig(type: network);
  final path = _jstr(v['path']);
  final host = _jstr(v['host']);
  switch (network) {
    case 'ws':
    case 'xhttp':
      t.path = path;
      t.host = host;
      final ed = dynToInt(v['ed']);
      if (ed > 0) {
        t.maxEarlyData = ed;
        t.earlyDataHeaderName = 'Sec-WebSocket-Protocol';
      }
      // ed 也可能被机场拼进 path（"path=/vless-argo?ed=2560"）— 统一规整
      normalizeWsEarlyData(t);
    case 'http':
    case 'httpupgrade':
      t.path = path;
      t.host = host;
    case 'grpc':
      // vmess JSON 用 "path" 表示 gRPC service name
      t.serviceName = path;
  }
  return t;
}

// ─── VLESS (URI format) ──────────────────────────────────────────────────────
// Reference: https://github.com/XTLS/Xray-core/discussions/716

Node _parseVLESS(String uri) {
  final u = _parseUri(uri);
  final q = u.queryParameters;
  final port = u.port;
  final network = normalizeNetwork(q['type'] ?? '');
  final transport = _buildTransportFromQuery(network, q);

  final security = q['security'] ?? '';
  final hasTLS = security == 'tls' || security == 'reality';

  final creds = _splitUserInfo(u.userInfo);
  var name = _fragment(u);
  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'vless',
    address: u.host,
    port: port,
    vless: VLESSConfig(
      uuid: creds.$1,
      flow: q['flow'] ?? '',
      tls: hasTLS,
      sni: q['sni'] ?? '',
      alpn: parseAlpn(q['alpn'] ?? ''),
      fingerprint: q['fp'] ?? '',
      insecure: queryBool(q['insecure']) || queryBool(q['allowInsecure']),
      echConfig: q['ech'] ?? '',
      publicKey: q['pbk'] ?? '',
      shortId: q['sid'] ?? '',
      transport: transport,
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'VLESS-${n.address}:${n.port}';
  }
  return n;
}

// ─── Trojan (URI format) ─────────────────────────────────────────────────────

Node _parseTrojan(String uri) {
  final u = _parseUri(uri);
  final q = u.queryParameters;
  final port = u.port;
  final network = normalizeNetwork(q['type'] ?? '');
  final transport = _buildTransportFromQuery(network, q);

  // peer 是 sni 的历史别名
  var sni = q['sni'] ?? '';
  if (sni.isEmpty) sni = q['peer'] ?? '';

  final creds = _splitUserInfo(u.userInfo);
  final name = _fragment(u);
  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'trojan',
    address: u.host,
    port: port,
    trojan: TrojanConfig(
      password: creds.$1,
      sni: sni,
      alpn: parseAlpn(q['alpn'] ?? ''),
      fingerprint: q['fp'] ?? '',
      insecure: queryBool(q['insecure']) || queryBool(q['allowInsecure']),
      echConfig: q['ech'] ?? '',
      transport: transport,
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'Trojan-${n.address}:${n.port}';
  }
  return n;
}

// ─── Shadowsocks (URI format) ────────────────────────────────────────────────
// Format 1: ss://BASE64(method:password)@host:port#name
// Format 2: ss://BASE64(method:password@host:port)#name  (legacy)
// SIP003 plugin in query: ?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dxxx

Node _parseSS(String uri) {
  var raw = uri.substring('ss://'.length);
  var name = '';
  var idx = raw.indexOf('#');
  if (idx >= 0) {
    name = queryUnescapeLenient(raw.substring(idx + 1));
    raw = raw.substring(0, idx);
  }
  // Strip query string (plugin opts sometimes encoded here)
  var query = '';
  idx = raw.indexOf('?');
  if (idx >= 0) {
    query = raw.substring(idx + 1);
    raw = raw.substring(0, idx);
  }

  var method = '', password = '', host = '';
  var port = 0;

  if (raw.contains('@')) {
    final at = raw.indexOf('@');
    var userinfo = raw.substring(0, at);
    // userinfo may be base64(method:password) or plain method:password
    final decoded = tryBase64Decode(userinfo);
    if (decoded != null && decoded.contains(':')) userinfo = decoded;
    userinfo = queryUnescapeLenient(userinfo);
    final ci = userinfo.indexOf(':');
    if (ci >= 0) {
      method = userinfo.substring(0, ci);
      password = userinfo.substring(ci + 1);
    }
    // host:port part
    final u = _parseUri('ss://${raw.substring(at + 1)}');
    host = u.host;
    port = u.port;
  } else {
    // entire payload is base64
    final decoded = tryBase64Decode(raw);
    if (decoded == null) throw ParseException('ss decode error');
    final u = _parseUri('ss://$decoded');
    final creds = _splitUserInfo(u.userInfo);
    method = creds.$1;
    password = creds.$2 ?? '';
    host = u.host;
    port = u.port;
  }

  final cfg = SSConfig(method: method, password: password);
  // SIP003 plugin via query string:
  //   plugin=<name>[;<opt>=<v>]...  (semicolon separated, URL-encoded as %3B)
  if (query.isNotEmpty) {
    final q = _parseQuery(query);
    final pluginRaw = q['plugin'] ?? '';
    if (pluginRaw.isNotEmpty) {
      final segs = pluginRaw.split(';');
      cfg.plugin = segs[0];
      if (segs.length > 1) cfg.pluginOpts = segs.sublist(1).join(';');
    }
    // some exporters use separate keys
    if (cfg.plugin.isEmpty) {
      cfg.plugin = q['plugin-name'] ?? '';
      cfg.pluginOpts = q['plugin-opts'] ?? '';
    }
  }

  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'ss',
    address: host,
    port: port,
    ss: cfg,
  );
  if (n.name.isEmpty) {
    n.name = 'SS-${n.address}:${n.port}';
  }
  return n;
}

// ─── Hysteria2 (URI format) ──────────────────────────────────────────────────
// hysteria2://[password]@host:port?sni=&insecure=&obfs=&obfs-password=&upmbps=&downmbps=&ech=&pinSHA256=

Node _parseHysteria2(String uri) {
  final u = _parseUri(uri.replaceFirst('hy2://', 'hysteria2://'));
  final q = u.queryParameters;
  var port = u.port;
  if (port == 0) port = 443;
  final name = _fragment(u);
  final insecure = parseBoolLoose(q['insecure'] ?? '');
  // 整个 userinfo 是密码（v2rayN 兼容），可含 ':' 且可能 URL 编码
  // —— e.g. hysteria2://pass%3Aword@host:443
  final creds = _splitUserInfo(u.userInfo);
  var password = creds.$1;
  if ((creds.$2 ?? '').isNotEmpty) password = '${creds.$1}:${creds.$2}';
  password = queryUnescapeLenient(password);

  final cfg = Hysteria2Config(
    password: password,
    sni: q['sni'] ?? '',
    insecure: insecure,
    alpn: parseAlpn(q['alpn'] ?? ''),
    echConfig: q['ech'] ?? '',
    upMbps: queryFirstInt(q, ['upmbps', 'up']),
    downMbps: queryFirstInt(q, ['downmbps', 'down']),
    obfs: q['obfs'] ?? '',
    obfsPassword: q['obfs-password'] ?? '',
  );
  // pinSHA256 意味着自签证书 pinning —— sing-box 只有 insecure
  if ((q['pinSHA256'] ?? '').isNotEmpty) cfg.insecure = true;
  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'hysteria2',
    address: u.host,
    port: port,
    hysteria2: cfg,
  );
  if (n.name.isEmpty) {
    n.name = 'Hysteria2-${n.address}:${n.port}';
  }
  return n;
}

// ─── Hysteria v1 (URI format) ────────────────────────────────────────────────
// hysteria://host:port?auth=&peer=&insecure=&upmbps=&downmbps=&obfs=&obfsParam=&alpn=

Node _parseHysteria(String uri) {
  final u = _parseUri(uri);
  final q = u.queryParameters;
  final port = u.port;
  final name = _fragment(u);
  final insecure = parseBoolLoose(q['insecure'] ?? '');

  // auth 可能在 userinfo 或 "auth" query 参数
  var auth = q['auth'] ?? '';
  if (auth.isEmpty) {
    final creds = _splitUserInfo(u.userInfo);
    auth = creds.$1;
    if ((creds.$2 ?? '').isNotEmpty) auth = '${creds.$1}:${creds.$2}';
  }

  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'hysteria',
    address: u.host,
    port: port,
    hysteria: HysteriaConfig(
      authStr: auth,
      sni: orDefault(q['peer'] ?? '', q['sni'] ?? ''),
      insecure: insecure,
      alpn: parseAlpn(q['alpn'] ?? ''),
      upMbps: queryFirstInt(q, ['upmbps', 'up']),
      downMbps: queryFirstInt(q, ['downmbps', 'down']),
      obfs: orDefault(q['obfsParam'] ?? '', q['obfs'] ?? ''),
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'Hysteria-${n.address}:${n.port}';
  }
  return n;
}

// ─── TUIC (URI format) ───────────────────────────────────────────────────────

Node _parseTUIC(String uri) {
  final u = _parseUri(uri);
  final q = u.queryParameters;
  var port = u.port;
  if (port == 0) port = 443;
  final name = _fragment(u);
  var insecure = parseBoolLoose(q['allow_insecure'] ?? '');
  final v = q['insecure'];
  if (v != null && parseBoolLoose(v)) insecure = true;
  final creds = _splitUserInfo(u.userInfo);

  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'tuic',
    address: u.host,
    port: port,
    tuic: TUICConfig(
      uuid: creds.$1,
      password: creds.$2 ?? '',
      sni: q['sni'] ?? '',
      alpn: parseAlpn(q['alpn'] ?? ''),
      insecure: insecure,
      congestionControl: orDefault(q['congestion_control'] ?? '', 'cubic'),
      udpRelayMode: q['udp_relay_mode'] ?? '',
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'TUIC-${n.address}:${n.port}';
  }
  return n;
}

// ─── Socks (URI format, v2rayN compatible) ───────────────────────────────────
// socks://BASE64(user:pass@host:port)#name  or  socks://user:pass@host:port#name

Node _parseSocks(String uri) {
  var raw = uri.substring('socks://'.length);
  var name = '';
  var idx = raw.indexOf('#');
  if (idx >= 0) {
    name = queryUnescapeLenient(raw.substring(idx + 1));
    raw = raw.substring(0, idx);
  }
  // whole payload may be base64
  if (!raw.contains('@')) {
    final decoded = tryBase64Decode(raw);
    if (decoded != null && decoded.contains('@')) raw = decoded;
  }
  final atIdx = raw.lastIndexOf('@');
  if (atIdx < 0) throw ParseException('socks link 格式错误');
  var userinfo = raw.substring(0, atIdx);
  final decodedUserinfo = tryBase64Decode(userinfo);
  if (decodedUserinfo != null && decodedUserinfo.contains(':')) {
    userinfo = decodedUserinfo;
  }
  userinfo = queryUnescapeLenient(userinfo);
  final hostPort = raw.substring(atIdx + 1);
  // last colon separates host:port (IPv6 in brackets handled below)
  String host;
  int port;
  if (hostPort.endsWith(']')) {
    // [v6]:port
    final i = hostPort.lastIndexOf(']:');
    if (i < 0) throw ParseException('socks link 端口错误');
    host = hostPort.substring(0, i + 1).replaceAll(RegExp(r'^\[|\]$'), '');
    port = int.tryParse(hostPort.substring(i + 2)) ?? 0;
  } else {
    final i = hostPort.lastIndexOf(':');
    if (i < 0) throw ParseException('socks link 端口错误');
    host = hostPort.substring(0, i);
    port = int.tryParse(hostPort.substring(i + 1)) ?? 0;
  }
  final cfg = SocksConfig(version: '5');
  final ci = userinfo.indexOf(':');
  if (ci >= 0) {
    cfg.username = userinfo.substring(0, ci);
    cfg.password = userinfo.substring(ci + 1);
  } else {
    cfg.username = userinfo;
  }
  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'socks',
    address: host,
    port: port,
    socks: cfg,
  );
  if (n.name.isEmpty) {
    n.name = 'SOCKS-${n.address}:${n.port}';
  }
  return n;
}

// ─── AnyTLS (URI format) ─────────────────────────────────────────────────────
// anytls://password@host:port?sni=&insecure=&alpn=&fp=&ech=#name

Node _parseAnyTLS(String uri) {
  final u = _parseUri(uri);
  final q = u.queryParameters;
  var port = u.port;
  if (port == 0) port = 443;
  final name = _fragment(u);
  final insecure = parseBoolLoose(q['insecure'] ?? '');
  final creds = _splitUserInfo(u.userInfo);

  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'anytls',
    address: u.host,
    port: port,
    anytls: AnyTLSConfig(
      password: creds.$1,
      sni: q['sni'] ?? '',
      insecure: insecure,
      alpn: parseAlpn(q['alpn'] ?? ''),
      fingerprint: q['fp'] ?? '',
      echConfig: q['ech'] ?? '',
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'AnyTLS-${n.address}:${n.port}';
  }
  return n;
}

// ─── ShadowsocksR (URI format) ───────────────────────────────────────────────
// ssr://base64(host:port:protocol:method:obfs:base64(password)/?obfsparam=&protoparam=&remarks=)

Node _parseSSR(String uri) {
  final raw = uri.substring('ssr://'.length);
  final decoded = tryBase64Decode(raw);
  if (decoded == null) throw ParseException('ssr decode error');
  var mainPart = decoded;
  var queryPart = '';
  final idx = decoded.indexOf('/?');
  if (idx >= 0) {
    mainPart = decoded.substring(0, idx);
    queryPart = decoded.substring(idx + 2);
  }
  var q = const <String, String>{};
  if (queryPart.isNotEmpty) {
    q = _parseQuery(queryPart);
  }
  // host:port:protocol:method:obfs:base64(password)
  final segs = mainPart.split(':');
  if (segs.length < 6) throw ParseException('ssr link 格式错误');
  final password64 = segs.sublist(5).join(':');
  final d = tryBase64Decode(password64);
  final password = d ?? password64;
  final name = queryUnescapeLenient(q['remarks'] ?? '');
  final port = int.tryParse(segs[1]) ?? 0;

  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'ssr',
    address: segs[0],
    port: port,
    ssr: SSRConfig(
      method: segs[3],
      password: password,
      protocol: segs[2],
      obfs: segs[4],
      protocolParam: q['protoparam'] ?? '',
      obfsParam: q['obfsparam'] ?? '',
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'SSR-${n.address}:${n.port}';
  }
  return n;
}

// ─── WireGuard (URI format, v2rayN compatible) ───────────────────────────────
// wireguard://privateKey@host:port?publickey=&presharedkey=&reserved=&address=&mtu=&dns=#name

Node _parseWireGuard(String uri) {
  final u = _parseUri(uri);
  final q = u.queryParameters;
  final port = u.port;
  final name = _fragment(u);

  List<int>? reserved;
  final resRaw = q['reserved'] ?? '';
  if (resRaw.isNotEmpty) {
    if (resRaw.contains(',')) {
      reserved = [];
      for (final s in resRaw.split(',')) {
        final v = int.tryParse(s.trim());
        if (v != null) reserved.add(v);
      }
    } else {
      try {
        final b = base64.decode(resRaw);
        if (b.length == 3) reserved = [b[0], b[1], b[2]];
      } on FormatException {
        // ignore
      }
    }
  }
  List<String>? localAddr;
  for (final s in (q['address'] ?? '').split(',')) {
    final t = s.trim();
    if (t.isNotEmpty) (localAddr ??= []).add(t);
  }
  List<String>? dns;
  for (final s in (q['dns'] ?? '').split(',')) {
    final t = s.trim();
    if (t.isNotEmpty) (dns ??= []).add(t);
  }

  final creds = _splitUserInfo(u.userInfo);
  final publicKey = q['publickey'] ?? '';
  if (publicKey.isEmpty) {
    throw ParseException('wireguard link 缺少 peer publickey');
  }
  final n = Node(
    id: newUuid(),
    name: name,
    protocol: 'wireguard',
    address: u.host,
    port: port,
    wireGuard: WireGuardConfig(
      privateKey: creds.$1,
      publicKey: publicKey,
      presharedKey: q['presharedkey'] ?? '',
      reserved: reserved,
      localAddress: localAddr,
      mtu: queryFirstInt(q, ['mtu']),
      dns: dns,
    ),
  );
  if (n.name.isEmpty) {
    n.name = 'WG-${n.address}:${n.port}';
  }
  return n;
}

// ─── Transport builder from URI query params ─────────────────────────────────
// Used by VLESS, Trojan (and any future URI-format protocol).
// URI params:
//   ws/httpupgrade/xhttp: path, host
//   ws only:              ed (max_early_data), eh (early_data_header_name)
//   http (h2):            path, host
//   grpc:                 serviceName (primary), path (fallback)
//   xhttp:                mode (auto/packet-up/stream-up/stream-one)

TransportConfig? _buildTransportFromQuery(String network, Map<String, String> q) {
  if (network.isEmpty) return null;
  final t = TransportConfig(type: network);
  switch (network) {
    case 'ws':
      t.path = q['path'] ?? '';
      t.host = q['host'] ?? '';
      final ed = int.tryParse((q['ed'] ?? '').trim()) ?? 0;
      if (ed > 0) {
        t.maxEarlyData = ed;
        t.earlyDataHeaderName = orDefault(q['eh'] ?? '', 'Sec-WebSocket-Protocol');
      }
      // ed/eh 也可能被机场拼进 path 参数（"path=%2Fvless-argo%3Fed%3D2560"）—
      // 提取为 maxEarlyData/earlyDataHeaderName 并清理 path（对齐 v2rayN 做法）
      normalizeWsEarlyData(t);
    case 'xhttp':
      t.path = q['path'] ?? '';
      t.host = q['host'] ?? '';
      t.mode = q['mode'] ?? '';
    case 'http':
    case 'httpupgrade':
      t.path = q['path'] ?? '';
      t.host = q['host'] ?? '';
    case 'grpc':
      // URI uses "serviceName"; some exporters use "path" as fallback
      t.serviceName = orDefault(q['serviceName'] ?? '', q['path'] ?? '');
    case 'quic':
      // no extra fields
      break;
  }
  return t;
}

// ─── 小工具 ───────────────────────────────────────────────────────────────────

/// JSON 字段安全取字符串（非字符串类型返回 ''，避免 TypeError）。
String _jstr(dynamic v) => v is String ? v : '';

Uri _parseUri(String uri) {
  try {
    return Uri.parse(uri);
  } on FormatException catch (e) {
    throw ParseException('URI 解析失败: ${e.message}');
  }
}

/// 解码 fragment（对齐 Go 的 url.QueryUnescape(u.Fragment)）。
String _fragment(Uri u) => queryUnescapeLenient(u.fragment);

/// 拆分 userinfo 为 (username, password)，均做宽容解码。
/// 对齐 Go 的 u.User.Username() / u.User.Password()（首个 ':' 分隔）。
(String, String?) _splitUserInfo(String userInfo) {
  if (userInfo.isEmpty) return ('', null);
  final ci = userInfo.indexOf(':');
  if (ci >= 0) {
    return (
      decodeUserInfo(userInfo.substring(0, ci)),
      decodeUserInfo(userInfo.substring(ci + 1)),
    );
  }
  return (decodeUserInfo(userInfo), null);
}

/// 解析 query 串（对应 Go 的 url.ParseQuery）：'+'→空格，% 解码。
/// 每个键保留第一个值（Go 的 q.Get 语义）。
Map<String, String> _parseQuery(String query) {
  final out = <String, String>{};
  for (final part in query.split('&')) {
    if (part.isEmpty) continue;
    final eq = part.indexOf('=');
    final rawKey = eq < 0 ? part : part.substring(0, eq);
    final rawVal = eq < 0 ? '' : part.substring(eq + 1);
    final key = queryUnescapeLenient(rawKey);
    final val = queryUnescapeLenient(rawVal);
    if (!out.containsKey(key)) out[key] = val;
  }
  return out;
}
