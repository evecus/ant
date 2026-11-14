/// 节点 → 分享链接 — 移植自 Go: backend/node/export.go
library;

import 'dart:convert';

import '../models/node.dart';
import '../parsing/common.dart';

/// 把 Node 转回分享 URI（v2rayN 兼容格式）。
/// Raw-only 协议（ssh / shadowtls / …）没有分享链接格式，抛 [ParseException]。
String nodeToUri(Node n) {
  switch (n.protocol) {
    case 'vmess':
      if (n.vMess == null) throw ParseException('VMess 配置为空');
      return _vmessToUri(n);
    case 'vless':
      if (n.vless == null) throw ParseException('VLESS 配置为空');
      return _vlessToUri(n);
    case 'trojan':
      if (n.trojan == null) throw ParseException('Trojan 配置为空');
      return _trojanToUri(n);
    case 'ss':
      if (n.ss == null) throw ParseException('Shadowsocks 配置为空');
      return _ssToUri(n);
    case 'hysteria2':
      if (n.hysteria2 == null) throw ParseException('Hysteria2 配置为空');
      return _hysteria2ToUri(n);
    case 'hysteria':
      if (n.hysteria == null) throw ParseException('Hysteria 配置为空');
      return _hysteriaToUri(n);
    case 'tuic':
      if (n.tuic == null) throw ParseException('TUIC 配置为空');
      return _tuicToUri(n);
    case 'socks':
      if (n.socks == null) throw ParseException('Socks 配置为空');
      return _socksToUri(n);
    case 'http':
      if (n.http == null) throw ParseException('HTTP 配置为空');
      return _httpToUri(n);
    case 'anytls':
      if (n.anytls == null) throw ParseException('AnyTLS 配置为空');
      return _anytlsToUri(n);
    case 'ssr':
      if (n.ssr == null) throw ParseException('SSR 配置为空');
      return _ssrToUri(n);
    case 'wireguard':
      if (n.wireGuard == null) throw ParseException('WireGuard 配置为空');
      return _wireguardToUri(n);
    default:
      throw ParseException('协议 "${n.protocol}" 无分享链接格式');
  }
}

// ─── helpers ─────────────────────────────────────────────────────────────────

String _b64Std(String s) => base64.encode(utf8.encode(s));

String _b64RawUrl(String s) =>
    base64Url.encode(utf8.encode(s)).replaceAll('=', '');

String _frag(String name) => '#${Uri.encodeQueryComponent(name)}';

/// TransportConfig.Type → URI "type" 命名。
String _transportNetName(TransportConfig? t) {
  if (t == null || t.type.isEmpty) return 'tcp';
  if (t.type == 'http') return 'h2';
  return t.type; // ws | grpc | httpupgrade | quic | xhttp
}

/// 为 transport 追加 path/host/serviceName/ed/mode 参数。
void _transportUriParams(TransportConfig? t, Map<String, String> q) {
  if (t == null || t.type.isEmpty) return;
  switch (t.type) {
    case 'ws':
    case 'httpupgrade':
    case 'http':
    case 'xhttp':
      if (t.path.isNotEmpty) q['path'] = t.path;
      if (t.host.isNotEmpty) q['host'] = t.host;
      if (t.type == 'ws' && t.maxEarlyData > 0) {
        q['ed'] = t.maxEarlyData.toString();
      }
      if (t.type == 'xhttp' && t.mode.isNotEmpty) q['mode'] = t.mode;
    case 'grpc':
      if (t.serviceName.isNotEmpty) q['serviceName'] = t.serviceName;
  }
}

/// 按键名排序输出 query（对齐 Go 的 url.Values.Encode）。
String _encodeQuery(Map<String, String> q) {
  if (q.isEmpty) return '';
  final keys = q.keys.toList()..sort();
  return keys
      .map((k) =>
          '${Uri.encodeQueryComponent(k)}=${Uri.encodeQueryComponent(q[k]!)}')
      .join('&');
}

// ─── VMess: vmess://BASE64(JSON) ─────────────────────────────────────────────

String _vmessToUri(Node n) {
  final v = n.vMess!;
  final net = _transportNetName(v.transport);
  var host = '', path = '';
  if (v.transport != null) {
    host = v.transport!.host;
    path = v.transport!.path;
    if (v.transport!.type == 'grpc') {
      path = v.transport!.serviceName;
    }
  }
  final obj = <String, dynamic>{
    'v': '2',
    'ps': n.name,
    'add': n.address,
    'port': n.port,
    'id': v.uuid,
    'aid': v.alterId,
    'scy': orDefault(v.security, 'auto'),
    'net': net,
    'type': 'none',
    'host': host,
    'path': path,
    'tls': v.tls ? 'tls' : '',
    'sni': v.sni,
    'alpn': (v.alpn ?? []).join(','),
    'fp': v.fingerprint,
  };
  if (v.transport != null && v.transport!.maxEarlyData > 0) {
    obj['ed'] = v.transport!.maxEarlyData;
  }
  return 'vmess://${_b64Std(jsonEncode(obj))}';
}

// ─── VLESS ───────────────────────────────────────────────────────────────────

String _vlessToUri(Node n) {
  final v = n.vless!;
  final q = <String, String>{};
  q['type'] = _transportNetName(v.transport);
  _transportUriParams(v.transport, q);

  if (v.publicKey.isNotEmpty) {
    q['security'] = 'reality';
    q['pbk'] = v.publicKey;
    q['sid'] = v.shortId;
    q['fp'] = orDefault(v.fingerprint, 'chrome');
  } else if (v.tls) {
    q['security'] = 'tls';
    if (v.fingerprint.isNotEmpty) q['fp'] = v.fingerprint;
  }
  if (v.tls && v.sni.isNotEmpty) q['sni'] = v.sni;
  if ((v.alpn ?? []).isNotEmpty) q['alpn'] = v.alpn!.join(',');
  if (v.flow.isNotEmpty) q['flow'] = v.flow;
  if (v.insecure) q['insecure'] = '1';
  if (v.echConfig.isNotEmpty) q['ech'] = v.echConfig;
  final user = Uri.encodeComponent(v.uuid);
  return 'vless://$user@${_hostPort(n.address, n.port)}?${_encodeQuery(q)}${_frag(n.name)}';
}

// ─── Trojan ──────────────────────────────────────────────────────────────────

String _trojanToUri(Node n) {
  final t = n.trojan!;
  final q = <String, String>{};
  q['type'] = _transportNetName(t.transport);
  _transportUriParams(t.transport, q);
  if (t.sni.isNotEmpty) q['sni'] = t.sni;
  if (t.fingerprint.isNotEmpty) q['fp'] = t.fingerprint;
  if ((t.alpn ?? []).isNotEmpty) q['alpn'] = t.alpn!.join(',');
  if (t.insecure) q['allowInsecure'] = '1';
  if (t.echConfig.isNotEmpty) q['ech'] = t.echConfig;
  final user = Uri.encodeComponent(t.password);
  return 'trojan://$user@${_hostPort(n.address, n.port)}?${_encodeQuery(q)}${_frag(n.name)}';
}

// ─── Shadowsocks: SIP002 ─────────────────────────────────────────────────────

String _ssToUri(Node n) {
  final s = n.ss!;
  final userinfo = _b64RawUrl('${s.method}:${s.password}');
  var link = 'ss://$userinfo@${_hostPort(n.address, n.port)}';
  final q = <String, String>{};
  if (s.plugin.isNotEmpty) {
    var pluginStr = s.plugin;
    if (s.pluginOpts.isNotEmpty) pluginStr = '$pluginStr;${s.pluginOpts}';
    q['plugin'] = pluginStr;
  }
  if (q.isNotEmpty) link += '?${_encodeQuery(q)}';
  return '$link${_frag(n.name)}';
}

// ─── Hysteria2 ───────────────────────────────────────────────────────────────

String _hysteria2ToUri(Node n) {
  final h = n.hysteria2!;
  final q = <String, String>{};
  if (h.sni.isNotEmpty) q['sni'] = h.sni;
  if (h.insecure) q['insecure'] = '1';
  if (h.obfs.isNotEmpty) q['obfs'] = h.obfs;
  if (h.obfsPassword.isNotEmpty) q['obfs-password'] = h.obfsPassword;
  if (h.upMbps > 0) q['upmbps'] = h.upMbps.toString();
  if (h.downMbps > 0) q['downmbps'] = h.downMbps.toString();
  if ((h.alpn ?? []).isNotEmpty) q['alpn'] = h.alpn!.join(',');
  if (h.echConfig.isNotEmpty) q['ech'] = h.echConfig;
  final user = Uri.encodeQueryComponent(h.password);
  return 'hysteria2://$user@${_hostPort(n.address, n.port)}?${_encodeQuery(q)}${_frag(n.name)}';
}

// ─── Hysteria v1 ─────────────────────────────────────────────────────────────

String _hysteriaToUri(Node n) {
  final h = n.hysteria!;
  final q = <String, String>{};
  if (h.authStr.isNotEmpty) q['auth'] = h.authStr;
  if (h.sni.isNotEmpty) q['peer'] = h.sni;
  if (h.insecure) q['insecure'] = '1';
  if (h.upMbps > 0) q['upmbps'] = h.upMbps.toString();
  if (h.downMbps > 0) q['downmbps'] = h.downMbps.toString();
  if (h.obfs.isNotEmpty) q['obfs'] = h.obfs;
  if ((h.alpn ?? []).isNotEmpty) q['alpn'] = h.alpn!.join(',');
  return 'hysteria://${_hostPort(n.address, n.port)}?${_encodeQuery(q)}${_frag(n.name)}';
}

// ─── TUIC ────────────────────────────────────────────────────────────────────

String _tuicToUri(Node n) {
  final t = n.tuic!;
  final q = <String, String>{};
  if (t.sni.isNotEmpty) q['sni'] = t.sni;
  if ((t.alpn ?? []).isNotEmpty) q['alpn'] = t.alpn!.join(',');
  q['congestion_control'] = orDefault(t.congestionControl, 'cubic');
  if (t.udpRelayMode.isNotEmpty) q['udp_relay_mode'] = t.udpRelayMode;
  if (t.insecure) q['allow_insecure'] = '1';
  final user =
      '${Uri.encodeComponent(t.uuid)}:${Uri.encodeComponent(t.password)}';
  return 'tuic://$user@${_hostPort(n.address, n.port)}?${_encodeQuery(q)}${_frag(n.name)}';
}

// ─── Socks: socks://BASE64(user:pass@host:port) ──────────────────────────────

String _socksToUri(Node n) {
  final s = n.socks!;
  var payload = _hostPort(n.address, n.port);
  if (s.username.isNotEmpty) {
    payload = '${s.username}:${s.password}@$payload';
  }
  return 'socks://${_b64Std(payload)}${_frag(n.name)}';
}

// ─── HTTP(S) proxy ───────────────────────────────────────────────────────────

String _httpToUri(Node n) {
  final s = n.http!;
  final scheme = s.tls ? 'https' : 'http';
  var link = '$scheme://${_hostPort(n.address, n.port)}';
  if (s.username.isNotEmpty) {
    final user =
        '${Uri.encodeComponent(s.username)}:${Uri.encodeComponent(s.password)}';
    link = '$scheme://$user@${_hostPort(n.address, n.port)}';
  }
  final q = <String, String>{};
  if (s.sni.isNotEmpty) q['sni'] = s.sni;
  if (s.insecure) q['insecure'] = '1';
  if (q.isNotEmpty) link += '?${_encodeQuery(q)}';
  return '$link${_frag(n.name)}';
}

// ─── AnyTLS ──────────────────────────────────────────────────────────────────

String _anytlsToUri(Node n) {
  final a = n.anytls!;
  final q = <String, String>{};
  if (a.sni.isNotEmpty) q['sni'] = a.sni;
  if (a.insecure) q['insecure'] = '1';
  if (a.fingerprint.isNotEmpty) q['fp'] = a.fingerprint;
  if ((a.alpn ?? []).isNotEmpty) q['alpn'] = a.alpn!.join(',');
  if (a.echConfig.isNotEmpty) q['ech'] = a.echConfig;
  final user = Uri.encodeQueryComponent(a.password);
  return 'anytls://$user@${_hostPort(n.address, n.port)}?${_encodeQuery(q)}${_frag(n.name)}';
}

// ─── ShadowsocksR ────────────────────────────────────────────────────────────

String _ssrToUri(Node n) {
  final s = n.ssr!;
  final q = <String, String>{};
  if (s.obfsParam.isNotEmpty) q['obfsparam'] = s.obfsParam;
  if (s.protocolParam.isNotEmpty) q['protoparam'] = s.protocolParam;
  q['remarks'] = n.name;
  final payload = '${_hostPort(n.address, n.port)}:${s.protocol}:'
      '${s.method}:${s.obfs}:${_b64Std(s.password)}/?${_encodeQuery(q)}';
  return 'ssr://${_b64Std(payload)}';
}

// ─── WireGuard ───────────────────────────────────────────────────────────────

String _wireguardToUri(Node n) {
  final w = n.wireGuard!;
  final q = <String, String>{};
  q['publickey'] = w.publicKey;
  if (w.presharedKey.isNotEmpty) q['presharedkey'] = w.presharedKey;
  if ((w.localAddress ?? []).isNotEmpty) {
    q['address'] = w.localAddress!.join(',');
  }
  if ((w.reserved ?? []).length == 3) {
    q['reserved'] = w.reserved!.join(',');
  }
  if (w.mtu > 0) q['mtu'] = w.mtu.toString();
  if ((w.dns ?? []).isNotEmpty) q['dns'] = w.dns!.join(',');
  final user = Uri.encodeComponent(w.privateKey);
  return 'wireguard://$user@${_hostPort(n.address, n.port)}?${_encodeQuery(q)}${_frag(n.name)}';
}

// ─── small helpers ───────────────────────────────────────────────────────────

String _hostPort(String host, int port) {
  // IPv6 字面量加方括号
  if (host.contains(':') && !host.startsWith('[')) {
    host = '[$host]';
  }
  return '$host:$port';
}
