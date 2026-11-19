/// ant 配置写入（单节点 → `proxies:` 条目）。
///
/// 思路：保留上游工程原来的 Clash/mihomo 写出（[nodeToClashProxy]，
/// 含 rawClashProxy 无损回写与全部协议分支），再按 ant 的 `ProxyConfig`
/// 做一次字段归一化：mihomo / sub-store 别名 → ant 键名、嵌套 `*-opts`
/// → ant 扁平字段、字符串化的数字/布尔、alpn 逗号串 → 列表。
/// 规则与 ant 的 `src/provider/parse.rs::normalize_clash_node` 一致，
/// 因此「订阅里读到的一个 Clash 节点」与「GUI 写进配置的一个节点」等价。
///
/// ant 没有对应出站的协议（`hysteria` v1 / `ssr` / 纯 `http`）以及 ant
/// 无法承载的 transport（`grpc` / `httpupgrade` / `h2` / `quic`）直接抛
/// [ParseException] fail-fast，不静默降级成不可用的节点。
library;

import '../export/clash_write.dart' show nodeToClashProxy;
import '../models/node.dart';
import '../parsing/common.dart';

/// ant 配置里「当前应用节点」的固定条目名，也是 `route:` 规则直接引用的
/// 出站名（ant 的 outbound_names 含 proxies 节点名，无需再建 proxy-groups）。
/// 与 mihomo 版同名，便于沿用原有 applyNode / findAppliedNodeID 流程。
const String antProxyName = 'proxy';

/// Node → ant 的 `proxies:` 条目。
Map<String, dynamic> nodeToAntProxy(Node n) =>
    clashProxyToAntProxy(nodeToClashProxy(n));

/// ant ProxyConfig 认识的键（其余 Clash 专属字段直接丢弃，避免干扰）。
/// 参照 ant `src/config.rs::ProxyConfig` 的 `#[serde(rename/alias)]`。
const Set<String> _knownKeys = {
  'name', 'type', 'server', 'port',
  'password', 'username', 'version', 'uuid', 'flow',
  'cipher', 'alter-id', 'network', 'tls', 'sni', 'servername', 'alpn',
  'skip-cert-verify', 'fingerprint', 'client-fingerprint',
  'ws-path', 'ws-host', 'ws-headers',
  'reality-public-key', 'reality-short-id',
  'ech', 'ech-config', 'ech-config-path', 'ech-query-server-name',
  'xhttp-path', 'xhttp-host', 'xhttp-mode', 'xhttp-headers',
  'obfs', 'obfs-password', 'up', 'down', 'ports', 'ca',
  'disable-mtu-discovery', 'udp-mtu',
  'congestion-control', 'heartbeat',
  'over-stream', 'zero-rtt', 'initial-mtu', 'min-mtu',
  'private-key', 'peer-public-key', 'pre-shared-key', 'local-address',
  'mtu', 'persistent-keepalive',
  // SSH / tailscale（ant 按需 feature；GUI 不主动生成，仅放行原始条目字段）
  'host-key', 'host-key-algorithms', 'private-key-passphrase', 'totp-opt',
  'auth-key', 'control-url', 'hostname', 'client-name', 'state-dir',
};

/// ant 不支持的出站协议（没有对应 dialer）。
const Set<String> _unsupportedTypes = {
  'hysteria', // v1
  'ssr',
  'http',
  'https',
  'snell',
  'ssh', // 仅 raw 且需 feature；由内核 fail-fast，这里显式拒绝更清楚
};

/// ant 的 `network` 只实现 tcp / ws / xhttp。
const Set<String> _supportedNetworks = {'tcp', 'ws', 'xhttp', ''};

/// Trojian / QUIC 系节点恒为 TLS（mihomo 的 Clash 条目通常不写 tls 字段）。
const Set<String> _alwaysTlsTypes = {
  'trojan', 'hysteria2', 'tuic', 'anytls', 'naive', 'shadowquic', 'spectre',
};

/// 把一个 Clash/mihomo `proxies:` 条目转换为 ant 的扁平 ProxyConfig 条目。
///
/// [name] / [server] / [port] 可覆盖（应用节点时统一改写为固定名与当前地址）。
Map<String, dynamic> clashProxyToAntProxy(
  Map<String, dynamic> raw, {
  String? name,
  String? server,
  int? port,
}) {
  final src = _deepCopy(raw);

  // ── 基础字段规范化 ────────────────────────────────────────────────
  src['name'] = name ?? _str(src['name']);
  src['server'] = server ?? _str(src['server']);
  src['port'] = port ?? _toInt(src['port']);
  var type = _str(src['type']).toLowerCase();
  if (type == 'hy2') type = 'hysteria2';
  src['type'] = type;

  if (type.isEmpty) {
    throw ParseException('ant 节点缺少 type 字段');
  }
  if (_unsupportedTypes.contains(type)) {
    throw ParseException('ant 不支持 $type 协议（无对应出站）');
  }
  if (type == 'socks5') {
    // Clash 的 socks5 与 ant 的 socks5 同名，保留
  }
  // `port` 可能是字符串
  if (src['port'] == 0) {
    throw ParseException('ant 节点端口无效');
  }

  // ── up/down 带宽字符串（"100 Mbps"）─────────────────────────────
  // ant 的 up/down 是 Option<String>；Clash 常写成数字。必须在下面的
  // 类型归一化之前转换，否则数字会先变成裸字符串（"30"），丢失单位，
  // 且下面的 num 判断也永远不会命中。
  for (final k in ['up', 'down']) {
    final v = src[k];
    if (v is num && v > 0) src[k] = '${v.toInt()} Mbps';
  }

  // ── 布尔 / 字符串字段类型归一（对齐 ant parse.rs）────────────────
  for (final k in [
    'tls', 'skip-cert-verify', 'disable-sni', 'ech', 'over-stream',
    'zero-rtt', 'disable-mtu-discovery', 'allowInsecure', 'verify_cert',
  ]) {
    if (src.containsKey(k)) src[k] = _toBool(src[k]);
  }
  for (final k in [
    'up', 'down', 'ports', 'obfs', 'obfs-password', 'congestion-control',
    'heartbeat', 'version', 'ws-path', 'ws-host', 'xhttp-path', 'xhttp-host',
    'xhttp-mode', 'sni', 'servername', 'password', 'uuid', 'username',
    'flow', 'client-fingerprint', 'fingerprint', 'reality-public-key',
    'reality-short-id', 'private-key', 'peer-public-key', 'pre-shared-key',
  ]) {
    final v = src[k];
    if (v != null && v is! String) src[k] = _str(v);
  }
  // alpn 逗号串 → 列表
  final alpn = src['alpn'];
  if (alpn is String) {
    src['alpn'] = alpn.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
  }
  // local-address 逗号串 → 列表
  final localAddr = src['local-address'];
  if (localAddr is String) {
    src['local-address'] =
        localAddr.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
  }
  // 嵌套 ws-opts / xhttp-opts / reality-opts → ant 扁平字段
  _flattenOpts(src, 'ws-opts', const {
    'path': 'ws-path',
    'mode': null, // ws 无 mode
  }, 'ws');
  _flattenOpts(src, 'xhttp-opts', const {
    'path': 'xhttp-path',
    'host': 'xhttp-host',
    'mode': 'xhttp-mode',
  }, 'xhttp');
  final reality = src['reality-opts'];
  if (reality is Map) {
    final pk = reality['public-key'];
    final sid = reality['short-id'];
    if (pk != null) src['reality-public-key'] = _str(pk);
    if (sid != null) src['reality-short-id'] = _str(sid);
  }
  // h2-opts / grpc-opts / httpupgrade-opts 若存在，说明是 ant 不支持的 transport
  for (final k in ['h2-opts', 'grpc-opts', 'httpupgrade-opts']) {
    if (src.containsKey(k)) {
      src['network'] = k == 'h2-opts' ? 'http' : k.replaceAll('-opts', '');
    }
  }
  // WS 的 headers.Host → ws-host
  final wsOpts = src['ws-opts'];
  if (wsOpts is Map) {
    final headers = wsOpts['headers'];
    if (headers is Map) {
      final host = headers['Host'] ?? headers['host'];
      if (host != null) src['ws-host'] = _str(host);
      src['ws-headers'] = _stringifyMap(headers);
    }
  }
  final xhttpOpts = src['xhttp-opts'];
  if (xhttpOpts is Map) {
    final headers = xhttpOpts['headers'];
    if (headers is Map) src['xhttp-headers'] = _stringifyMap(headers);
  }

  // ── 别名（mihomo / sub-store → ant）──────────────────────────────
  if (_str(src['password']).isEmpty) {
    for (final k in ['auth', 'auth-str', 'auth_str']) {
      final v = _str(src[k]);
      if (v.isNotEmpty) {
        src['password'] = v;
        break;
      }
    }
  }
  if (_str(src['congestion-control']).isEmpty) {
    for (final k in ['congestion-controller', 'congestion_controller']) {
      final v = _str(src[k]);
      if (v.isNotEmpty) {
        src['congestion-control'] = v;
        break;
      }
    }
  }
  if (_str(src['fingerprint']).isEmpty) {
    for (final k in ['tls-fingerprint', 'server-cert-fingerprint']) {
      final v = _str(src[k]);
      if (v.isNotEmpty) {
        src['fingerprint'] = v;
        break;
      }
    }
  }
  if (_str(src['sni']).isEmpty) {
    final sn = _str(src['servername']);
    if (sn.isNotEmpty) src['sni'] = sn;
  }
  // vmess alterId（Clash camelCase）→ ant 的 alter-id（config.rs 也有 alias，
  // 但这里统一收敛为 ant 键名，避免白名单过滤后字段丢失）。
  if (src.containsKey('alterId') && !src.containsKey('alter-id')) {
    src['alter-id'] = src['alterId'];
  }
  // security 与 cipher 同时出现会重复字段：保留 cipher，丢弃 security。
  if (src.containsKey('cipher') && src.containsKey('security')) {
    src.remove('security');
  }
  // `security` 单独出现时 SS/VMess 用它表达 cipher
  if (!src.containsKey('cipher') && src.containsKey('security')) {
    final sec = _str(src['security']);
    if (sec.isNotEmpty && sec != 'tls' && sec != 'none') src['cipher'] = sec;
    src.remove('security');
  }
  // peer → sni（v2rayN vmess 链接）
  if (_str(src['sni']).isEmpty) {
    final peer = _str(src['peer']);
    if (peer.isNotEmpty) src['sni'] = peer;
  }
  // verify_cert:false / allowInsecure → skip-cert-verify
  if (src['skip-cert-verify'] != true) {
    if (src['allowInsecure'] == true || src['verify_cert'] == false) {
      src['skip-cert-verify'] = true;
    }
  }
  // ── WireGuard 字段别名（对齐 ant parse.rs）───────────────────────
  if (type == 'wireguard' || type == 'wg') {
    final peers = src['peers'];
    if (peers is List && peers.isNotEmpty && peers.first is Map) {
      final p = peers.first as Map;
      for (final k in ['server', 'port', 'public-key', 'pre-shared-key']) {
        if (!src.containsKey(k) && p.containsKey(k)) src[k] = p[k];
      }
    }
    final pub = src['public-key'];
    if (pub != null && !src.containsKey('peer-public-key')) {
      src['peer-public-key'] = _str(pub);
    }
    if (!src.containsKey('local-address')) {
      final addrs = <String>[];
      for (final k in ['ip', 'ipv6', 'address', 'local-address']) {
        final v = src[k];
        if (v is String) {
          addrs.addAll(v.split(',').map((s) => s.trim()).where((s) => s.isNotEmpty));
        } else if (v is List) {
          addrs.addAll(v.map(_str).where((s) => s.isNotEmpty));
        }
      }
      if (addrs.isNotEmpty) src['local-address'] = addrs;
    }
  }

  // ── transport（ant 只实现 tcp / ws / xhttp）──────────────────────
  final network = _str(src['network']).toLowerCase();
  if (!_supportedNetworks.contains(network)) {
    throw ParseException(
        'ant 不支持 network=$network 的传输层（仅 tcp / ws / xhttp）');
  }
  if (network.isNotEmpty) src['network'] = network;
  // 插件（SIP003）ant 没有对应实现
  final plugin = _str(src['plugin']);
  if (plugin.isNotEmpty) {
    throw ParseException('ant 不支持 Shadowsocks 插件 plugin=$plugin');
  }

  // ── TLS 默认值 ───────────────────────────────────────────────────
  // ant 的 ProxyConfig.tls 全局默认 true；mihomo 默认 false。
  // 未显式给出 tls 时按协议补默认值，避免明文节点被意外套上 TLS。
  if (!raw.containsKey('tls')) {
    src['tls'] = _alwaysTlsTypes.contains(type);
  }

  // ── 白名单过滤 ──────────────────────────────────────────────────
  final out = <String, dynamic>{};
  for (final k in [
    'name', 'type', 'server', 'port',
    ..._knownKeys.where((k) => k != 'name' && k != 'type' && k != 'server' && k != 'port'),
  ]) {
    if (!src.containsKey(k)) continue;
    final v = src[k];
    if (v == null) continue;
    if (v is String && v.isEmpty && k != 'name') continue;
    if (v is List && v.isEmpty) continue;
    out[k] = v;
  }
  // 原始 Clash 条目里可能带 ant 认识的键，但被上面按白名单顺序重新组织；
  // 保证四个基础字段在最前（YAML 输出顺序稳定）。
  return <String, dynamic>{
    'name': out.remove('name') ?? '',
    'type': out.remove('type') ?? '',
    'server': out.remove('server') ?? '',
    'port': out.remove('port') ?? 0,
    ...out,
  };
}

/// 把 `*-opts` 里的 path/host/mode 提到顶层（ant 的扁平字段）。
void _flattenOpts(Map<String, dynamic> src, String optsKey,
    Map<String, String?> mapping, String network) {
  final opts = src[optsKey];
  if (opts is! Map) return;
  mapping.forEach((srcKey, dstKey) {
    if (dstKey == null) return;
    final v = opts[srcKey];
    if (v != null) src[dstKey] = _str(v);
  });
  if (src['network'] == null || _str(src['network']).isEmpty) {
    src['network'] = network;
  }
}

/// header map 的 value 统一为字符串（ant 的 `HashMap<String,String>`）。
Map<String, dynamic> _stringifyMap(Map m) => <String, dynamic>{
      for (final e in m.entries) e.key.toString(): _str(e.value),
    };

/// 深拷贝（YamlMap / LinkedHashMap → 普通 Map/List）。
Map<String, dynamic> _deepCopy(Map m) {
  final out = <String, dynamic>{};
  m.forEach((k, v) => out[k.toString()] = _copyValue(v));
  return out;
}

dynamic _copyValue(dynamic v) {
  if (v is Map) return _deepCopy(v);
  if (v is List) return v.map(_copyValue).toList();
  return v;
}

String _str(dynamic v) {
  if (v == null) return '';
  if (v is String) return v;
  if (v is bool) return v ? 'true' : 'false';
  return '$v';
}

int _toInt(dynamic v) {
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v.trim()) ?? 0;
  return 0;
}

bool _toBool(dynamic v) {
  if (v is bool) return v;
  if (v is num) return v != 0;
  if (v is String) {
    final s = v.toLowerCase().trim();
    return s == 'true' || s == '1' || s == 'yes' || s == 'tls';
  }
  return false;
}
