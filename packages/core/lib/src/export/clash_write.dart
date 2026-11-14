/// Clash/mihomo 配置写入（单节点 → proxies 条目）— 移植自 Go: backend/node/clash_write.go。
///
/// 全量 mihomo 配置的组装（proxies/proxy-groups 落盘）在 Go 版位于
/// backend/config 包，不在本文件移植范围。
///
/// 错误统一抛 [ParseException]（Go 版通过 error 返回值表达）。
library;

import 'package:yaml/yaml.dart';
import 'package:yaml_writer/yaml_writer.dart';

import '../models/node.dart';
import '../parsing/common.dart';

/// 把 Node 转换为 Clash/mihomo 风格的 proxies 条目
///（name 保留原节点名，写入配置时由调用方改写为固定名 "proxy"）。
/// 它是 clashProxyToNode 的逆向转换，字段名遵循 Clash YAML 规范。
///
/// 优先级：若节点带有 rawClashProxy（从 Clash YAML 导入），直接使用原始
/// 条目（仅刷新 name/server/port），实现无损回写；否则按结构化字段生成。
/// 不支持的协议（ssh 等仅 rawOutbound 的节点）抛 [ParseException]。
Map<String, dynamic> nodeToClashProxy(Node n) {
  if (n.rawClashProxy != null) {
    final p = _cloneClashProxy(n.rawClashProxy!);
    if (p == null) {
      throw ParseException('节点原始 Clash 数据无效');
    }
    p['name'] = n.name;
    p['server'] = n.address;
    p['port'] = n.port;
    return p;
  }

  final p = <String, dynamic>{
    'name': n.name,
    'server': n.address,
    'port': n.port,
  };

  switch (n.protocol) {
    case 'vmess':
      if (n.vMess == null) throw ParseException('VMess 配置为空');
      p['type'] = 'vmess';
      p['uuid'] = n.vMess!.uuid;
      p['alterId'] = n.vMess!.alterId;
      p['cipher'] = orDefault(n.vMess!.security, 'auto');
      _setClashTLS(p, n.vMess!.tls, n.vMess!.sni, n.vMess!.alpn, n.vMess!.insecure, n.vMess!.fingerprint);
      _applyClashTransport(p, n.vMess!.transport);

    case 'vless':
      if (n.vless == null) throw ParseException('VLESS 配置为空');
      final v = n.vless!;
      p['type'] = 'vless';
      p['uuid'] = v.uuid;
      if (v.flow.isNotEmpty) p['flow'] = v.flow;
      _setClashTLS(p, v.tls, v.sni, v.alpn, v.insecure, v.fingerprint);
      if (v.publicKey.isNotEmpty) {
        p['tls'] = true;
        p['reality-opts'] = <String, dynamic>{
          'public-key': v.publicKey,
          'short-id': v.shortId,
        };
      }
      _applyClashTransport(p, v.transport);

    case 'trojan':
      if (n.trojan == null) throw ParseException('Trojan 配置为空');
      final t = n.trojan!;
      p['type'] = 'trojan';
      p['password'] = t.password;
      if (t.sni.isNotEmpty) p['sni'] = t.sni;
      if ((t.alpn ?? []).isNotEmpty) p['alpn'] = t.alpn;
      if (t.insecure) p['skip-cert-verify'] = true;
      if (t.fingerprint.isNotEmpty) p['client-fingerprint'] = t.fingerprint;
      _applyClashTransport(p, t.transport);

    case 'ss':
      if (n.ss == null) throw ParseException('Shadowsocks 配置为空');
      final s = n.ss!;
      p['type'] = 'ss';
      p['cipher'] = s.method;
      p['password'] = s.password;
      if (s.plugin.isNotEmpty) {
        p['plugin'] = s.plugin;
        if (s.pluginOpts.isNotEmpty) {
          final opts = _parsePluginOpts(s.pluginOpts);
          if (opts != null) p['plugin-opts'] = opts;
        }
      }

    case 'hysteria2':
      if (n.hysteria2 == null) throw ParseException('Hysteria2 配置为空');
      final h = n.hysteria2!;
      p['type'] = 'hysteria2';
      if (h.password.isNotEmpty) p['password'] = h.password;
      if (h.sni.isNotEmpty) p['sni'] = h.sni;
      if (h.insecure) p['skip-cert-verify'] = true;
      if ((h.alpn ?? []).isNotEmpty) p['alpn'] = h.alpn;
      if (h.upMbps > 0) p['up'] = h.upMbps;
      if (h.downMbps > 0) p['down'] = h.downMbps;
      if (h.obfs.isNotEmpty) {
        p['obfs'] = h.obfs;
        if (h.obfsPassword.isNotEmpty) p['obfs-password'] = h.obfsPassword;
      }

    case 'hysteria':
      if (n.hysteria == null) throw ParseException('Hysteria 配置为空');
      final h = n.hysteria!;
      p['type'] = 'hysteria';
      if (h.authStr.isNotEmpty) p['auth-str'] = h.authStr;
      if (h.sni.isNotEmpty) p['sni'] = h.sni;
      if (h.insecure) p['skip-cert-verify'] = true;
      if ((h.alpn ?? []).isNotEmpty) p['alpn'] = h.alpn;
      if (h.upMbps > 0) p['up'] = h.upMbps;
      if (h.downMbps > 0) p['down'] = h.downMbps;
      if (h.obfs.isNotEmpty) p['obfs'] = h.obfs;

    case 'tuic':
      if (n.tuic == null) throw ParseException('TUIC 配置为空');
      final t = n.tuic!;
      p['type'] = 'tuic';
      p['uuid'] = t.uuid;
      if (t.password.isNotEmpty) p['password'] = t.password;
      if (t.sni.isNotEmpty) p['sni'] = t.sni;
      if ((t.alpn ?? []).isNotEmpty) p['alpn'] = t.alpn;
      p['congestion-controller'] = orDefault(t.congestionControl, 'cubic');
      if (t.udpRelayMode.isNotEmpty) p['udp-relay-mode'] = t.udpRelayMode;
      if (t.insecure) p['skip-cert-verify'] = true;

    case 'socks':
      if (n.socks == null) throw ParseException('Socks 配置为空');
      p['type'] = 'socks5';
      if (n.socks!.username.isNotEmpty) p['username'] = n.socks!.username;
      if (n.socks!.password.isNotEmpty) p['password'] = n.socks!.password;

    case 'http':
      if (n.http == null) throw ParseException('HTTP 配置为空');
      final h = n.http!;
      p['type'] = 'http';
      if (h.username.isNotEmpty) p['username'] = h.username;
      if (h.password.isNotEmpty) p['password'] = h.password;
      if (h.tls) p['tls'] = true;
      if (h.sni.isNotEmpty) p['sni'] = h.sni;
      if (h.insecure) p['skip-cert-verify'] = true;
      if ((h.alpn ?? []).isNotEmpty) p['alpn'] = h.alpn;

    case 'anytls':
      if (n.anytls == null) throw ParseException('AnyTLS 配置为空');
      final a = n.anytls!;
      p['type'] = 'anytls';
      p['password'] = a.password;
      if (a.sni.isNotEmpty) p['sni'] = a.sni;
      if (a.insecure) p['skip-cert-verify'] = true;
      if ((a.alpn ?? []).isNotEmpty) p['alpn'] = a.alpn;
      if (a.fingerprint.isNotEmpty) p['client-fingerprint'] = a.fingerprint;

    case 'ssr':
      if (n.ssr == null) throw ParseException('SSR 配置为空');
      final s = n.ssr!;
      p['type'] = 'ssr';
      if (s.method.isNotEmpty) p['cipher'] = s.method;
      p['password'] = s.password;
      if (s.protocol.isNotEmpty) p['protocol'] = s.protocol;
      if (s.protocolParam.isNotEmpty) p['protocol-param'] = s.protocolParam;
      if (s.obfs.isNotEmpty) p['obfs'] = s.obfs;
      if (s.obfsParam.isNotEmpty) p['obfs-param'] = s.obfsParam;

    case 'wireguard':
      if (n.wireGuard == null) throw ParseException('WireGuard 配置为空');
      final wg = n.wireGuard!;
      p['type'] = 'wireguard';
      p['private-key'] = wg.privateKey;
      p['public-key'] = wg.publicKey;
      if (wg.presharedKey.isNotEmpty) p['pre-shared-key'] = wg.presharedKey;
      if ((wg.reserved ?? []).isNotEmpty) p['reserved'] = wg.reserved;
      if ((wg.localAddress ?? []).isNotEmpty) {
        p['ip'] = wg.localAddress![0];
        if (wg.localAddress!.length > 1) p['ipv6'] = wg.localAddress![1];
      }
      if (wg.mtu > 0) p['mtu'] = wg.mtu;
      if ((wg.dns ?? []).isNotEmpty) p['dns'] = wg.dns;

    default:
      // ssh 等仅有 rawOutbound 的节点无法表达为 Clash 条目
      throw ParseException('协议 ${n.protocol} 不支持写入 ant 配置');
  }
  return p;
}

/// 写入 Clash 通用 TLS 字段（vmess/vless 使用 servername）。
void _setClashTLS(Map<String, dynamic> p, bool tls, String sni, List<String>? alpn,
    bool insecure, String fingerprint) {
  if (tls) p['tls'] = true;
  if (sni.isNotEmpty) p['servername'] = sni;
  if ((alpn ?? []).isNotEmpty) p['alpn'] = alpn;
  if (insecure) p['skip-cert-verify'] = true;
  if (fingerprint.isNotEmpty) p['client-fingerprint'] = fingerprint;
}

/// 把 TransportConfig 写回 Clash 的 network + "*-opts" 结构。
void _applyClashTransport(Map<String, dynamic> p, TransportConfig? t) {
  if (t == null || t.type.isEmpty) return;
  p['network'] = t.type;
  final opts = <String, dynamic>{};
  switch (t.type) {
    case 'ws':
      // 兜底：path 里嵌的 ed/eh 提取为 max-early-data/early-data-header-name
      normalizeWsEarlyData(t);
      if (t.path.isNotEmpty) opts['path'] = t.path;
      if (t.host.isNotEmpty) opts['headers'] = <String, dynamic>{'Host': t.host};
      if (t.maxEarlyData > 0) {
        opts['max-early-data'] = t.maxEarlyData;
        opts['early-data-header-name'] = orDefault(t.earlyDataHeaderName, 'Sec-WebSocket-Protocol');
      }
    case 'http':
      if (t.path.isNotEmpty) opts['path'] = t.path;
      if (t.host.isNotEmpty) opts['host'] = [t.host];
    case 'grpc':
      if (t.serviceName.isNotEmpty) opts['grpc-service-name'] = t.serviceName;
    case 'httpupgrade':
      if (t.path.isNotEmpty) opts['path'] = t.path;
      if (t.host.isNotEmpty) opts['host'] = t.host;
    case 'xhttp':
      if (t.path.isNotEmpty) opts['path'] = t.path;
      if (t.host.isNotEmpty) opts['host'] = [t.host];
      if (t.mode.isNotEmpty) opts['mode'] = t.mode;
    case 'quic':
      // 无附加字段
    default:
      return; // 未知 transport 不写 *-opts（注意：与 Go 版一致，network 已先写入）
  }
  if (opts.isNotEmpty) {
    var key = '${t.type}-opts';
    if (t.type == 'http') key = 'h2-opts';
    p[key] = opts;
  }
}

/// 把 sing-box 风格的 "k=v;k=v" 插件参数串转回 Clash 的 map。
Map<String, dynamic>? _parsePluginOpts(String s) {
  final m = <String, dynamic>{};
  for (final part in s.split(';')) {
    // 对应 Go 的 strings.SplitN(part, "=", 2)：按第一个 '=' 切分
    final i = part.indexOf('=');
    if (i != -1) {
      m[part.substring(0, i)] = part.substring(i + 1);
    }
  }
  if (m.isEmpty) return null;
  return m;
}

/// 深拷贝一个 Clash proxies 条目（经 yaml 序列化往返，
/// 同时把类型规范化为 YAML 原生类型，保证写入/回读后逐字段可比较）。
/// 失败返回 null（对应 Go 版 cloneClashProxy 的 error 分支）。
Map<String, dynamic>? _cloneClashProxy(Map<String, dynamic> m) {
  try {
    final data = YamlWriter().write(m);
    final doc = loadYaml(data);
    if (doc is! YamlMap) return null;
    return _yamlToPlain(doc).cast<String, dynamic>();
  } catch (_) {
    return null;
  }
}

/// YamlMap/YamlList → 普通 Map/List（保持插入顺序）。
dynamic _yamlToPlain(dynamic node) {
  if (node is YamlMap) {
    return node.map((k, v) => MapEntry(k.toString(), _yamlToPlain(v)));
  }
  if (node is YamlList) {
    return node.map(_yamlToPlain).toList();
  }
  return node;
}
