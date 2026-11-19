/// ant 配置文件增量编辑 — 由上游 GUI 工程的 mihomo_edit.dart 完整搬运。
///
/// 约定（与 Go / mihomo 版一致，字段名换成 ant 的）：
///   - `proxies:` 中 name 为 "proxy" 的条目代表「当前应用的节点」；
///   - `route:` 规则直接按节点名 "proxy" 引用它作为出站（ant 的
///     outbound_names 含 proxies 节点名，无需 proxy-groups）；
///   - TUN 是顶层 `tun:` 对象（enable/mtu/dns-hijack/auto-route/
///     strict-route），ant 为内核 NAT 系统栈，无 stack，address /
///     auto-detect-interface 由内核自行处理；
///   - 系统代理对应顶层 `mixed-port` + 全局 `bind-address`。
///
/// 节点写出走 [clashProxyToAntProxy] / [nodeToAntProxy]：先复用 Clash 条目
/// （含 rawClashProxy 无损回写），再归一化成 ant 的扁平 ProxyConfig 字段。
library;

import 'dart:io';

import 'package:yaml/yaml.dart';
import 'package:yaml_writer/yaml_writer.dart';

import '../export/ant_write.dart';
import '../models/node.dart';
import '../parsing/common.dart';

final YamlWriter _yamlWriter = YamlWriter(allowUnquotedStrings: true);

// ─── YAML load / save ─────────────────────────────────────────────────────────

/// 读取 YAML 配置为普通 Map — 移植自 Go: mihomo.go loadYAML。
/// 读文件/解析失败抛 [ParseException]。
Map<String, dynamic> loadYamlFile(String path) {
  String data;
  try {
    data = File(path).readAsStringSync();
  } catch (e) {
    throw ParseException('读取配置文件失败: $e');
  }
  dynamic doc;
  try {
    doc = loadYaml(data);
  } on YamlException catch (e) {
    throw ParseException('解析配置文件失败: ${e.message}');
  } catch (e) {
    throw ParseException('解析配置文件失败: $e');
  }
  if (doc == null) return <String, dynamic>{};
  if (doc is! Map) {
    throw ParseException('解析配置文件失败: 配置根节点不是映射');
  }
  return _toPlainMap(doc);
}

/// 写 YAML 配置（yaml_writer 输出，原子写：临时文件 + rename）—
/// 移植自 Go: mihomo.go saveYAML（yaml.Marshal + tmp + rename）。
void saveYamlFile(String path, Map<String, dynamic> cfg) {
  String data;
  try {
    data = _yamlWriter.write(cfg);
  } catch (e) {
    throw ParseException('序列化配置失败: $e');
  }
  _atomicWrite(path, data);
}

/// 原子写：临时文件 + rename，避免崩溃时损坏配置。
void _atomicWrite(String path, String data) {
  final tmp = '$path.tmp';
  try {
    File(tmp).writeAsStringSync(data, flush: true);
    File(tmp).renameSync(path);
  } catch (e) {
    throw ParseException('写入配置文件失败: $e');
  }
}

/// YamlMap/嵌套结构 → 普通 Map/List（保持插入顺序），便于后续修改与比较。
Map<String, dynamic> _toPlainMap(Map m) {
  final out = <String, dynamic>{};
  m.forEach((k, v) {
    out[k.toString()] = _toPlainValue(v);
  });
  return out;
}

dynamic _toPlainValue(dynamic node) {
  if (node is Map) return _toPlainMap(node);
  if (node is List) return node.map(_toPlainValue).toList();
  return node;
}

/// 返回配置中的 proxies 列表 — 移植自 Go: mihomo.go getProxies。
List<dynamic> getProxies(Map<String, dynamic> cfg) {
  final v = cfg['proxies'];
  return v is List ? List<dynamic>.from(v) : <dynamic>[];
}

/// 深拷贝一个 map — 移植自 Go: mihomo.go cloneMap。
Map<String, dynamic> cloneMap(Map m) {
  final out = <String, dynamic>{};
  m.forEach((k, v) {
    out[k.toString()] = _deepCopyValue(v);
  });
  return out;
}

dynamic _deepCopyValue(dynamic v) {
  if (v is Map) return cloneMap(v);
  if (v is List) return v.map(_deepCopyValue).toList();
  return v;
}

// ─── Apply Node ───────────────────────────────────────────────────────────────

/// 把节点写入 ant 配置：替换/追加 name 为 "proxy" 的 proxies 条目 —
/// 移植自 Go: mihomo.go ApplyNodeToMihomoConfig。route 规则直接按节点名引用。
void applyNodeToAntConfig(String cfgPath, Node n) {
  final cfg = loadYamlFile(cfgPath);
  Map<String, dynamic> proxy;
  if (n.rawClashProxy != null) {
    // 原始 Clash YAML 条目无损回写（同 sing-box rawOutbound 的做法），
    // 经 ant 字段归一化后写入。
    proxy = clashProxyToAntProxy(
      n.rawClashProxy!,
      name: antProxyName,
      server: n.address,
      port: n.port,
    );
  } else {
    proxy = nodeToAntProxy(n);
  }
  proxy['name'] = antProxyName;

  final proxies = getProxies(cfg);
  var replaced = false;
  for (var i = 0; i < proxies.length; i++) {
    final pr = proxies[i];
    if (pr is Map && pr['name'] == antProxyName) {
      proxies[i] = proxy;
      replaced = true;
      break;
    }
  }
  if (!replaced) {
    proxies.add(proxy);
  }
  cfg['proxies'] = proxies;
  saveYamlFile(cfgPath, cfg);
}

// ─── TUN ──────────────────────────────────────────────────────────────────────

/// 写/删顶层 tun 配置 — 移植自 Go: mihomo.go SetTunMihomo。
/// ant 的 TUN 是内核 NAT 系统栈，没有 stack；字段换成 mtu /
/// dns-hijack / auto-route / strict-route；address / auto-detect-interface
/// 交由内核自行处理，GUI 不再生成。
/// 启用时保留用户 tun 块中的其他字段，仅覆盖本 GUI 管理的字段。
void setTunAnt(String cfgPath, bool enable, int mtu, bool strictRoute) {
  final cfg = loadYamlFile(cfgPath);
  if (!enable) {
    cfg.remove('tun');
    saveYamlFile(cfgPath, cfg);
    return;
  }
  final existing = cfg['tun'];
  final tun = existing is Map ? cloneMap(existing) : <String, dynamic>{};
  var validMtu = mtu;
  if (validMtu <= 0) validMtu = 9000;
  tun['enable'] = true;
  tun['mtu'] = validMtu;
  tun['auto-route'] = true;
  tun['strict-route'] = strictRoute;
  if (!tun.containsKey('dns-hijack')) {
    tun['dns-hijack'] = <dynamic>['any:53'];
  }
  cfg['tun'] = tun;
  saveYamlFile(cfgPath, cfg);
}

/// 判断配置是否启用了 tun（tun.enable == true）— 移植自 Go: mihomo.go HasTunMihomo。
bool hasTunAnt(String cfgPath) {
  Map<String, dynamic> cfg;
  try {
    cfg = loadYamlFile(cfgPath);
  } on ParseException {
    return false;
  }
  final tun = cfg['tun'];
  if (tun is! Map) return false;
  return tun['enable'] == true;
}

// ─── 系统代理（mixed-port）─────────────────────────────────────────────────────

/// 写/删顶层 mixed-port — 移植自 Go: mihomo.go SetMixedInboundMihomo。
/// ant 没有 allow-lan：监听地址由全局 `bind-address` 控制（0.0.0.0 允许 LAN）。
void setMixedInboundAnt(
    String cfgPath, bool enable, String listen, int port) {
  final cfg = loadYamlFile(cfgPath);
  if (!enable) {
    cfg.remove('mixed-port');
    saveYamlFile(cfgPath, cfg);
    return;
  }
  var p = port;
  if (p <= 0) p = 2080;
  cfg['mixed-port'] = p;
  // bind-address 是 ant 的全局监听地址，只接受 127.0.0.1 / 0.0.0.0。
  cfg['bind-address'] = listen == '0.0.0.0' || listen == '::'
      ? '0.0.0.0'
      : '127.0.0.1';
  saveYamlFile(cfgPath, cfg);
}

// ─── Applied node detection ──────────────────────────────────────────────────

/// 找出配置中 name 为 "proxy" 的条目对应的节点 ID —
/// 移植自 Go: mihomo.go FindAppliedNodeIDMihomo。
/// 比较方式：把该条目与每个节点生成的 ant 条目规范化为 YAML 后逐一比对。
/// 找不到匹配返回 ""。
String findAppliedNodeIDAnt(String cfgPath, List<Node> nodes) {
  Map<String, dynamic> cfg;
  try {
    cfg = loadYamlFile(cfgPath);
  } on ParseException {
    return '';
  }
  Map<String, dynamic>? current;
  for (final pr in getProxies(cfg)) {
    if (pr is Map && pr['name'] == antProxyName) {
      current = cloneMap(pr);
      break;
    }
  }
  if (current == null) return '';
  final curData = _canonicalYaml(current);
  for (final n in nodes) {
    Map<String, dynamic> p;
    try {
      if (n.rawClashProxy != null) {
        p = clashProxyToAntProxy(n.rawClashProxy!);
      } else {
        p = nodeToAntProxy(n);
      }
    } on ParseException {
      continue;
    }
    p['name'] = antProxyName;
    if (_canonicalYaml(p) == curData) {
      return n.id;
    }
  }
  return '';
}

/// 把 map 递归按 key 排序后写为 YAML。Go yaml.v3 输出 map 时会对 key 排序
/// （Go map 本身无序），这里显式排序以保持与 Go 版一致的比较语义。
String _canonicalYaml(Map m) => _yamlWriter.write(_sortedDeep(m));

dynamic _sortedDeep(dynamic v) {
  if (v is Map) {
    final keys = v.keys.map((k) => k.toString()).toList()..sort();
    final out = <String, dynamic>{};
    for (final k in keys) {
      out[k] = _sortedDeep(v[k]);
    }
    return out;
  }
  if (v is List) return v.map(_sortedDeep).toList();
  return v;
}

// ─── Remove Node ──────────────────────────────────────────────────────────────

/// 移除 "proxy" proxies 条目 —
/// 移植自 Go: mihomo.go removeNodeFromMihomoConfig（取消应用）。
void removeNodeFromAntConfig(String cfgPath) {
  final cfg = loadYamlFile(cfgPath);
  final proxies = getProxies(cfg);
  final keptProxies = <dynamic>[];
  var removed = false;
  for (final pr in proxies) {
    if (pr is Map && pr['name'] == antProxyName) {
      removed = true;
      continue;
    }
    keptProxies.add(pr);
  }
  if (!removed) {
    return; // 未应用过节点 — 无事可做
  }
  cfg['proxies'] = keptProxies;
  saveYamlFile(cfgPath, cfg);
}
