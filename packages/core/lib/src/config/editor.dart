/// ant 配置文件增量编辑入口 — 移植自 Go: backend/config/editor.go。
///
/// 单内核版：去掉 sing-box JSON 分支（loadJson/saveJson/出站构造），
/// 全部入口保留一一对应，只是统一转发到 ant_edit.dart 的 YAML 实现。
/// Go 版 editor.go 的每个公开函数在这里都有同名等价物：
///   ApplyNodeToConfig / SetTun / SetMixedInbound / HasTunInbound /
///   FindAppliedNodeID / RemoveNodeFromConfig / BuildTunInbound。
library;

import '../models/node.dart';
import '../parsing/common.dart';
import 'ant_edit.dart';

export 'ant_edit.dart'
    show
        loadYamlFile,
        saveYamlFile,
        cloneMap,
        getProxies,
        hasTunAnt;

// ─── Apply Node ───────────────────────────────────────────────────────────────

/// 把节点写入配置文件（替换/追加 name 为 "proxy" 的 proxies 条目，
/// route 规则直接按节点名引用）— 移植自 Go: editor.go ApplyNodeToConfig。
void applyNodeToConfig(String cfgPath, Node n) {
  applyNodeToAntConfig(cfgPath, n);
}

// ─── TUN ──────────────────────────────────────────────────────────────────────

/// 构造 ant 的 `tun:` 段（内置配置合成与 custom 增量编辑共用）。
/// ant 为内核 NAT 系统栈，无 stack 选项；address / auto-detect-interface
/// 交由内核自行处理，GUI 不再生成。
Map<String, dynamic> buildAntTunInbound(
  int mtu,
  bool strictRoute,
) {
  var validMtu = mtu;
  if (validMtu <= 0) validMtu = 9000;
  return <String, dynamic>{
    'enable': true,
    'mtu': validMtu,
    'dns-hijack': <dynamic>['any:53'],
    'auto-route': true,
    'strict-route': strictRoute,
  };
}

/// 写/删顶层 tun 配置 — 移植自 Go: editor.go SetTun。
void setTun(String cfgPath, bool enable, int mtu, bool strictRoute) {
  setTunAnt(cfgPath, enable, mtu, strictRoute);
}

/// 判断配置是否启用了 tun（tun.enable == true）—
/// 移植自 Go: editor.go HasTunInbound。
bool hasTunInbound(String cfgPath) => hasTunAnt(cfgPath);

// ─── 系统代理（mixed-port）─────────────────────────────────────────────────────

/// 写/删顶层 mixed-port — 移植自 Go: editor.go SetMixedInbound。
void setMixedInbound(
    String cfgPath, bool enable, String listen, int port) {
  setMixedInboundAnt(cfgPath, enable, listen, port);
}

// ─── Applied node detection ──────────────────────────────────────────────────

/// 找出配置中 name 为 "proxy" 的条目对应的节点 ID —
/// 移植自 Go: editor.go FindAppliedNodeID。
String findAppliedNodeId(String cfgPath, List<Node> nodes) =>
    findAppliedNodeIDAnt(cfgPath, nodes);

// ─── Remove Node ──────────────────────────────────────────────────────────────

/// 移除 "proxy" proxies 条目 —
/// 移植自 Go: editor.go RemoveNodeFromConfig（取消应用）。
void removeNodeFromConfig(String cfgPath) {
  removeNodeFromAntConfig(cfgPath);
}

/// 兼容旧调用：读取配置根节点（ant 为 YAML）。
/// 解析失败抛 [ParseException]，与 Go loadYAML 一致。
Map<String, dynamic> loadConfig(String path) => loadYamlFile(path);

/// 兼容旧调用：原子写回配置根节点（ant 为 YAML）。
void saveConfig(String path, Map<String, dynamic> cfg) =>
    saveYamlFile(path, cfg);
