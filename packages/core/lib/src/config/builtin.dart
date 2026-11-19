/// 内置路由模式配置合成 — 移植自 Go: backend/config/builtin.go。
///
/// 单内核版：参照 v2rayN 的三种路由模板生成 **ant YAML** 配置，直接合成到
/// run 目录，不修改用户 configs/ 中的配置文件。上游工程的全部流程逻辑保留：
/// 三种模板的规则顺序 / 规则集引用 / 规则文件前置校验 / DNS 分流 /
/// fake-ip / TUN / 系统代理 / clash-api（ant 的 api 面板）/ 持久化缓存。
///
///   - bypass    绕过大陆（v2rayN "Whitelist"）：国内/私网直连，其余走代理，final=proxy
///   - blacklist GFW列表（v2rayN "Blacklist"）：被墙域名/海外服务 IP 走代理，其余直连，final=DIRECT
///   - global    全局代理（v2rayN "Global"）：仅私网直连，其余走代理，final=proxy
///
/// 规则引用本地二进制规则集：run/rules/ant/`<tag>`.ars（ant 的 ARST 格式，
/// 由 evecus/ant 的 ruleset 分支提供，随源码内置）。
/// DNS 由 `dns.rule-follow-route: true` 复用 `route:` 规则决定上游：
/// direct 出站用 direct-nameserver、节点出站用 proxy-nameserver、
/// REJECT 回 NOERROR 空应答 —— 与上游工程的 nameserver-policy 分流等价。
library;

import 'dart:io';

import 'package:yaml_writer/yaml_writer.dart';

import '../export/ant_write.dart'
    show antProxyName, clashProxyToAntProxy, nodeToAntProxy;
import '../models/node.dart';
import '../parsing/common.dart';
import 'editor.dart' show buildAntTunInbound;
import 'settings.dart';

/// DNS 模式常量（与 Settings.Builtin.DNSMode 对应）。
const String dnsModeRedirHost = 'redir-host';
const String dnsModeFakeIP = 'fake-ip';

/// 内置规则集所在子目录 / 扩展名（ant 的 .ars 二进制规则集）。
const String antRuleDirName = 'ant';
const String antRuleExt = 'ars';

/// BuiltinPrefix 内置配置在下拉列表中的显示前缀。
const String builtinPrefix = '内置配置：';

/// 内置模式 → 显示名（顺序即下拉顺序）。
const List<(String, String)> _builtinModeNames = [
  (modeBypass, '绕过大陆'),
  (modeBlacklist, 'GFW列表'),
  (modeGlobal, '全局代理'),
];

/// IsBuiltinMode 判断是否为内置路由模式。
bool isBuiltinMode(String mode) =>
    mode == modeBypass || mode == modeBlacklist || mode == modeGlobal;

/// BuiltinDisplayName 返回内置模式的下拉显示名（如 "内置配置：绕过大陆"）；
/// 非内置模式返回 null。
String? builtinDisplayName(String mode) {
  for (final (m, name) in _builtinModeNames) {
    if (m == mode) return builtinPrefix + name;
  }
  return null;
}

/// ParseBuiltinName 把下拉项解析为路由模式（仅接受 "内置配置：xxx" 形式）；
/// 失败返回 null。
String? parseBuiltinName(String name) {
  for (final (m, n) in _builtinModeNames) {
    if (name == builtinPrefix + n) return m;
  }
  return null;
}

/// BuiltinDisplayNames 返回全部内置配置的显示名（供 GetConfigFiles 追加）。
List<String> builtinDisplayNames() =>
    [for (final (_, n) in _builtinModeNames) builtinPrefix + n];

// ─── 规则文件 ────────────────────────────────────────────────────────────────

/// antRuleFiles 各模式需要的规则集基础名（不含扩展名）。
/// geosite-* → behavior=domain；geoip-* → behavior=ip。
/// fake-ip 模式追加 geosite-fakeipfilter（fakeip 白名单域名走直连 DNS）。
List<String> antRuleFiles(String mode, String dnsMode) {
  final Map<String, List<String>> files = {
    modeBypass: [
      'geosite-private', 'geoip-private', 'geosite-cn', 'geosite-google',
      'geoip-cn',
    ],
    modeBlacklist: [
      'geosite-private', 'geoip-private', //
      'geosite-google', 'geosite-gfw', 'geosite-greatfire', //
      'geoip-facebook', 'geoip-fastly', 'geoip-google', //
      'geoip-netflix', 'geoip-telegram', 'geoip-twitter', //
    ],
    modeGlobal: ['geosite-private', 'geoip-private'],
  };
  var result = files[mode] ?? const <String>[];
  if (dnsMode == dnsModeFakeIP) {
    result = [...result, 'geosite-fakeipfilter'];
  }
  return result;
}

/// builtinRuleFilesAll 全部内置模式规则文件的并集（供 ensureRuleFiles 释放，
/// 宁多勿缺）。
List<String> builtinRuleFilesAll(String mode, String dnsMode) =>
    antRuleFiles(mode, dnsMode);

/// isGeositeTag 判断规则 tag 是否为 geosite 类（决定 rule-provider 的 behavior）。
bool isGeositeTag(String tag) => tag.length > 7 && tag.startsWith('geosite');

/// 规则集文件的绝对路径。
String antRulePath(String rulesDir, String tag) =>
    _pathJoin([rulesDir, antRuleDirName, '$tag.$antRuleExt']);

/// CheckRuleFiles 校验内置模式所需的规则文件是否齐全（rulesDir/ant 下）。
/// 抛出的 [ParseException] 一次性列出全部缺失文件。
/// [extraRuleFiles] 用于追加用户在设置里自定义的 fakeip-filter 规则集名。
void checkRuleFiles(String mode, String dnsMode, String rulesDir,
    {List<String>? extraRuleFiles}) {
  final seen = <String>{};
  final files = <String>[];
  for (final tag in antRuleFiles(mode, dnsMode)) {
    if (seen.add(tag)) files.add(tag);
  }
  // 用户自定义 fakeip-filter 规则集仅在 fake-ip 模式被 dns 段引用；
  // redir-host 模式既不生成 provider 也不要求文件存在（对齐上游原版）。
  if (dnsMode == dnsModeFakeIP) {
    for (final tag in extraRuleFiles ?? const <String>[]) {
      final t = tag.trim();
      if (t.isNotEmpty && seen.add(t)) files.add(t);
    }
  }
  if (files.isEmpty) return;
  final missing = <String>[];
  for (final f in files) {
    if (!File(antRulePath(rulesDir, f)).existsSync()) {
      missing.add('run/rules/$antRuleDirName/$f.$antRuleExt');
    }
  }
  if (missing.isNotEmpty) {
    throw ParseException(
        '缺少规则文件:\n  ${missing.join('\n  ')}\n'
        '请将对应 .ars 二进制规则集放入上述目录'
        '（内置规则集来自 evecus/ant 的 ruleset 分支；也可用 '
        '`ant ruleset-convert -i in.json -o out.ars` 自行编译）');
  }
}

// ─── 私网直连 ────────────────────────────────────────────────────────────────
// ant：geosite-private / geoip-private 规则集（private.ars）。

/// antIPRule IP 类规则集的 no-resolve 策略：
/// 仅 geoip-cn 不加（域名需解析为 IP 以命中国内 IP 段），其余 IP 规则集都加
/// （域名连接跳过 IP 匹配，避免不必要的 DNS 解析）。
String _antIPRule(String tag, String target) {
  if (tag == 'geoip-cn') {
    return 'RULE-SET,$tag,$target';
  }
  return 'RULE-SET,$tag,$target,no-resolve';
}

// ─── 配置生成入口 ─────────────────────────────────────────────────────────────

/// BuiltinOptions 内置配置生成参数（运行时开关状态 + Settings.Builtin）。
class BuiltinOptions {
  String mode;
  bool tunEnabled;
  int tunMTU;
  bool tunStrictRoute;
  bool proxyEnabled; // 系统代理开关（决定 mixed-port 是否写入）
  String proxyListen;
  int proxyPort;
  String rulesDir; // run/rules 绝对路径
  String uiDir; // 保留字段：ant 内置 /ui 面板，无需 external-ui 目录
  String cachePath; // cache-file 绝对路径（run/cache.db）
  BuiltinSettings? cfg; // 可配置参数（null 时用 DefaultBuiltin）

  BuiltinOptions({
    this.mode = '',
    this.tunEnabled = false,
    this.tunMTU = 0,
    this.tunStrictRoute = false,
    this.proxyEnabled = false,
    this.proxyListen = '',
    this.proxyPort = 0,
    this.rulesDir = '',
    this.uiDir = '',
    this.cachePath = '',
    this.cfg,
  });

  /// 返回可配置参数（null 兜底为默认值）。
  BuiltinSettings settings() => cfg ?? defaultBuiltin();
}

/// BuildBuiltinConfig 生成内置模式的 ant YAML 配置文本。
/// 非内置模式或无节点抛 [ParseException]。
String buildBuiltinConfig(BuiltinOptions opts, Node? n) {
  if (!isBuiltinMode(opts.mode)) {
    throw ParseException('非内置路由模式: ${opts.mode}');
  }
  if (n == null) {
    throw ParseException('内置路由模式需要先应用一个节点');
  }
  return _buildBuiltinAnt(opts, n);
}

/// mapLogLevel UI 日志等级 → ant 等级（ant 用 warn，不认 warning）。
String _mapLogLevel(String level) => level == 'warning' ? 'warn' : level;

// ─── 序列化 ──────────────────────────────────────────────────────────────────

/// 生成 YAML 配置（用 yaml_writer 包编码；int/bool 保持原生类型，
/// 与 Go yaml.v3 一致；Dart LinkedHashMap 保持插入序）。
String _marshalYAML(Map<String, dynamic> cfg) {
  // YamlWriter.config()：仅在必要时加引号（默认构造会强制给所有字符串加引号）。
  return YamlWriter.config().write(cfg);
}

/// filepath.Join 对应实现（Windows 用 \，其余用 /）。
String _pathJoin(List<String> parts) {
  final sep = Platform.isWindows ? r'\' : '/';
  return parts.where((p) => p.isNotEmpty).join(sep);
}

// ─── ant ─────────────────────────────────────────────────────────────────────

/// buildBuiltinAnt 合成 ant YAML 配置（与 mihomo 版逐条对齐）。
String _buildBuiltinAnt(BuiltinOptions opts, Node n) {
  final b = opts.settings();

  // proxy 条目：RawClashProxy 无损回写优先，统一经 ant 字段归一化
  Map<String, dynamic> proxy;
  if (n.rawClashProxy != null) {
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

  final cfg = <String, dynamic>{
    'log-level': _mapLogLevel(b.logLevel),
    // 顶层 IPv6 开关（入站 + 规则集 + DNS）
    'ipv6': b.ipv6,
    // TLS SNI / HTTP Host / QUIC 嗅探（对应 mihomo 的 sniffer）
    'sniff': true,
    // 全局监听地址（ant 只接受 127.0.0.1 / 0.0.0.0）
    'bind-address': _antBindAddress(opts.proxyListen),
    // 常驻记录活跃连接（对应 clash-api 的 connection 页）
    'api-connection-record': true,
    // 持久化缓存（对应 sing-box cache_file：DNS / FakeIP / select 状态）
    'cache': true,
    'cache-file': opts.cachePath,
    'proxies': <dynamic>[proxy],
    'dns': _buildAntDNS(opts),
  };
  // ant API 面板（/ui + JSON 接口）：关闭时完全不生成
  if (!b.apiDisabled) {
    cfg['api'] = '${b.api.listen}:${b.api.port}';
    cfg['api-secret'] = b.api.secret;
  }
  _appendAntMixed(cfg, opts);
  if (opts.tunEnabled) {
    cfg['tun'] = buildAntTunInbound(opts.tunMTU, opts.tunStrictRoute);
  }
  _appendAntRoute(cfg, opts);
  return _marshalYAML(cfg);
}

/// ant 的 bind-address 只接受 127.0.0.1 / 0.0.0.0；
/// 旧配置里的 :: / * 一律收敛为 0.0.0.0（LAN），空值用 127.0.0.1。
String _antBindAddress(String listen) {
  final s = listen.trim();
  if (s.isEmpty || s == 'localhost' || s == '127.0.0.1') return '127.0.0.1';
  return '0.0.0.0';
}

/// DNS 类型默认端口。
int _dnsDefaultPort(String t) {
  switch (t) {
    case 'tls':
      return 853;
    case 'https':
      return 443;
    default: // udp / tcp
      return 53;
  }
}

/// 把 DNSServer 设置转成 ant 的 nameserver URL。
/// udp/tcp/tls → `scheme://host:port`；https → `https://host[:port]/path`。
String _dnsUrl(DNSServer ds) {
  final type = ds.type.trim().isEmpty ? 'udp' : ds.type.trim().toLowerCase();
  final host = ds.address.trim();
  final port = ds.port > 0 ? ds.port : _dnsDefaultPort(type);
  if (type == 'https') {
    var path = ds.path.trim();
    if (path.isEmpty) path = '/dns-query';
    if (!path.startsWith('/')) path = '/$path';
    final authority = port == 443 ? host : '$host:$port';
    return 'https://$authority$path';
  }
  return '$type://$host:$port';
}

/// bootstrap 上游（必须是纯 IP）。补 :53，已带端口则不重复。
String _bootstrapNS(String resolver) {
  var s = resolver.trim();
  if (s.startsWith('[')) return s; // IPv6 字面量原样交给内核校验
  if (s.contains('://')) s = s.split('://').last;
  if (!s.contains(':')) s = '$s:53';
  return s;
}

/// buildAntDNS 生成 DNS 段（redir-host / fake-ip）。
/// ant 的 `rule-follow-route: true` 直接复用 `route:` 规则：
///   - 绕过大陆：国内/私网域名 → DIRECT → direct-nameserver，其余 → proxy-nameserver；
///   - GFW列表：被墙域名 → proxy（节点）→ proxy-nameserver，其余 → direct-nameserver；
///   - 全局：全部 → proxy-nameserver。
/// fake-ip 模式：白名单规则集内域名真实解析，其余 A/AAAA 返回 fakeip。
Map<String, dynamic> _buildAntDNS(BuiltinOptions opts) {
  final b = opts.settings();
  // Windows 无 tproxy 重定向到 DNS 端口，省略 `port`：ant 仅经 route-hijack /
  // TUN dns-hijack 应答（DnsConfig.port 是 Option<u16>，省略即不监听）。
  final dns = <String, dynamic>{
    'enable': true,
    'ipv6': b.ipv6,
    'default-nameserver': _bootstrapNS(b.resolverDNS),
    'rule-follow-route': true,
    'direct-nameserver': _dnsUrl(b.directDNS),
    'proxy-nameserver': _dnsUrl(b.proxyDNS),
    // 路由层劫持 53 端口 / 嗅探到的 DNS 查询（对应 TUN dns-hijack）
    'route-hijack': true,
    'mode': b.dnsMode == dnsModeFakeIP ? 'fakeip' : dnsModeRedirHost,
  };
  if (b.dnsMode == dnsModeFakeIP) {
    dns['fakeip-range'] = b.fakeipRange.trim();
    final filter = (b.fakeipFilter ?? const <String>[])
        .map((s) => s.trim())
        .where((s) => s.isNotEmpty)
        .toList();
    if (filter.isNotEmpty) {
      dns['fakeip-filter'] = filter;
      dns['fakeip-filter-mode'] = 'blacklist';
    }
    if (b.ipv6) dns['fakeip6-range'] = 'fc00::/18';
  }
  return dns;
}

/// appendAntMixed 按系统代理开关写 mixed-port（对齐 SetMixedInboundAnt）。
void _appendAntMixed(Map<String, dynamic> cfg, BuiltinOptions opts) {
  if (!opts.proxyEnabled) return;
  var port = opts.proxyPort;
  if (port <= 0) port = 2080;
  cfg['mixed-port'] = port;
}

/// appendAntRoute 写 rule-providers（file 型 .ars 二进制）与 route
/// （对齐 sing-box / mihomo 版的规则顺序）。
/// ant 的 route 只支持 RULE-SET / DOMAIN-* / IP-CIDR / SRC-IP-CIDR / MATCH，
/// 因此原 mihomo 版的 `AND,((NETWORK,udp),(DST-PORT,443)),REJECT`（阻断 QUIC）
/// 无法表达 —— ant 没有端口/网络匹配规则，此处不生成（其余规则逐条保留）。
void _appendAntRoute(Map<String, dynamic> cfg, BuiltinOptions opts) {
  final dnsMode = opts.settings().dnsMode;
  // rule-providers：仅生成当前模式引用的条目
  final providers = <String, dynamic>{};
  for (final tag in antRuleFiles(opts.mode, dnsMode)) {
    providers[tag] = <String, dynamic>{
      'type': 'file',
      'behavior': isGeositeTag(tag) ? 'domain' : 'ip',
      'format': 'ars',
      'path': antRulePath(opts.rulesDir, tag),
    };
  }
  // fakeip-filter 可能引用用户自定义规则集名（仅 fake-ip 模式生成）。
  if (dnsMode == dnsModeFakeIP) {
    for (final tag in opts.settings().fakeipFilter ?? const <String>[]) {
      final t = tag.trim();
      if (t.isEmpty || providers.containsKey(t)) continue;
      providers[t] = <String, dynamic>{
        'type': 'file',
        'behavior': 'domain',
        'format': 'ars',
        'path': antRulePath(opts.rulesDir, t),
      };
    }
  }
  if (providers.isNotEmpty) {
    cfg['rule-providers'] = providers;
  }

  // 私网直连：private 规则集（geosite 匹配局域网域名，geoip 匹配私网 IP）
  final privateDirect = <String>[
    'RULE-SET,geosite-private,DIRECT',
    _antIPRule('geoip-private', 'DIRECT'),
  ];

  final rules = <String>[];
  switch (opts.mode) {
    case modeBypass:
      rules.addAll([
        'RULE-SET,geosite-google,$antProxyName',
      ]);
      rules.addAll(privateDirect);
      rules.addAll([
        'RULE-SET,geosite-cn,DIRECT',
        _antIPRule('geoip-cn', 'DIRECT'),
        'MATCH,$antProxyName',
      ]);
    case modeBlacklist:
      rules.addAll([
        'DOMAIN,api.ip.sb,$antProxyName',
        'RULE-SET,geosite-google,$antProxyName',
      ]);
      rules.addAll(privateDirect);
      for (final tag in [
        'geoip-facebook', 'geoip-fastly', 'geoip-google', //
        'geoip-netflix', 'geoip-telegram', 'geoip-twitter', //
      ]) {
        rules.add(_antIPRule(tag, antProxyName));
      }
      rules.addAll([
        'RULE-SET,geosite-gfw,$antProxyName',
        'RULE-SET,geosite-greatfire,$antProxyName',
        'MATCH,DIRECT',
      ]);
    case modeGlobal:
      rules.addAll(privateDirect);
      rules.add('MATCH,$antProxyName');
  }
  cfg['route'] = rules;
}
