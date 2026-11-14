/// 持久化设置 — 移植自 Go: backend/config/manager.go（Settings / DNSServer /
/// ClashAPIConfig / BuiltinSettings 类与 Defaults/Normalize/Validate/applyDefaults）。
///
/// 单内核版：去掉内核选择与各内核各自的配置文件记忆，其余流程
/// （默认值 / 归一化 / 校验 / JSON 往返 / 旧 settings.json 兼容）完整保留。
/// BuiltinSettings 的字段按 ant 的配置语义重新解释，每一项都真实写入生成的
/// ant 配置（见 builtin.dart），不存在只保存不生效的死字段。
library;

import 'dart:io';

import '../parsing/common.dart';

// ── 常量 ─────────────────────────────────────────────────────────────────────

/// 唯一内核标识（用于引擎 label / 界面文案，不再有内核选择分支）。
const String coreAnt = 'ant';

/// 配置文件扩展名（ant 为 mihomo 风格 YAML）。
const List<String> antConfigExts = ['.yaml', '.yml'];

/// 路由模式常量（移植自 Go: builtin.go，与 Settings.RoutingMode 对应）。
const String modeCustom = 'custom';
const String modeBypass = 'bypass';
const String modeBlacklist = 'blacklist';
const String modeGlobal = 'global';

// ── 配置数据类 ───────────────────────────────────────────────────────────────

/// DNS 服务器（类型/地址/端口/路径）。
/// ant 的 nameserver 是 URL：udp/tcp/tls 为 `scheme://host:port`，
/// https 为 `https://host[:port]/path`。地址必填；端口为零值时按类型补默认
/// 端口（udp/tcp 53、tls 853、https 443），路径仅 https 类型写入。
class DNSServer {
  String type; // udp | tcp | tls | https
  String address; // IP 或域名
  int port; // 0 = 按类型默认端口
  String path; // https 类型的 URL 路径

  DNSServer({
    this.type = '',
    this.address = '',
    this.port = 0,
    this.path = '',
  });

  Map<String, dynamic> toJson() => {
        'type': type,
        'address': address,
        'port': port,
        'path': path,
      };

  static DNSServer fromJson(Map<String, dynamic> j) => DNSServer(
        type: j['type'] as String? ?? '',
        address: j['address'] as String? ?? '',
        port: (j['port'] as num?)?.toInt() ?? 0,
        path: j['path'] as String? ?? '',
      );
}

/// ant API 面板监听配置：`api: "<listen>:<port>"` + `api-secret: <secret>`。
class ClashAPIConfig {
  String listen; // 127.0.0.1 | 0.0.0.0
  int port;
  String secret;

  ClashAPIConfig({
    this.listen = '',
    this.port = 0,
    this.secret = '',
  });

  Map<String, dynamic> toJson() => {
        'listen': listen,
        'port': port,
        'secret': secret,
      };

  static ClashAPIConfig fromJson(Map<String, dynamic> j) => ClashAPIConfig(
        listen: j['listen'] as String? ?? '',
        port: (j['port'] as num?)?.toInt() ?? 0,
        secret: j['secret'] as String? ?? '',
      );
}

/// BuiltinSettings 内置路由模式可配置参数（settings.json 的 builtin 段）。
/// 默认值即此前写死的值，旧 settings.json 缺段时自动补默认。
/// apiDisabled 用反转语义——零值 false 即默认启用，无需缺字段探测。
class BuiltinSettings {
  String logLevel; // debug | info | warning | error（ant warning→warn）
  String dnsMode; // redir-host | fake-ip（ant dns.mode 为 redir-host | fakeip）
  bool ipv6;
  bool apiDisabled; // true 时完全不生成 api / api-secret 配置
  String resolverDNS; // dns.default-nameserver（bootstrap，必须纯 IP）
  ClashAPIConfig api; // ant api 面板
  DNSServer directDNS; // dns.direct-nameserver
  DNSServer proxyDNS; // dns.proxy-nameserver
  List<String>? fakeipFilter; // dns.fakeip-filter（规则集名，最多两项）
  String fakeipRange; // dns.fakeip-range

  BuiltinSettings({
    this.logLevel = '',
    this.dnsMode = '',
    this.ipv6 = false,
    this.apiDisabled = false,
    this.resolverDNS = '',
    ClashAPIConfig? api,
    DNSServer? directDNS,
    DNSServer? proxyDNS,
    this.fakeipFilter,
    this.fakeipRange = '',
  })  : api = api ?? ClashAPIConfig(),
        directDNS = directDNS ?? DNSServer(),
        proxyDNS = proxyDNS ?? DNSServer();

  Map<String, dynamic> toJson() => {
        'log_level': logLevel,
        'dns_mode': dnsMode,
        'ipv6': ipv6,
        'api_disabled': apiDisabled,
        'resolver_dns': resolverDNS,
        'api': api.toJson(),
        'direct_dns': directDNS.toJson(),
        'proxy_dns': proxyDNS.toJson(),
        // 旧版字段（clash_api_disabled / clash_api / singbox_direct /
        // singbox_proxy / resolver_dns_backup）不再写出；fromJson 仍兼容读入。
        'fakeip_filter': fakeipFilter,
        'fakeip_range': fakeipRange,
      };

  /// 兼容上游旧版 settings.json：旧键作为新键的 fallback。
  static BuiltinSettings fromJson(Map<String, dynamic> j) => BuiltinSettings(
        logLevel: j['log_level'] as String? ?? '',
        dnsMode: j['dns_mode'] as String? ?? '',
        ipv6: j['ipv6'] as bool? ?? false,
        apiDisabled: (j['api_disabled'] as bool?) ??
            (j['clash_api_disabled'] as bool?) ??
            false,
        resolverDNS: j['resolver_dns'] as String? ?? '',
        api: _apiFromJson(j),
        directDNS: _dnsFromJson(j['direct_dns'] ?? j['singbox_direct']),
        proxyDNS: _dnsFromJson(j['proxy_dns'] ?? j['singbox_proxy']),
        fakeipFilter: (j['fakeip_filter'] as List?)?.cast<String>(),
        fakeipRange: j['fakeip_range'] as String? ?? '',
      );

  static ClashAPIConfig _apiFromJson(Map<String, dynamic> j) {
    final raw = j['api'] ?? j['clash_api'];
    if (raw == null) return ClashAPIConfig();
    return ClashAPIConfig.fromJson((raw as Map).cast<String, dynamic>());
  }

  static DNSServer _dnsFromJson(dynamic raw) {
    if (raw == null) return DNSServer();
    return DNSServer.fromJson((raw as Map).cast<String, dynamic>());
  }
}

/// DefaultBuiltin 返回内置路由参数的默认设置（与写死版本行为一致）。
/// 移植自 Go: manager.go DefaultBuiltin()。
BuiltinSettings defaultBuiltin() => BuiltinSettings(
      logLevel: 'warning',
      dnsMode: 'redir-host',
      resolverDNS: '223.5.5.5',
      api: ClashAPIConfig(listen: '127.0.0.1', port: 9090),
      directDNS: DNSServer(type: 'udp', address: '223.5.5.5', port: 53),
      proxyDNS: DNSServer(
          type: 'https', address: '1.1.1.1', port: 443, path: '/dns-query'),
      fakeipFilter: ['geosite-fakeipfilter'],
      fakeipRange: '198.18.0.0/15',
    );

// ── Settings ─────────────────────────────────────────────────────────────────

/// Settings 持久化设置。新增字段必须同时在 applyDefaults 里给默认值，
/// 否则旧 settings.json 升级后会出现零值。
class Settings {
  // 当前选中的配置文件名（configs 目录下，非完整路径）。
  // 旧版字段 config_path 保留并直接读取回显；单内核无需按内核分别记忆。
  String configPath;

  List<String>? subscriptions;

  // 当前应用的节点 ID（切配置文件后据此重新应用）
  String appliedNodeID;

  // 路由模式：custom（跟随用户配置文件）| bypass（内置:绕过大陆）|
  // blacklist（内置:GFW列表）| global（内置:全局代理）。
  // 内置模式下配置由程序模板合成，直接写入 run 目录，不碰用户 configs 文件。
  String routingMode;

  // TUN 开关持久化状态（内置模式据此生成 tun；custom 模式与配置文件保持同步）。
  bool tunEnabled;

  // 系统代理
  String proxyListen; // mixed inbound 监听地址（127.0.0.1 / 0.0.0.0）
  int proxyPort; // mixed inbound 监听端口
  bool exitDisableProxy; // 退出程序时自动关闭系统代理

  // 底部栏三个开关的期望状态持久化（TUN 复用上面的 tunEnabled）：
  // 记录"用户上一次主动设置的开关状态"，下次启动按此自动恢复，
  // 与 exitDisableProxy 等运行期自动动作互不覆盖对方语义。
  bool sysProxyDesired; // 系统代理：用户上一次主动开启/关闭的状态
  bool coreRunningDesired; // 启动核心：用户上一次主动启动/停止的状态

  // TUN 模式（ant 为内核 NAT 系统栈，无 stack 选项；MTU / strict-route 对应
  // tun.mtu / tun.strict-route）
  int tunMTU; // TUN 网卡 MTU
  bool tunStrictRoute; // tun.strict-route

  // 订阅
  String subUserAgent; // 拉取订阅时的 User-Agent
  int subTimeoutSec; // 拉取订阅超时秒数

  // 日志与界面
  int logMaxLines; // 运行日志最大保留行数
  int pollIntervalMs; // 前端状态轮询间隔(毫秒)

  // 启动
  bool autoStart; // 开机自启动
  bool silentStart; // 自启动时静默：不显示主窗口，仅托盘图标

  // 内置路由模式的可配置参数（合成 run 配置时使用，custom 模式不涉及）
  BuiltinSettings builtin;

  // 记录 JSON 文件中 bool 字段是否真实存在（不序列化），
  // 用于区分"旧文件缺字段"与"用户显式关闭"。
  bool exitDisableProxySet;
  bool tunStrictRouteSet;

  Settings({
    this.configPath = '',
    this.subscriptions,
    this.appliedNodeID = '',
    this.routingMode = '',
    this.tunEnabled = false,
    this.proxyListen = '',
    this.proxyPort = 0,
    this.exitDisableProxy = false,
    this.sysProxyDesired = false,
    this.coreRunningDesired = false,
    this.tunMTU = 0,
    this.tunStrictRoute = false,
    this.subUserAgent = '',
    this.subTimeoutSec = 0,
    this.logMaxLines = 0,
    this.pollIntervalMs = 0,
    this.autoStart = false,
    this.silentStart = false,
    BuiltinSettings? builtin,
    this.exitDisableProxySet = false,
    this.tunStrictRouteSet = false,
  }) : builtin = builtin ?? BuiltinSettings();

  /// 从 JSON 反序列化（对应 Go 的 settingsAlias unmarshal + presence 回填）。
  /// 兼容旧版：core / config_path_singbox / config_path_mihomo 被忽略，
  /// 旧 config_path_mihomo 作为 config_path 的 fallback（YAML 配置）。
  static Settings fromJson(Map<String, dynamic> j) => Settings(
        configPath: (j['config_path'] as String? ?? '').isNotEmpty
            ? j['config_path'] as String
            : (j['config_path_mihomo'] as String? ?? ''),
        subscriptions: (j['subscriptions'] as List?)?.cast<String>(),
        appliedNodeID: j['applied_node_id'] as String? ?? '',
        routingMode: j['routing_mode'] as String? ?? '',
        tunEnabled: j['tun_enabled'] as bool? ?? false,
        proxyListen: j['proxy_listen'] as String? ?? '',
        proxyPort: (j['proxy_port'] as num?)?.toInt() ?? 0,
        exitDisableProxy: j['exit_disable_proxy'] as bool? ?? false,
        sysProxyDesired: j['sys_proxy_desired'] as bool? ?? false,
        coreRunningDesired: j['core_running_desired'] as bool? ?? false,
        tunMTU: (j['tun_mtu'] as num?)?.toInt() ?? 0,
        tunStrictRoute: j['tun_strict_route'] as bool? ?? false,
        subUserAgent: j['sub_user_agent'] as String? ?? '',
        subTimeoutSec: (j['sub_timeout_sec'] as num?)?.toInt() ?? 0,
        logMaxLines: (j['log_max_lines'] as num?)?.toInt() ?? 0,
        pollIntervalMs: (j['poll_interval_ms'] as num?)?.toInt() ?? 0,
        autoStart: j['auto_start'] as bool? ?? false,
        silentStart: j['silent_start'] as bool? ?? false,
        builtin: j['builtin'] == null
            ? BuiltinSettings()
            : BuiltinSettings.fromJson(
                (j['builtin'] as Map).cast<String, dynamic>()),
        exitDisableProxySet: j.containsKey('exit_disable_proxy'),
        tunStrictRouteSet: j.containsKey('tun_strict_route'),
      );

  /// 序列化为 JSON map（字段名与 Go tag 一致，含 omitempty 语义；
  /// set 标志不序列化，与 Go unexported 字段行为一致）。
  Map<String, dynamic> toJson() => {
        'config_path': configPath,
        'subscriptions': subscriptions,
        if (appliedNodeID.isNotEmpty) 'applied_node_id': appliedNodeID,
        'routing_mode': routingMode,
        'tun_enabled': tunEnabled,
        'proxy_listen': proxyListen,
        'proxy_port': proxyPort,
        'exit_disable_proxy': exitDisableProxy,
        'sys_proxy_desired': sysProxyDesired,
        'core_running_desired': coreRunningDesired,
        'tun_mtu': tunMTU,
        'tun_strict_route': tunStrictRoute,
        'sub_user_agent': subUserAgent,
        'sub_timeout_sec': subTimeoutSec,
        'log_max_lines': logMaxLines,
        'poll_interval_ms': pollIntervalMs,
        'auto_start': autoStart,
        'silent_start': silentStart,
        'builtin': builtin.toJson(),
      };

  /// Defaults 返回一份全新默认设置（含内置路由参数——
  /// 此前全新安装漏填 Builtin 段，导致设置界面显示全 0）。
  static Settings defaults() => Settings(
        routingMode: modeCustom,
        subscriptions: [],
        proxyListen: '127.0.0.1',
        proxyPort: 2080,
        exitDisableProxy: true,
        tunMTU: 9000,
        tunStrictRoute: true,
        subUserAgent: 'clash.meta',
        subTimeoutSec: 30,
        logMaxLines: 500,
        pollIntervalMs: 2000,
        builtin: defaultBuiltin(),
      );

  /// Normalize 为零值字段补默认值（供外部包在保存前调用）。
  void normalize() {
    applyDefaults();
    // fakeip-filter 去掉空白项
    builtin.fakeipFilter = _trimNonEmpty(builtin.fakeipFilter);
  }

  /// applyDefaults 为零值字段补默认值（兼容旧版 settings.json）。
  void applyDefaults() {
    final def = Settings.defaults();
    if (routingMode.isEmpty) routingMode = modeCustom;
    subscriptions ??= [];
    if (proxyListen.trim().isEmpty) proxyListen = def.proxyListen;
    // 旧配置可能是 ::（mihomo/sing-box 的 IPv6 监听写法），ant 只接受
    // 0.0.0.0 / 127.0.0.1，收敛到 127.0.0.1。
    if (proxyListen.trim() == '::' || proxyListen.trim() == '*') {
      proxyListen = def.proxyListen;
    }
    if (proxyPort <= 0) proxyPort = def.proxyPort;
    if (tunMTU <= 0) tunMTU = def.tunMTU;
    if (subUserAgent.trim().isEmpty) subUserAgent = def.subUserAgent;
    if (subTimeoutSec <= 0) subTimeoutSec = def.subTimeoutSec;
    if (logMaxLines <= 0) logMaxLines = def.logMaxLines;
    if (pollIntervalMs <= 0) pollIntervalMs = def.pollIntervalMs;
    // 内置路由参数逐字段补默认
    final b = builtin;
    final d = defaultBuiltin();
    if (b.logLevel.isEmpty) b.logLevel = d.logLevel;
    if (b.dnsMode.isEmpty) b.dnsMode = d.dnsMode;
    if (b.resolverDNS.isEmpty) b.resolverDNS = d.resolverDNS;
    if (b.api.listen.isEmpty) b.api.listen = d.api.listen;
    if (b.api.port == 0) b.api.port = d.api.port;
    if (b.directDNS.type.isEmpty && b.directDNS.address.isEmpty) {
      b.directDNS = d.directDNS;
    }
    if (b.proxyDNS.type.isEmpty && b.proxyDNS.address.isEmpty) {
      b.proxyDNS = d.proxyDNS;
    }
    if (b.fakeipFilter == null || b.fakeipFilter!.isEmpty) {
      b.fakeipFilter = d.fakeipFilter;
    }
    if (b.fakeipRange.isEmpty) b.fakeipRange = d.fakeipRange;
    // bool 零值为 false，但 exitDisableProxy / tunStrictRoute 的默认值是 true。
    // 旧文件中不存在这两个字段时无法区分"显式关闭"与"未设置"，
    // 用 fromJson 记录的存在标志判断。
    if (!exitDisableProxySet) exitDisableProxy = def.exitDisableProxy;
    if (!tunStrictRouteSet) tunStrictRoute = def.tunStrictRoute;
  }

  /// ActiveConfigPath 返回当前记忆的配置文件名（configs 目录下，非完整路径）。
  String activeConfigPath() => configPath;

  /// SetConfigPath 记录当前配置文件名（单内核，无需按内核分别记忆）。
  void setConfigPath(String name) {
    configPath = name;
  }

  /// Validate 校验设置合法性（保存前调用）。
  /// 失败抛 [ParseException]（对应 Go 的 error 返回值）。
  void validate() {
    if (routingMode != modeCustom &&
        routingMode != modeBypass &&
        routingMode != modeBlacklist &&
        routingMode != modeGlobal) {
      throw ParseException('路由模式必须是 custom / bypass / blacklist / global');
    }
    if (proxyListen.trim().isEmpty) {
      throw ParseException('监听地址不能为空');
    }
    if (proxyListen.trim() != '127.0.0.1' && proxyListen.trim() != '0.0.0.0') {
      throw ParseException('监听地址必须是 127.0.0.1 / 0.0.0.0');
    }
    if (proxyPort < 1 || proxyPort > 65535) {
      throw ParseException('代理端口必须在 1-65535 之间');
    }
    if (tunMTU < 576 || tunMTU > 65535) {
      throw ParseException('TUN MTU 必须在 576-65535 之间');
    }
    if (subUserAgent.trim().isEmpty) {
      throw ParseException('订阅 User-Agent 不能为空');
    }
    if (subTimeoutSec < 1 || subTimeoutSec > 600) {
      throw ParseException('订阅超时必须在 1-600 秒之间');
    }
    if (logMaxLines < 50 || logMaxLines > 100000) {
      throw ParseException('日志行数必须在 50-100000 之间');
    }
    if (pollIntervalMs < 500 || pollIntervalMs > 60000) {
      throw ParseException('轮询间隔必须在 500-60000 毫秒之间');
    }
    // 内置路由参数
    if (builtin.logLevel != 'debug' &&
        builtin.logLevel != 'info' &&
        builtin.logLevel != 'warning' &&
        builtin.logLevel != 'error') {
      throw ParseException('日志等级必须是 debug / info / warning / error');
    }
    if (builtin.dnsMode != 'redir-host' && builtin.dnsMode != 'fake-ip') {
      throw ParseException('DNS 模式必须是 redir-host / fake-ip');
    }
    if (!_isIP(builtin.resolverDNS.trim())) {
      throw ParseException('解析 DNS 服务器必须是 IP 地址');
    }
    if (builtin.api.listen != '127.0.0.1' &&
        builtin.api.listen != '0.0.0.0') {
      throw ParseException('API 面板监听地址必须是 127.0.0.1 / 0.0.0.0');
    }
    if (builtin.api.port < 1 || builtin.api.port > 65535) {
      throw ParseException('API 面板端口必须在 1-65535 之间');
    }
    for (final ds in [
      ('直连 DNS', builtin.directDNS),
      ('代理 DNS', builtin.proxyDNS),
    ]) {
      final name = ds.$1;
      final svr = ds.$2;
      if (svr.type != 'udp' &&
          svr.type != 'tcp' &&
          svr.type != 'tls' &&
          svr.type != 'https') {
        throw ParseException('$name 类型必须是 udp / tcp / tls / https');
      }
      if (svr.address.trim().isEmpty) {
        throw ParseException('$name 地址不能为空');
      }
      if (svr.port < 0 || svr.port > 65535) {
        throw ParseException('$name 端口必须在 0-65535 之间');
      }
    }
    for (final v in builtin.fakeipFilter ?? const <String>[]) {
      if (v.trim().isEmpty) {
        throw ParseException('fakeip-filter 规则集名不能为空');
      }
    }
    if (builtin.fakeipRange.trim().isEmpty) {
      throw ParseException('fakeip-range 不能为空');
    }
  }
}

/// trimNonEmpty 去掉空白项（对应 Go 的 trimNonEmpty）。
List<String>? _trimNonEmpty(List<String>? ss) {
  if (ss == null) return null;
  final out = <String>[];
  for (final v in ss) {
    final t = v.trim();
    if (t.isNotEmpty) out.add(t);
  }
  return out;
}

/// Go 的 net.ParseIP 对应实现：IPv4 / IPv6 字面量校验。
bool _isIP(String s) {
  if (s.isEmpty) return false;
  return InternetAddress.tryParse(s) != null;
}
