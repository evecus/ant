/// 节点表单 schema — 数据驱动（对齐 ant-afa 的 NodeSchema 设计）。
///
/// 设计要点（与 afa 一致）：
///  * 表单字段由一张 [FieldSpec] 表描述（key/label/kind/group/hint/options/
///    required/showIf），UI 只遍历渲染，不含任何按协议的 switch-case。
///  * 每个 FieldSpec 自带 [FieldSpec.get] / [FieldSpec.set] 访问器，直接读写
///    强类型 Node 的 Config 对象——这是 GUI 与 afa 的唯一差异：afa 存储是
///    扁平 Map，GUI 是强类型模型，故用闭包桥接，避免重写解析/写出链路。
///  * 新增协议只需在 [NodeSchema.protocols] 增加一条 ProtocolDef（字段表 +
///    初始化器），表单渲染、校验、切换协议全部自动生效。
///  * key 采用 ant 的 YAML key（与 afa 完全一致），便于对照内核 config.rs。
library;

import 'node.dart';

// ── ant YAML 字段 key（与 afa/内核 config.rs 对齐）──────────────────────────
const kName = 'name';
const kServer = 'server';
const kPort = 'port';
const kUuid = 'uuid';
const kPassword = 'password';
const kUsername = 'username';
const kCipher = 'cipher';
const kAlterId = 'alter-id';
const kSni = 'sni';
const kAlpn = 'alpn';
const kSkipCert = 'skip-cert-verify';
const kFingerprint = 'fingerprint';
const kClientFp = 'client-fingerprint';
const kNetwork = 'network';
const kWsPath = 'ws-path';
const kWsHost = 'ws-host';
const kXhttpPath = 'xhttp-path';
const kXhttpHost = 'xhttp-host';
const kXhttpMode = 'xhttp-mode';
const kFlow = 'flow';
const kRealityPbk = 'reality-public-key';
const kRealitySid = 'reality-short-id';
const kObfs = 'obfs';
const kObfsPassword = 'obfs-password';
const kUp = 'up';
const kDown = 'down';
const kCongestion = 'congestion-control';
const kHeartbeat = 'heartbeat';
const kOverStream = 'over-stream';
const kZeroRtt = 'zero-rtt';
const kInitialMtu = 'initial-mtu';
const kMinMtu = 'min-mtu';
const kEch = 'ech';
const kSecurityMode = 'security-mode'; // UI 态：none | tls | reality，不写入内核配置
const kVersion = 'version';
const kPrivateKey = 'private-key';
const kPeerKey = 'peer-public-key';
const kPresharedKey = 'pre-shared-key';
const kLocalAddress = 'local-address';
const kMtu = 'mtu';
const kReserved = 'reserved';

// ── 表单分组 ────────────────────────────────────────────────────────────────
const gBasic = '基本';
const gAuth = '认证';
const gTransport = '传输';
const gTls = 'TLS';
const gAdv = '高级';

/// 字段类型：决定 UI 控件与值的序列化方式。
enum FieldKind { text, number, secret, toggle, select }

/// 单个表单字段的声明 + 访问器。
class FieldSpec {
  final String key;
  final String label;
  final FieldKind kind;
  final String group;
  final String hint;
  final List<String> options;
  final bool required;

  /// 条件显示：直接读取草稿节点判断（如 network=ws 才显示 ws-path）。
  final bool Function(Node node) showIf;

  /// 从草稿节点读值（字符串形式：bool→'true'/'false'，list→逗号分隔）。
  final String Function(Node node) get;

  /// 写值到草稿节点。
  final void Function(Node node, String value) set;

  FieldSpec({
    required this.key,
    required this.label,
    this.kind = FieldKind.text,
    this.group = gBasic,
    this.hint = '',
    this.options = const [],
    this.required = false,
    this.showIf = _always,
    required this.get,
    required this.set,
  });

  static bool _always(Node _) => true;
}

/// 协议定义：显示名 + 字段表 + 初始化器（新建/切换协议时调用）。
class ProtocolDef {
  final String key;
  final String display;
  final List<FieldSpec> fields;
  final void Function(Node node) init;

  ProtocolDef({
    required this.key,
    required this.display,
    required this.fields,
    required this.init,
  });
}

// ── 下拉选项 ────────────────────────────────────────────────────────────────
/// ant 内核只实现 tcp / ws / xhttp 三种传输（config.rs::network）。
const _networks = ['', 'tcp', 'ws', 'xhttp'];
/// 安全模式三选一：仅 vless 有 reality（内核 reality 为 vless 专属）。
const _securityModesVless = ['none', 'tls', 'reality'];
const _securityModesPlain = ['none', 'tls'];
const _ssCiphers = [
  'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
  '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305', 'none',
];
const _vmessCiphers = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'];
const _utlsFps = [
  '', 'chrome', 'firefox', 'safari', 'edge', 'ios', 'android', '360', 'qq',
  'random', 'none',
];
const _xhttpModes = ['', 'auto', 'stream-one', 'packet-up', 'stream-up'];
const _ccModes = ['cubic', 'bbr', 'new_reno'];

// ── 配置访问 helper（get 用 ?. ，set 用 ??= 惰性创建）────────────────────────
VMessConfig _vm(Node n) => n.vMess ??= VMessConfig();
VLESSConfig _vl(Node n) => n.vless ??= VLESSConfig();
TrojanConfig _trj(Node n) => n.trojan ??= TrojanConfig();
SSConfig _ss(Node n) => n.ss ??= SSConfig();
Hysteria2Config _hy2(Node n) => n.hysteria2 ??= Hysteria2Config();
TUICConfig _tuic(Node n) => n.tuic ??= TUICConfig();
SocksConfig _socks(Node n) => n.socks ??= SocksConfig();
AnyTLSConfig _any(Node n) => n.anytls ??= AnyTLSConfig();
WireGuardConfig _wg(Node n) => n.wireGuard ??= WireGuardConfig();
NaiveConfig _naive(Node n) => n.naive ??= NaiveConfig();
ShadowquicConfig _sq(Node n) => n.shadowquic ??= ShadowquicConfig();
SpectreConfig _spectre(Node n) => n.spectre ??= SpectreConfig();

String _listGet(List<String>? v) => v?.join(',') ?? '';
List<String>? _listSet(String v) {
  final parts = v.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty);
  return parts.isEmpty ? null : parts.toList();
}

List<int>? _intListSet(String v) {
  final parts = v.split(',').map((e) => int.tryParse(e.trim())).whereType<int>();
  return parts.isEmpty ? null : parts.toList();
}

String _networkOf(Node n) => switch (n.protocol) {
      'vmess' => n.vMess?.transport?.type ?? '',
      'vless' => n.vless?.transport?.type ?? '',
      'trojan' => n.trojan?.transport?.type ?? '',
      _ => '',
    };
bool _tlsOn(Node n) => switch (n.protocol) {
      'vmess' => n.vMess?.tls ?? false,
      'vless' => n.vless?.tls ?? false,
      _ => true,
    };

/// 当前安全模式（none / tls / reality）。
/// 优先读 UI 态字段；老节点（链接/订阅导入，securityMode 为空）按
/// tls + publicKey 派生——与 afa 的 securityMode() 一致。
String _securityModeOf(Node n) {
  final sm = n.securityMode;
  if (sm == 'none' || sm == 'tls' || sm == 'reality') return sm;
  if (!_tlsOn(n)) return 'none';
  if (n.protocol == 'vless' && (n.vless?.publicKey.isNotEmpty ?? false)) {
    return 'reality';
  }
  return 'tls';
}

/// 设置安全模式：写 UI 态 + 联动各 Config.tls / publicKey / shortId。
/// 选 none → 关 tls、清 reality；选 tls → 开 tls、清 reality；
/// 选 reality → 开 tls（publicKey 留给下面的 REALITY 字段填写）。
void _applySecurityMode(Node n, String mode) {
  n.securityMode = mode;
  switch (n.protocol) {
    case 'vmess':
      final c = _vm(n);
      c.tls = mode != 'none';
      if (mode != 'reality') { c.echConfig = ''; }
      break;
    case 'vless':
      final c = _vl(n);
      c.tls = mode != 'none';
      if (mode == 'none' || mode == 'tls') {
        c.publicKey = '';
        c.shortId = '';
      }
      // reality 与 ECH 互斥：切到 reality 清掉 ECH（uTLS 由内核忽略，字段隐藏即可）
      if (mode == 'reality') c.echConfig = '';
      // 不加密时 flow 无意义，清掉避免残留非法组合
      if (mode == 'none') c.flow = '';
      break;
  }
}

/// 有安全模式三选一的协议（其余协议内核强制 TLS，无选择）。
const _securityModeTypes = {'vless', 'vmess'};

/// showIf 片段：当前安全模式 == [mode]。
bool Function(Node) _modeIs(String mode) => (n) => _securityModeOf(n) == mode;
/// showIf 片段：已启用加密（tls 或 reality）。
bool _modeSecured(Node n) => _securityModeOf(n) != 'none';
/// showIf 片段：TCP + 已加密（vless flow 的内核约束）。
bool _flowAvailable(Node n) =>
    (_networkOf(n).isEmpty || _networkOf(n) == 'tcp') && _modeSecured(n);

TransportConfig? _transportPeek(Node n) => switch (n.protocol) {
      'vmess' => n.vMess?.transport,
      'vless' => n.vless?.transport,
      'trojan' => n.trojan?.transport,
      _ => null,
    };
TransportConfig _transportOf(Node n) => switch (n.protocol) {
      'vmess' => _vm(n).transport ??= TransportConfig(),
      'vless' => _vl(n).transport ??= TransportConfig(),
      'trojan' => _trj(n).transport ??= TransportConfig(),
      _ => TransportConfig(),
    };

// ── 字段片段构造 ────────────────────────────────────────────────────────────

List<FieldSpec> _basic() => [
      FieldSpec(
          key: kName,
          label: '节点名称',
          required: true,
          hint: '例如 HK-01',
          get: (n) => n.name,
          set: (n, v) => n.name = v),
      FieldSpec(
          key: kServer,
          label: '服务器地址',
          required: true,
          hint: '域名或 IP',
          get: (n) => n.address,
          set: (n, v) => n.address = v),
      FieldSpec(
          key: kPort,
          label: '端口',
          kind: FieldKind.number,
          required: true,
          hint: '443',
          get: (n) => n.port.toString(),
          set: (n, v) => n.port = int.tryParse(v) ?? 0),
    ];

List<FieldSpec> _auth(String type) => switch (type) {
      'vless' => [
          FieldSpec(
              key: kUuid, label: 'UUID', group: gAuth, required: true,
              get: (n) => _vl(n).uuid, set: (n, v) => _vl(n).uuid = v),
        ],
      'vmess' => [
          FieldSpec(
              key: kUuid, label: 'UUID', group: gAuth, required: true,
              get: (n) => _vm(n).uuid, set: (n, v) => _vm(n).uuid = v),
          FieldSpec(
              key: kCipher, label: '加密方式', kind: FieldKind.select,
              group: gAuth, options: _vmessCiphers,
              get: (n) => _vm(n).security, set: (n, v) => _vm(n).security = v),
          FieldSpec(
              key: kAlterId, label: 'alterId', kind: FieldKind.number,
              group: gAuth, hint: '0',
              get: (n) => _vm(n).alterId.toString(),
              set: (n, v) => _vm(n).alterId = int.tryParse(v) ?? 0),
        ],
      'trojan' => [
          FieldSpec(
              key: kPassword, label: '密码', kind: FieldKind.secret,
              group: gAuth, required: true,
              get: (n) => _trj(n).password, set: (n, v) => _trj(n).password = v),
        ],
      'ss' => [
          FieldSpec(
              key: kPassword, label: '密码', kind: FieldKind.secret,
              group: gAuth, required: true,
              get: (n) => _ss(n).password, set: (n, v) => _ss(n).password = v),
          FieldSpec(
              key: kCipher, label: '加密方式', kind: FieldKind.select,
              group: gAuth, options: _ssCiphers, required: true,
              get: (n) => _ss(n).method, set: (n, v) => _ss(n).method = v),
          FieldSpec(
              key: 'plugin', label: '插件 (plugin)', group: gAuth,
              hint: 'obfs-local / v2ray-plugin',
              get: (n) => _ss(n).plugin, set: (n, v) => _ss(n).plugin = v),
          FieldSpec(
              key: 'plugin-opts', label: '插件参数 (plugin_opts)', group: gAuth,
              hint: 'obfs=http;obfs-host=xxx',
              get: (n) => _ss(n).pluginOpts, set: (n, v) => _ss(n).pluginOpts = v),
        ],
      'hysteria2' => [
          FieldSpec(
              key: kPassword, label: '密码', kind: FieldKind.secret,
              group: gAuth, required: true,
              get: (n) => _hy2(n).password, set: (n, v) => _hy2(n).password = v),
        ],
      'tuic' => [
          FieldSpec(
              key: kUuid, label: 'UUID', group: gAuth, required: true,
              get: (n) => _tuic(n).uuid, set: (n, v) => _tuic(n).uuid = v),
          FieldSpec(
              key: kPassword, label: '密码', kind: FieldKind.secret,
              group: gAuth, required: true,
              get: (n) => _tuic(n).password, set: (n, v) => _tuic(n).password = v),
        ],
      'anytls' => [
          FieldSpec(
              key: kPassword, label: '密码', kind: FieldKind.secret,
              group: gAuth, required: true,
              get: (n) => _any(n).password, set: (n, v) => _any(n).password = v),
        ],
      'socks' => [
          FieldSpec(
              key: kUsername, label: '用户名', group: gAuth, hint: '可留空',
              get: (n) => _socks(n).username, set: (n, v) => _socks(n).username = v),
          FieldSpec(
              key: kPassword, label: '密码', kind: FieldKind.secret,
              group: gAuth, hint: '可留空',
              get: (n) => _socks(n).password, set: (n, v) => _socks(n).password = v),
        ],
      'naive' => [
          FieldSpec(
              key: kUsername, label: '用户名', group: gAuth, required: true,
              get: (n) => _naive(n).username, set: (n, v) => _naive(n).username = v),
          FieldSpec(
              key: kPassword, label: '密码', kind: FieldKind.secret,
              group: gAuth, required: true,
              get: (n) => _naive(n).password, set: (n, v) => _naive(n).password = v),
        ],
      'shadowquic' => [
          FieldSpec(
              key: kUsername, label: '用户名 (JLS user iv)', group: gAuth,
              required: true,
              get: (n) => _sq(n).username, set: (n, v) => _sq(n).username = v),
          FieldSpec(
              key: kPassword, label: '密码 (JLS password)',
              kind: FieldKind.secret, group: gAuth, required: true,
              get: (n) => _sq(n).password, set: (n, v) => _sq(n).password = v),
        ],
      'spectre' => [
          FieldSpec(
              key: kUsername, label: '用户名 (JLS user iv)', group: gAuth,
              required: true,
              get: (n) => _spectre(n).username,
              set: (n, v) => _spectre(n).username = v),
          FieldSpec(
              key: kPassword, label: '密码 (JLS password)',
              kind: FieldKind.secret, group: gAuth, required: true,
              get: (n) => _spectre(n).password,
              set: (n, v) => _spectre(n).password = v),
        ],
      'wireguard' => [
          FieldSpec(
              key: kPrivateKey, label: '本机私钥 (private_key)',
              kind: FieldKind.secret, group: gAuth,
              get: (n) => _wg(n).privateKey, set: (n, v) => _wg(n).privateKey = v),
          FieldSpec(
              key: kPeerKey, label: '对端公钥 (peer_public_key)', group: gAuth,
              get: (n) => _wg(n).publicKey, set: (n, v) => _wg(n).publicKey = v),
          FieldSpec(
              key: kPresharedKey, label: '预共享密钥',
              kind: FieldKind.secret, group: gAuth,
              get: (n) => _wg(n).presharedKey,
              set: (n, v) => _wg(n).presharedKey = v),
          FieldSpec(
              key: kLocalAddress, label: '本机地址 (逗号分隔)', group: gAuth,
              hint: '172.16.0.2/32',
              get: (n) => _listGet(_wg(n).localAddress),
              set: (n, v) => _wg(n).localAddress = _listSet(v)),
        ],
      _ => const <FieldSpec>[],
    };

List<FieldSpec> _transport() => [
      FieldSpec(
          key: kNetwork, label: '传输协议', kind: FieldKind.select,
          group: gTransport, options: _networks,
          get: (n) => _transportPeek(n)?.type ?? '',
          set: (n, v) => _transportOf(n).type = v),
      FieldSpec(
          key: kWsPath, label: 'WebSocket 路径', group: gTransport, hint: '/path',
          showIf: (n) => _networkOf(n) == 'ws',
          get: (n) => _transportPeek(n)?.path ?? '',
          set: (n, v) => _transportOf(n).path = v),
      FieldSpec(
          key: kWsHost, label: 'WebSocket Host', group: gTransport,
          showIf: (n) => _networkOf(n) == 'ws',
          get: (n) => _transportPeek(n)?.host ?? '',
          set: (n, v) => _transportOf(n).host = v),
      FieldSpec(
          key: kXhttpPath, label: 'XHTTP 路径', group: gTransport, hint: '/xhttp',
          showIf: (n) => _networkOf(n) == 'xhttp',
          get: (n) => _transportPeek(n)?.path ?? '',
          set: (n, v) => _transportOf(n).path = v),
      FieldSpec(
          key: kXhttpHost, label: 'XHTTP Host', group: gTransport,
          showIf: (n) => _networkOf(n) == 'xhttp',
          get: (n) => _transportPeek(n)?.host ?? '',
          set: (n, v) => _transportOf(n).host = v),
      FieldSpec(
          key: kXhttpMode, label: 'XHTTP 模式', kind: FieldKind.select,
          group: gTransport, options: _xhttpModes,
          showIf: (n) => _networkOf(n) == 'xhttp',
          get: (n) => _transportPeek(n)?.mode ?? '',
          set: (n, v) => _transportOf(n).mode = v),
    ];

// 标准 TLS 字段（sni + alpn + insecure + uTLS fingerprint + ECH），按协议分发。
List<FieldSpec> _tlsStandard(String type) {
  String Function(Node) sni;
  void Function(Node, String) setSni;
  String Function(Node) alpn;
  void Function(Node, String) setAlpn;
  String Function(Node) insecure;
  void Function(Node, String) setInsecure;
  String Function(Node) fingerprint;
  void Function(Node, String) setFingerprint;
  switch (type) {
    case 'trojan':
      sni = (n) => _trj(n).sni; setSni = (n, v) => _trj(n).sni = v;
      alpn = (n) => _listGet(_trj(n).alpn); setAlpn = (n, v) => _trj(n).alpn = _listSet(v);
      insecure = (n) => _trj(n).insecure.toString(); setInsecure = (n, v) => _trj(n).insecure = v == 'true';
      fingerprint = (n) => _trj(n).fingerprint; setFingerprint = (n, v) => _trj(n).fingerprint = v;
      break;
    case 'anytls':
      sni = (n) => _any(n).sni; setSni = (n, v) => _any(n).sni = v;
      alpn = (n) => _listGet(_any(n).alpn); setAlpn = (n, v) => _any(n).alpn = _listSet(v);
      insecure = (n) => _any(n).insecure.toString(); setInsecure = (n, v) => _any(n).insecure = v == 'true';
      fingerprint = (n) => _any(n).fingerprint; setFingerprint = (n, v) => _any(n).fingerprint = v;
      break;
    case 'hysteria2':
      sni = (n) => _hy2(n).sni; setSni = (n, v) => _hy2(n).sni = v;
      alpn = (n) => _listGet(_hy2(n).alpn); setAlpn = (n, v) => _hy2(n).alpn = _listSet(v);
      insecure = (n) => _hy2(n).insecure.toString(); setInsecure = (n, v) => _hy2(n).insecure = v == 'true';
      fingerprint = (n) => ''; setFingerprint = (n, v) {}; // Hy2 无 uTLS 字段
      break;
    case 'tuic':
      sni = (n) => _tuic(n).sni; setSni = (n, v) => _tuic(n).sni = v;
      alpn = (n) => _listGet(_tuic(n).alpn); setAlpn = (n, v) => _tuic(n).alpn = _listSet(v);
      insecure = (n) => _tuic(n).insecure.toString(); setInsecure = (n, v) => _tuic(n).insecure = v == 'true';
      fingerprint = (n) => ''; setFingerprint = (n, v) {}; // TUIC 无 uTLS 字段
      break;
    default:
      return [];
  }
  final list = <FieldSpec>[
    FieldSpec(key: kSni, label: 'SNI / 服务器名', group: gTls, get: sni, set: setSni),
    FieldSpec(key: kAlpn, label: 'ALPN', group: gTls, hint: '逗号分隔，如 h3,h2', get: alpn, set: setAlpn),
    FieldSpec(key: kSkipCert, label: '跳过证书验证', kind: FieldKind.toggle, group: gTls, get: insecure, set: setInsecure),
  ];
  if (type != 'hysteria2' && type != 'tuic') {
    list.add(FieldSpec(
        key: kFingerprint, label: 'uTLS 指纹 (fingerprint)', group: gTls,
        hint: 'chrome / firefox / safari / ios …',
        get: fingerprint, set: setFingerprint));
  }
  // vmess/vless 的 ECH 已在安全配置区（_tlsWithSecurityMode）提供，此处仅强制 TLS 协议。
  if (['trojan', 'hysteria2', 'anytls'].contains(type)) {
    String Function(Node) ech;
    void Function(Node, String) setEch;
    switch (type) {
      case 'trojan': ech = (n) => _trj(n).echConfig; setEch = (n, v) => _trj(n).echConfig = v; break;
      case 'hysteria2': ech = (n) => _hy2(n).echConfig; setEch = (n, v) => _hy2(n).echConfig = v; break;
      default: ech = (n) => _any(n).echConfig; setEch = (n, v) => _any(n).echConfig = v;
    }
    list.add(FieldSpec(key: kEch, label: 'ECH 配置 (ech.config)', group: gTls, get: ech, set: setEch));
  }
  return list;
}

/// security-mode 三选一驱动的安全配置区（仅 vless / vmess）。
/// 选中模式时联动写 tls / publicKey / shortId / echConfig；字段按模式显隐。
List<FieldSpec> _tlsWithSecurityMode(String type) {
  final vless = type == 'vless';
  final list = <FieldSpec>[
    FieldSpec(
        key: kSecurityMode,
        label: '安全配置',
        kind: FieldKind.select,
        group: gTls,
        hint: '不加密 / TLS 加密 / REALITY（仅 VLESS）',
        options: vless ? _securityModesVless : _securityModesPlain,
        get: _securityModeOf,
        set: _applySecurityMode),
    // SNI：tls 与 reality 都需要（reality 作 server-name）
    FieldSpec(
        key: kSni,
        label: 'SNI / 服务器名',
        group: gTls,
        showIf: _modeSecured,
        get: vless ? (n) => _vl(n).sni : (n) => _vm(n).sni,
        set: vless ? (n, v) => _vl(n).sni = v : (n, v) => _vm(n).sni = v),
  ];

  // 仅普通 TLS：ALPN / 跳过证书验证 / uTLS 指纹 / ECH（与 reality 互斥）
  void tlsField({
    required String key,
    required String label,
    FieldKind kind = FieldKind.text,
    String hint = '',
    required String Function(Node) get,
    required void Function(Node, String) set,
  }) {
    list.add(FieldSpec(
        key: key,
        label: label,
        kind: kind,
        group: gTls,
        hint: hint,
        showIf: _modeIs('tls'),
        get: get,
        set: set));
  }

  tlsField(
      key: kAlpn,
      label: 'ALPN',
      hint: '逗号分隔，如 h2,h3',
      get: vless ? (n) => _listGet(_vl(n).alpn) : (n) => _listGet(_vm(n).alpn),
      set: vless ? (n, v) => _vl(n).alpn = _listSet(v) : (n, v) => _vm(n).alpn = _listSet(v));
  tlsField(
      key: kSkipCert,
      label: '跳过证书验证',
      kind: FieldKind.toggle,
      get: vless
          ? (n) => _vl(n).insecure.toString()
          : (n) => _vm(n).insecure.toString(),
      set: vless
          ? (n, v) => _vl(n).insecure = v == 'true'
          : (n, v) => _vm(n).insecure = v == 'true');
  tlsField(
      key: kFingerprint,
      label: 'uTLS 指纹 (fingerprint)',
      hint: 'chrome / firefox / safari / ios …',
      get: vless ? (n) => _vl(n).fingerprint : (n) => _vm(n).fingerprint,
      set: vless
          ? (n, v) => _vl(n).fingerprint = v
          : (n, v) => _vm(n).fingerprint = v);
  tlsField(
      key: kEch,
      label: 'ECH 配置 (ech.config)',
      hint: 'REALITY 下不可用',
      get: vless ? (n) => _vl(n).echConfig : (n) => _vm(n).echConfig,
      set: vless
          ? (n, v) => _vl(n).echConfig = v
          : (n, v) => _vm(n).echConfig = v);

  // REALITY 专有：仅 vless，仅 reality 模式显示，pbk 必填
  if (vless) {
    list.add(FieldSpec(
        key: kRealityPbk,
        label: 'REALITY 公钥 pbk',
        group: gTls,
        required: true,
        showIf: _modeIs('reality'),
        get: (n) => _vl(n).publicKey,
        set: (n, v) => _vl(n).publicKey = v));
    list.add(FieldSpec(
        key: kRealitySid,
        label: 'REALITY shortId',
        group: gTls,
        hint: '可选',
        showIf: _modeIs('reality'),
        get: (n) => _vl(n).shortId,
        set: (n, v) => _vl(n).shortId = v));
    // flow：仅 TCP + tls/reality 可用（内核 vless.rs::apply_flow 校验）
    list.add(FieldSpec(
        key: kFlow,
        label: 'Flow',
        kind: FieldKind.select,
        group: gTls,
        hint: '仅 TCP + TLS/REALITY 可用',
        options: const ['', 'xtls-rprx-vision'],
        showIf: _flowAvailable,
        get: (n) => _vl(n).flow,
        set: (n, v) => _vl(n).flow = v));
  }
  return list;
}

List<FieldSpec> _tlsVmess() => _tlsWithSecurityMode('vmess');
List<FieldSpec> _tlsVless() => _tlsWithSecurityMode('vless');

List<FieldSpec> _tlsFor(String type) => _tlsStandard(type);

List<FieldSpec> _tlsNaive() => [
      FieldSpec(key: kSni, label: 'SNI / 服务器名', group: gTls,
          get: (n) => _naive(n).sni, set: (n, v) => _naive(n).sni = v),
      FieldSpec(key: kSkipCert, label: '跳过证书验证', kind: FieldKind.toggle, group: gTls,
          get: (n) => _naive(n).insecure.toString(),
          set: (n, v) => _naive(n).insecure = v == 'true'),
      FieldSpec(key: kClientFp, label: 'uTLS 指纹', kind: FieldKind.select, group: gTls,
          options: _utlsFps,
          get: (n) => _naive(n).clientFingerprint,
          set: (n, v) => _naive(n).clientFingerprint = v),
      FieldSpec(key: kFingerprint, label: '证书指纹 pinSHA256', group: gTls,
          hint: 'base64 SHA256',
          get: (n) => _naive(n).fingerprint,
          set: (n, v) => _naive(n).fingerprint = v),
    ];

List<FieldSpec> _tlsShadowquic() => [
      FieldSpec(key: kSni, label: 'SNI（须匹配 jls-upstream 域名）', group: gTls,
          required: true, hint: '必填，不能是 IP',
          get: (n) => _sq(n).sni, set: (n, v) => _sq(n).sni = v),
      FieldSpec(key: kAlpn, label: 'ALPN', group: gTls, hint: '逗号分隔，默认 h3',
          get: (n) => _listGet(_sq(n).alpn), set: (n, v) => _sq(n).alpn = _listSet(v)),
      FieldSpec(key: kSkipCert, label: '跳过证书验证', kind: FieldKind.toggle, group: gTls,
          get: (n) => _sq(n).insecure.toString(),
          set: (n, v) => _sq(n).insecure = v == 'true'),
    ];

List<FieldSpec> _tlsSpectre() => [
      FieldSpec(key: kSni, label: 'SNI（须匹配伪装域名）', group: gTls,
          required: true, hint: '必填，不能是 IP',
          get: (n) => _spectre(n).sni, set: (n, v) => _spectre(n).sni = v),
    ];

List<FieldSpec> _advanced(String type) => switch (type) {
      // vless 的 flow / reality 字段已移入安全配置区（_tlsWithSecurityMode），
      // 由 security-mode 联动显隐；高级区不再重复。
      'vless' => const <FieldSpec>[],
      'hysteria2' => [
          FieldSpec(key: kObfs, label: '混淆类型', kind: FieldKind.select, group: gAdv,
              options: const ['', 'salamander'],
              get: (n) => _hy2(n).obfs, set: (n, v) => _hy2(n).obfs = v),
          FieldSpec(key: kObfsPassword, label: '混淆密码', kind: FieldKind.secret, group: gAdv,
              hint: '内核暂未启用混淆，仅供兼容',
              showIf: (n) => _hy2(n).obfs.isNotEmpty,
              get: (n) => _hy2(n).obfsPassword, set: (n, v) => _hy2(n).obfsPassword = v),
          FieldSpec(key: kUp, label: '上行带宽 up (Mbps)', group: gAdv, hint: '如 100 Mbps',
              get: (n) => _hy2(n).upMbps.toString(),
              set: (n, v) => _hy2(n).upMbps = int.tryParse(v) ?? 0),
          FieldSpec(key: kDown, label: '下行带宽 down (Mbps)', group: gAdv, hint: '如 300 Mbps',
              get: (n) => _hy2(n).downMbps.toString(),
              set: (n, v) => _hy2(n).downMbps = int.tryParse(v) ?? 0),
        ],
      'tuic' => [
          FieldSpec(key: kCongestion, label: '拥塞控制', kind: FieldKind.select, group: gAdv,
              options: _ccModes,
              get: (n) => _tuic(n).congestionControl,
              set: (n, v) => _tuic(n).congestionControl = v),
        ],
      'shadowquic' => [
          FieldSpec(key: kCongestion, label: '拥塞控制', kind: FieldKind.select, group: gAdv,
              options: _ccModes, hint: '默认 bbr',
              get: (n) => _sq(n).congestionControl,
              set: (n, v) => _sq(n).congestionControl = v),
          FieldSpec(key: kHeartbeat, label: 'QUIC keep-alive', group: gAdv,
              hint: '如 10s；off / 0 关闭',
              get: (n) => _sq(n).heartbeat, set: (n, v) => _sq(n).heartbeat = v),
          FieldSpec(key: kOverStream, label: 'UDP 走 QUIC stream', kind: FieldKind.toggle,
              group: gAdv, hint: '默认关（datagram）；代理 HTTP/3 时保持关闭',
              get: (n) => _sq(n).overStream.toString(),
              set: (n, v) => _sq(n).overStream = v == 'true'),
          FieldSpec(key: kZeroRtt, label: '0-RTT 握手', kind: FieldKind.toggle, group: gAdv,
              get: (n) => _sq(n).zeroRtt.toString(),
              set: (n, v) => _sq(n).zeroRtt = v == 'true'),
          FieldSpec(key: kInitialMtu, label: '初始 MTU', kind: FieldKind.number, group: gAdv,
              hint: '默认 1300，≥1200',
              get: (n) => _sq(n).initialMtu.toString(),
              set: (n, v) => _sq(n).initialMtu = int.tryParse(v) ?? 0),
          FieldSpec(key: kMinMtu, label: '最小 MTU', kind: FieldKind.number, group: gAdv,
              hint: '默认 1290，≥1200',
              get: (n) => _sq(n).minMtu.toString(),
              set: (n, v) => _sq(n).minMtu = int.tryParse(v) ?? 0),
        ],
      'spectre' => [
          FieldSpec(key: kUp, label: '上行速率 up', group: gAdv,
              hint: '如 50mbps / 12500000（字节/秒）',
              get: (n) => _spectre(n).up, set: (n, v) => _spectre(n).up = v),
          FieldSpec(key: kDown, label: '下行速率 down', group: gAdv, hint: '如 200mbps / 25000000',
              get: (n) => _spectre(n).down, set: (n, v) => _spectre(n).down = v),
        ],
      'socks' => [
          FieldSpec(key: kVersion, label: '版本', kind: FieldKind.select, group: gAdv,
              options: const ['5', '4a'],
              get: (n) => _socks(n).version, set: (n, v) => _socks(n).version = v),
        ],
      'wireguard' => [
          FieldSpec(key: kMtu, label: 'MTU', kind: FieldKind.number, group: gAdv,
              get: (n) => _wg(n).mtu.toString(),
              set: (n, v) => _wg(n).mtu = int.tryParse(v) ?? 0),
          FieldSpec(key: kReserved, label: '保留字段 (reserved, 逗号分隔)', group: gAdv,
              hint: '1,2,3',
              get: (n) => _wg(n).reserved?.join(',') ?? '',
              set: (n, v) => _wg(n).reserved = _intListSet(v)),
        ],
      _ => const <FieldSpec>[],
    };

// ── 初始化器（内核默认值）────────────────────────────────────────────────────
void _initVmess(Node n) {
  final c = _vm(n);
  if (n.securityMode.isEmpty) n.securityMode = 'tls';
  c.tls = n.securityMode != 'none';
  if (c.security.isEmpty) c.security = 'auto';
  c.transport = TransportConfig(type: 'tcp');
}
void _initVless(Node n) {
  final c = _vl(n);
  if (n.securityMode.isEmpty) n.securityMode = 'tls';
  c.tls = n.securityMode != 'none';
  c.transport = TransportConfig(type: 'tcp');
}
void _initSs(Node n) {
  final c = _ss(n);
  if (c.method.isEmpty) c.method = 'aes-256-gcm';
}
void _initTrojan(Node n) {
  _trj(n).transport = TransportConfig(type: 'tcp');
}
void _initHy2(Node n) { _hy2(n); }
void _initTuic(Node n) {
  final c = _tuic(n);
  if (c.congestionControl.isEmpty) c.congestionControl = 'cubic';
}
void _initAny(Node n) { _any(n); }
void _initSocks(Node n) {
  final c = _socks(n);
  if (c.version.isEmpty) c.version = '5';
  if (n.port == 0) n.port = 1080;
}
void _initWg(Node n) { _wg(n); }
void _initNaive(Node n) {
  final c = _naive(n);
  if (c.clientFingerprint.isEmpty) c.clientFingerprint = 'chrome';
}
void _initSq(Node n) {
  final c = _sq(n);
  if (c.alpn == null || c.alpn!.isEmpty) c.alpn = ['h3'];
  if (c.congestionControl.isEmpty) c.congestionControl = 'bbr';
  c.zeroRtt = true;
  c.overStream = false;
}
void _initSpectre(Node n) { _spectre(n); }

/// 切换协议时保留的通用字段 key。
const _keepOnTypeChange = {
  kName, kServer, kPort, kUuid, kPassword, kUsername, kCipher, kAlterId,
  kSni, kAlpn, kSkipCert, kFingerprint, kClientFp, kNetwork, kWsPath, kWsHost,
  kXhttpPath, kXhttpHost, kXhttpMode, kFlow, kRealityPbk, kRealitySid, kEch,
  kSecurityMode,
};

/// 协议 schema 注册表 —— 新增/删减协议只改这里。
class NodeSchema {
  NodeSchema._();

  static const groupOrder = [gBasic, gAuth, gTransport, gTls, gAdv];

  static final List<ProtocolDef> protocols = [
    ProtocolDef(key: 'vmess', display: 'VMess', init: _initVmess, fields: [
      ..._basic(), ..._auth('vmess'), ..._transport(), ..._tlsVmess(),
    ]),
    ProtocolDef(key: 'vless', display: 'VLESS', init: _initVless, fields: [
      ..._basic(), ..._auth('vless'), ..._transport(), ..._tlsVless(),
      ..._advanced('vless'),
    ]),
    ProtocolDef(key: 'ss', display: 'SS', init: _initSs, fields: [
      ..._basic(), ..._auth('ss'),
    ]),
    ProtocolDef(key: 'trojan', display: 'Trojan', init: _initTrojan, fields: [
      ..._basic(), ..._auth('trojan'), ..._transport(), ..._tlsFor('trojan'),
    ]),
    ProtocolDef(key: 'hysteria2', display: 'Hy2', init: _initHy2, fields: [
      ..._basic(), ..._auth('hysteria2'), ..._tlsFor('hysteria2'),
      ..._advanced('hysteria2'),
    ]),
    ProtocolDef(key: 'tuic', display: 'TUIC', init: _initTuic, fields: [
      ..._basic(), ..._auth('tuic'), ..._tlsFor('tuic'), ..._advanced('tuic'),
    ]),
    ProtocolDef(key: 'anytls', display: 'AnyTLS', init: _initAny, fields: [
      ..._basic(), ..._auth('anytls'), ..._tlsFor('anytls'),
    ]),
    ProtocolDef(key: 'socks', display: 'SOCKS', init: _initSocks, fields: [
      ..._basic(), ..._auth('socks'), ..._advanced('socks'),
    ]),
    ProtocolDef(key: 'wireguard', display: 'WG', init: _initWg, fields: [
      ..._basic(), ..._auth('wireguard'), ..._advanced('wireguard'),
    ]),
    ProtocolDef(key: 'naive', display: 'Naive', init: _initNaive, fields: [
      ..._basic(), ..._auth('naive'), ..._tlsNaive(),
    ]),
    ProtocolDef(key: 'shadowquic', display: 'SQ', init: _initSq, fields: [
      ..._basic(), ..._auth('shadowquic'), ..._tlsShadowquic(),
      ..._advanced('shadowquic'),
    ]),
    ProtocolDef(key: 'spectre', display: 'Spectre', init: _initSpectre, fields: [
      ..._basic(), ..._auth('spectre'), ..._tlsSpectre(), ..._advanced('spectre'),
    ]),
  ];

  static ProtocolDef? def(String type) {
    for (final d in protocols) {
      if (d.key == type) return d;
    }
    return null;
  }

  static String display(String type) => def(type)?.display ?? type.toUpperCase();
  static bool supports(String type) => def(type) != null;
  static List<String> get keys => protocols.map((p) => p.key).toList();

  /// 该协议的完整字段表。
  static List<FieldSpec> fieldsFor(String type) => def(type)?.fields ?? _basic();

  /// 新建 / 切换协议时初始化 Config 与内核默认值。
  static void init(Node node, String type) {
    node.protocol = type;
    def(type)?.init(node);
  }

  /// 切换协议：保留通用字段值，重建目标协议 Config 默认值。
  static void changeType(Node draft, String from, String to) {
    final kept = <String, String>{};
    for (final spec in fieldsFor(from)) {
      if (_keepOnTypeChange.contains(spec.key) && spec.showIf(draft)) {
        kept[spec.key] = spec.get(draft);
      }
    }
    _clearConfigs(draft);
    init(draft, to);
    // 目标协议不支持 reality 时降级：vmess / 强制 TLS 协议无 reality。
    final keptMode = kept[kSecurityMode];
    if (keptMode == 'reality' && to != 'vless') {
      kept[kSecurityMode] = 'tls';
    }
    for (final spec in fieldsFor(to)) {
      final v = kept[spec.key];
      if (v != null) spec.set(draft, v);
    }
  }

  static void _clearConfigs(Node n) {
    n.vMess = null;
    n.vless = null;
    n.trojan = null;
    n.ss = null;
    n.hysteria2 = null;
    n.tuic = null;
    n.socks = null;
    n.anytls = null;
    n.wireGuard = null;
    n.naive = null;
    n.shadowquic = null;
    n.spectre = null;
  }

  /// 校验，返回错误文案；null 表示通过。
  static String? validate(Node node) {
    final type = node.protocol;
    if (!supports(type)) return null; // raw 协议仅编辑基本信息
    if (node.name.trim().isEmpty) return '请填写节点名称';
    if (node.address.trim().isEmpty) return '请填写服务器地址';
    if (node.port < 1 || node.port > 65535) return '端口需为 1 – 65535 的数字';
    for (final spec in fieldsFor(type)) {
      if (spec.required && spec.showIf(node) && spec.get(node).trim().isEmpty) {
        return '请填写「${spec.label}」';
      }
    }
    // ── 互斥关系校验（fail-fast，对齐内核 config.rs）──────────────────────
    if (_securityModeTypes.contains(type)) {
      final mode = _securityModeOf(node);
      final network = _networkOf(node);
      if (mode == 'reality' && type != 'vless') {
        return '仅 VLESS 支持 REALITY';
      }
      // REALITY 仅 TCP（xhttp 下仅 auto/stream-one）
      if (mode == 'reality' && network == 'ws') {
        return 'REALITY 不支持 WebSocket 传输，请改用 TCP';
      }
      if (mode == 'reality' && network == 'xhttp') {
        final xm = node.vless?.transport?.mode ?? '';
        if (xm.isNotEmpty && xm != 'auto' && xm != 'stream-one') {
          return 'REALITY 下 XHTTP 模式仅支持 auto / stream-one';
        }
      }
      // flow 仅在 TCP + tls/reality 下可用
      final flow = type == 'vless' ? node.vless?.flow ?? '' : '';
      if (flow.isNotEmpty && !_flowAvailable(node)) {
        return 'Flow 仅在 TCP + TLS/REALITY 下可用';
      }
    }
    return null;
  }
}
