/// 节点编辑弹窗 — 按协议字段编辑（对齐原 EditNodeModal.jsx）：
/// vmess/vless/trojan/ss/hysteria/hysteria2/tuic/socks/http/anytls/ssr/wireguard
/// 的常用字段 + 传输层（ws/http/grpc/httpupgrade/quic/xhttp）+ TLS/Reality。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

import '../providers.dart';

/// 支持结构化编辑的协议。
const _supported = [
  'vmess', 'vless', 'trojan', 'ss', 'hysteria', 'hysteria2',
  'tuic', 'socks', 'http', 'anytls', 'ssr', 'wireguard',
];

/// 「添加节点」菜单的协议顺序（对齐 v2rayN，含上游工程同样支持的
/// hysteria/ssr）。
const addableProtocols = [
  'vmess', 'vless', 'ss', 'trojan', 'hysteria2', 'hysteria',
  'wireguard', 'socks', 'http', 'tuic', 'anytls', 'ssr',
];

const _transportTypes = [
  ('', '无 (TCP / RAW)'),
  ('ws', 'ws (WebSocket)'),
  ('http', 'http (h2/h3)'),
  ('grpc', 'grpc'),
  ('httpupgrade', 'httpupgrade'),
  ('quic', 'quic'),
  ('xhttp', 'xhttp'),
];

const _securityTypes = [
  'auto', 'none', 'zero', 'aes-128-gcm', 'chacha20-poly1305',
];
const _flowTypes = [('', '(无)'), ('xtls-rprx-vision', 'xtls-rprx-vision')];
const _ccTypes = ['cubic', 'new_reno', 'bbr'];
const _udpModes = ['native', 'quic'];
const _xhttpModes = ['auto', 'packet-up', 'stream-up', 'stream-one'];

class EditNodeModal extends ConsumerStatefulWidget {
  final Node node;

  /// true = 新建模式：保存时入库新增（自动生成 id/归组），
  /// false = 编辑模式：按原 id 更新。
  final bool isNew;

  const EditNodeModal({super.key, required this.node, this.isNew = false});

  @override
  ConsumerState<EditNodeModal> createState() => _EditNodeModalState();
}

class _EditNodeModalState extends ConsumerState<EditNodeModal> {
  late final Node _n = widget.node;
  late final String _proto = _n.protocol;
  bool get _supportedProto => _supported.contains(_proto);
  bool get _hasTransport => ['vmess', 'vless', 'trojan'].contains(_proto);
  bool get _hasTlsSection =>
      ['vmess', 'vless', 'http', 'anytls'].contains(_proto);
  bool get _hasFixedTls =>
      ['hysteria', 'hysteria2', 'trojan', 'tuic'].contains(_proto);

  final Map<String, TextEditingController> _c = {};
  final Map<String, Object> _st = {};
  bool _saving = false;
  String? _error;

  TextEditingController _ctl(String key, String initial) =>
      _c.putIfAbsent(key, () => TextEditingController(text: initial));

  Object _state(String key, Object? initial) =>
      _st.putIfAbsent(key, () => initial!);

  String _text(String key) => _c[key]?.text ?? '';

  @override
  void dispose() {
    for (final c in _c.values) {
      c.dispose();
    }
    super.dispose();
  }

  TransportConfig? _transportOf() {
    if (!_hasTransport) return null;
    return switch (_proto) {
      'vmess' => _n.vMess?.transport,
      'vless' => _n.vless?.transport,
      'trojan' => _n.trojan?.transport,
      _ => null,
    };
  }

  // ─── 保存 ─────────────────────────────────────────────────────────────────

  Future<void> _save() async {
    if (_saving) return;
    final name = _text('name').trim();
    final address = _text('address').trim();
    final port = int.tryParse(_text('port')) ?? 0;
    if (name.isEmpty) return _setError('请输入节点名称');
    if (address.isEmpty) return _setError('请输入服务器地址');
    if (port <= 0 || port > 65535) return _setError('端口无效');

    final app = ref.read(antAppProvider);
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      // 深拷贝后改写，避免直接动到原对象
      final out = Node.fromJson(_n.toJson());
      out.name = name;
      out.address = address;
      out.port = port;
      out.subUrl = _n.subUrl;
      out.groupId = _n.groupId;

      List<String>? toAlpn(String key) {
        final t = _text(key).trim();
        if (t.isEmpty) return null;
        return t.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();
      }

      TransportConfig? readTransport() {
        if (!_hasTransport) return null;
        final type = _state('transport.type', '') as String;
        if (type.isEmpty) return null;
        final t = TransportConfig(type: type);
        if (['ws', 'http', 'httpupgrade', 'xhttp'].contains(type)) {
          t.path = _text('transport.path');
          t.host = _text('transport.host');
        }
        if (type == 'ws') {
          t.maxEarlyData = int.tryParse(_text('transport.maxEarlyData')) ?? 0;
          t.earlyDataHeaderName = _text('transport.earlyDataHeaderName');
        }
        if (type == 'grpc') {
          t.serviceName = _text('transport.serviceName');
        }
        if (type == 'xhttp') {
          t.mode = (_state('transport.mode', 'auto') as String);
        }
        return t;
      }

      switch (_proto) {
        case 'vmess':
          final c = out.vMess ?? VMessConfig();
          c.uuid = _text('uuid');
          c.security = _state('security', 'auto') as String;
          c.alterId = int.tryParse(_text('alterId')) ?? 0;
          c.tls = _state('tls', c.tls) as bool;
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.fingerprint = _text('fingerprint');
          c.insecure = _state('insecure', c.insecure) as bool;
          c.echConfig = _text('echConfig');
          c.transport = readTransport();
          out.vMess = c;
        case 'vless':
          final c = out.vless ?? VLESSConfig();
          c.uuid = _text('uuid');
          c.flow = _state('flow', '') as String;
          c.tls = _state('tls', c.tls) as bool;
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.fingerprint = _text('fingerprint');
          c.insecure = _state('insecure', c.insecure) as bool;
          c.echConfig = _text('echConfig');
          c.publicKey = _text('publicKey');
          c.shortId = _text('shortId');
          c.transport = readTransport();
          out.vless = c;
        case 'trojan':
          final c = out.trojan ?? TrojanConfig();
          c.password = _text('password');
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.fingerprint = _text('fingerprint');
          c.insecure = _state('insecure', c.insecure) as bool;
          c.echConfig = _text('echConfig');
          c.transport = readTransport();
          out.trojan = c;
        case 'ss':
          final c = out.ss ?? SSConfig();
          c.method = _text('method');
          c.password = _text('password');
          c.plugin = _text('plugin');
          c.pluginOpts = _text('pluginOpts');
          out.ss = c;
        case 'hysteria':
          final c = out.hysteria ?? HysteriaConfig();
          c.authStr = _text('authStr');
          c.upMbps = int.tryParse(_text('upMbps')) ?? 0;
          c.downMbps = int.tryParse(_text('downMbps')) ?? 0;
          c.obfs = _text('obfs');
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.insecure = _state('insecure', c.insecure) as bool;
          out.hysteria = c;
        case 'hysteria2':
          final c = out.hysteria2 ?? Hysteria2Config();
          c.password = _text('password');
          c.obfs = _text('obfs');
          c.obfsPassword = _text('obfsPassword');
          c.upMbps = int.tryParse(_text('upMbps')) ?? 0;
          c.downMbps = int.tryParse(_text('downMbps')) ?? 0;
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.insecure = _state('insecure', c.insecure) as bool;
          c.echConfig = _text('echConfig');
          out.hysteria2 = c;
        case 'tuic':
          final c = out.tuic ?? TUICConfig();
          c.uuid = _text('uuid');
          c.password = _text('password');
          c.congestionControl = _state('cc', 'cubic') as String;
          c.udpRelayMode = _state('udpMode', 'native') as String;
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.insecure = _state('insecure', c.insecure) as bool;
          out.tuic = c;
        case 'socks':
          final c = out.socks ?? SocksConfig();
          c.version = _state('version', '5') as String;
          c.username = _text('username');
          c.password = _text('password');
          out.socks = c;
        case 'http':
          final c = out.http ?? HTTPConfig();
          c.username = _text('username');
          c.password = _text('password');
          c.tls = _state('tls', c.tls) as bool;
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.insecure = _state('insecure', c.insecure) as bool;
          out.http = c;
        case 'anytls':
          final c = out.anytls ?? AnyTLSConfig();
          c.password = _text('password');
          c.sni = _text('sni');
          c.alpn = toAlpn('alpn');
          c.fingerprint = _text('fingerprint');
          c.insecure = _state('insecure', c.insecure) as bool;
          c.echConfig = _text('echConfig');
          out.anytls = c;
        case 'ssr':
          final c = out.ssr ?? SSRConfig();
          c.method = _text('method');
          c.password = _text('password');
          c.protocol = _text('protocol');
          c.protocolParam = _text('protocolParam');
          c.obfs = _text('obfs');
          c.obfsParam = _text('obfsParam');
          out.ssr = c;
        case 'wireguard':
          final c = out.wireGuard ?? WireGuardConfig();
          c.privateKey = _text('privateKey');
          c.publicKey = _text('publicKey');
          c.presharedKey = _text('presharedKey');
          c.localAddress = toAlpn('localAddress');
          c.mtu = int.tryParse(_text('mtu')) ?? 0;
          final reserved = _text('reserved')
              .split(',')
              .map((e) => int.tryParse(e.trim()))
              .whereType<int>()
              .toList();
          c.reserved = reserved.isEmpty ? null : reserved;
          out.wireGuard = c;
      }

      // 结构化协议保存后清除 raw 透传，让编辑内容生效
      if (_supportedProto) {
        out.rawOutbound = null;
        out.rawClashProxy = null;
      }

      if (widget.isNew) {
        // 新建：入库新增（补全 id 与归属分组）
        app.addNode(out);
      } else {
        app.updateNode(out);
      }
      if (mounted) {
        AppToast.show(context, '节点已保存', ToastType.success);
        Navigator.of(context).pop();
      }
    } catch (e) {
      _setError('保存失败: $e');
    }
    if (mounted) setState(() => _saving = false);
    await ref.read(nodesProvider.notifier).reload();
  }

  void _setError(String msg) {
    setState(() => _error = msg);
  }

  // ─── 表单小部件 ────────────────────────────────────────────────────────────

  Widget _field(String label, String key, String initial,
      {String? hint}) {
    return _formRow(label, TextField(
      controller: _ctl(key, initial),
      decoration: InputDecoration(hintText: hint),
      style: const TextStyle(
          color: AntPalette.text, fontSize: 12, fontFamily: 'Consolas'),
    ));
  }

  Widget _numField(String label, String key, String initial) {
    return _formRow(label, TextField(
      controller: _ctl(key, initial),
      keyboardType: TextInputType.number,
      decoration: const InputDecoration(),
      style: const TextStyle(color: AntPalette.text, fontSize: 12),
    ));
  }

  Widget _checkRow(String label, String key, bool initial) {
    final v = _state(key, initial) as bool;
    return _formRow(label, Row(children: [
      SizedBox(
        width: 16,
        height: 16,
        child: Checkbox(
          value: v,
          onChanged: (nv) => setState(() => _st[key] = nv ?? false),
        ),
      ),
    ]));
  }

  Widget _dropdownRow<T>(String label, String key, T initial,
      List<(T, String)> options) {
    final v = _state(key, initial) as T;
    return _formRow(label, DropdownButtonFormField<T>(
      initialValue: v,
      items: [
        for (final (val, lab) in options)
          DropdownMenuItem(value: val, child: Text(lab)),
      ],
      onChanged: (nv) {
        if (nv != null) setState(() => _st[key] = nv);
      },
    ));
  }

  Widget _formRow(String label, Widget child) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          children: [
            SizedBox(
              width: 150,
              child: Text(label,
                  style: const TextStyle(
                      color: AntPalette.textDim, fontSize: 12)),
            ),
            Expanded(child: child),
          ],
        ),
      );

  Widget _section(String title) => Padding(
        padding: const EdgeInsets.only(top: 10, bottom: 2),
        child: Text(title,
            style: const TextStyle(
                color: AntPalette.accent,
                fontSize: 12,
                fontWeight: FontWeight.w600)),
      );

  // ─── 构建 ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final transport = _transportOf();
    final tlsEnabled = switch (_proto) {
      'vmess' => _state('tls', _n.vMess?.tls ?? false) as bool,
      'vless' => _state('tls', _n.vless?.tls ?? false) as bool,
      'http' => _state('tls', _n.http?.tls ?? false) as bool,
      'anytls' => true,
      _ => true,
    };

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      mainAxisSize: MainAxisSize.min,
      children: [
        if (!_supportedProto)
          Container(
            padding: const EdgeInsets.all(8),
            margin: const EdgeInsets.only(bottom: 8),
            decoration: BoxDecoration(
              color: AntPalette.yellow.withValues(alpha: 0.08),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              '该节点 ($_proto) 来自完整配置(raw)，仅支持编辑基本信息。',
              style: const TextStyle(color: AntPalette.yellow, fontSize: 12),
            ),
          ),
        if (_error != null)
          Container(
            padding: const EdgeInsets.all(8),
            margin: const EdgeInsets.only(bottom: 8),
            decoration: BoxDecoration(
              color: AntPalette.red.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(_error!,
                style: const TextStyle(color: AntPalette.red, fontSize: 12)),
          ),

        // ── 常规 ──
        _section('常规设置'),
        _field('别名', 'name', _n.name),
        _formRow('协议', Text(_proto,
            style: const TextStyle(color: AntPalette.textDim, fontSize: 12))),
        _field('地址 (服务器)', 'address', _n.address),
        _numField('端口', 'port', '${_n.port}'),

        // ── 协议参数 ──
        if (_supportedProto) ...[
          _section('协议参数'),
          ..._protoFields(),
        ],

        // ── 传输层 ──
        if (_hasTransport && _supportedProto) ...[
          _section('传输层配置 (transport)'),
          _dropdownRow('传输类型', 'transport.type',
              transport?.type ?? '', _transportTypes),
          if (_state('transport.type', transport?.type ?? '') != '')
            ..._transportFields(),
        ],

        // ── TLS ──
        if (_hasTlsSection && _supportedProto) ...[
          _section('TLS 安全设置'),
          if (_proto != 'trojan' && _proto != 'anytls')
            _checkRow('启用 TLS', 'tls', tlsEnabled),
          if (tlsEnabled) ..._tlsFields(withFingerprint: true),
          if (_proto == 'vless' &&
              tlsEnabled &&
              (_text('publicKey').isNotEmpty ||
                  (_n.vless?.publicKey.isNotEmpty ?? false))) ...[
            _field('公钥 (public_key / pbk)', 'publicKey',
                _n.vless?.publicKey ?? ''),
            _field('短 ID (short_id / sid)', 'shortId',
                _n.vless?.shortId ?? ''),
          ],
        ],

        // ── 固定 TLS 协议 ──
        if (_hasFixedTls &&
            _supportedProto &&
            !['trojan'].contains(_proto)) ...[
          _section('TLS 安全设置 (${_proto == 'tuic' ? 'TLS 必需' : 'QUIC / TLS 必需'})'),
          ..._tlsFields(withFingerprint: false),
        ],

        const SizedBox(height: 12),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            ModalButton(
              label: '取消',
              onPressed: () => Navigator.of(context).pop(),
            ),
            ModalButton(
              label: _saving ? '保存中…' : '保存',
              primary: true,
              onPressed: _saving ? null : _save,
            ),
          ],
        ),
      ],
    );
  }

  List<Widget> _protoFields() {
    switch (_proto) {
      case 'vmess':
        return [
          _field('UUID / 用户 ID', 'uuid', _n.vMess?.uuid ?? ''),
          _dropdownRow('加密方式 (security)', 'security',
              _n.vMess?.security.isEmpty ?? true
                  ? 'auto'
                  : _n.vMess!.security,
              [for (final s in _securityTypes) (s, s)]),
          _numField('alterId', 'alterId', '${_n.vMess?.alterId ?? 0}'),
        ];
      case 'vless':
        return [
          _field('UUID / 用户 ID', 'uuid', _n.vless?.uuid ?? ''),
          _dropdownRow('流控 (flow)', 'flow', _n.vless?.flow ?? '', _flowTypes),
        ];
      case 'trojan':
        return [
          _field('密码', 'password', _n.trojan?.password ?? ''),
        ];
      case 'ss':
        return [
          _field('加密方法 (method)', 'method', _n.ss?.method ?? ''),
          _field('密码', 'password', _n.ss?.password ?? ''),
          _field('插件 (plugin)', 'plugin', _n.ss?.plugin ?? '',
              hint: 'obfs-local / v2ray-plugin'),
          _field('插件参数 (plugin_opts)', 'pluginOpts',
              _n.ss?.pluginOpts ?? '',
              hint: 'obfs=http;obfs-host=xxx'),
        ];
      case 'hysteria':
        return [
          _field('认证 (auth_str)', 'authStr', _n.hysteria?.authStr ?? ''),
          _numField('上传限速 (Mbps)', 'upMbps',
              '${_n.hysteria?.upMbps ?? ''}'),
          _numField('下载限速 (Mbps)', 'downMbps',
              '${_n.hysteria?.downMbps ?? ''}'),
          _field('混淆 (obfs)', 'obfs', _n.hysteria?.obfs ?? ''),
        ];
      case 'hysteria2':
        return [
          _field('密码', 'password', _n.hysteria2?.password ?? ''),
          _field('混淆类型 (obfs)', 'obfs', _n.hysteria2?.obfs ?? '',
              hint: 'salamander'),
          _field('混淆密码', 'obfsPassword',
              _n.hysteria2?.obfsPassword ?? ''),
          _numField('上传限速 (Mbps)', 'upMbps',
              '${_n.hysteria2?.upMbps ?? ''}'),
          _numField('下载限速 (Mbps)', 'downMbps',
              '${_n.hysteria2?.downMbps ?? ''}'),
        ];
      case 'tuic':
        return [
          _field('UUID / 用户 ID', 'uuid', _n.tuic?.uuid ?? ''),
          _field('密码', 'password', _n.tuic?.password ?? ''),
          _dropdownRow('拥塞控制', 'cc',
              _n.tuic?.congestionControl.isEmpty ?? true
                  ? 'cubic'
                  : _n.tuic!.congestionControl,
              [for (final s in _ccTypes) (s, s)]),
          _dropdownRow('UDP 中继模式', 'udpMode',
              _n.tuic?.udpRelayMode.isEmpty ?? true
                  ? 'native'
                  : _n.tuic!.udpRelayMode,
              [for (final s in _udpModes) (s, s)]),
        ];
      case 'socks':
        return [
          _dropdownRow('版本', 'version', _n.socks?.version ?? '5',
              const [('5', '5'), ('4a', '4a')]),
          _field('用户名', 'username', _n.socks?.username ?? ''),
          _field('密码', 'password', _n.socks?.password ?? ''),
        ];
      case 'http':
        return [
          _field('用户名', 'username', _n.http?.username ?? ''),
          _field('密码', 'password', _n.http?.password ?? ''),
        ];
      case 'anytls':
        return [
          _field('密码', 'password', _n.anytls?.password ?? ''),
        ];
      case 'ssr':
        return [
          _field('加密方法', 'method', _n.ssr?.method ?? ''),
          _field('密码', 'password', _n.ssr?.password ?? ''),
          _field('协议 (protocol)', 'protocol', _n.ssr?.protocol ?? ''),
          _field('协议参数', 'protocolParam',
              _n.ssr?.protocolParam ?? ''),
          _field('混淆 (obfs)', 'obfs', _n.ssr?.obfs ?? ''),
          _field('混淆参数', 'obfsParam', _n.ssr?.obfsParam ?? ''),
        ];
      case 'wireguard':
        return [
          _field('本机私钥 (private_key)', 'privateKey',
              _n.wireGuard?.privateKey ?? ''),
          _field('对端公钥 (peer_public_key)', 'publicKey',
              _n.wireGuard?.publicKey ?? ''),
          _field('预共享密钥', 'presharedKey',
              _n.wireGuard?.presharedKey ?? ''),
          _field('本机地址 (逗号分隔)', 'localAddress',
              _n.wireGuard?.localAddress?.join(',') ?? '',
              hint: '172.16.0.2/32'),
          _numField('MTU', 'mtu', _n.wireGuard!.mtu > 0 ? '${_n.wireGuard!.mtu}' : ''),
          _field('保留字段 (reserved, 逗号分隔)', 'reserved',
              _n.wireGuard?.reserved?.join(',') ?? '',
              hint: '1,2,3'),
        ];
      default:
        return [];
    }
  }

  List<Widget> _transportFields() {
    final t = _transportOf();
    final type = _state('transport.type', t?.type ?? '') as String;
    return [
      if (['ws', 'http', 'httpupgrade', 'xhttp'].contains(type)) ...[
        _field('路径 (path)', 'transport.path', t?.path ?? ''),
        _field('Host', 'transport.host', t?.host ?? ''),
      ],
      if (type == 'ws') ...[
        _numField('早期数据上限', 'transport.maxEarlyData',
            t!.maxEarlyData > 0 ? '${t.maxEarlyData}' : ''),
        _field('早期数据头', 'transport.earlyDataHeaderName',
            t.earlyDataHeaderName,
            hint: 'Sec-WebSocket-Protocol'),
      ],
      if (type == 'grpc')
        _field('服务名称 (service_name)', 'transport.serviceName',
            t!.serviceName),
      if (type == 'xhttp')
        _dropdownRow('模式 (mode)', 'transport.mode',
            t!.mode.isEmpty ? 'auto' : t.mode,
            [for (final m in _xhttpModes) (m, m)]),
    ];
  }

  List<Widget> _tlsFields({required bool withFingerprint}) {
    final cfgSni = switch (_proto) {
      'vmess' => _n.vMess?.sni ?? '',
      'vless' => _n.vless?.sni ?? '',
      'trojan' => _n.trojan?.sni ?? '',
      'hysteria' => _n.hysteria?.sni ?? '',
      'hysteria2' => _n.hysteria2?.sni ?? '',
      'tuic' => _n.tuic?.sni ?? '',
      'http' => _n.http?.sni ?? '',
      'anytls' => _n.anytls?.sni ?? '',
      _ => '',
    };
    String cfgAlpn() => switch (_proto) {
          'vmess' => _n.vMess?.alpn?.join(',') ?? '',
          'vless' => _n.vless?.alpn?.join(',') ?? '',
          'trojan' => _n.trojan?.alpn?.join(',') ?? '',
          'hysteria' => _n.hysteria?.alpn?.join(',') ?? '',
          'hysteria2' => _n.hysteria2?.alpn?.join(',') ?? '',
          'tuic' => _n.tuic?.alpn?.join(',') ?? '',
          'http' => _n.http?.alpn?.join(',') ?? '',
          'anytls' => _n.anytls?.alpn?.join(',') ?? '',
          _ => '',
        };
    bool cfgInsecure() => switch (_proto) {
          'vmess' => _n.vMess?.insecure ?? false,
          'vless' => _n.vless?.insecure ?? false,
          'trojan' => _n.trojan?.insecure ?? false,
          'hysteria' => _n.hysteria?.insecure ?? false,
          'hysteria2' => _n.hysteria2?.insecure ?? false,
          'tuic' => _n.tuic?.insecure ?? false,
          'http' => _n.http?.insecure ?? false,
          'anytls' => _n.anytls?.insecure ?? false,
          _ => false,
        };
    String cfgFingerprint() => switch (_proto) {
          'vmess' => _n.vMess?.fingerprint ?? '',
          'vless' => _n.vless?.fingerprint ?? '',
          'trojan' => _n.trojan?.fingerprint ?? '',
          'anytls' => _n.anytls?.fingerprint ?? '',
          _ => '',
        };
    String cfgEch() => switch (_proto) {
          'vmess' => _n.vMess?.echConfig ?? '',
          'vless' => _n.vless?.echConfig ?? '',
          'trojan' => _n.trojan?.echConfig ?? '',
          'hysteria2' => _n.hysteria2?.echConfig ?? '',
          'anytls' => _n.anytls?.echConfig ?? '',
          _ => '',
        };

    return [
      _field('SNI (server_name)', 'sni', cfgSni),
      _field('ALPN (逗号分隔)', 'alpn', cfgAlpn(), hint: 'h2, http/1.1'),
      _checkRow('跳过证书验证 (insecure)', 'insecure', cfgInsecure()),
      if (withFingerprint)
        _field('uTLS 指纹 (fingerprint)', 'fingerprint',
            cfgFingerprint(),
            hint: 'chrome / firefox / safari / ios …'),
      if (_proto == 'vmess' || _proto == 'vless' || _proto == 'anytls' || _proto == 'hysteria2')
        _field('ECH 配置 (ech.config)', 'echConfig', cfgEch()),
    ];
  }
}
