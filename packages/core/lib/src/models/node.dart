/// 节点模型 — 移植自 Go: backend/node/types.go
///
/// JSON 字段名与 Go 版完全一致（含 omitempty 语义），
/// 保证与旧版 data/nodes.db 中 JSON 数据的兼容性。
library;

/// V2Ray transport 设置，VMess/VLESS/Trojan 共用。
/// sing-box transport types: ws | http | grpc | httpupgrade | quic
/// xhttp（Xray transport，sing-box fork 支持）按 Xray 规范写入。
/// URI "type" / vmess-json "net" 映射：
///   ws→ws, h2/http→http, grpc→grpc, httpupgrade→httpupgrade,
///   quic→quic, xhttp/splithttp→xhttp, tcp/raw/""→无 transport 块, kcp→拒绝
class TransportConfig {
  String type; // ws | http | grpc | httpupgrade | quic | xhttp

  // ws / http / httpupgrade
  String path;
  String host;

  // ws only
  int maxEarlyData;
  String earlyDataHeaderName; // usually "Sec-WebSocket-Protocol"

  // grpc only
  String serviceName;

  // xhttp only (Xray transport)
  String mode; // auto(default) | packet-up | stream-up | stream-one

  TransportConfig({
    this.type = '',
    this.path = '',
    this.host = '',
    this.maxEarlyData = 0,
    this.earlyDataHeaderName = '',
    this.serviceName = '',
    this.mode = '',
  });

  Map<String, dynamic> toJson() => {
        'type': type,
        if (path.isNotEmpty) 'path': path,
        if (host.isNotEmpty) 'host': host,
        if (maxEarlyData > 0) 'max_early_data': maxEarlyData,
        if (earlyDataHeaderName.isNotEmpty)
          'early_data_header_name': earlyDataHeaderName,
        if (serviceName.isNotEmpty) 'service_name': serviceName,
        if (mode.isNotEmpty) 'mode': mode,
      };

  static TransportConfig fromJson(Map<String, dynamic> j) => TransportConfig(
        type: j['type'] as String? ?? '',
        path: j['path'] as String? ?? '',
        host: j['host'] as String? ?? '',
        maxEarlyData: (j['max_early_data'] as num?)?.toInt() ?? 0,
        earlyDataHeaderName: j['early_data_header_name'] as String? ?? '',
        serviceName: j['service_name'] as String? ?? '',
        mode: j['mode'] as String? ?? '',
      );
}

// ── VMess ────────────────────────────────────────────────────────────────────
// sing-box fields: uuid(req), security, alter_id, tls, transport
// security: auto(default) | none | zero | aes-128-gcm | chacha20-poly1305
class VMessConfig {
  String uuid;
  int alterId; // 0=AEAD (recommended), >=1=legacy
  String security; // default "auto"; must NOT be empty string
  bool tls;
  String sni;
  List<String>? alpn;
  String fingerprint; // uTLS fingerprint
  bool insecure;
  String echConfig; // TLS ECH config list
  TransportConfig? transport;

  VMessConfig({
    this.uuid = '',
    this.alterId = 0,
    this.security = 'auto',
    this.tls = false,
    this.sni = '',
    this.alpn,
    this.fingerprint = '',
    this.insecure = false,
    this.echConfig = '',
    this.transport,
  });

  Map<String, dynamic> toJson() => {
        'uuid': uuid,
        'alter_id': alterId,
        'security': security,
        'tls': tls,
        if (sni.isNotEmpty) 'sni': sni,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
        if (fingerprint.isNotEmpty) 'fingerprint': fingerprint,
        if (insecure) 'insecure': insecure,
        if (echConfig.isNotEmpty) 'ech_config': echConfig,
        if (transport != null) 'transport': transport!.toJson(),
      };

  static VMessConfig fromJson(Map<String, dynamic> j) => VMessConfig(
        uuid: j['uuid'] as String? ?? '',
        alterId: (j['alter_id'] as num?)?.toInt() ?? 0,
        security: j['security'] as String? ?? '',
        tls: j['tls'] as bool? ?? false,
        sni: j['sni'] as String? ?? '',
        alpn: (j['alpn'] as List?)?.cast<String>(),
        fingerprint: j['fingerprint'] as String? ?? '',
        insecure: j['insecure'] as bool? ?? false,
        echConfig: j['ech_config'] as String? ?? '',
        transport: j['transport'] == null
            ? null
            : TransportConfig.fromJson((j['transport'] as Map).cast<String, dynamic>()),
      );
}

// ── VLESS ────────────────────────────────────────────────────────────────────
// flow: "" | "xtls-rprx-vision"
class VLESSConfig {
  String uuid;
  String flow;
  bool tls;
  String sni;
  List<String>? alpn;
  String fingerprint;
  bool insecure;
  String echConfig;
  // Reality fields (TLS must be true)
  String publicKey; // URI: pbk
  String shortId; // URI: sid
  TransportConfig? transport;

  VLESSConfig({
    this.uuid = '',
    this.flow = '',
    this.tls = false,
    this.sni = '',
    this.alpn,
    this.fingerprint = '',
    this.insecure = false,
    this.echConfig = '',
    this.publicKey = '',
    this.shortId = '',
    this.transport,
  });

  Map<String, dynamic> toJson() => {
        'uuid': uuid,
        if (flow.isNotEmpty) 'flow': flow,
        'tls': tls,
        if (sni.isNotEmpty) 'sni': sni,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
        if (fingerprint.isNotEmpty) 'fingerprint': fingerprint,
        if (insecure) 'insecure': insecure,
        if (echConfig.isNotEmpty) 'ech_config': echConfig,
        if (publicKey.isNotEmpty) 'public_key': publicKey,
        if (shortId.isNotEmpty) 'short_id': shortId,
        if (transport != null) 'transport': transport!.toJson(),
      };

  static VLESSConfig fromJson(Map<String, dynamic> j) => VLESSConfig(
        uuid: j['uuid'] as String? ?? '',
        flow: j['flow'] as String? ?? '',
        tls: j['tls'] as bool? ?? false,
        sni: j['sni'] as String? ?? '',
        alpn: (j['alpn'] as List?)?.cast<String>(),
        fingerprint: j['fingerprint'] as String? ?? '',
        insecure: j['insecure'] as bool? ?? false,
        echConfig: j['ech_config'] as String? ?? '',
        publicKey: j['public_key'] as String? ?? '',
        shortId: j['short_id'] as String? ?? '',
        transport: j['transport'] == null
            ? null
            : TransportConfig.fromJson((j['transport'] as Map).cast<String, dynamic>()),
      );
}

// ── Trojan ───────────────────────────────────────────────────────────────────
class TrojanConfig {
  String password;
  String sni;
  List<String>? alpn;
  String fingerprint;
  bool insecure;
  String echConfig;
  TransportConfig? transport;

  TrojanConfig({
    this.password = '',
    this.sni = '',
    this.alpn,
    this.fingerprint = '',
    this.insecure = false,
    this.echConfig = '',
    this.transport,
  });

  Map<String, dynamic> toJson() => {
        'password': password,
        if (sni.isNotEmpty) 'sni': sni,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
        if (fingerprint.isNotEmpty) 'fingerprint': fingerprint,
        if (insecure) 'insecure': insecure,
        if (echConfig.isNotEmpty) 'ech_config': echConfig,
        if (transport != null) 'transport': transport!.toJson(),
      };

  static TrojanConfig fromJson(Map<String, dynamic> j) => TrojanConfig(
        password: j['password'] as String? ?? '',
        sni: j['sni'] as String? ?? '',
        alpn: (j['alpn'] as List?)?.cast<String>(),
        fingerprint: j['fingerprint'] as String? ?? '',
        insecure: j['insecure'] as bool? ?? false,
        echConfig: j['ech_config'] as String? ?? '',
        transport: j['transport'] == null
            ? null
            : TransportConfig.fromJson((j['transport'] as Map).cast<String, dynamic>()),
      );
}

// ── Shadowsocks ──────────────────────────────────────────────────────────────
class SSConfig {
  String method;
  String password;
  String plugin; // obfs-local | v2ray-plugin
  String pluginOpts; // SIP003 plugin options, e.g. "obfs=http;obfs-host=xxx"

  SSConfig({
    this.method = '',
    this.password = '',
    this.plugin = '',
    this.pluginOpts = '',
  });

  Map<String, dynamic> toJson() => {
        'method': method,
        'password': password,
        if (plugin.isNotEmpty) 'plugin': plugin,
        if (pluginOpts.isNotEmpty) 'plugin_opts': pluginOpts,
      };

  static SSConfig fromJson(Map<String, dynamic> j) => SSConfig(
        method: j['method'] as String? ?? '',
        password: j['password'] as String? ?? '',
        plugin: j['plugin'] as String? ?? '',
        pluginOpts: j['plugin_opts'] as String? ?? '',
      );
}

// ── Hysteria (v1, deprecated in sing-box 1.12+) ──────────────────────────────
class HysteriaConfig {
  String authStr;
  String sni;
  bool insecure;
  List<String>? alpn;
  int upMbps;
  int downMbps;
  String obfs; // string obfs password (hysteria v1)

  HysteriaConfig({
    this.authStr = '',
    this.sni = '',
    this.insecure = false,
    this.alpn,
    this.upMbps = 0,
    this.downMbps = 0,
    this.obfs = '',
  });

  Map<String, dynamic> toJson() => {
        if (authStr.isNotEmpty) 'auth_str': authStr,
        if (sni.isNotEmpty) 'sni': sni,
        if (insecure) 'insecure': insecure,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
        if (upMbps > 0) 'up_mbps': upMbps,
        if (downMbps > 0) 'down_mbps': downMbps,
        if (obfs.isNotEmpty) 'obfs': obfs,
      };

  static HysteriaConfig fromJson(Map<String, dynamic> j) => HysteriaConfig(
        authStr: j['auth_str'] as String? ?? '',
        sni: j['sni'] as String? ?? '',
        insecure: j['insecure'] as bool? ?? false,
        alpn: (j['alpn'] as List?)?.cast<String>(),
        upMbps: (j['up_mbps'] as num?)?.toInt() ?? 0,
        downMbps: (j['down_mbps'] as num?)?.toInt() ?? 0,
        obfs: j['obfs'] as String? ?? '',
      );
}

// ── Hysteria2 ────────────────────────────────────────────────────────────────
class Hysteria2Config {
  String password;
  String sni;
  bool insecure;
  List<String>? alpn;
  String echConfig; // URI: ech
  int upMbps; // 0 = BBR CC (no limit)
  int downMbps; // 0 = BBR CC (no limit)
  String obfs; // "salamander"
  String obfsPassword;

  Hysteria2Config({
    this.password = '',
    this.sni = '',
    this.insecure = false,
    this.alpn,
    this.echConfig = '',
    this.upMbps = 0,
    this.downMbps = 0,
    this.obfs = '',
    this.obfsPassword = '',
  });

  Map<String, dynamic> toJson() => {
        'password': password,
        if (sni.isNotEmpty) 'sni': sni,
        if (insecure) 'insecure': insecure,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
        if (echConfig.isNotEmpty) 'ech_config': echConfig,
        if (upMbps > 0) 'up_mbps': upMbps,
        if (downMbps > 0) 'down_mbps': downMbps,
        if (obfs.isNotEmpty) 'obfs': obfs,
        if (obfsPassword.isNotEmpty) 'obfs_password': obfsPassword,
      };

  static Hysteria2Config fromJson(Map<String, dynamic> j) => Hysteria2Config(
        password: j['password'] as String? ?? '',
        sni: j['sni'] as String? ?? '',
        insecure: j['insecure'] as bool? ?? false,
        alpn: (j['alpn'] as List?)?.cast<String>(),
        echConfig: j['ech_config'] as String? ?? '',
        upMbps: (j['up_mbps'] as num?)?.toInt() ?? 0,
        downMbps: (j['down_mbps'] as num?)?.toInt() ?? 0,
        obfs: j['obfs'] as String? ?? '',
        obfsPassword: j['obfs_password'] as String? ?? '',
      );
}

// ── TUIC ─────────────────────────────────────────────────────────────────────
class TUICConfig {
  String uuid;
  String password;
  String sni;
  List<String>? alpn;
  bool insecure;
  String congestionControl; // default "cubic"
  String udpRelayMode; // default "native"

  TUICConfig({
    this.uuid = '',
    this.password = '',
    this.sni = '',
    this.alpn,
    this.insecure = false,
    this.congestionControl = '',
    this.udpRelayMode = '',
  });

  Map<String, dynamic> toJson() => {
        'uuid': uuid,
        if (password.isNotEmpty) 'password': password,
        if (sni.isNotEmpty) 'sni': sni,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
        if (insecure) 'insecure': insecure,
        if (congestionControl.isNotEmpty) 'congestion_control': congestionControl,
        if (udpRelayMode.isNotEmpty) 'udp_relay_mode': udpRelayMode,
      };

  static TUICConfig fromJson(Map<String, dynamic> j) => TUICConfig(
        uuid: j['uuid'] as String? ?? '',
        password: j['password'] as String? ?? '',
        sni: j['sni'] as String? ?? '',
        alpn: (j['alpn'] as List?)?.cast<String>(),
        insecure: j['insecure'] as bool? ?? false,
        congestionControl: j['congestion_control'] as String? ?? '',
        udpRelayMode: j['udp_relay_mode'] as String? ?? '',
      );
}

// ── Socks ────────────────────────────────────────────────────────────────────
class SocksConfig {
  String version; // "5" (default) | "4a"
  String username;
  String password;

  SocksConfig({
    this.version = '5',
    this.username = '',
    this.password = '',
  });

  Map<String, dynamic> toJson() => {
        'version': version,
        if (username.isNotEmpty) 'username': username,
        if (password.isNotEmpty) 'password': password,
      };

  static SocksConfig fromJson(Map<String, dynamic> j) => SocksConfig(
        version: j['version'] as String? ?? '5',
        username: j['username'] as String? ?? '',
        password: j['password'] as String? ?? '',
      );
}

// ── HTTP(S) proxy ────────────────────────────────────────────────────────────
class HTTPConfig {
  String username;
  String password;
  bool tls;
  String sni;
  bool insecure;
  List<String>? alpn;

  HTTPConfig({
    this.username = '',
    this.password = '',
    this.tls = false,
    this.sni = '',
    this.insecure = false,
    this.alpn,
  });

  Map<String, dynamic> toJson() => {
        if (username.isNotEmpty) 'username': username,
        if (password.isNotEmpty) 'password': password,
        if (tls) 'tls': tls,
        if (sni.isNotEmpty) 'sni': sni,
        if (insecure) 'insecure': insecure,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
      };

  static HTTPConfig fromJson(Map<String, dynamic> j) => HTTPConfig(
        username: j['username'] as String? ?? '',
        password: j['password'] as String? ?? '',
        tls: j['tls'] as bool? ?? false,
        sni: j['sni'] as String? ?? '',
        insecure: j['insecure'] as bool? ?? false,
        alpn: (j['alpn'] as List?)?.cast<String>(),
      );
}

// ── AnyTLS ───────────────────────────────────────────────────────────────────
class AnyTLSConfig {
  String password;
  String sni;
  bool insecure;
  List<String>? alpn;
  String fingerprint;
  String echConfig;

  AnyTLSConfig({
    this.password = '',
    this.sni = '',
    this.insecure = false,
    this.alpn,
    this.fingerprint = '',
    this.echConfig = '',
  });

  Map<String, dynamic> toJson() => {
        'password': password,
        if (sni.isNotEmpty) 'sni': sni,
        if (insecure) 'insecure': insecure,
        if (alpn != null && alpn!.isNotEmpty) 'alpn': alpn,
        if (fingerprint.isNotEmpty) 'fingerprint': fingerprint,
        if (echConfig.isNotEmpty) 'ech_config': echConfig,
      };

  static AnyTLSConfig fromJson(Map<String, dynamic> j) => AnyTLSConfig(
        password: j['password'] as String? ?? '',
        sni: j['sni'] as String? ?? '',
        insecure: j['insecure'] as bool? ?? false,
        alpn: (j['alpn'] as List?)?.cast<String>(),
        fingerprint: j['fingerprint'] as String? ?? '',
        echConfig: j['ech_config'] as String? ?? '',
      );
}

// ── ShadowsocksR (removed from sing-box 1.13, kept for older cores) ──────────
class SSRConfig {
  String method;
  String password;
  String protocol; // origin | auth_sha1_v4 | ...
  String protocolParam;
  String obfs; // plain | http_simple | tls1.2_ticket_auth...
  String obfsParam;

  SSRConfig({
    this.method = '',
    this.password = '',
    this.protocol = '',
    this.protocolParam = '',
    this.obfs = '',
    this.obfsParam = '',
  });

  Map<String, dynamic> toJson() => {
        'method': method,
        'password': password,
        if (protocol.isNotEmpty) 'protocol': protocol,
        if (protocolParam.isNotEmpty) 'protocol_param': protocolParam,
        if (obfs.isNotEmpty) 'obfs': obfs,
        if (obfsParam.isNotEmpty) 'obfs_param': obfsParam,
      };

  static SSRConfig fromJson(Map<String, dynamic> j) => SSRConfig(
        method: j['method'] as String? ?? '',
        password: j['password'] as String? ?? '',
        protocol: j['protocol'] as String? ?? '',
        protocolParam: j['protocol_param'] as String? ?? '',
        obfs: j['obfs'] as String? ?? '',
        obfsParam: j['obfs_param'] as String? ?? '',
      );
}

// ── WireGuard (sing-box 1.13+: endpoint; outbound still supported) ───────────
class WireGuardConfig {
  String privateKey; // URI userinfo (secret key)
  String publicKey; // json: peer_public_key; URI: publickey
  String presharedKey; // json: pre_shared_key; URI: presharedkey
  List<int>? reserved; // URI: reserved "1,2,3" or base64
  List<String>? localAddress; // json: local_address; URI: address
  int mtu; // URI: mtu
  List<String>? dns; // URI: dns

  WireGuardConfig({
    this.privateKey = '',
    this.publicKey = '',
    this.presharedKey = '',
    this.reserved,
    this.localAddress,
    this.mtu = 0,
    this.dns,
  });

  Map<String, dynamic> toJson() => {
        'private_key': privateKey,
        'peer_public_key': publicKey,
        if (presharedKey.isNotEmpty) 'pre_shared_key': presharedKey,
        if (reserved != null && reserved!.isNotEmpty) 'reserved': reserved,
        if (localAddress != null && localAddress!.isNotEmpty)
          'local_address': localAddress,
        if (mtu > 0) 'mtu': mtu,
        if (dns != null && dns!.isNotEmpty) 'dns': dns,
      };

  static WireGuardConfig fromJson(Map<String, dynamic> j) => WireGuardConfig(
        privateKey: j['private_key'] as String? ?? '',
        publicKey: j['peer_public_key'] as String? ?? '',
        presharedKey: j['pre_shared_key'] as String? ?? '',
        reserved: (j['reserved'] as List?)?.map((e) => (e as num).toInt()).toList(),
        localAddress: (j['local_address'] as List?)?.cast<String>(),
        mtu: (j['mtu'] as num?)?.toInt() ?? 0,
        dns: (j['dns'] as List?)?.cast<String>(),
      );
}

/// Node — 由 URI 或订阅解析出的代理节点。
class Node {
  String id;
  String name;
  // vmess | vless | trojan | ss | hysteria | hysteria2 | tuic | socks |
  // http | anytls | ssr | wireguard | ssh | shadowtls | ...（raw-only 协议）
  String protocol;
  String address;
  int port;
  String subUrl;
  String groupId; // 所属分组 ID, 空 = 默认分组

  /// 原始 sing-box outbound JSON 对象（无损保留）。
  /// 参照 v2rayN 做法：任意 sing-box outbound 协议（ssh/shadowtls/
  /// shadowsocksr/mieru/tor/未来协议…）无损往返——所有 TLS 类型
  /// （标准/uTLS/Reality/ECH）与 transport 字段原样保留、原样回写。
  Map<String, dynamic>? rawOutbound;

  /// 原始 Clash/mihomo proxies 条目（YAML map），
  /// 来自 Clash YAML 的节点用它无损回写 mihomo 配置。
  Map<String, dynamic>? rawClashProxy;

  VMessConfig? vMess;
  VLESSConfig? vless;
  TrojanConfig? trojan;
  SSConfig? ss;
  HysteriaConfig? hysteria;
  Hysteria2Config? hysteria2;
  TUICConfig? tuic;
  SocksConfig? socks;
  HTTPConfig? http;
  AnyTLSConfig? anytls;
  SSRConfig? ssr;
  WireGuardConfig? wireGuard;

  Node({
    required this.id,
    this.name = '',
    this.protocol = '',
    this.address = '',
    this.port = 0,
    this.subUrl = '',
    this.groupId = '',
    this.rawOutbound,
    this.rawClashProxy,
    this.vMess,
    this.vless,
    this.trojan,
    this.ss,
    this.hysteria,
    this.hysteria2,
    this.tuic,
    this.socks,
    this.http,
    this.anytls,
    this.ssr,
    this.wireGuard,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'protocol': protocol,
        'address': address,
        'port': port,
        if (subUrl.isNotEmpty) 'sub_url': subUrl,
        if (groupId.isNotEmpty) 'group_id': groupId,
        if (rawOutbound != null) 'raw_outbound': rawOutbound,
        if (rawClashProxy != null) 'raw_clash_proxy': rawClashProxy,
        if (vMess != null) 'vmess': vMess!.toJson(),
        if (vless != null) 'vless': vless!.toJson(),
        if (trojan != null) 'trojan': trojan!.toJson(),
        if (ss != null) 'ss': ss!.toJson(),
        if (hysteria != null) 'hysteria': hysteria!.toJson(),
        if (hysteria2 != null) 'hysteria2': hysteria2!.toJson(),
        if (tuic != null) 'tuic': tuic!.toJson(),
        if (socks != null) 'socks': socks!.toJson(),
        if (http != null) 'http': http!.toJson(),
        if (anytls != null) 'anytls': anytls!.toJson(),
        if (ssr != null) 'ssr': ssr!.toJson(),
        if (wireGuard != null) 'wireguard': wireGuard!.toJson(),
      };

  static Node fromJson(Map<String, dynamic> j) => Node(
        id: j['id'] as String? ?? '',
        name: j['name'] as String? ?? '',
        protocol: j['protocol'] as String? ?? '',
        address: j['address'] as String? ?? '',
        port: (j['port'] as num?)?.toInt() ?? 0,
        subUrl: j['sub_url'] as String? ?? '',
        groupId: j['group_id'] as String? ?? '',
        rawOutbound: (j['raw_outbound'] as Map?)?.cast<String, dynamic>(),
        rawClashProxy: (j['raw_clash_proxy'] as Map?)?.cast<String, dynamic>(),
        vMess: j['vmess'] == null
            ? null
            : VMessConfig.fromJson((j['vmess'] as Map).cast<String, dynamic>()),
        vless: j['vless'] == null
            ? null
            : VLESSConfig.fromJson((j['vless'] as Map).cast<String, dynamic>()),
        trojan: j['trojan'] == null
            ? null
            : TrojanConfig.fromJson((j['trojan'] as Map).cast<String, dynamic>()),
        ss: j['ss'] == null
            ? null
            : SSConfig.fromJson((j['ss'] as Map).cast<String, dynamic>()),
        hysteria: j['hysteria'] == null
            ? null
            : HysteriaConfig.fromJson((j['hysteria'] as Map).cast<String, dynamic>()),
        hysteria2: j['hysteria2'] == null
            ? null
            : Hysteria2Config.fromJson((j['hysteria2'] as Map).cast<String, dynamic>()),
        tuic: j['tuic'] == null
            ? null
            : TUICConfig.fromJson((j['tuic'] as Map).cast<String, dynamic>()),
        socks: j['socks'] == null
            ? null
            : SocksConfig.fromJson((j['socks'] as Map).cast<String, dynamic>()),
        http: j['http'] == null
            ? null
            : HTTPConfig.fromJson((j['http'] as Map).cast<String, dynamic>()),
        anytls: j['anytls'] == null
            ? null
            : AnyTLSConfig.fromJson((j['anytls'] as Map).cast<String, dynamic>()),
        ssr: j['ssr'] == null
            ? null
            : SSRConfig.fromJson((j['ssr'] as Map).cast<String, dynamic>()),
        wireGuard: j['wireguard'] == null
            ? null
            : WireGuardConfig.fromJson((j['wireguard'] as Map).cast<String, dynamic>()),
      );
}
