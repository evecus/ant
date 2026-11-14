/// 解析层公共工具 — 移植自 Go: backend/node/parser.go 底部 helpers
library;

import 'dart:convert';
import 'dart:math';

import '../models/node.dart';

/// 解析失败（对应 Go 版的 error 返回值）。
class ParseException implements Exception {
  final String message;
  ParseException(this.message);

  @override
  String toString() => message;
}

Random _rng = Random.secure();

/// 生成 UUID v4（对应 Go 的 uuid.New().String()）。
String newUuid() {
  final b = List<int>.generate(16, (_) => _rng.nextInt(256));
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10
  String hex(int i) => b[i].toRadixString(16).padLeft(2, '0');
  final h = List.generate(16, hex).join();
  return '${h.substring(0, 8)}-${h.substring(8, 12)}-'
      '${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}';
}

/// 宽容 base64 解码：依次尝试 std/url、带/不带 padding。
/// 全部失败返回 null（对应 Go 的 base64Decode error）。
String? tryBase64Decode(String s) {
  s = s.trim();
  // 统一字母表为 url-safe，去掉 padding 后按长度补齐。
  final norm = s.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  final pad = (4 - norm.length % 4) % 4;
  final padded = norm + '=' * pad;
  try {
    final bytes = base64Url.decode(padded);
    // Go 版用 string(b) 原样转字符串；宽容解码避免坏字节直接抛异常。
    return utf8.decode(bytes, allowMalformed: true);
  } on FormatException {
    return null;
  }
}

/// 将 URI "type" / vmess-json "net" 值映射为 sing-box transport 类型名。
/// kcp 为 Xray 专有，拒绝。失败抛 [ParseException]。
/// 返回空字符串表示 tcp/raw → 不写 transport 块。
String normalizeNetwork(String net) {
  switch (net.trim().toLowerCase()) {
    case '':
    case 'tcp':
    case 'raw':
    case 'none':
      return ''; // tcp / raw / "" → 无 transport 块
    case 'h2':
    case 'http':
      return 'http';
    case 'ws':
      return 'ws';
    case 'grpc':
    case 'gun':
      return 'grpc';
    case 'httpupgrade':
      return 'httpupgrade';
    case 'quic':
      return 'quic';
    case 'xhttp':
    case 'splithttp':
      return 'xhttp';
    case 'kcp':
      throw ParseException('sing-box 不支持传输层 "$net" (仅 Xray 支持)');
    default:
      throw ParseException('未知传输层类型: "$net"');
  }
}

/// 解析 alpn 逗号串为列表；空串返回 null。
List<String>? parseAlpn(String s) {
  if (s.isEmpty) return null;
  final result = <String>[];
  for (final p in s.split(',')) {
    final t = p.trim();
    if (t.isNotEmpty) result.add(t);
  }
  return result.isEmpty ? null : result;
}

/// 动态值转 int（Go 的 toInt）：num / 数字字符串。
int dynToInt(dynamic v) {
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? 0;
  return 0;
}

String orDefault(String s, String def) => s.isEmpty ? def : s;

/// Go strconv.ParseBool 语义：失败一律视为 false。
bool parseBoolLoose(String v) {
  switch (v) {
    case '1':
    case 't':
    case 'T':
    case 'true':
    case 'TRUE':
    case 'True':
      return true;
    default:
      return false;
  }
}

/// query 布尔参数：等于 "1"/"true"/"yes"（不区分大小写）为真。
bool queryBool(String? v) {
  final t = (v ?? '').trim().toLowerCase();
  return t == '1' || t == 'true' || t == 'yes';
}

/// 返回第一个非空的 int 值（对应 Go 的 queryFirstInt）。
/// 值允许 "100 mbps" 后缀（精确匹配 " mbps" 后缀后裁掉）。
int queryFirstInt(Map<String, String> q, List<String> keys) {
  for (final k in keys) {
    final v = q[k];
    if (v != null && v.isNotEmpty) {
      var s = v;
      if (s.endsWith(' mbps')) s = s.substring(0, s.length - ' mbps'.length);
      final n = int.tryParse(s);
      if (n != null) return n;
    }
  }
  return 0;
}

/// Go 的 url.QueryUnescape 宽容版：解码 %XX 与 '+'→空格；失败原样返回。
String queryUnescapeLenient(String s) {
  if (!s.contains('%')) return s.replaceAll('+', ' ');
  try {
    return Uri.decodeQueryComponent(s);
  } on ArgumentError {
    return s;
  }
}

/// URI userinfo 段解码（Go 的 url.User.Username()/Password() 已是解码值）。
/// 含 '%' 时再走一次宽容解码；失败原样返回。
String decodeUserInfo(String s) => queryUnescapeLenient(s);

/// 规整嵌在 ws path 里的 early-data 参数（对齐 v2rayN SingboxOutboundService
/// 对生成 sing-box ws transport 的处理）。
///
/// 机场订阅常见写法是把 ed/eh 拼进 path，如 `/vless-argo?ed=2560` 或
/// URI 中 `path=%2Fvless-argo%3Fed%3D2560`。sing-box / mihomo 内核只认
/// 独立的 `max_early_data` / `early-data-header-name` 字段，path 里的
/// `?ed=` 不会被识别 —— 既丢失 0-RTT，也会因服务器路径校验不过而无法连接。
/// 此处把 `ed` / `eh` 从 path 中提取到字段并清理 path，幂等可重复调用。
void normalizeWsEarlyData(TransportConfig t) {
  if (t.type != 'ws' || t.path.isEmpty) return;
  var touched = false;

  final edRe = RegExp(r'[?&]ed=(\d+)');
  final edMatch = edRe.firstMatch(t.path);
  if (edMatch != null) {
    final ed = int.tryParse(edMatch.group(1)!) ?? 0;
    if (ed > 0 && t.maxEarlyData == 0) {
      t.maxEarlyData = ed;
      t.earlyDataHeaderName =
          orDefault(t.earlyDataHeaderName, 'Sec-WebSocket-Protocol');
    }
    t.path = t.path.replaceAll(edRe, '');
    touched = true;
  }

  final ehRe = RegExp(r'[?&]eh=([^&]+)');
  final ehMatch = ehRe.firstMatch(t.path);
  if (ehMatch != null) {
    final eh = queryUnescapeLenient(ehMatch.group(1)!);
    if (eh.isNotEmpty) t.earlyDataHeaderName = eh;
    t.path = t.path.replaceAll(ehRe, '');
    touched = true;
  }

  if (touched) {
    var p = t.path.replaceFirst('?&', '?');
    while (p.endsWith('?') || p.endsWith('&')) {
      p = p.substring(0, p.length - 1);
    }
    t.path = p;
  }
}
