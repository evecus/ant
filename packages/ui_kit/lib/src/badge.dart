/// 协议类型徽章 — 对齐原 React 版 NodeList.jsx 的
/// PROTOCOL_COLORS / PROTOCOL_LABELS：每种协议一个专属颜色的小标签。
library;

import 'package:flutter/material.dart';

import 'palette.dart';

/// 协议 → 显示名（与原版 PROTOCOL_LABELS 一致）。
const Map<String, String> protocolLabels = {
  'vmess': 'VMess',
  'vless': 'VLESS',
  'trojan': 'Trojan',
  'ss': 'SS',
  'hysteria': 'Hy1',
  'hysteria2': 'Hy2',
  'tuic': 'TUIC',
  'socks': 'SOCKS',
  'http': 'HTTP',
  'anytls': 'AnyTLS',
  'ssr': 'SSR',
  'wireguard': 'WG',
  'ssh': 'SSH',
  'shadowtls': 'STLS',
};

/// 协议 → 专属颜色（与原版 PROTOCOL_COLORS 一致）。
const Map<String, Color> protocolColors = {
  'vmess': Color(0xFF5b7cf6),
  'vless': Color(0xFF3ddc84),
  'trojan': Color(0xFFf59e0b),
  'ss': Color(0xFFe879f9),
  'hysteria': Color(0xFFfb7185),
  'hysteria2': Color(0xFFf05252),
  'tuic': Color(0xFF22d3ee),
  'socks': Color(0xFF94a3b8),
  'http': Color(0xFFa3e635),
  'anytls': Color(0xFF34d399),
  'ssr': Color(0xFFf97316),
  'wireguard': Color(0xFF60a5fa),
  'ssh': Color(0xFFc084fc),
  'shadowtls': Color(0xFF2dd4bf),
};

/// 协议显示名；未知协议回退为大写原文。
String protocolDisplayName(String protocol) =>
    protocolLabels[protocol] ?? protocol.toUpperCase();

/// 协议颜色；未知协议回退为中性灰。
Color protocolColor(String protocol) =>
    protocolColors[protocol] ?? const Color(0xFF9ea3c0);

/// 小圆角协议徽章，如 [VMess] [Hy2]。
class ProtocolBadge extends StatelessWidget {
  final String protocol;

  const ProtocolBadge({super.key, required this.protocol});

  @override
  Widget build(BuildContext context) {
    final color = protocolColor(protocol);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.07),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.25)),
      ),
      child: Text(
        protocolDisplayName(protocol),
        style: TextStyle(
          color: color,
          fontSize: 11,
          height: 1.5,
          fontWeight: FontWeight.w600,
        ),
      ),
    );
  }
}

/// 通用信息小徽章（TLS / REALITY / 传输层等）。
class MetaBadge extends StatelessWidget {
  final String label;
  final Color color;

  const MetaBadge({super.key, required this.label, this.color = AntPalette.cyan});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 10,
          height: 1.5,
        ),
      ),
    );
  }
}
