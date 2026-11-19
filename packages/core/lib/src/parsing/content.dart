/// 订阅内容解析入口 — 移植自 Go: backend/node/parser.go（ParseContent）
library;

import '../models/node.dart';
import 'common.dart';
import 'clash_yaml.dart';
import 'singbox_json.dart';
import 'uri_parser.dart';

/// 尝试从原始内容解析节点。
/// 优先级：sing-box JSON → Clash YAML → base64 解码后的 URI 列表 → 原始 URI 列表
/// 找不到任何节点抛 [ParseException]。
List<Node> parseContent(String content) {
  content = content.trim();

  try {
    final nodes = parseSingBoxJson(content);
    if (nodes.isNotEmpty) return nodes;
  } on ParseException {
    // fall through
  }
  try {
    final nodes = parseClashYaml(content);
    if (nodes.isNotEmpty) return nodes;
  } on ParseException {
    // fall through
  }
  final decoded = tryBase64Decode(content);
  if (decoded != null) {
    try {
      final nodes = parseUriLines(splitLines(decoded));
      if (nodes.isNotEmpty) return nodes;
    } on ParseException {
      // fall through
    }
  }
  return parseUriLines(splitLines(content));
}

List<String> splitLines(String s) {
  final lines = <String>[];
  for (final l in s.split('\n')) {
    final t = l.trim();
    if (t.isNotEmpty) lines.add(t);
  }
  return lines;
}

/// 逐行解析 URI，跳过无法解析的行；一个都解析不出来抛 [ParseException]。
List<Node> parseUriLines(List<String> lines) {
  final nodes = <Node>[];
  for (final line in lines) {
    try {
      nodes.add(parseUri(line));
    } on ParseException {
      continue;
    }
  }
  if (nodes.isEmpty) throw ParseException('没有找到可解析的节点');
  return nodes;
}
