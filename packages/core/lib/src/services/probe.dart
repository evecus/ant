/// 节点延迟探测（TCP 连接级）。
///
/// 与 Go 版 backend/probe 的差异：Go 版按内核出站构造真实代理链路测试；
/// 一期用 TCP 握手延迟近似（不经过代理），真实链路探测在 M4 接入。
library;

import 'dart:io';

/// 测量到 address:port 的 TCP 连接延迟（毫秒）；失败返回 -1。
Future<int> probeTcp(String address, int port,
    {Duration timeout = const Duration(seconds: 3)}) async {
  final sw = Stopwatch()..start();
  try {
    final socket = await Socket.connect(address, port, timeout: timeout);
    sw.stop();
    socket.destroy();
    return sw.elapsedMilliseconds;
  } catch (_) {
    return -1;
  }
}
