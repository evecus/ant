/// 真实链路延迟/速度探测 — 移植自 Go: backend/probe/probe.go
///
/// 参考 v2rayN 的做法：为被测节点生成一份临时 ant 配置
/// （mixed-port 监听随机端口 + 节点 proxies 条目 + MATCH 该节点），
/// 拉起独立 ant 进程，通过该本地代理发起真实 HTTP 请求，测完立即杀进程
/// 并清理临时目录。
/// 延迟对齐 v2rayN GetRealPingTime：同一客户端连测 2 次 generate_204
/// （首次含建链/TLS 握手开销，第二次复用已建立的连接），取最小值；
/// 速度 = 经代理下载固定大小文件的吞吐（Mbps，最长 10 秒）。
library;

import 'dart:async';
import 'dart:io';

import 'package:yaml_writer/yaml_writer.dart';

import '../export/ant_write.dart' show nodeToAntProxy;
import '../models/node.dart';
import 'app.dart' show AppException;

const String _latencyURL = 'https://www.gstatic.com/generate_204';
const String _speedURL =
    'https://speed.cloudflare.com/__down?bytes=26214400'; // 25 MB

/// 测量节点真连接延迟（毫秒）。节点不可达 / 超时抛 [AppException]。
///
/// 对齐 v2rayN GetRealPingTime：同一 HttpClient 连测 2 次，取最小值。
/// 首次请求包含经代理建链 + TLS 握手的冷启动开销，第二次复用已建立的
/// 连接；v2rayN 也取两者较小值，因此冷启动开销不会虚高延迟数值。
Future<int> testLatencyReal(String coreBin, Node n) async {
  final instance = await _startTestInstance(coreBin, n);
  try {
    final client = _proxyClient(instance.port, const Duration(seconds: 3));
    try {
      final times = <int>[];
      for (var i = 0; i < 2; i++) {
        final sw = Stopwatch()..start();
        final HttpClientResponse resp;
        try {
          resp = await client
              .getUrl(Uri.parse(_latencyURL))
              .then((r) => r.close())
              .timeout(const Duration(seconds: 9));
        } on TimeoutException {
          throw AppException('连接失败: 请求超时');
        } catch (e) {
          throw AppException('连接失败: $e');
        }
        await resp.listen((_) {}).asFuture<void>();
        sw.stop();
        if (resp.statusCode < 200 || resp.statusCode > 399) {
          throw AppException('HTTP ${resp.statusCode}');
        }
        times.add(sw.elapsedMilliseconds);
        if (i == 0) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
      }
      return times.reduce((a, b) => a < b ? a : b);
    } finally {
      client.close(force: true);
    }
  } finally {
    await instance.stop();
  }
}

/// 测量节点下载速度（Mbps）。节点不可达 / 下载失败抛 [AppException]。
Future<double> testSpeedReal(String coreBin, Node n) async {
  final instance = await _startTestInstance(coreBin, n);
  try {
    final client = _proxyClient(instance.port, null);
    final req = await client.getUrl(Uri.parse(_speedURL));
    final resp = await req.close();
    if (resp.statusCode != 200) {
      throw AppException('HTTP ${resp.statusCode}');
    }
    var nBytes = 0;
    final start = DateTime.now();
    final maxTime = const Duration(seconds: 10);
    final done = Completer<void>();
    late final StreamSubscription<List<int>> sub;
    final timer = Timer(maxTime, () {
      sub.cancel();
      if (!done.isCompleted) done.complete();
    });
    sub = resp.listen(
      (chunk) => nBytes += chunk.length,
      onDone: () {
        if (!done.isCompleted) done.complete();
      },
      onError: (Object e) {
        if (!done.isCompleted) done.complete();
      },
      cancelOnError: true,
    );
    await done.future;
    timer.cancel();
    var elapsed = DateTime.now().difference(start);
    if (elapsed <= Duration.zero) elapsed = const Duration(milliseconds: 1);
    if (nBytes == 0) throw AppException('下载失败');
    // 部分实现提前超时截断读流，此时 nBytes 仍有效，按已有数据计算
    return nBytes * 8 / (elapsed.inMicroseconds / 1e6) / 1e6;
  } on AppException {
    rethrow;
  } catch (e) {
    throw AppException('下载失败: $e');
  } finally {
    await instance.stop();
  }
}

/// 构造经本地 mixed inbound 的 HTTP 客户端（timeout 为 null 表示不限时）。
HttpClient _proxyClient(int proxyPort, Duration? timeout) {
  final client = HttpClient();
  client.findProxy =
      (uri) => 'PROXY 127.0.0.1:$proxyPort';
  if (timeout != null) client.connectionTimeout = timeout;
  return client;
}

class _TestInstance {
  final int port;
  final Process process;
  final Directory tmpDir;

  _TestInstance(this.port, this.process, this.tmpDir);

  /// 停止测试进程并清理临时目录（测完立即杀，对齐 Go 版语义）。
  Future<void> stop() async {
    try {
      process.kill();
      await process.exitCode.timeout(const Duration(seconds: 3));
    } catch (_) {
      /* 忽略退出等待失败 */
    }
    try {
      for (final e in tmpDir.listSync()) {
        if (e is File) e.deleteSync();
      }
      tmpDir.deleteSync();
    } catch (_) {
      /* 清理失败不影响结果 */
    }
  }
}

/// 拉起临时 ant 实例（mixed-port + 节点 proxies + MATCH 该节点）。
Future<_TestInstance> _startTestInstance(String coreBin, Node n) async {
  if (!File(coreBin).existsSync()) {
    throw AppException('未找到 ant 内核: $coreBin（测试延迟/速度需要 bin/ant.exe）');
  }
  final Map<String, dynamic> proxy;
  try {
    proxy = nodeToAntProxy(n);
  } catch (e) {
    rethrow;
  }
  proxy['name'] = 'probe';

  final port = await _freePort();
  // ant 的极简配置：只开 mixed 入站，全部流量走被测节点。
  // 不写 dns: 块 → DNS 模块关闭，节点 server 域名由系统 resolver 解析。
  final cfg = <String, dynamic>{
    'log-level': 'error',
    'mixed-port': port,
    'bind-address': '127.0.0.1',
    'proxies': <dynamic>[proxy],
    'route': <dynamic>['MATCH,probe'],
  };

  final tmpDir = await Directory.systemTemp.createTemp('antgui-probe-');
  final cfgPath = '${tmpDir.path}${Platform.pathSeparator}config.yaml';
  try {
    await File(cfgPath).writeAsString(YamlWriter.config().write(cfg));
  } catch (e) {
    await _cleanupDir(tmpDir);
    throw AppException('写入测试配置失败: $e');
  }

  Process process;
  try {
    process = await Process.start(coreBin, ['-c', cfgPath]);
  } catch (e) {
    await _cleanupDir(tmpDir);
    throw AppException('启动测试进程失败: $e');
  }
  final inst = _TestInstance(port, process, tmpDir);

  // 进程提前退出则报错（节点配置可能不被当前内核支持）
  var exitedEarly = false;
  unawaited(process.exitCode.then((code) {
    if (code != 0) exitedEarly = true;
  }));

  // 等待 mixed 入站就绪（最多 5 秒）
  final addr = InternetAddress.loopbackIPv4;
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (true) {
    if (exitedEarly) {
      await inst.stop();
      throw AppException('测试进程提前退出（节点配置可能不被当前内核支持）');
    }
    try {
      final socket = await Socket.connect(addr, port,
          timeout: const Duration(milliseconds: 300));
      socket.destroy();
      return inst;
    } catch (_) {
      if (DateTime.now().isAfter(deadline)) {
        await inst.stop();
        throw AppException('测试实例启动超时');
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
  }
}

Future<int> _freePort() async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = server.port;
  await server.close();
  return port;
}

Future<void> _cleanupDir(Directory dir) async {
  try {
    for (final e in dir.listSync()) {
      if (e is File) e.deleteSync();
    }
    dir.deleteSync();
  } catch (_) {}
}
