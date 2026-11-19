/// 运行日志面板 — coreLogSnapshot 初始 + coreLogLines 增量，自动滚底、分级着色。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ui_kit/ui_kit.dart';

import '../providers.dart';

class LogPanel extends ConsumerStatefulWidget {
  const LogPanel({super.key});

  @override
  ConsumerState<LogPanel> createState() => _LogPanelState();
}

class _LogPanelState extends ConsumerState<LogPanel> {
  final ScrollController _scroll = ScrollController();
  bool _autoScroll = true;
  int _lastCount = 0;

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  void _maybeScroll(int count) {
    if (!_autoScroll || count == _lastCount) return;
    _lastCount = count;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!_scroll.hasClients) return;
      _scroll.jumpTo(_scroll.position.maxScrollExtent);
    });
  }

  Color _lineColor(String line) {
    final lower = line.toLowerCase();
    if (lower.contains('error') || lower.contains('fatal')) {
      return AntPalette.red;
    }
    if (lower.contains('warn')) return AntPalette.yellow;
    if (lower.contains('started') ||
        lower.contains('已启动') ||
        lower.contains('success')) {
      return AntPalette.green;
    }
    return AntPalette.text;
  }

  @override
  Widget build(BuildContext context) {
    final logs = ref.watch(logProvider);
    _maybeScroll(logs.length);

    return Container(
      color: AntPalette.bg,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // 工具栏
          Container(
            padding:
                const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
            decoration: const BoxDecoration(
              color: AntPalette.bgPanel,
              border:
                  Border(bottom: BorderSide(color: AntPalette.border)),
            ),
            child: Row(
              children: [
                const Text('运行日志',
                    style: TextStyle(
                        color: AntPalette.text, fontSize: 13)),
                const SizedBox(width: 10),
                Text('${logs.length} 条',
                    style: const TextStyle(
                        color: AntPalette.textDim, fontSize: 12)),
                const Spacer(),
                InkWell(
                  onTap: () => setState(() => _autoScroll = !_autoScroll),
                  child: Row(
                    children: [
                      SizedBox(
                        width: 14,
                        height: 14,
                        child: Checkbox(
                          value: _autoScroll,
                          onChanged: (v) =>
                              setState(() => _autoScroll = v ?? false),
                        ),
                      ),
                      const SizedBox(width: 4),
                      const Text('自动滚动',
                          style: TextStyle(
                              color: AntPalette.textDim, fontSize: 12)),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                TextButton(
                  onPressed: () =>
                      ref.read(logProvider.notifier).clear(),
                  child: const Text('清空',
                      style: TextStyle(
                          color: AntPalette.textDim, fontSize: 12)),
                ),
              ],
            ),
          ),
          // 日志体
          Expanded(
            child: logs.isEmpty
                ? const Center(
                    child: Text(
                      '暂无日志，启动 ant 后日志将在此显示',
                      style: TextStyle(
                          color: AntPalette.textDim, fontSize: 12),
                    ),
                  )
                : Container(
                    color: AntPalette.bg,
                    padding: const EdgeInsets.symmetric(horizontal: 8),
                    child: ListView.builder(
                      controller: _scroll,
                      itemCount: logs.length,
                      itemExtent: 18,
                      itemBuilder: (context, i) {
                        final line = logs[i];
                        return Text(
                          line,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: _lineColor(line),
                            fontSize: 11,
                            fontFamily: 'Consolas',
                          ),
                        );
                      },
                    ),
                  ),
          ),
        ],
      ),
    );
  }
}
