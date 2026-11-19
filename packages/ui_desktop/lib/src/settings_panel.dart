/// 设置页 — 对齐 Go 版 SettingsPanel.jsx：
/// 「程序 / 配置」两个子视图，全部设置项与提示文案一致，
/// 前端预校验 + 保存编排（核心在跑则停 → 重建 TUN/系统代理 → 拉起）。
///
/// 单内核版：去掉「代理内核」下拉（固定 ant），把原来按内核区分的 DNS
/// 设置映射到 ant 的 `dns.*` 字段。表单快照、预校验、保存编排、恢复默认、
/// 双视图切换、提示文案等逻辑全部保留。
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:ant_core/ant_core.dart';
import 'package:ui_kit/ui_kit.dart';

import 'actions.dart';
import 'providers.dart';

/// 系统代理监听地址可选项（ant 的 bind-address 只接受这两个值）。
const _listenAddrs = ['127.0.0.1', '0.0.0.0'];

const _logLevels = ['debug', 'info', 'warning', 'error'];

const _dnsModes = [
  ('redir-host', 'redir-host（真实 IP）'),
  ('fake-ip', 'fake-ip（假 IP，白名单真实解析）'),
];

/// ant 的 nameserver URL 协议（udp / tcp / tls / https，无 quic）。
const _antDnsTypes = ['udp', 'tcp', 'tls', 'https'];

/// DNS 类型默认端口（与后端 dnsDefaultPort 一致）
int _dnsDefaultPort(String t) =>
    const {'udp': 53, 'tcp': 53, 'tls': 853, 'https': 443}[t] ?? 53;

const _apiListens = ['127.0.0.1', '0.0.0.0'];

class SettingsPanel extends ConsumerStatefulWidget {
  const SettingsPanel({super.key});

  @override
  ConsumerState<SettingsPanel> createState() => _SettingsPanelState();
}

class _SettingsPanelState extends ConsumerState<SettingsPanel> {
  /// 表单快照（克隆，校验失败不污染运行中的设置对象）。
  late Settings _f;
  String _view = 'app'; // app = 程序 | conf = 配置
  bool _saving = false;

  // 文本/数字输入控制器
  final _subUa = TextEditingController();
  final _subTimeout = TextEditingController();
  final _logLines = TextEditingController();
  final _poll = TextEditingController();
  final _proxyPort = TextEditingController();
  final _tunMtu = TextEditingController();
  final _resolverDns = TextEditingController();
  final _directAddr = TextEditingController();
  final _directPort = TextEditingController();
  final _directPath = TextEditingController();
  final _proxyAddr = TextEditingController();
  final _proxyPortDns = TextEditingController();
  final _proxyPath = TextEditingController();
  final _fakeipFilter0 = TextEditingController();
  final _fakeipFilter1 = TextEditingController();
  final _fakeipRange = TextEditingController();
  final _apiPort = TextEditingController();
  final _apiSecret = TextEditingController();

  @override
  void initState() {
    super.initState();
    _loadForm(ref.read(antAppProvider).settings);
  }

  @override
  void dispose() {
    for (final c in [
      _subUa, _subTimeout, _logLines, _poll, _proxyPort, _tunMtu,
      _resolverDns, _directAddr, _directPort, _directPath,
      _proxyAddr, _proxyPortDns, _proxyPath,
      _fakeipFilter0, _fakeipFilter1, _fakeipRange,
      _apiPort, _apiSecret,
    ]) {
      c.dispose();
    }
    super.dispose();
  }

  /// 用设置快照填充表单（初始 & 恢复默认时复用）。
  void _loadForm(Settings s) {
    _f = Settings.fromJson(s.toJson());
    final b = _f.builtin;
    _f.subscriptions ??= [];
    _subUa.text = _f.subUserAgent;
    _subTimeout.text = '${_f.subTimeoutSec}';
    _logLines.text = '${_f.logMaxLines}';
    _poll.text = '${_f.pollIntervalMs}';
    _proxyPort.text = '${_f.proxyPort}';
    _tunMtu.text = '${_f.tunMTU}';
    _resolverDns.text = b.resolverDNS;
    _directAddr.text = b.directDNS.address;
    _directPort.text = b.directDNS.port > 0 ? '${b.directDNS.port}' : '';
    _directPath.text = b.directDNS.path;
    _proxyAddr.text = b.proxyDNS.address;
    _proxyPortDns.text = b.proxyDNS.port > 0 ? '${b.proxyDNS.port}' : '';
    _proxyPath.text = b.proxyDNS.path;
    _fakeipFilter0.text =
        b.fakeipFilter != null && b.fakeipFilter!.isNotEmpty
            ? b.fakeipFilter![0]
            : '';
    _fakeipFilter1.text =
        b.fakeipFilter != null && b.fakeipFilter!.length > 1
            ? b.fakeipFilter![1]
            : '';
    _fakeipRange.text = b.fakeipRange;
    _apiPort.text = '${b.api.port}';
    _apiSecret.text = b.api.secret;
  }

  /// 恢复默认（对齐 React handleReset）。
  void _reset() {
    setState(() => _loadForm(Settings.defaults()));
  }

  Future<void> _alert(String msg) async {
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        content: Text(msg),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('确定'),
          ),
        ],
      ),
    );
  }

  // ─── 保存 ─────────────────────────────────────────────────────────────────

  Future<void> _save() async {
    if (_saving) return;
    // 把控制器值写回表单快照（b 与 _f.builtin 是同一对象引用）
    final b = _f.builtin;
    _f
      ..subUserAgent = _subUa.text.trim()
      ..subTimeoutSec = int.tryParse(_subTimeout.text) ?? 0
      ..logMaxLines = int.tryParse(_logLines.text) ?? 0
      ..pollIntervalMs = int.tryParse(_poll.text) ?? 0
      ..proxyPort = int.tryParse(_proxyPort.text) ?? 0
      ..tunMTU = int.tryParse(_tunMtu.text) ?? 0;
    b
      ..resolverDNS = _resolverDns.text.trim()
      // 两个 fakeip-filter 输入框允许留空：写回前过滤空白项，与
      // settings.normalize() 的 trimNonEmpty 语义一致。默认只配置了 1 个
      // 规则集（第二个框为空），若不这里过滤，空串会触发下方预校验拦截，
      // 也会把空规则集名写进配置。
      ..fakeipFilter = [
        _fakeipFilter0.text.trim(),
        _fakeipFilter1.text.trim(),
      ].where((s) => s.isNotEmpty).toList()
      ..fakeipRange = _fakeipRange.text.trim();
    b.directDNS
      ..address = _directAddr.text.trim()
      ..port = int.tryParse(_directPort.text) ?? 0
      ..path = _directPath.text.trim();
    b.proxyDNS
      ..address = _proxyAddr.text.trim()
      ..port = int.tryParse(_proxyPortDns.text) ?? 0
      ..path = _proxyPath.text.trim();
    b.api
      ..port = int.tryParse(_apiPort.text) ?? 0
      ..secret = _apiSecret.text;

    // ── 前端预校验（对齐 React handleSave，alert 提示）──
    final port = _f.proxyPort;
    if (port < 1 || port > 65535) {
      await _alert('代理端口必须是 1-65535 的整数');
      return;
    }
    if (_f.subUserAgent.trim().isEmpty) {
      await _alert('订阅 User-Agent 不能为空');
      return;
    }
    final checks = [
      (_f.subTimeoutSec, 1, 600, '订阅超时'),
      (_f.logMaxLines, 50, 100000, '日志行数'),
      (_f.pollIntervalMs, 500, 60000, '轮询间隔'),
      (_f.tunMTU, 576, 65535, 'TUN MTU'),
    ];
    for (final (v, min, max, label) in checks) {
      if (v < min || v > max) {
        await _alert('$label必须是 $min-$max 的整数');
        return;
      }
    }
    if (!_isIP(b.resolverDNS)) {
      await _alert('解析 DNS（default-nameserver）必须是 IP 地址');
      return;
    }
    if (b.api.port < 1 || b.api.port > 65535) {
      await _alert('API 面板端口必须是 1-65535 的整数');
      return;
    }
    if (b.directDNS.address.trim().isEmpty) {
      await _alert('直连 DNS（direct-nameserver）地址不能为空');
      return;
    }
    if (b.proxyDNS.address.trim().isEmpty) {
      await _alert('代理 DNS（proxy-nameserver）地址不能为空');
      return;
    }
    for (final v in b.fakeipFilter ?? const <String>[]) {
      if (v.trim().isEmpty) {
        await _alert('fakeip-filter 规则集名不能为空');
        return;
      }
    }
    if (b.fakeipRange.trim().isEmpty) {
      await _alert('fakeip-range 不能为空');
      return;
    }

    // ── 保存编排（对齐 React handleSaveSettings）──
    setState(() => _saving = true);
    final app = ref.read(antAppProvider);
    try {
      await app.saveSettings(_f);
      final fresh = app.settings;
      // 核心在跑则先停 → 重写 TUN/系统代理配置 → 再拉起核心。
      // 整段编排包在 withRestartSuppression 内：期间"启动核心"开关等 UI
      // 保持"运行中"外观，不因内部停-启而视觉上关闭再开启。
      final wasRunning = app.coreRunning;
      final isBuiltin = isBuiltinMode(fresh.routingMode);
      final hasConfig = fresh.activeConfigPath().isNotEmpty || isBuiltin;
      if (wasRunning) {
        await app.withRestartSuppression(() async {
          try {
            await app.stopCore();
          } catch (_) {}
          if (hasConfig) {
            if (fresh.tunEnabled) {
              await app.disableTun();
              await app.enableTun();
            }
            if (await app.sysProxyEnabled()) {
              await app.disableSystemProxy();
              await app.enableSystemProxy();
            }
            await app.startCore();
          }
        });
      }
      ref.read(settingsVersionProvider.notifier).bump();
      ref.read(configFilesProvider.notifier).reload();
      if (mounted) {
        AppToast.show(
            context,
            wasRunning && hasConfig ? '设置已保存，核心已重启生效' : '设置已保存',
            ToastType.success);
      }
    } on AppException catch (e) {
      // 提权重启信号：Toast 后退出进程（对齐 actions.dart 统一处理）
      if (isElevationRestart(e)) {
        if (mounted) await showActionError(context, e);
        return;
      }
      ref.read(settingsVersionProvider.notifier).bump();
      if (mounted) {
        AppToast.show(context, '保存设置失败: ${e.message}', ToastType.error);
      }
    } on ParseException catch (e) {
      if (mounted) AppToast.show(context, '保存设置失败: ${e.message}', ToastType.error);
    } catch (e) {
      if (mounted) {
        AppToast.show(context, '保存设置失败: $e', ToastType.error);
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  bool _isIP(String s) {
    final t = s.trim();
    if (t.isEmpty) return false;
    final v4 = RegExp(r'^(\d{1,3}\.){3}\d{1,3}$');
    final v6 = RegExp(r'^[0-9a-fA-F:]+$');
    return v4.hasMatch(t) || v6.hasMatch(t);
  }

  // ─── 构建 ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final b = _f.builtin;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // ── 顶部视图切换 ──
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          decoration: const BoxDecoration(
            color: AntPalette.bgPanel,
            border: Border(bottom: BorderSide(color: AntPalette.border)),
          ),
          child: Row(
            children: [
              _viewBtn('程序', 'app'),
              const SizedBox(width: 6),
              _viewBtn('配置', 'conf'),
            ],
          ),
        ),
        // ── 表单体 ──
        Expanded(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (_view == 'app') ...[
                  _section('启动'),
                  _row('开机自启动', _check(_f.autoStart, (v) {
                    setState(() => _f.autoStart = v);
                  })),
                  _row('静默启动', _check(_f.silentStart, (v) {
                    setState(() => _f.silentStart = v);
                  })),
                  _section('内核'),
                  _row('代理内核', const Text('ant（单内核，配置为 YAML）',
                      style: TextStyle(color: AntPalette.textMid, fontSize: 12))),
                  _section('订阅'),
                  _row('User-Agent', _text(_subUa, hint: 'clash.meta')),
                  _row('请求超时', _num(_subTimeout)),
                  _section('日志与界面'),
                  _row('日志保留行数', _num(_logLines)),
                  _row('状态轮询间隔', _num(_poll)),
                ],
                if (_view == 'conf') ...[
                  _section('系统代理'),
                  _row(
                    '监听地址',
                    _dropdown(
                        _listenAddrs.contains(_f.proxyListen)
                            ? _f.proxyListen
                            : '127.0.0.1',
                        [for (final a in _listenAddrs) (a, a)],
                        (v) => setState(() => _f.proxyListen = v)),
                  ),
                  _row('代理端口', _num(_proxyPort)),
                  _row('退出时关闭系统代理', _check(_f.exitDisableProxy, (v) {
                    setState(() => _f.exitDisableProxy = v);
                  })),
                  _section('TUN 模式'),
                  _row('MTU', _num(_tunMtu)),
                  _row('strict_route', _check(_f.tunStrictRoute, (v) {
                    setState(() => _f.tunStrictRoute = v);
                  })),
                  _section('生成配置（内置路由模式）'),
                  _row(
                    '日志等级',
                    _dropdown(b.logLevel,
                        [for (final l in _logLevels) (l, l)],
                        (v) => setState(() => b.logLevel = v)),
                  ),
                  _row(
                    'DNS 模式',
                    _dropdown(b.dnsMode, _dnsModes,
                        (v) => setState(() => b.dnsMode = v)),
                  ),
                  _row('IPv6', _check(b.ipv6, (v) {
                    setState(() => b.ipv6 = v);
                  })),
                  _row('解析 DNS',
                      _text(_resolverDns, hint: 'bootstrap 纯 IP，如 223.5.5.5')),
                  _row('直连 DNS', _dnsServer(
                    type: b.directDNS.type,
                    onType: (v) => setState(() => b.directDNS.type = v),
                    addr: _directAddr,
                    port: _directPort,
                    path: _directPath,
                  )),
                  _row('代理 DNS', _dnsServer(
                    type: b.proxyDNS.type,
                    onType: (v) => setState(() => b.proxyDNS.type = v),
                    addr: _proxyAddr,
                    port: _proxyPortDns,
                    path: _proxyPath,
                  )),
                  _row('fakeip 过滤规则集',
                      _twoFields(_fakeipFilter0, _fakeipFilter1)),
                  _row('fakeip 网段',
                      _text(_fakeipRange, hint: '198.18.0.0/15')),
                  _section('API 面板'),
                  _row('启用 API 面板', _check(!b.apiDisabled, (v) {
                    setState(() => b.apiDisabled = !v);
                  })),
                  if (!b.apiDisabled) ...[
                    _row(
                      '监听地址',
                      _dropdown(
                          _apiListens.contains(b.api.listen)
                              ? b.api.listen
                              : '127.0.0.1',
                          [for (final a in _apiListens) (a, a)],
                          (v) => setState(() => b.api.listen = v)),
                    ),
                    _row('端口', _num(_apiPort)),
                    _row('密码', _text(_apiSecret, hint: '留空表示无密码')),
                  ],
                ],
                const SizedBox(height: 12),
                const Text(
                  '提示：「生成配置」仅作用于内置路由模式（绕过大陆 / GFW列表 / 全局代理）合成的配置文件；\n'
                  '代理端口 / TUN / 生成配置相关设置在下次「开启系统代理 / 开启 TUN / 启动核心」时生效；\n'
                  '日志行数与轮询间隔保存后立即生效。ant 的 DNS 上游用 URL 表示（udp/tcp/tls/https）。',
                  style: TextStyle(color: AntPalette.textDim, fontSize: 11),
                ),
              ],
            ),
          ),
        ),
        // ── 底部按钮 ──
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: const BoxDecoration(
            color: AntPalette.bgPanel,
            border: Border(top: BorderSide(color: AntPalette.border)),
          ),
          child: Row(
            children: [
              OutlinedButton(
                onPressed: _saving ? null : _reset,
                style: OutlinedButton.styleFrom(
                  foregroundColor: AntPalette.textMid,
                  side: const BorderSide(color: AntPalette.border),
                  padding: const EdgeInsets.symmetric(
                      horizontal: 18, vertical: 10),
                ),
                child: const Text('恢复默认'),
              ),
              const Spacer(),
              FilledButton(
                onPressed: _saving ? null : _save,
                style: FilledButton.styleFrom(
                  backgroundColor: AntPalette.accent,
                  padding: const EdgeInsets.symmetric(
                      horizontal: 24, vertical: 10),
                ),
                child: Text(_saving ? '保存中…' : '保存'),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _viewBtn(String label, String view) {
    final active = _view == view;
    return InkWell(
      onTap: () => setState(() => _view = view),
      borderRadius: BorderRadius.circular(7),
      child: Container(
        padding:
            const EdgeInsets.symmetric(horizontal: 16, vertical: 5),
        decoration: BoxDecoration(
          color: active ? AntPalette.accentDim : AntPalette.bgInput,
          borderRadius: BorderRadius.circular(7),
          border: Border.all(
            color: active ? AntPalette.accent : Colors.transparent,
          ),
        ),
        child: Text(label,
            style: TextStyle(
                color: active ? AntPalette.accent : AntPalette.textMid,
                fontSize: 12,
                fontWeight: active ? FontWeight.w600 : FontWeight.w400)),
      ),
    );
  }

  Widget _section(String title) => Padding(
        padding: const EdgeInsets.only(top: 14, bottom: 6),
        child: Text(title,
            style: const TextStyle(
                color: AntPalette.accent,
                fontSize: 12,
                fontWeight: FontWeight.w600)),
      );

  Widget _row(String label, Widget child) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.center,
          children: [
            SizedBox(
              width: 150,
              child: Text(label,
                  style: const TextStyle(
                      color: AntPalette.textMid, fontSize: 12)),
            ),
            Expanded(child: child),
          ],
        ),
      );

  Widget _dropdown<T>(T value, List<(T, String)> options,
          ValueChanged<T> onChanged) =>
      DropdownButtonFormField<T>(
        initialValue: value,
        isDense: true,
        isExpanded: true,
        items: [
          for (final (v, label) in options)
            DropdownMenuItem(
                value: v,
                child: Text(label,
                    style: const TextStyle(fontSize: 12),
                    overflow: TextOverflow.ellipsis)),
        ],
        onChanged: (v) => v != null ? onChanged(v) : null,
      );

  Widget _text(TextEditingController c, {String? hint}) => TextField(
        controller: c,
        decoration: InputDecoration(hintText: hint),
      );

  Widget _num(TextEditingController c) => TextField(
        controller: c,
        keyboardType: TextInputType.number,
      );

  Widget _check(bool value, ValueChanged<bool> onChanged) => Row(
        children: [
          SizedBox(
            width: 16,
            height: 16,
            child: Checkbox(value: value, onChanged: (v) => onChanged(v ?? false)),
          ),
        ],
      );

  /// DNS 服务器复合输入（类型 / 地址 / 端口 / 路径 → ant nameserver URL）。
  Widget _dnsServer({
    required String type,
    required ValueChanged<String> onType,
    required TextEditingController addr,
    required TextEditingController port,
    required TextEditingController path,
  }) =>
      Row(
        children: [
          SizedBox(
            width: 80,
            child: DropdownButtonFormField<String>(
              initialValue: type,
              isDense: true,
              items: [
                for (final t in _antDnsTypes)
                  DropdownMenuItem(
                      value: t,
                      child: Text(t, style: const TextStyle(fontSize: 12))),
              ],
              onChanged: (v) => v != null ? onType(v) : null,
            ),
          ),
          const SizedBox(width: 6),
          // 地址：弹性占满剩余宽度（最短 160，避免被挤压不可见）
          Expanded(
            child: ConstrainedBox(
              constraints: const BoxConstraints(minWidth: 160),
              child: TextField(
                controller: addr,
                decoration: const InputDecoration(hintText: '地址（必填）'),
              ),
            ),
          ),
          const SizedBox(width: 6),
          SizedBox(
            width: 90,
            child: TextField(
              controller: port,
              keyboardType: TextInputType.number,
              decoration: InputDecoration(
                  hintText: '${_dnsDefaultPort(type)}'),
            ),
          ),
          const SizedBox(width: 6),
          SizedBox(
            width: 130,
            child: TextField(
              controller: path,
              decoration: const InputDecoration(hintText: 'https 路径'),
            ),
          ),
        ],
      );

  Widget _twoFields(TextEditingController a, TextEditingController b) => Row(
        children: [
          Expanded(
              child: TextField(
                  controller: a,
                  decoration:
                      const InputDecoration(hintText: '规则集 1'))),
          const SizedBox(width: 6),
          Expanded(
              child: TextField(
                  controller: b,
                  decoration:
                      const InputDecoration(hintText: '规则集 2'))),
        ],
      );
}
