/// config 包测试 — 移植自 Go: backend/config/builtin_test.go + manager_test.go，
/// 用例数据原样照抄，作为移植验收标准；单内核版断言全部改为 ant YAML 语义。
///
/// Go 版对生成配置做精确字符串比较的地方，本移植改为「解析后结构比较」
/// （断言点一一对应），因此 ant YAML 的输出只需保证反序列化后结构等价。
library;

import 'dart:io';

import 'package:ant_core/src/config/builtin.dart';
import 'package:ant_core/src/config/settings.dart';
import 'package:ant_core/src/config/settings_manager.dart';
import 'package:ant_core/src/export/ant_write.dart' show antProxyName;
import 'package:ant_core/src/models/node.dart';
import 'package:ant_core/src/parsing/common.dart';
import 'package:test/test.dart';
import 'package:yaml/yaml.dart';

// ─── 测试辅助 ────────────────────────────────────────────────────────────────

Map<String, dynamic> parseYAMLBytes(String data) =>
    _yamlToDart(loadYaml(data)) as Map<String, dynamic>;

dynamic _yamlToDart(dynamic v) {
  if (v is YamlMap) {
    return {
      for (final e in v.entries) e.key.toString(): _yamlToDart(e.value),
    };
  }
  if (v is YamlList) return [for (final e in v) _yamlToDart(e)];
  return v;
}

List<String> toStringSlice(List<dynamic> v) => [for (final e in v) e as String];

/// 临时目录（对应 Go 的 t.TempDir()）。
Directory tempDir() {
  final dir = Directory.systemTemp.createTempSync('ant_config_test_');
  addTearDown(() {
    try {
      dir.deleteSync(recursive: true);
    } catch (_) {}
  });
  return dir;
}

/// 在 rulesDir/ant/ 下写一个 .ars 规则集文件。
void writeRuleFile(String rulesDir, String tag) {
  final dir = Directory('$rulesDir/$antRuleDirName');
  dir.createSync(recursive: true);
  File('${dir.path}/$tag.$antRuleExt').writeAsStringSync('x');
}

/// 补齐所有模式 × DNS 模式所需的规则集文件。
void writeAllRuleFiles(String rulesDir) {
  for (final dnsMode in [dnsModeRedirHost, dnsModeFakeIP]) {
    for (final mode in [modeBypass, modeBlacklist, modeGlobal]) {
      for (final tag in builtinRuleFilesAll(mode, dnsMode)) {
        writeRuleFile(rulesDir, tag);
      }
    }
  }
}

/// 测试用节点（vless + tls）。
Node testNode() => Node(
      id: 'n1',
      protocol: 'vless',
      address: 'example.com',
      port: 443,
      vless: VLESSConfig(
        uuid: 'b831381d-6324-4d53-ad4f-8cda48b30811',
        tls: true,
        sni: 'example.com',
      ),
    );

/// 一份默认值完整、可按需覆盖的 BuiltinSettings。
BuiltinSettings builtinCfg({
  String dnsMode = dnsModeRedirHost,
  bool ipv6 = false,
  bool apiDisabled = false,
  DNSServer? directDNS,
  DNSServer? proxyDNS,
  List<String>? fakeipFilter,
}) {
  final b = defaultBuiltin();
  b.dnsMode = dnsMode;
  b.ipv6 = ipv6;
  b.apiDisabled = apiDisabled;
  if (directDNS != null) b.directDNS = directDNS;
  if (proxyDNS != null) b.proxyDNS = proxyDNS;
  if (fakeipFilter != null) b.fakeipFilter = fakeipFilter;
  return b;
}

// ─── 测试 ────────────────────────────────────────────────────────────────────

void main() {
  group('builtin', () {
    // TestBuiltinNameRoundTrip
    test('name round trip', () {
      for (final mode in [modeBypass, modeBlacklist, modeGlobal]) {
        final name = builtinDisplayName(mode);
        expect(name, isNotNull);
        expect(name, startsWith(builtinPrefix));
        final got = parseBuiltinName(name!);
        expect(got, mode);
      }
      expect(parseBuiltinName('config.yaml'), isNull,
          reason: '真实文件名不应被解析为内置模式');
      expect(isBuiltinMode(modeCustom), isFalse, reason: 'custom 不应被视为内置模式');
      expect(builtinDisplayNames(), hasLength(3));
    });

    // TestCheckRuleFiles（内置 .ars 二进制规则集）
    test('check rule files', () {
      final dir = tempDir();
      // redir-host：global 也要 private 两个
      expect(() => checkRuleFiles(modeGlobal, dnsModeRedirHost, dir.path),
          throwsA(predicate<ParseException>((e) =>
              e.toString().contains('run/rules/ant/geosite-private.ars') &&
              e.toString().contains('run/rules/ant/geoip-private.ars'))),
          reason: '空目录应报缺失，且路径指向 run/rules/ant/*.ars');
      // fake-ip：额外要求 fakeipfilter
      expect(() => checkRuleFiles(modeGlobal, dnsModeFakeIP, dir.path),
          throwsA(predicate<ParseException>(
              (e) => e.toString().contains('geosite-fakeipfilter'))));

      // 补齐全部文件后两种 DNS 模式、三种路由模式都通过
      writeAllRuleFiles(dir.path);
      for (final dnsMode in [dnsModeRedirHost, dnsModeFakeIP]) {
        for (final mode in [modeBypass, modeBlacklist, modeGlobal]) {
          expect(() => checkRuleFiles(mode, dnsMode, dir.path), returnsNormally,
              reason: '补齐后不应报错');
        }
      }
      // redir-host 模式不校验用户自定义 fakeip-filter 规则集
      expect(
          () => checkRuleFiles(modeGlobal, dnsModeRedirHost, dir.path,
              extraRuleFiles: const ['custom-not-present']),
          returnsNormally,
          reason: 'redir-host 不引用 fakeip-filter，不要求其文件存在');
      // fake-ip 模式会校验用户自定义规则集
      expect(
          () => checkRuleFiles(modeGlobal, dnsModeFakeIP, dir.path,
              extraRuleFiles: const ['custom-not-present']),
          throwsA(predicate<ParseException>(
              (e) => e.toString().contains('custom-not-present'))));
      // 全面切换 .ars 后，只存在同名 .yaml 不算（fail-fast 报缺失）
      final dir2 = tempDir();
      for (final tag in builtinRuleFilesAll(modeGlobal, dnsModeRedirHost)) {
        final d = Directory('${dir2.path}/$antRuleDirName')
          ..createSync(recursive: true);
        File('${d.path}/$tag.yaml').writeAsStringSync('x');
      }
      expect(() => checkRuleFiles(modeGlobal, dnsModeRedirHost, dir2.path),
          throwsA(isA<ParseException>()),
          reason: '仅存在 .yaml 应报缺失（内置规则集已全面切到 .ars）');
    });

    // TestBuildBuiltin（三模板：规则顺序 / 规则集 / DNS / 入站 / 面板 / 缓存）
    test('build builtin ant：三模板规则与结构', () {
      final cases = [
        // mode, wantMatch, wantSets, wantBypass
        (modeBypass, 'MATCH,$antProxyName', 5, true),
        (modeBlacklist, 'MATCH,DIRECT', 11, false),
        (modeGlobal, 'MATCH,$antProxyName', 2, false),
      ];
      for (final (mode, wantMatch, wantSets, wantBypass) in cases) {
        final opts = BuiltinOptions(
          mode: mode,
          tunEnabled: true,
          tunMTU: 9000,
          tunStrictRoute: true,
          proxyEnabled: true,
          proxyListen: '127.0.0.1',
          proxyPort: 2080,
          rulesDir: '/run/rules',
          uiDir: '/run/ui',
          cachePath: '/run/cache.db',
        );
        final cfg = parseYAMLBytes(buildBuiltinConfig(opts, testNode()));

        // ── route：MATCH 收尾 + 私网直连 + no-resolve 策略 ──
        final rules = toStringSlice(cfg['route'] as List<dynamic>);
        expect(rules.last, wantMatch, reason: '[$mode] 末条规则');
        final rulesSet = rules.toSet();
        expect(rulesSet.contains('RULE-SET,geosite-private,DIRECT'), isTrue,
            reason: '[$mode] 应含 geosite-private 直连');
        expect(rulesSet.contains('RULE-SET,geoip-private,DIRECT,no-resolve'),
            isTrue, reason: '[$mode] 私网 IP 规则应带 no-resolve');
        if (wantBypass) {
          expect(rulesSet.contains('RULE-SET,geoip-cn,DIRECT'), isTrue,
              reason: '[$mode] geoip-cn 规则不应带 no-resolve（需解析域名）');
          final idxCN = rules.indexOf('RULE-SET,geosite-cn,DIRECT');
          final idxMatch = rules.indexOf(wantMatch);
          expect(idxCN, greaterThanOrEqualTo(0), reason: '[$mode] geosite-cn 直连缺失');
          expect(idxCN <= idxMatch, isTrue, reason: '[$mode] geosite-cn 直连须在 MATCH 之前');
        }
        if (mode == modeBlacklist) {
          expect(rulesSet.contains('RULE-SET,geosite-gfw,$antProxyName'), isTrue,
              reason: '[$mode] 应含被墙域名走代理');
        }

        // ── rule-providers：file / ars / behavior ──
        final providers = cfg['rule-providers'] as Map<String, dynamic>;
        expect(providers, hasLength(wantSets), reason: '[$mode] rule-providers 数量');
        providers.forEach((name, p) {
          final pm = p as Map<String, dynamic>;
          expect(pm['type'], 'file', reason: '[$mode] provider $name 应为 file');
          expect(pm['format'], 'ars', reason: '[$mode] provider $name 应为 ars 二进制');
          final wantBehavior = isGeositeTag(name) ? 'domain' : 'ip';
          expect(pm['behavior'], wantBehavior,
              reason: '[$mode] provider $name behavior（ant 认 domain/ip）');
          expect((pm['path'] as String).endsWith('$name.$antRuleExt'), isTrue,
              reason: '[$mode] provider $name path 应指向 .ars 规则集');
        });

        // ── proxies / mixed-port / tun（route 直引用节点名，无 proxy-groups）──
        final proxies = cfg['proxies'] as List<dynamic>;
        expect(proxies, hasLength(1), reason: '[$mode] proxies 应只含当前节点');
        expect((proxies[0] as Map)['name'], antProxyName);
        expect(cfg.containsKey('proxy-groups'), isFalse,
            reason: '[$mode] route 直接引用节点名，无需 proxy-groups');
        expect(cfg['mixed-port'], 2080, reason: '[$mode] 系统代理开 → mixed-port');
        expect(cfg['bind-address'], '127.0.0.1', reason: '[$mode] bind-address');
        final tun = cfg['tun'] as Map<String, dynamic>;
        expect(tun['enable'], true, reason: '[$mode] tun.enable');
        expect(tun['auto-route'], true, reason: '[$mode] tun.auto-route');
        expect(tun['strict-route'], true, reason: '[$mode] tun.strict-route');
        expect(tun['mtu'], 9000, reason: '[$mode] tun.mtu');
        expect(tun.containsKey('address'), isFalse,
            reason: '[$mode] tun.address 由内核自行处理，GUI 不生成');
        expect(tun.containsKey('auto-detect-interface'), isFalse,
            reason: '[$mode] tun.auto-detect-interface 由内核自行处理');
        expect(tun.containsKey('stack'), isFalse,
            reason: '[$mode] ant 为内核 NAT 系统栈，无 stack 字段');

        // ── 顶层：日志 / 嗅探 / 面板 / 缓存 / ipv6 ──
        expect(cfg['log-level'], 'warn', reason: '[$mode] warning → ant 的 warn');
        expect(cfg['sniff'], true, reason: '[$mode] 嗅探开启');
        expect(cfg['ipv6'], false, reason: '[$mode] 默认 ipv6 关闭');
        expect(cfg['api'], '127.0.0.1:9090', reason: '[$mode] ant api 面板');
        expect(cfg['api-secret'], '', reason: '[$mode] 默认空密钥');
        expect(cfg['api-connection-record'], true, reason: '[$mode] 常驻连接记录');
        expect(cfg['cache'], true, reason: '[$mode] 持久化缓存开启');
        expect(cfg['cache-file'], '/run/cache.db', reason: '[$mode] cache-file');

        // ── dns：rule-follow-route 分流 / bootstrap（无监听端口）──
        _assertAntDNS(cfg['dns'], ipv6: false, fakeip: false);
      }
    });

    // TestBuildBuiltinFakeIP
    test('build builtin ant：fake-ip 模式', () {
      final opts = BuiltinOptions(
        mode: modeBypass,
        rulesDir: '/run/rules',
        cfg: builtinCfg(dnsMode: dnsModeFakeIP, ipv6: true),
      );
      final cfg = parseYAMLBytes(buildBuiltinConfig(opts, testNode()));
      final dns = cfg['dns'] as Map<String, dynamic>;
      expect(dns['mode'], 'fakeip', reason: 'ant 的 dns.mode 为 fakeip（不带连字符）');
      expect(dns['fakeip-range'], '198.18.0.0/15');
      expect(toStringSlice(dns['fakeip-filter'] as List<dynamic>),
          contains('geosite-fakeipfilter'));
      expect(dns['fakeip-filter-mode'], 'blacklist');
      expect(dns['fakeip6-range'], 'fc00::/18', reason: 'IPv6 开 → fakeip6-range');
      expect(dns['ipv6'], true);
      expect(cfg['ipv6'], true);
      final providers = cfg['rule-providers'] as Map<String, dynamic>;
      expect(providers.containsKey('geosite-fakeipfilter'), isTrue,
          reason: 'fake-ip 模式应生成 fakeipfilter provider');
      expect(cfg.containsKey('tun'), isFalse, reason: '本用例未开 TUN');
    });

    // TestBuildBuiltinDNSFields：默认端口 / https path
    test('build builtin ant：DNS 服务器字段', () {
      final opts = BuiltinOptions(
        mode: modeGlobal,
        rulesDir: '/run/rules',
        cfg: builtinCfg(
          directDNS: DNSServer(
              type: 'https', address: 'dns.alidns.com', path: '/dns-query'),
          proxyDNS: DNSServer(type: 'udp', address: '8.8.8.8', port: 53),
        ),
      );
      final cfg = parseYAMLBytes(buildBuiltinConfig(opts, testNode()));
      final dns = cfg['dns'] as Map<String, dynamic>;
      expect(dns['direct-nameserver'], 'https://dns.alidns.com/dns-query',
          reason: 'https 端口 0 → 默认 443 且省略端口，仅写 path');
      expect(dns['proxy-nameserver'], 'udp://8.8.8.8:53');
      expect(dns['default-nameserver'], '223.5.5.5:53',
          reason: 'bootstrap 必须纯 IP 且补 :53');
    });

    test('build builtin ant：DNS 类型默认端口（tls 853）', () {
      final opts = BuiltinOptions(
        mode: modeGlobal,
        rulesDir: '/run/rules',
        cfg: builtinCfg(directDNS: DNSServer(type: 'tls', address: '1.1.1.1')),
      );
      final cfg = parseYAMLBytes(buildBuiltinConfig(opts, testNode()));
      expect((cfg['dns'] as Map)['direct-nameserver'], 'tls://1.1.1.1:853');
    });

    // TestBuildBuiltinIPv6：TUN 地址补 IPv6 段
    test('build builtin ant：IPv6 开启时 TUN 双栈地址', () {
      final opts = BuiltinOptions(
        mode: modeBypass,
        tunEnabled: true,
        tunMTU: 9000,
        rulesDir: '/run/rules',
        cfg: builtinCfg(ipv6: true),
      );
      final cfg = parseYAMLBytes(buildBuiltinConfig(opts, testNode()));
      final tunAddr = (cfg['tun'] as Map)['address'] as List<dynamic>;
      expect(tunAddr, hasLength(2), reason: 'IPv6 开启时 TUN 地址应含 IPv6 段');
      expect(tunAddr[1], 'fdfe:dcba:9876::1/126');
      expect(cfg['ipv6'], true);
      expect((cfg['dns'] as Map)['ipv6'], true);
    });

    // TestBuildBuiltinInboundSwitches
    test('build builtin ant：TUN/系统代理全关时不生成入站', () {
      final opts = BuiltinOptions(mode: modeGlobal, rulesDir: '/run/rules');
      final cfg = parseYAMLBytes(buildBuiltinConfig(opts, testNode()));
      expect(cfg.containsKey('tun'), isFalse, reason: 'TUN 关 → 无 tun 段');
      expect(cfg.containsKey('mixed-port'), isFalse,
          reason: '系统代理关 → 无 mixed-port');
    });

    // TestBuildBuiltinAPIDisabled：面板关闭但缓存仍生成
    test('build builtin ant：关闭 API 面板', () {
      final opts = BuiltinOptions(
        mode: modeBypass,
        rulesDir: '/run/rules',
        cachePath: '/run/cache.db',
        cfg: builtinCfg(apiDisabled: true),
      );
      final cfg = parseYAMLBytes(buildBuiltinConfig(opts, testNode()));
      for (final k in ['api', 'api-secret']) {
        expect(cfg.containsKey(k), isFalse, reason: '面板关闭时不应生成 $k');
      }
      expect(cfg['cache'], true, reason: '缓存与面板无关，仍应生成');
      expect(cfg['cache-file'], '/run/cache.db');
    });

    // TestBuildBuiltinErrors
    test('build builtin errors', () {
      final opts = BuiltinOptions(mode: modeBypass, rulesDir: '/run/rules');
      expect(() => buildBuiltinConfig(opts, null), throwsA(isA<ParseException>()),
          reason: '无节点应报错');
      expect(
          () => buildBuiltinConfig(BuiltinOptions(mode: modeCustom), testNode()),
          throwsA(isA<ParseException>()),
          reason: 'custom 模式不应生成内置配置');
    });

    // TestSettingsRoutingModeDefaults
    test('settings routing mode defaults 与校验', () {
      var s = Settings();
      s.applyDefaults();
      expect(s.routingMode, modeCustom, reason: '缺省路由模式应为 custom');
      expect(s.builtin.logLevel, 'warning');
      expect(s.builtin.dnsMode, dnsModeRedirHost);
      expect(s.builtin.api.port, 9090);
      expect(s.builtin.resolverDNS, '223.5.5.5');
      expect(s.builtin.directDNS.address, isNotEmpty);
      expect(s.builtin.proxyDNS.address, isNotEmpty);
      expect(s.builtin.fakeipRange, isNotEmpty);
      expect(antConfigExts, containsAll(<String>['.yaml', '.yml']),
          reason: 'ant 配置扩展名为 YAML');

      final d = Settings.defaults();
      expect(d.builtin.api.port, 9090, reason: 'Defaults() 的 builtin 段缺省');
      expect(d.builtin.resolverDNS, isNotEmpty);
      expect(d.builtin.directDNS.address, isNotEmpty);

      void expectInvalid(void Function(Settings) mutate) {
        final t = Settings();
        t.applyDefaults();
        mutate(t);
        expect(() => t.validate(), throwsA(isA<ParseException>()));
      }

      expectInvalid((t) => t.routingMode = 'bogus');
      expectInvalid((t) => t.builtin.dnsMode = 'bogus');
      expectInvalid((t) => t.builtin.resolverDNS = 'not-an-ip');
      expectInvalid((t) => t.builtin.api.port = 0);
      expectInvalid((t) => t.builtin.api.listen = '::');
      expectInvalid((t) => t.builtin.directDNS.type = 'bogus');
      expectInvalid((t) => t.builtin.proxyDNS.address = '');
      expectInvalid((t) => t.builtin.fakeipRange = '');
      expectInvalid((t) => t.proxyListen = '::');
      expect(() {
        final t = Settings();
        t.applyDefaults();
        t.validate();
      }, returnsNormally, reason: '合法默认设置不应报错');
    });

    test('settings 旧版字段兼容与 normalize', () {
      final s = Settings.fromJson(<String, dynamic>{
        'core': 'mihomo',
        'config_path': '',
        'config_path_singbox': 'config.json',
        'config_path_mihomo': 'white.yaml',
        'proxy_listen': '::',
        'routing_mode': 'custom',
        'builtin': <String, dynamic>{'clash_api_disabled': true},
      });
      expect(s.configPath, 'white.yaml', reason: '旧 mihomo YAML 路径作为 fallback');
      expect(s.builtin.apiDisabled, isTrue, reason: '旧 clash_api_disabled 兼容');
      s.normalize();
      expect(s.proxyListen, '127.0.0.1', reason: ':: 收敛为 127.0.0.1');
      expect(() => s.validate(), returnsNormally);
    });
  });

  group('manager', () {
    // TestSettingsPathAndBuiltinDefaults
    test('settings path and builtin defaults', () {
      final dir = tempDir();
      const old = '''
{
  "core": "sing-box",
  "config_path": "",
  "config_path_singbox": "config.json",
  "config_path_mihomo": "white.yaml",
  "routing_mode": "custom"
}''';
      File('${dir.path}/settings.json').writeAsStringSync(old);
      final m = SettingsManager('${dir.path}/settings.json');
      m.load();
      final s = m.settings;
      expect(s.configPath, 'white.yaml', reason: '旧 mihomo YAML 路径应作为 fallback');
      expect(s.builtin.logLevel, 'warning');
      expect(s.builtin.apiDisabled, false);
      s.setConfigPath('config.yaml');
      m.save();
      final m2 = SettingsManager('${dir.path}/settings.json');
      m2.load();
      expect(m2.settings.configPath, 'config.yaml');
      expect(m2.settings.builtin.apiDisabled, false);
      m2.settings.builtin.apiDisabled = true;
      m2.save();
      final m3 = SettingsManager('${dir.path}/settings.json');
      m3.load();
      expect(m3.settings.builtin.apiDisabled, true);
      // 单内核：settings.json 不再写出 core / 分内核路径
      final raw = File('${dir.path}/settings.json').readAsStringSync();
      expect(raw.contains('"core"'), isFalse);
      expect(raw.contains('config_path_singbox'), isFalse);
      expect(raw.contains('config_path_mihomo'), isFalse);
    });

    test('settings manager 文件不存在时用全新默认', () {
      final dir = tempDir();
      final m = SettingsManager('${dir.path}/settings.json');
      m.load();
      expect(m.settings.routingMode, modeCustom);
      expect(m.settings.builtin.api.port, 9090);
      expect(() => m.save(), returnsNormally);
    });
  });
}

/// 校验 ant DNS 段：rule-follow-route 分流 + bootstrap + 模式（Windows 省略监听端口）。
void _assertAntDNS(dynamic dnsV, {required bool ipv6, required bool fakeip}) {
  final dns = dnsV as Map<String, dynamic>?;
  expect(dns, isNotNull, reason: 'dns 段缺失');
  expect(dns!['enable'], true);
  expect(dns['rule-follow-route'], true,
      reason: 'ant DNS 复用 route 规则决定上游');
  expect(dns['route-hijack'], true, reason: '劫持 53 端口/嗅探到的 DNS');
  expect(dns['direct-nameserver'], isNotEmpty);
  expect(dns['proxy-nameserver'], isNotEmpty);
  expect(dns['default-nameserver'], isNotEmpty);
  expect(dns.containsKey('port'), isFalse,
      reason: 'Windows 省略 dns.port，仅经 route-hijack / TUN dns-hijack 应答');
  expect(dns['ipv6'], ipv6);
  expect(dns['mode'], fakeip ? 'fakeip' : dnsModeRedirHost);
}
