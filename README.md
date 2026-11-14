# ant GUI（Windows 桌面端）

由 **上游 GUI 工程** 的桌面端代码整体抽离而来，**单内核 ant**，只做 Windows 桌面，
不支持 sing-box / mihomo。上游工程的运行方式与全部流程逻辑完整保留，仅把
内核选择相关的分支收敛为 ant。

## 保留的流程逻辑（未精简）

- 内置三模板路由（绕过大陆 / GFW列表 / 全局代理）+ 规则文件前置校验与 assets 兜底释放
- `custom` 模式的用户配置文件增量编辑（应用/取消应用节点、TUN、mixed-port）
- 订阅拉取、分组、节点解析与无损回写（Clash/mihomo 原始条目）
- 真实链路延迟/速度测速（临时 ant 实例 + 本地代理）
- 系统代理（注册表）、TUN 提权（UAC 重启恢复）、开机自启动/静默启动
- 托盘、状态恢复、日志、设置保存编排、前端预校验、双视图设置页、全部测试

## 内核相关改动（相对上游工程）

| 项目 | 上游工程 | ant GUI |
| --- | --- | --- |
| 内核 | sing-box(`.json`) / mihomo(`.yaml`) 双内核可切换 | 固定 `ant`，仅 `.yaml` |
| 二进制 | `sing-box.exe` / `mihomo.exe` | `bin/ant.exe`（+ 可选 `wintun.dll`） |
| 启动参数 | 按内核分支 | `ant -c run/config.yaml` |
| 运行配置 | `config.json` / `config.yaml` | `run/config.yaml` |
| 规则集 | `.srs` / `.mrs` 二进制 | `run/rules/ant/*.ars`（ant ARST 二进制，随源码内置） |
| API 面板 | clash-api / external-controller | `api: "127.0.0.1:9090"` + `api-secret` |
| DNS | nameserver-policy / DNS servers | `rule-follow-route: true` 复用 `route:` 规则，`direct-nameserver` / `proxy-nameserver` / `default-nameserver` |
| 缓存 | cache_file | `cache: true` + `cache-file` |
| TUN | gvisor/system stack | 内核 NAT 系统栈，无 `stack`，`address` 用 `/30` |
| 系统代理 | inbounds / allow-lan | `mixed-port` + 全局 `bind-address` |

`Settings` 去掉 `core` / `config_path_singbox` / `config_path_mihomo`；
`settings.json` 旧版字段仍可读入（旧 `config_path_mihomo` 作为 YAML 配置的
fallback），但不再写出，避免升级后残留双内核状态。

## 目录结构

```
pubspec.yaml                 # pub workspace：4 个成员；core_engine 为 path 依赖（沿用原版）
apps/desktop/                # Windows runner / 托盘 / 入口 / 规则集 assets
  assets/ruleset/ant/*.ars   # 14 个内置 .ars 二进制规则集（随源码提交，启动时兜底释放）
packages/
  core/                      # 纯 Dart：模型、解析、ant 配置合成/增量编辑、服务层、测速
  core_engine/               # ant 子进程管理、Windows 系统代理、提权/自启动
  ui_desktop/                # 桌面 UI（Riverpod）
  ui_kit/                    # 通用组件与主题
.github/workflows/win.yml    # 测试 + flutter build windows + 打包 portable zip
```

## 关键内核语义（已对齐 ant `config.rs` / `ruleset/compiler.rs`）

- `route:` 是字符串列表，关键字 `RULE-SET` / `DOMAIN*` / `IP-CIDR` / `MATCH`，
  IP 规则集用 `no-resolve` 尾字段；`geoip-cn` 不加（需解析域名判断国内 IP）。
- `rule-providers`：`type: file`、`format: ars`、`behavior: domain|ip`、
  `path` 指向 `run/rules/ant/<tag>.ars`。ant 按 `ARST` 文件头自动识别二进制
  规则集；`.ars` 内含精确域名 / 后缀 FST、关键字、正则与 IPv4/IPv6 CIDR 段。
- `dns.mode` 只认 `redir-host` / `fakeip`（不带连字符）；`fake-ip` 是 GUI
  设置层的值，写入配置时映射为 `fakeip`。`fakeip-filter` 仅在 fake-ip 模式
  生成对应 provider 并校验文件存在。
- 应用节点固定名为 `proxy`；`route:` 规则直接引用该节点名作为出站，不再生成
  `proxy-groups`（ant 的 `outbound_names()` 含 `proxies` 节点名，`proxy` 不是
  保留名，引用前需在 `proxies:` 中配置）。
- Windows 不写 `dns.port`、设置页也去掉「DNS 监听端口」：ant 的
  `DnsConfig.port` 是 `Option<u16>`，省略即不监听 DNS 端口，仅经
  `route-hijack` / TUN `dns-hijack` 应答。
- 节点 `proxies:` 条目按 ant `ProxyConfig` 归一化：嵌套 `ws-opts` → `ws-path`
  / `ws-host` / `ws-headers`，`reality-opts` → `reality-public-key` /
  `reality-short-id`，`alterId` → `alter-id`，`up`/`down` 数字 → `"N Mbps"`。
  ant 无对应出站的协议（`hysteria` v1 / `ssr` / `http` / `ssh`）与 transport
  （`grpc` / `httpupgrade` / `h2` / `quic`）**fail-fast 报错**，不静默降级。

## 构建（GitHub Actions）

`Build Windows` 工作流（`workflow_dispatch`）：

1. `flutter pub get` → `dart test packages/core` + 三处 `flutter test`
2. `flutter build windows --release`
3. 从 **evecus/ant 最新 release** 下载 `ant-windows-x64.exe` → `bin/ant.exe`
   （`gh release download` 省略 tag 即取最新；可用 `ANT_REPO` 覆盖；
   离线时把 `ant.exe` 提交到 `bin/` 兜底）
4. 下载 `wintun.dll`（TUN 模式需要）
5. 校验 14 个 `.ars`（随源码内置，CI 不下载）→ 打包
   `ant-gui-windows-x64.zip`：`Release/` + `bin/` + `run/rules/ant/*.ars`

本机 Dart 2.17 低于项目要求的 SDK ≥ 3.6，无法本地跑 `dart test` /
`flutter test`。交付前已做全量静态自检：内部包/相对路径 import 与
`export ... show` 符号均可解析、9 个外部依赖全部在 pubspec 声明、Dart
文件括号与字符串（含 raw、`${}` 插值）平衡、旧双内核 API 清零、窗口标题
与自启动项名统一为 ant GUI。14 个 `.ars` 全部通过 `ARST` 结构解析，并用
ant 自带的 `check -c` 实际加载验证通过。
**最终编译与测试结果以 GitHub Actions 为准。**

## 规则集来源与替换

`apps/desktop/assets/ruleset/ant/*.ars` 共 14 个，**随源码提交**（Flutter
编译期打进 assets，启动时兜底释放到 `run/rules/ant/`；CI 打包时再复制一份）。

- 12 个来自 [evecus/ant](https://github.com/evecus/ant) 的 `ruleset` 分支
  （自动同步 MetaCubeX/meta-rules-dat 并编译成 `.ars`），按 `domain/` 与
  `ip/` 目录下载后扁平化为 `<tag>.ars`。
- `geosite-private.ars` / `geosite-fakeipfilter.ars` 在 `ruleset` 分支没有
  对应文件，用 sing-box JSON 源经
  `ant ruleset-convert -i <src>.json -o <tag>.ars` 自行编译。

替换某个规则集时保持文件名 `<tag>.ars` 不变即可；也可自行编译后覆盖。
`checkRuleFiles` 只校验 `.ars` 是否存在（不再接受 `.yaml`）。
