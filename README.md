# AFA — ant 代理客户端（Kotlin Compose 版）


基于 `VpnService` +独立 `ant` 核心（Rust 二进制）的 Android 代理客户端。本版在保留核心逻辑的前提，把 UI 层整体重写为 **Jetpack Compose (Material 3)**，并把节点管理从「交给 ant 解析」改为 **App 自己存储、自己生成配置**；路由规则与规则集同样由 App 结构化存储、启动时渲染进 `config.yaml`

```
APK (Kotlin / Compose)
  ├─ NodeStore            节点结构化存储（files/nodes.json）
  ├─ LinkParser           分享链接 → 结构化节点（App 自己解析，不经 ant）
  ├─ RouteStore           路由规则 + 规则集（files/routes.json）
  ├─ RuleSetManager       内置释放 / 文件导入 / URL 订阅刷新
  ├─ ConfigManager        节点 + 路由状态 → config.yaml
  └─ AntVpnService
       ├─ VpnService.Builder.establish() → TUN FD
       └─ 启动 libant.so（ANT_TUN_FD / ANT_PROTECT_SOCK）
```

## 本版改动

| 项目 | 旧版 | 本版 |
|---|---|---|
| UI | 3 个 Activity + XML 布局 + ViewBinding | 单 `ComponentActivity` + Compose Navigation |
| 布局 | 大圆形电源按钮 | 顶部工具栏 + 左侧抽屉 + 节点卡片列表 + 底部飞机 FAB |
| 节点 | 分享链接原样写入 `nodes.txt`，由 ant 的 `proxy-provider` 解析 | App 解析成结构化字段存入 `nodes.json`，可增删改查 |
| 路由 | 模板里写死 3 行 `route:` | 路由页管理（开关 / 编辑 / 新增 / 删除 / 排序），`route:` 与 `rule-providers:` 由页面数据渲染 |
| 规则集 | 仅内置 2 个 `.ars` | 内置 + 本地文件导入 + URL 订阅，独立管理页，运行中可热更新 |
| 配置生成 | 模板 + `proxy-providers` + `use: [nodes]` | 模板 + 直接渲染 `proxies:`（只写选中的 1 个节点）+ 渲染路由两段 |
| 启停 | 页面按钮 | 首页底部中央飞机图标（颜色表达状态：蓝=停止 / 橙=启动中 / 绿=运行） |
| 设置 / 日志入口 | 首页按钮 | 首页汉堡菜单打开的左侧边栏 |

## 节点管理

**支持的协议（11 种，均为 ant 默认编译范围内）**：VLESS、VMess、Trojan、Shadowsocks、Hysteria2、TUIC、AnyTLS、SOCKS5、NaiveProxy、ShadowQUIC、Spectre。

ant-native 三种协议的字段（与 `config.example.yaml` / `outbound/*.rs` 对齐）：

| 协议 | 必填 | 可选字段 | 说明 |
|---|---|---|---|
| NaiveProxy | `username` / `password` | `sni`、`skip-cert-verify`、`client-fingerprint`（默认 chrome）、`fingerprint` | HTTP/2 CONNECT over TLS，ant 强制 `tls=true` 与 ALPN=h2，故不输出这两个字段 |
| ShadowQUIC | `username`(JLS user iv) / `password` / `sni`(须匹配 jls-upstream 域名) | `alpn`（默认 h3）、`skip-cert-verify`、`congestion-control`、`heartbeat`、`over-stream`、`zero-rtt`、`initial-mtu`、`min-mtu` | JLS over QUIC；`min-mtu ≥ 1200` 且 `initial-mtu ≥ min-mtu`，否则 ant 启动 fail-fast |
| Spectre | `username` / `password` / `sni`(须匹配伪装域名) | `up` / `down`（`50mbps` 或裸字节/秒数） | JLS over QUIC + Brutal 拥塞控制；0 或省略回退 BBR |

原生分享链接格式：`naive://user:pass@host:port?sni=&insecure=&fp=`、`shadowquic://user:pass@host:port?sni=<必填>&alpn=h3&over-stream=1&disable-zero-rtt=1&initial-mtu=1300&min-mtu=1200`（`sq://` 为别名）、`spectre://user:pass@host:port?sni=<必填>&up=50mbps&down=200mbps`。缺 SNI / 缺凭据的链接按 ant 的 fail-fast 语义跳过，不会污染节点列表。

**导入方式**：首页右上角粘贴图标 → 多行分享链接或整段 Base64 订阅。App 按 ant `link.rs` 的参数规则自己解析（`sni/peer`、`alpn`、`fp`、`insecure`、`path`、`host`、`mode`、`security=reality` + `pbk/sid`、`flow`、`obfs`、`up/down`、`congestion-control` 等），解析结果写入 `files/nodes.json`。无法识别的行会跳过，不会让整批导入失败。

**编辑表单**：由 `NodeSchema.fieldsFor(type)` 数据驱动，按协议动态生成字段，包含：

- 基本：名称、服务器、端口
- 认证：UUID / 密码 / 用户名 / cipher / alterId
- 传输：`tcp | ws | xhttp` 及 `ws-path/ws-host`、`xhttp-path/xhttp-host/xhttp-mode`
- TLS：开关、SNI、ALPN、跳过证书验证、uTLS 指纹、证书 pin
- 高级：REALITY（pbk / sid）、flow、Hysteria2 混淆与带宽、TUIC 拥塞控制与心跳

**卡片操作**：点击选中（左侧蓝色竖条）、铅笔编辑、分享（导出分享链接）、垃圾桶删除。更多菜单里可新建节点、导出全部节点、清空全部节点。

**生效策略**：启动 VPN 时只把**当前选中的 1 个节点**写进 `proxies:`，`PROXY` 组为 `select`，成员是「选中节点 + DIRECT」。运行中切换节点会提示重启 VPN 后生效（不自动重启）。没有节点时不允许启动。

## 路由 / 规则集

抽屉里的「路由」是**唯一的路由配置入口**，侧边栏「规则集」按钮进入规则集管理页。`config.yaml` 的 `route:` 与 `rule-providers:` 两段完全由路由页数据渲染，模板里不再写死任何规则：**页面上看到的几条，就是生效的几条**。

**默认规则**（沿用 afa 原有「绕过大陆」模板，不照抄 NekoBox）：

| # | 名称 | 条件 | 动作 |
|---|---|---|---|
| 1 | 国内域名直连 | `RULE-SET,geosite-cn` | 绕过 |
| 2 | 国内 IP 直连 | `RULE-SET,geoip-cn`（`no-resolve`） | 绕过 |
| 3 | 兜底：其余走代理 | `MATCH`（固定） | 代理 |

最后一条「兜底」对应 ant 强制要求的 `MATCH,<outbound>`：不可删除、不可关闭、不可调整顺序，只能改名称与动作。页面支持每条规则的开关、编辑、新增、删除、上下排序，以及「恢复默认规则」。

**可配字段严格限定为 ant 内核支持的能力**（`src/config.rs::parse_rule_line`），不暴露端口 / network / 按应用等内核不支持的条件：

| 匹配方式 | 写入 route 的关键字 |
|---|---|
| 域名精确 / 后缀 / 关键字 / 正则 | `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `DOMAIN-REGEX` |
| 目标 IP / 源 IP | `IP-CIDR` / `SRC-IP-CIDR` |
| 规则集 | `RULE-SET` |
| 兜底 | `MATCH` |

动作只有三选一：**代理**（`PROXY` 组）、**绕过**（`DIRECT`）、**屏蔽**（`BLOCK`）。IP 类规则可加 `no-resolve`。模板已开启 `dns.rule-follow-route: true`，因此新增规则自动联动 DNS 上游（绕过 → 直连 DNS、代理 → 远端 DNS、屏蔽 → NOERROR 空应答），无需单独写 DNS 规则。

**规则集管理**：

- 内置 `geosite-cn.ars` / `geoip-cn.ars`，由 `ConfigManager.ensureAssets()` 释放到 `files/rules/`，不可删除。
- 「导入文件」通过系统文件选择器复制 `.ars` / `.yaml` / `.json` / `.txt` 到 `files/rules/`，按扩展名写 `format` 与 `behavior`。
- 「URL 订阅」生成 `type: http` + 绝对 `path` + `update-interval`（小时），由 ant 在启动 VPN 时下载并按需自动更新；运行中点「刷新」调用 `PUT /providers/rules/{name}` 立即热更新，内核不支持该接口或调用失败时自动退化为删缓存、下次启动重新下载；未运行时同样删缓存。
- 删除规则集前检查引用：若仍被路由规则引用则拒绝删除，避免生成 ant 会 fail-fast 的配置。

**校验与生效**：`RouteConfigRenderer.validate()` 在写配置前做 fail-fast 校验（MATCH 唯一且在最后、规则值不含逗号/换行、RULE-SET 引用的规则集存在、本地规则集文件就绪、URL 协议合法等），不合法就不写配置、不启动。路由规则在 ant 启动时解析，改动后需**重启 VPN** 生效；页面会提示，不自动重启。

## 配置生成

`assets/config-template.yaml` 只保留 DNS / TUN / 端口等固定框架，`ConfigManager.regenerateConfig()` 每次启动 VPN 时重新生成 `files/config.yaml`：

```yaml
proxies:
  - name: "PROXY"
    type: vless
    server: "vl.example.com"
    port: 443
    uuid: "uuid-vless"
    network: "ws"
    ws-path: "/ws"
    ws-host: "cdn.example.com"
    tls: true
    sni: "vl.example.com"
    alpn: ["h3", "h2"]
    skip-cert-verify: true
    client-fingerprint: "chrome"

rule-providers:
  "geosite-cn":
    type: file
    behavior: domain
    path: "/data/user/0/com.ant.proxy/files/rules/geosite-cn.ars"
    format: ars

route:
  - "RULE-SET,geosite-cn,DIRECT"
  - "RULE-SET,geoip-cn,DIRECT,no-resolve"
  - "MATCH,PROXY"
```

不再生成 `proxy-groups:`：选中节点写进 `proxies:` 时 `name` 固定为 `PROXY`，路由里的「代理」动作直接引用它（ant 的 route 出站本就支持 proxies 名）。节点在 App 里的名称不受影响，也就不存在节点名含逗号 / 空白 / 与 DIRECT 重名的问题。

模板里用 `# @PROXIES@` / `# @RULE_PROVIDERS@` / `# @ROUTE@` 三个唯一注入标记（注释中不得出现这些字符串，否则替换会污染 YAML）。`__FILES_DIR__` 占位符已移除：规则集 path 由渲染器直接生成绝对路径。TUN 段与 `log-level` 由 `AntProcessManager.applyManagedConfig()` 在启动时按设置页参数统一覆盖；不要在 YAML 里写 `file-descriptor`，FD 通过 `ANT_TUN_FD` 运行时传入。

## 构建

| 组件 | 版本 |
|---|---|
| Gradle | 8.9（wrapper 已附带） |
| Android Gradle Plugin | 8.7.2 |
| Kotlin | 2.0.21（Compose Compiler plugin） |
| Compose BOM | 2024.12.01 |
| compileSdk / minSdk | 35 / 24 |
| ABI | arm64-v8a（`libant.so` 已内置） |

```bash
./gradlew :app:assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
```

需要 Android SDK 35、Build Tools 35、CMake 3.22.1 与 NDK（`app/src/main/cpp/spawn_fd.c` 用 JNI fork+exec 传递 TUN FD）。首次运行会用 `ANDROID_HOME` / `ANDROID_SDK_ROOT` 或自动生成的 `local.properties` 定位 SDK，无需手动创建。

> `gradle/wrapper/gradle-wrapper.properties` 的 `distributionUrl` 默认指向腾讯云镜像（官方源在国内常超时，`networkTimeout` 已调到 60s）。如需切回官方源，改为 `https\://services.gradle.org/distributions/gradle-8.9-bin.zip` 即可，或用 `file://` 指向本地已下载的发行版。

## 验证情况

核心逻辑已在 JVM 上用 Kotlin 2.0.21 真实编译并运行测试（13 种链接解析场景覆盖 11 种协议、字段校验、YAML 渲染无重复键、导出→再导入往返、Base64 订阅解析、NodeStore 增删选改、无效链接跳过、新建默认值），全部通过；VLESS / NaiveProxy / ShadowQUIC / Spectre 四种节点生成的完整 `config.yaml` 均经 PyYAML 解析校验（bool / MTU 数字 / ALPN 数组类型、路由引用 PROXY 一致）。路由侧纯逻辑（JSON 往返、默认规则渲染、开关/排序/新增、MATCH 不变量、fail-fast 校验、YAML 双引号标量）同样在 JVM 上编译运行验证。UI 层需 Android SDK 环境编译。

## 限制

- 仅 arm64-v8a
- 未做实时速率 / 节点累计流量统计（状态仅由 FAB 颜色与日志页体现）
- 节点订阅 URL 自动更新、Clash YAML 订阅解析、运行时 API 热切换节点仍未实现（规则集 URL 订阅已支持）
- 路由仅支持 ant 内核已有的匹配条件，无端口 / network / 按应用分流；改动路由后需重启 VPN
- 规则集 URL 订阅与热更新依赖 ant 的 `type: http` rule-provider 及 `PUT /providers/rules/{name}` 接口；若内置的 `libant.so` 版本较旧，需替换为包含该能力的二进制（无需修改 ant 源码）
- `wireguard` / `ssh` / `tailscale` 需 ant 单独开 build feature，预编译 `libant.so` 未启用，故未暴露

## 分应用代理

设置页 → 「分应用代理」。三种模式（`PerAppMode`）：关闭（默认，所有应用）/ 只代理选中 / 选中的不代理。对应 `VpnService.Builder` 的 `addAllowedApplication` / `addDisallowedApplication`（系统限制两者互斥）。

- **本 App 始终留在 VPN 内**：ant 与 App 同 UID，其 system-stack TCP 监听的回包必须走 tun0，所以白名单模式自动把 AFA 自己加进去，黑名单模式忽略名单里的 AFA。出站 socket 的防回环仍由 `ProtectServer` 负责。
- 白名单为空（或只剩 AFA）时拒绝启动并在日志里报错，不会静默退化。
- 改动即时保存，**重启 VPN 后生效**（Builder 在 `establish()` 时固化）。
- 应用列表需要 `QUERY_ALL_PACKAGES`（侧载分发可直接用；上架 Play 需改用 `<queries>` 或提交用途声明）。
- 逻辑在纯 Kotlin 的 `PerAppSettings`，持久化在 `PerAppStore`，界面在 `ui/PerAppScreen.kt`。

## 入站与 API

纯 VPN 场景下配置里**没有** `mixed-port`，`dns:` 段也不写 `port`：DNS 由 `tun.dns-hijack` 在 TUN 协议栈内直接应答（`dns::answer_query`），不经过任何本地端口；入站只有 TUN。唯一保留的监听是 API 面板（规则集热更新用），设置页可开关并修改监听地址：`IPv4:端口`（默认 `127.0.0.1:9095`）、`[IPv6]:端口`、`:端口` 或 `端口`（后两种等同 127.0.0.1）；与 ant 一样不支持主机名。监听 `0.0.0.0` 会向局域网开放面板，App 不配置 `api-secret`，请自行评估。App 访问 API 时自动跟随该地址（通配地址改连回环）。
