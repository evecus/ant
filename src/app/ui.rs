//! Embedded dashboard HTML: proxy-groups / connections / rules / info / logs
//! (mihomo-style), plus the api-secret login page.
//!
//! The five tabs each own a URL (`/ui/proxies`, `/ui/connection`, `/ui/rules`,
//! `/ui/info`, `/ui/log`); `/ui` is redirected to the first one by the API server.

pub const LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ant — 登录</title>
<style>
  :root { color-scheme: light; --line:#e7ebf3; --muted:#8b94a8; --text:#1b2333; --acc:#4f6bff; --acc2:#8b5cf6; --bad:#e5484d; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
    color:var(--text); padding:16px;
    background:
      radial-gradient(900px 500px at 6% -12%, rgba(79,107,255,.13), transparent 62%),
      radial-gradient(780px 460px at 98% 2%, rgba(139,92,246,.11), transparent 60%),
      #f3f5fb;
    background-attachment: fixed;
  }
  .box { width:100%; max-width:350px; background:#fff; border:1px solid var(--line);
    border-radius:20px; padding:32px 26px 26px; position:relative; overflow:hidden;
    box-shadow:0 18px 48px rgba(31,45,86,.13);
    animation:rise .4s cubic-bezier(.22,.68,0,1.2) both; }
  .box::before { content:''; position:absolute; left:0; right:0; top:0; height:3px;
    background:linear-gradient(90deg,var(--acc),var(--acc2),#38bdf8); }
  @keyframes rise { from { opacity:0; translate:0 12px; } to { opacity:1; translate:0 0; } }
  .logo { width:34px; height:34px; margin:0 auto 16px; border-radius:11px;
    background:linear-gradient(135deg,var(--acc),var(--acc2));
    box-shadow:0 8px 20px rgba(79,107,255,.38);
    display:flex; align-items:center; justify-content:center; }
  .logo::after { content:''; width:11px; height:11px; border-radius:50%; background:#fff; }
  h1 { font-size:19px; margin:0 0 4px; font-weight:700; text-align:center; letter-spacing:.5px; }
  p { margin:0 0 22px; font-size:12px; color:var(--muted); text-align:center; }
  input {
    width:100%; background:#f7f9fd; border:1px solid var(--line); color:var(--text);
    border-radius:11px; padding:11px 13px; font-size:14px; outline:none;
    transition:border-color .2s, box-shadow .2s;
  }
  input:focus { border-color:var(--acc); box-shadow:0 0 0 3px rgba(79,107,255,.14); }
  button {
    width:100%; margin-top:14px; color:#fff; font-weight:600;
    background:linear-gradient(135deg,var(--acc),var(--acc2)); border:1px solid transparent;
    border-radius:11px; padding:11px 0; font-size:14px; cursor:pointer;
    box-shadow:0 8px 20px rgba(79,107,255,.28);
    transition:transform .2s, box-shadow .2s, filter .2s;
  }
  button:hover { transform:translateY(-2px); filter:brightness(1.06); box-shadow:0 12px 26px rgba(79,107,255,.38); }
  button:disabled { opacity:.55; cursor:default; transform:none; box-shadow:none; }
  .err { color:var(--bad); font-size:12px; text-align:center; min-height:16px; margin-top:12px; }
  @media (prefers-reduced-motion: reduce) { * { animation:none !important; transition:none !important; } }
</style>
</head>
<body>
<div class="box">
  <div class="logo"></div>
  <h1>ant</h1>
  <p>此面板受 api-secret 保护，请输入访问密码</p>
  <input id="pw" type="password" autocomplete="current-password" placeholder="密码" autofocus/>
  <button id="go" type="button">登 录</button>
  <div class="err" id="err"></div>
</div>
<script>
const pw = document.getElementById('pw');
const go = document.getElementById('go');
const err = document.getElementById('err');
async function login() {
  go.disabled = true;
  err.textContent = '';
  try {
    const r = await fetch('/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: pw.value })
    });
    if (r.ok) { location.reload(); return; }
    err.textContent = r.status === 401 ? '密码错误，请重试' : ('登录失败 ' + r.status);
  } catch (e) {
    err.textContent = String(e);
  }
  go.disabled = false;
  pw.focus(); pw.select();
}
go.addEventListener('click', login);
pw.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
</script>
</body>
</html>
"#;

pub const UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ant</title>
<style>
  :root {
    color-scheme: light;
    --bg:#f3f5fb; --card:#ffffff; --line:#e7ebf3; --muted:#8b94a8; --text:#1b2333;
    --acc:#4f6bff; --acc2:#8b5cf6; --ok:#12a150; --bad:#e5484d; --warn:#a855f7;
    --shadow:0 6px 22px rgba(31,45,86,.07);
    --shadow-hi:0 14px 32px rgba(31,45,86,.13);
  }
  * { box-sizing: border-box; }
  html { -webkit-text-size-adjust:100%; }
  body {
    margin:0; min-height:100vh;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
    color:var(--text);
    background:
      radial-gradient(900px 500px at 6% -12%, rgba(79,107,255,.13), transparent 62%),
      radial-gradient(780px 460px at 98% 2%, rgba(139,92,246,.11), transparent 60%),
      var(--bg);
    background-attachment: fixed;
  }
  ::-webkit-scrollbar { width:9px; height:9px; }
  ::-webkit-scrollbar-thumb { background:#d5dce9; border-radius:9px; border:2px solid transparent; background-clip:content-box; }
  ::-webkit-scrollbar-thumb:hover { background:#bcc7dd; background-clip:content-box; }
  header {
    display:flex; align-items:center; gap:12px; padding:14px 18px;
    background:rgba(255,255,255,.82);
    -webkit-backdrop-filter:blur(14px) saturate(1.4);
    backdrop-filter:blur(14px) saturate(1.4);
    border-bottom:1px solid var(--line);
    box-shadow:0 4px 20px rgba(31,45,86,.05);
    position:sticky; top:0; z-index:30; flex-wrap:wrap;
  }
  header::before {
    content:''; position:absolute; left:0; right:0; top:0; height:3px;
    background:linear-gradient(90deg,var(--acc),var(--acc2),#38bdf8);
  }
  .brand { display:flex; align-items:center; gap:9px; }
  h1 { font-size:17px; margin:0; font-weight:700; letter-spacing:.4px; }
  .logo {
    width:22px; height:22px; border-radius:8px; flex-shrink:0;
    background:linear-gradient(135deg,var(--acc),var(--acc2));
    display:flex; align-items:center; justify-content:center;
    animation:breathe 3.6s ease-in-out infinite;
  }
  .logo::after { content:''; width:7px; height:7px; border-radius:50%; background:#fff; }
  @keyframes breathe {
    0%,100% { box-shadow:0 5px 14px rgba(79,107,255,.34); }
    50%     { box-shadow:0 6px 20px rgba(139,92,246,.55); }
  }
  .nav { display:flex; gap:4px; margin-left:8px; flex-wrap:wrap; }
  .nav button {
    background:transparent; border:1px solid transparent; color:var(--muted);
    padding:7px 14px; border-radius:999px; cursor:pointer; font-size:13px; font-weight:500;
    transition:all .2s cubic-bezier(.22,.68,0,1.25);
  }
  .nav button:hover { color:var(--acc); background:rgba(79,107,255,.07); transform:translateY(-1px); }
  .nav button.active {
    color:#fff; border-color:transparent;
    background:linear-gradient(135deg,var(--acc),var(--acc2));
    box-shadow:0 6px 16px rgba(79,107,255,.30);
  }
  .meta { color:var(--muted); font-size:12px; margin-left:auto; }
  .pill {
    background:linear-gradient(135deg,rgba(79,107,255,.10),rgba(139,92,246,.10));
    border:1px solid rgba(79,107,255,.20); border-radius:999px;
    padding:3px 11px; font-size:12px; color:var(--acc); font-weight:600;
  }
  main { padding:18px 16px 40px; max-width:1100px; margin:0 auto; }
  .page { display:none; }
  .page.active { display:block; animation:rise .35s ease both; }
  @keyframes rise { from { opacity:0; translate:0 10px; } to { opacity:1; translate:0 0; } }
  .proxy-view { animation:rise .3s ease both; }
  .card {
    background:var(--card); border:1px solid var(--line); border-radius:18px;
    padding:16px 18px; margin-bottom:14px; box-shadow:var(--shadow);
    transition:transform .22s ease, box-shadow .22s ease, border-color .22s ease;
  }
  .card:hover { transform:translateY(-2px); box-shadow:var(--shadow-hi); }
  .card h2 { margin:0 0 12px; font-size:14px; font-weight:700; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .tag {
    font-size:11px; color:var(--muted); background:#f4f6fb; border:1px solid var(--line);
    border-radius:999px; padding:2px 9px; font-weight:500;
  }
  .tag.now { color:var(--ok); background:#ecfdf3; border-color:#bbf7d0; font-weight:600; }
  .members { display:flex; flex-wrap:wrap; gap:9px; }
  .mem {
    background:#fff; border:1px solid var(--line); border-radius:14px;
    padding:10px 14px; min-width:124px; cursor:pointer; font-size:13px;
    display:flex; flex-direction:column; gap:5px;
    box-shadow:0 2px 8px rgba(31,45,86,.04);
    transition:transform .2s ease, box-shadow .2s ease, border-color .2s ease, background .2s ease;
  }
  .mem:hover { transform:translateY(-3px); border-color:rgba(79,107,255,.5); box-shadow:0 10px 22px rgba(79,107,255,.15); }
  .mem.active { border-color:var(--ok); background:linear-gradient(180deg,#f0fdf5,#fff); box-shadow:0 6px 18px rgba(18,161,80,.13); }
  .mem .name { font-weight:600; }
  .mem .delay { font-size:11px; color:var(--muted); font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-weight:600; }
  .mem .delay.ok { color:var(--ok); }
  .mem .delay.bad { color:var(--bad); }
  .actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:12px; align-items:center; }
  .btn {
    background:#fff; border:1px solid var(--line); color:var(--text);
    border-radius:10px; padding:7px 14px; font-size:12px; font-weight:600; cursor:pointer;
    box-shadow:0 2px 7px rgba(31,45,86,.04);
    transition:transform .2s ease, box-shadow .2s ease, border-color .2s ease, color .2s ease, filter .2s ease;
  }
  .btn:hover { transform:translateY(-2px); border-color:var(--acc); color:var(--acc); box-shadow:0 8px 18px rgba(79,107,255,.14); }
  .btn.primary {
    background:linear-gradient(135deg,var(--acc),var(--acc2));
    border-color:transparent; color:#fff;
    box-shadow:0 6px 18px rgba(79,107,255,.28);
  }
  .btn.primary:hover { color:#fff; filter:brightness(1.06); box-shadow:0 10px 24px rgba(79,107,255,.40); }
  .btn:disabled { opacity:.55; cursor:default; transform:none; box-shadow:none; }
  code, .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; }
  .kv { display:grid; grid-template-columns:140px 1fr; gap:10px 14px; font-size:13px; }
  .kv .k { color:var(--muted); }
  .kv .v { word-break:break-all; }
  .pgrid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px 12px; font-size:13px; }
  .pgrid .pi { min-width:0; }
  .pgrid .k { color:var(--muted); font-size:12px; }
  .pgrid .v { margin-top:2px; word-break:break-all; font-weight:600; }
  @media (min-width:601px) {
    .pgrid { grid-template-columns:repeat(auto-fill,minmax(150px,1fr)); gap:16px 20px; }
  }
  .list { margin:0; padding-left:18px; font-size:13px; color:var(--text); }
  .list li { margin:5px 0; }
  .on { color:var(--ok); font-weight:600; } .off { color:var(--muted); }
  .empty { text-align:center; color:var(--muted); font-size:13px; padding:28px 0; }

  /* ── proxy-providers（订阅，位于代理组页）────────────────── */
  .prov { background:#fbfcff; border:1px solid var(--line); border-radius:14px; padding:11px 13px; margin-bottom:9px; }
  .prov:last-child { margin-bottom:0; }
  .prov-top { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .prov-sub { margin-top:6px; font-size:11px; color:var(--muted); display:flex; gap:4px 14px; flex-wrap:wrap; }
  .prov-sub b { font-weight:600; color:var(--text); }
  .prov-err { margin-top:5px; font-size:11px; color:var(--bad); word-break:break-all; }
  .prov .btn { margin-top:9px; }

  /* ── connections ────────────────────────────────────────── */
  .conn-list { display:flex; flex-direction:column; gap:9px; }
  .conn-card {
    background:var(--card); border:1px solid var(--line); border-radius:14px;
    padding:11px 15px; cursor:pointer; box-shadow:var(--shadow);
    transition:transform .2s ease, box-shadow .2s ease, border-color .2s ease;
  }
  .conn-card:hover { transform:translateY(-2px); border-color:rgba(79,107,255,.45); box-shadow:var(--shadow-hi); }
  .conn-top { display:flex; align-items:center; gap:8px; min-width:0; }
  .net { font-size:10px; font-weight:700; border-radius:6px; padding:2px 7px; text-transform:uppercase; letter-spacing:.5px; flex-shrink:0; }
  .net.tcp { color:#2563eb; background:#eef4ff; border:1px solid #dbe6ff; }
  .net.udp { color:#7c3aed; background:#f5f0ff; border:1px solid #e9dcff; }
  .net.quic { color:#c2620a; background:#fff5e8; border:1px solid #ffe4c2; }
  .conn-host { font-size:14px; font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; min-width:0; }
  .conn-host .port { color:var(--muted); font-size:12px; font-weight:500; }
  .chip { font-size:11px; border-radius:999px; padding:2px 10px; border:1px solid var(--line); color:var(--muted); background:#f7f9fd; flex-shrink:0; max-width:40%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-weight:600; }
  .chip.ob-direct { color:#2563eb; background:#eef4ff; border-color:#dbe6ff; }
  .chip.ob-block { color:var(--bad); background:#fff1f1; border-color:#ffd6d6; }
  .chip.ob-proxy { color:var(--ok); background:#ecfdf3; border-color:#bbf7d0; }
  .conn-sub { display:flex; gap:6px 14px; flex-wrap:wrap; margin-top:6px; font-size:11px; color:var(--muted); }
  .conn-sub .rule { color:var(--warn); font-weight:600; }
  .conn-sub span { white-space:nowrap; }

  /* ── 连接详情弹窗 ───────────────────────────────────────── */
  .mask {
    display:none; position:fixed; inset:0; background:rgba(19,28,48,.42);
    -webkit-backdrop-filter:blur(3px); backdrop-filter:blur(3px);
    z-index:100; align-items:center; justify-content:center; padding:16px;
  }
  .mask.open { display:flex; }
  .modal {
    background:var(--card); border:1px solid var(--line); border-radius:20px;
    width:100%; max-width:560px; max-height:85vh; overflow-y:auto; padding:20px 22px;
    box-shadow:0 24px 60px rgba(19,28,48,.24); animation:rise .25s ease both;
  }
  .modal-head { display:flex; align-items:flex-start; gap:10px; margin-bottom:16px; }
  .modal-head h2 { margin:0; font-size:15px; font-weight:700; word-break:break-all; flex:1; }
  .modal-head .close { flex-shrink:0; width:30px; height:30px; padding:0; border-radius:9px; font-size:14px; line-height:1; }

  /* ── logs ───────────────────────────────────────────────── */
  .log-box {
    background:var(--card); border:1px solid var(--line); border-radius:16px;
    padding:10px 13px; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:12px; line-height:1.6; max-height:calc(100vh - 150px); overflow-y:auto;
    white-space:pre-wrap; word-break:break-all; box-shadow:var(--shadow);
  }
  .log-line { padding:2px 4px; border-radius:6px; border-bottom:1px solid transparent; }
  .log-line:hover { background:#f3f6fd; }
  .log-ts { color:var(--muted); margin-right:8px; }
  .log-lv { font-weight:700; margin-right:8px; min-width:42px; display:inline-block; }
  .log-lv.ERROR { color:var(--bad); }
  .log-lv.WARN { color:#d97706; }
  .log-lv.INFO { color:var(--acc); }
  .log-lv.DEBUG { color:#7c879c; }
  .log-lv.TRACE { color:#a3acc0; }
  .log-msg { color:var(--text); }

  @media (max-width:600px) {
    header { padding:12px 14px; }
    main { padding:14px 12px 34px; }
    .kv { grid-template-columns:1fr; gap:2px 0; }
    .kv .k { margin-top:8px; }
    .modal { max-height:90vh; padding:16px; }
    .chip { max-width:50%; }
    .nav { margin-left:0; width:100%; gap:2px; }
    .nav button { padding:6px 10px; font-size:12px; }
  }
  @media (prefers-reduced-motion: reduce) {
    * { animation:none !important; transition:none !important; }
  }
</style>
</head>
<body>
<header>
  <span class="brand"><span class="logo"></span><h1>ant</h1></span>
  <nav class="nav">
    <button type="button" data-page="proxies" class="active">代理组</button>
    <button type="button" data-page="connections">连接</button>
    <button type="button" data-page="rules">规则</button>
    <button type="button" data-page="info">信息</button>
    <button type="button" data-page="logs">日志</button>
  </nav>
  <span class="pill" id="count" style="display:none">0</span>
  <span class="meta" id="updated">—</span>
</header>
<main>
  <!-- 1. proxy groups / providers -->
  <section id="page-proxies" class="page active">
    <div class="actions" style="margin-bottom:12px">
      <button class="btn primary" type="button" id="btn-test-all">全部测速</button>
      <button class="btn" type="button" id="btn-refresh-proxies">刷新</button>
      <button class="btn" type="button" id="btn-providers" aria-pressed="false">providers</button>
    </div>
    <div id="proxy-view-groups" class="proxy-view">
      <div id="groups"></div>
      <div class="empty" id="groups-empty" style="display:none">暂无代理组</div>
    </div>
    <div id="proxy-view-providers" class="proxy-view" style="display:none">
      <div class="card">
        <h2>订阅 / proxy-providers <span class="tag" id="provider-count">0</span></h2>
        <div id="providers-list"></div>
      </div>
    </div>
  </section>

  <!-- 2. connections: card list + detail modal -->
  <section id="page-connections" class="page">
    <div class="actions" style="margin-bottom:12px">
      <button class="btn" type="button" id="btn-close-all-conn">关闭全部连接</button>
    </div>
    <div class="conn-list" id="conn-list"></div>
    <div class="empty" id="empty" style="display:none">暂无活动连接</div>
  </section>

  <!-- 3. rules: 上面路由规则，下面规则集 -->
  <section id="page-rules" class="page">
    <div class="actions" style="margin-bottom:12px">
      <button class="btn primary" type="button" id="btn-refresh-rules">刷新</button>
    </div>
    <div class="card">
      <h2>路由规则 <span class="tag" id="route-count">0</span></h2>
      <ul class="list mono" id="rules-routes"></ul>
    </div>
    <div class="card">
      <h2>规则集 <span class="tag" id="ruleset-count">0</span></h2>
      <ul class="list" id="rules-rulesets"></ul>
    </div>
  </section>

  <!-- 4. info -->
  <section id="page-info" class="page">
    <div class="card">
      <h2>入站 / 端口</h2>
      <div class="pgrid" id="info-ports"></div>
    </div>
    <div class="card">
      <h2>进程 / 运行时</h2>
      <div class="pgrid" id="info-runtime"></div>
    </div>
  </section>

  <!-- 5. logs -->
  <section id="page-logs" class="page">
    <div class="actions" style="margin-bottom:12px">
      <button class="btn primary" type="button" id="btn-refresh-logs">刷新</button>
      <button class="btn" type="button" id="btn-clear-logs">清空</button>
      <label class="meta" style="display:flex;align-items:center;gap:6px;cursor:pointer;margin-left:0">
        <input type="checkbox" id="logs-auto" checked/> 自动刷新
      </label>
      <span class="meta" id="logs-count">0 条</span>
    </div>
    <div class="log-box" id="log-box"><div class="empty" id="logs-empty">暂无日志</div></div>
  </section>
</main>

<div class="mask" id="conn-mask">
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">
      <h2 id="modal-title"></h2>
      <button class="btn close" type="button" id="modal-close">✕</button>
    </div>
    <div class="kv" id="modal-kv"></div>
    <div class="actions" style="margin-top:14px">
      <button class="btn primary" type="button" id="btn-close-conn">关闭此连接</button>
    </div>
  </div>
</div>

<script>
const TEST_URL = 'http://www.gstatic.com/generate_204';
// DIRECT 用国内可达的小米 204，避免 gstatic 直连必超时
const DIRECT_TEST_URL = 'http://connect.rom.miui.com/generate_204';
const delays = {}; // name -> ms | -1 超时 | undefined 未测（启动时由服务端内存恢复）
let connData = [];  // latest /connections payload (for the detail modal)
let connModalId = null;
let proxyView = 'groups'; // 'groups' = 节点组，'providers' = 订阅列表

// 五个页面各自拥有独立 URL；/ui 由服务端 302 到第一个页面。
const PAGE_PATH = {
  proxies:     '/ui/proxies',
  connections: '/ui/connection',
  rules:       '/ui/rules',
  info:        '/ui/info',
  logs:        '/ui/log',
};
const DEFAULT_PAGE = 'proxies';
const PATH_PAGE = Object.fromEntries(Object.entries(PAGE_PATH).map(([p, path]) => [path, p]));

// 带鉴权的 fetch：凭证过期（401）时回到登录页。
async function api(path, opts) {
  const r = await fetch(path, opts);
  if (r.status === 401) { location.reload(); throw new Error('unauthorized'); }
  return r;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtAge(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm' + (s % 60) + 's';
  const h = Math.floor(m / 60);
  return h + 'h' + (m % 60) + 'm';
}
function delayText(name) {
  const d = delays[name];
  if (d === undefined) return '—';
  if (d < 0) return '超时';
  return d + ' ms';
}
function delayClass(name) {
  const d = delays[name];
  if (d === undefined) return '';
  if (d < 0) return 'bad';
  return 'ok';
}
function obClass(outbound) {
  const o = (outbound || '').toLowerCase();
  if (o === 'direct') return 'ob-direct';
  if (o === 'block') return 'ob-block';
  return 'ob-proxy';
}

// ── 页面路由：地址栏与 tab 双向同步 ────────────────────────
function pageFromLocation() {
  return PATH_PAGE[location.pathname.replace(/\/+$/, '')] || DEFAULT_PAGE;
}
function activate(page, push) {
  if (!PAGE_PATH[page]) page = DEFAULT_PAGE;
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
  document.getElementById('count').style.display = page === 'connections' ? '' : 'none';
  if (push) {
    const target = PAGE_PATH[page];
    if (location.pathname.replace(/\/+$/, '') !== target) {
      // file:// 预览 / 部分 WebView 不允许 pushState，忽略即可。
      try { history.pushState({ page }, '', target); } catch (_) {}
    }
  }
  if (page === 'proxies') refreshActiveProxyView();
  else if (page === 'connections') refreshConn();
  else if (page === 'rules') refreshRules();
  else if (page === 'info') { refreshInfo(); refreshRuntime(); }
  else if (page === 'logs') refreshLogs(true);
}
document.querySelectorAll('.nav button').forEach(btn => {
  btn.addEventListener('click', () => activate(btn.dataset.page, true));
});
window.addEventListener('popstate', () => activate(pageFromLocation(), false));

// 从服务端内存取回「最近一次测速结果」：刷新 / 重进页面仍可见，
// 直到下一次测速写入新值才更新。
async function loadDelays() {
  try {
    const r = await api('/delays');
    if (!r.ok) return;
    const d = await r.json();
    for (const k of Object.keys(d)) delays[k] = d[k];
  } catch (_) { /* ignore */ }
}

// ── 代理组页：节点组 / providers 两个视图 ───────────────────
function refreshActiveProxyView() {
  if (proxyView === 'providers') refreshProviders();
  else refreshProxies();
}
function setProxyView(view) {
  proxyView = view === 'providers' ? 'providers' : 'groups';
  const groups = document.getElementById('proxy-view-groups');
  const provs = document.getElementById('proxy-view-providers');
  groups.style.display = proxyView === 'groups' ? '' : 'none';
  provs.style.display = proxyView === 'providers' ? '' : 'none';
  const btn = document.getElementById('btn-providers');
  btn.classList.toggle('primary', proxyView === 'providers');
  btn.setAttribute('aria-pressed', proxyView === 'providers' ? 'true' : 'false');
  document.getElementById('btn-test-all').style.display = proxyView === 'groups' ? '' : 'none';
  document.getElementById('btn-refresh-proxies').textContent = proxyView === 'groups' ? '刷新' : '刷新订阅';
  // 重播淡入动画，让切换更灵动
  const shown = proxyView === 'groups' ? groups : provs;
  shown.classList.remove('proxy-view');
  void shown.offsetWidth;
  shown.classList.add('proxy-view');
  refreshActiveProxyView();
}
document.getElementById('btn-providers').addEventListener('click', () => {
  setProxyView(proxyView === 'groups' ? 'providers' : 'groups');
});
document.getElementById('btn-refresh-proxies').addEventListener('click', refreshActiveProxyView);

// ── proxies ──────────────────────────────────────────────
async function refreshProxies() {
  try {
    const r = await api('/proxies');
    const data = await r.json();
    const root = document.getElementById('groups');
    const empty = document.getElementById('groups-empty');
    if (!data.length) {
      root.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    root.innerHTML = data.map(g => {
      // Only real select groups can switch member; GLOBAL is list + latency only.
      const selectable = g.type === 'select';
      const isGlobal = g.type === 'global' || (g.name || '').toUpperCase() === 'GLOBAL';
      const members = (g.all || []).map(m => {
        const active = !isGlobal && m === g.now ? ' active' : '';
        return `<div class="mem${active}" data-group="${esc(g.name)}" data-member="${esc(m)}" data-selectable="${selectable}">
          <span class="name">${esc(m)}</span>
          <span class="delay ${delayClass(m)}">${delayText(m)}</span>
        </div>`;
      }).join('');
      const nowTag = isGlobal ? '' : `<span class="tag now">now: ${esc(g.now)}</span>`;
      return `<div class="card" data-group-card="${esc(g.name)}">
        <h2>${esc(g.name)} <span class="tag">${esc(g.type)}</span>
          ${nowTag}</h2>
        <div class="members">${members}</div>
        <div class="actions">
          <button class="btn" type="button" data-test-group="${esc(g.name)}">测速本组</button>
        </div>
      </div>`;
    }).join('');

    root.querySelectorAll('.mem').forEach(el => {
      el.addEventListener('click', async () => {
        if (el.dataset.selectable !== 'true') return;
        const group = el.dataset.group;
        const member = el.dataset.member;
        try {
          const r = await api('/proxies/' + encodeURIComponent(group), {
            method: 'PUT',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ name: member })
          });
          if (!r.ok) {
            const j = await r.json().catch(() => ({}));
            alert(j.message || ('切换失败 ' + r.status));
            return;
          }
          await refreshProxies();
        } catch (e) { if (String(e) !== 'Error: unauthorized') alert(String(e)); }
      });
    });
    root.querySelectorAll('[data-test-group]').forEach(btn => {
      btn.addEventListener('click', () => testGroup(btn.dataset.testGroup));
    });
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') document.getElementById('updated').textContent = 'error: ' + e;
  }
}

function testUrlFor(name) {
  return (name || '').toLowerCase() === 'direct' ? DIRECT_TEST_URL : TEST_URL;
}
async function testOne(name) {
  try {
    const url = testUrlFor(name);
    const r = await api('/proxies/' + encodeURIComponent(name) + '/delay?url=' + encodeURIComponent(url) + '&timeout=5000');
    const j = await r.json();
    if (typeof j.delay === 'number' && j.delay >= 0) delays[name] = j.delay;
    else delays[name] = -1;
  } catch (_) {
    delays[name] = -1;
  }
  // update visible delay labels
  document.querySelectorAll('.mem[data-member="'+CSS.escape(name)+'"] .delay').forEach(el => {
    el.textContent = delayText(name);
    el.className = 'delay ' + delayClass(name);
  });
}

async function testGroup(groupName) {
  const card = document.querySelector('[data-group-card="'+CSS.escape(groupName)+'"]');
  if (!card) return;
  const names = [...card.querySelectorAll('.mem')].map(el => el.dataset.member);
  await Promise.all(names.map(n => testOne(n)));
}

document.getElementById('btn-test-all').addEventListener('click', async () => {
  const names = new Set();
  document.querySelectorAll('#proxy-view-groups .mem').forEach(el => names.add(el.dataset.member));
  for (const n of names) await testOne(n); // sequential to avoid stampede
});

// ── proxy-providers（订阅，代理组页的第二个视图）─────────────
function fmtBytes(n) {
  const v = Number(n) || 0;
  if (v <= 0) return '0';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = Math.min(u.length - 1, Math.floor(Math.log(v) / Math.log(1024)));
  return (v / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + ' ' + u[i];
}
function fmtTime(ms) {
  if (!ms) return '从未';
  const d = new Date(Number(ms));
  if (isNaN(d.getTime())) return '从未';
  return d.toLocaleString();
}
function fmtExpire(sec) {
  if (!sec) return '';
  const d = new Date(Number(sec) * 1000);
  if (isNaN(d.getTime())) return '';
  return d.toLocaleDateString();
}
function renderProviders(pps) {
  const box = document.getElementById('providers-list');
  document.getElementById('provider-count').textContent = pps.length;
  if (!pps.length) { box.innerHTML = '<div class="off">无</div>'; return; }
  box.innerHTML = pps.map(x => {
    const isHttp = (x.providerType || '').toLowerCase() === 'http';
    const sub = x.subscriptionInfo;
    const left = sub ? Math.max(0, sub.total - sub.upload - sub.download) : null;
    const meta = [
      `<span class="tag">${esc(isHttp ? 'HTTP' : 'File')}</span>`,
      `<span class="tag">${x.count ?? 0} 节点</span>`,
      `<span class="tag">${x['interval-time'] ? x['interval-time'] + ' 小时' : '手动'}</span>`
    ].join('');
    const src = isHttp ? (x.url || '') : (x.path || '');
    const lines = [`<span>更新 <b>${esc(fmtTime(x.updatedAt))}</b></span>`];
    if (sub) {
      lines.push(`<span>剩余 <b>${esc(fmtBytes(left))}</b> / ${esc(fmtBytes(sub.total))}</span>`);
      if (sub.expire) lines.push(`<span>到期 <b>${esc(fmtExpire(sub.expire))}</b></span>`);
    }
    if (src) lines.push(`<span class="mono">${esc(src)}</span>`);
    return `<div class="prov" data-provider="${esc(x.name)}">
      <div class="prov-top"><code>${esc(x.name)}</code>${meta}</div>
      <div class="prov-sub">${lines.join('')}</div>
      ${x.error ? `<div class="prov-err">${esc(x.error)}</div>` : ''}
      <button class="btn${isHttp ? ' primary' : ''}" type="button" data-pull="${esc(x.name)}">${isHttp ? '拉取订阅' : '重新加载'}</button>
    </div>`;
  }).join('');
  box.querySelectorAll('[data-pull]').forEach(btn => {
    btn.addEventListener('click', () => pullProvider(btn));
  });
}

async function refreshProviders() {
  try {
    const r = await api('/configs');
    const c = await r.json();
    renderProviders(c.proxy_providers || []);
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') document.getElementById('updated').textContent = 'error: ' + e;
  }
}

async function pullProvider(btn) {
  const name = btn.dataset.pull;
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = '拉取中…';
  try {
    const r = await api('/providers/proxies/' + encodeURIComponent(name), { method: 'PUT' });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      alert(j.message || ('拉取失败 ' + r.status));
    } else {
      await refreshProviders();
      await refreshProxies();
    }
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') alert(String(e));
  }
  btn.disabled = false;
  btn.textContent = old;
}

// ── connections：列表只显示简略信息，点击弹窗看详情 ──────────
async function refreshConn() {
  try {
    const r = await api('/connections');
    const data = await r.json();
    connData = data;
    const list = document.getElementById('conn-list');
    const empty = document.getElementById('empty');
    document.getElementById('count').textContent = data.length + ' connections';
    if (document.querySelector('.nav button.active')?.dataset.page === 'connections') {
      document.getElementById('updated').textContent = new Date().toLocaleTimeString();
    }
    if (!data.length) {
      list.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    list.innerHTML = data.map(c => {
      return `<div class="conn-card" data-id="${c.id}">
        <div class="conn-top">
          <span class="net ${esc(c.network)}">${esc(c.network)}</span>
          <span class="conn-host">${esc(c.dest_host)}<span class="port">:${esc(c.dest_port)}</span></span>
          <span class="chip ${obClass(c.outbound)}">${esc(c.outbound)}</span>
        </div>
        <div class="conn-sub">
          <span class="rule">${esc(c.rule)}</span>
          <span>${esc(c.inbound)}</span>
          <span>${esc(c.src_ip)}:${esc(c.src_port)}</span>
          <span>${fmtAge(c.age_ms)}</span>
        </div>
      </div>`;
    }).join('');
    list.querySelectorAll('.conn-card').forEach(el => {
      el.addEventListener('click', () => openConnModal(Number(el.dataset.id)));
    });
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') document.getElementById('updated').textContent = 'error: ' + e;
  }
}

function openConnModal(id) {
  const c = connData.find(x => x.id === id);
  if (!c) return;
  connModalId = id;
  document.getElementById('modal-title').innerHTML =
    `<span class="net ${esc(c.network)}" style="vertical-align:2px;margin-right:8px">${esc(c.network)}</span>${esc(c.dest_host)}`;
  document.getElementById('modal-kv').innerHTML = [
    row('目标地址', `<code>${esc(c.dest_ip)}:${esc(c.dest_port)}</code>`),
    row('源地址', `<code>${esc(c.src_ip)}:${esc(c.src_port)}</code>`),
    row('入站', esc(c.inbound)),
    row('流量类型', esc(c.network)),
    row('规则', `<span class="rule" style="color:var(--warn)">${esc(c.rule)}</span>`),
    row('出站', esc(c.outbound)),
    row('建立时间', esc(new Date(c.start_ms).toLocaleString())),
    row('已持续', fmtAge(c.age_ms)),
  ].join('');
  document.getElementById('conn-mask').classList.add('open');
}
function closeConnModal() {
  connModalId = null;
  document.getElementById('conn-mask').classList.remove('open');
}
document.getElementById('modal-close').addEventListener('click', closeConnModal);
document.getElementById('conn-mask').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeConnModal();
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeConnModal(); });

document.getElementById('btn-close-all-conn').addEventListener('click', async () => {
  if (!confirm('关闭全部活动连接？')) return;
  try {
    await api('/connections', { method: 'DELETE' });
    closeConnModal();
    refreshConn();
  } catch (e) {
    alert('关闭失败: ' + e);
  }
});
document.getElementById('btn-close-conn').addEventListener('click', async () => {
  if (connModalId == null) return;
  try {
    await api('/connections/' + connModalId, { method: 'DELETE' });
    closeConnModal();
    refreshConn();
  } catch (e) {
    alert('关闭失败: ' + e);
  }
});

function row(k, v) { return `<div class="k">${esc(k)}</div><div class="v">${v}</div>`; }
function pitem(k, v) { return `<div class="pi"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`; }

// ── rules：上面路由规则，下面规则集 ─────────────────────────
async function refreshRules() {
  try {
    const r = await api('/configs');
    const c = await r.json();
    const routes = c.route || [];
    document.getElementById('route-count').textContent = routes.length;
    document.getElementById('rules-routes').innerHTML = routes.length
      ? routes.map(x => `<li>${esc(x)}</li>`).join('')
      : '<li class="off">无</li>';
    const rs = c.rule_providers || [];
    document.getElementById('ruleset-count').textContent = rs.length;
    const rsBox = document.getElementById('rules-rulesets');
    if (!rs.length) {
      rsBox.innerHTML = '<li class="off">无</li>';
    } else {
      rsBox.innerHTML = rs.map(x => {
        const isHttp = (x.type || '').toLowerCase() === 'http';
        const meta = [x.behavior, x.type].filter(Boolean).join(' · ');
        const btn = isHttp
          ? ` <button class="btn primary rs-refresh" type="button" data-rs-pull="${esc(x.name)}" style="margin-left:8px;padding:2px 10px;font-size:12px">更新</button>`
          : '';
        return `<li style="display:flex;align-items:center;flex-wrap:wrap;gap:4px"><span><code>${esc(x.name)}</code>${meta ? ' · ' + esc(meta) : ''} · <span class="tag">${x.count ?? 0} 条</span></span>${btn}</li>`;
      }).join('');
      rsBox.querySelectorAll('[data-rs-pull]').forEach(btn => {
        btn.addEventListener('click', () => pullRuleset(btn));
      });
    }
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') document.getElementById('updated').textContent = 'error: ' + e;
  }
}
document.getElementById('btn-refresh-rules').addEventListener('click', refreshRules);

async function pullRuleset(btn) {
  const name = btn.dataset.rsPull;
  const old = btn.textContent;
  btn.disabled = true;
  btn.textContent = '刷新中…';
  try {
    const r = await api('/providers/rules/' + encodeURIComponent(name), { method: 'PUT' });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) {
      alert(j.message || ('刷新失败 ' + r.status));
    } else {
      await refreshRules();
    }
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') alert(String(e));
  }
  btn.disabled = false;
  btn.textContent = old;
}

// ── info：入站端口 + 进程运行时 ─────────────────────────────
function yn(v) { return v ? '<span class="on">开启</span>' : '<span class="off">关闭</span>'; }

async function refreshInfo() {
  try {
    const r = await api('/configs');
    const c = await r.json();
    const dnsPort = c.dns_port == null ? '—' : (c.dns_port || '未监听');
    document.getElementById('info-ports').innerHTML = [
      pitem('mixed-port', c.mixed_port || 0),
      pitem('http-port', c.http_port || 0),
      pitem('socks-port', c.socks_port || 0),
      pitem('tproxy-port', c.tproxy_port || 0),
      pitem('redir-port', c.redir_port || 0),
      pitem('dns-port', dnsPort),
      pitem('允许局域网', yn(!!c.lan)),
      pitem('IPv6', yn(!!c.ipv6)),
      pitem('TUN', yn(!!c.tun_enable)),
    ].join('');
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') document.getElementById('updated').textContent = 'error: ' + e;
  }
}

// ant 进程 PID 与常驻内存（RSS），定时刷新。
async function refreshRuntime() {
  try {
    const r = await api('/runtime');
    const c = await r.json();
    document.getElementById('info-runtime').innerHTML = [
      pitem('PID', c.pid ?? '—'),
      pitem('内存占用', c.memory_bytes == null ? '—' : fmtBytes(c.memory_bytes)),
    ].join('');
  } catch (_) { /* ignore */ }
}

// ── logs ─────────────────────────────────────────────────
function fmtLogTs(ms) {
  const d = new Date(ms);
  const p = n => String(n).padStart(2, '0');
  return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
async function refreshLogs(scrollBottom) {
  try {
    const r = await api('/logs');
    const data = await r.json();
    const box = document.getElementById('log-box');
    document.getElementById('logs-count').textContent = data.length + ' 条';
    if (!data.length) {
      box.innerHTML = '<div class="empty" id="logs-empty">暂无日志</div>';
      return;
    }
    const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
    box.innerHTML = data.map(l =>
      `<div class="log-line"><span class="log-ts">${fmtLogTs(l.ts_ms)}</span>` +
      `<span class="log-lv ${esc(l.level)}">${esc(l.level)}</span>` +
      `<span class="log-msg">${esc(l.msg)}</span></div>`
    ).join('');
    if (scrollBottom || nearBottom) box.scrollTop = box.scrollHeight;
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') document.getElementById('updated').textContent = 'error: ' + e;
  }
}
document.getElementById('btn-refresh-logs').addEventListener('click', () => refreshLogs(true));
document.getElementById('btn-clear-logs').addEventListener('click', async () => {
  try {
    await api('/logs', { method: 'DELETE' });
    refreshLogs(true);
  } catch (e) { /* ignore */ }
});

// ── 启动 ─────────────────────────────────────────────────
(async function init() {
  await loadDelays();                  // 先恢复服务端内存里的最近一次测速结果
  activate(pageFromLocation(), false); // 再按当前 URL 激活对应页面
  refreshConn();                       // 连接数徽标
})();
setInterval(() => {
  const page = document.querySelector('.nav button.active')?.dataset.page;
  if (page === 'connections') refreshConn();
  else if (page === 'logs' && document.getElementById('logs-auto')?.checked) refreshLogs(false);
  else if (page === 'info') refreshRuntime();
  else if (page === 'proxies') { /* keep delays; soft refresh optional */ }
}, 1500);
</script>
</body>
</html>
"#;
