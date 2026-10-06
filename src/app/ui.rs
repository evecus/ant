//! Embedded dashboard HTML: proxy-groups / connections / info (mihomo-style),
//! plus the api-secret login page.

pub const LOGIN_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ant — 登录</title>
<style>
  :root { color-scheme: dark; --bg:#0f1419; --card:#161b22; --line:#30363d; --muted:#8b949e; --text:#e7ecf3; --acc:#58a6ff; --bad:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background:var(--bg); color:var(--text); padding:16px; }
  .box { width:100%; max-width:340px; background:var(--card); border:1px solid var(--line);
    border-radius:14px; padding:28px 24px; }
  h1 { font-size:18px; margin:0 0 4px; font-weight:600; text-align:center; }
  p { margin:0 0 20px; font-size:12px; color:var(--muted); text-align:center; }
  input {
    width:100%; background:#0d1117; border:1px solid var(--line); color:var(--text);
    border-radius:10px; padding:10px 12px; font-size:14px; outline:none;
  }
  input:focus { border-color:var(--acc); }
  button {
    width:100%; margin-top:12px; background:#1f6feb33; border:1px solid #1f6feb; color:var(--acc);
    border-radius:10px; padding:10px 0; font-size:14px; cursor:pointer;
  }
  button:hover { filter:brightness(1.2); }
  button:disabled { opacity:.5; cursor:default; }
  .err { color:var(--bad); font-size:12px; text-align:center; min-height:16px; margin-top:10px; }
</style>
</head>
<body>
<div class="box">
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
  :root { color-scheme: dark; --bg:#0f1419; --card:#161b22; --line:#30363d; --muted:#8b949e; --text:#e7ecf3; --acc:#58a6ff; --ok:#3fb950; --bad:#f85149; --warn:#d2a8ff; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:var(--bg); color:var(--text); }
  header {
    display:flex; align-items:center; gap:12px; padding:12px 16px;
    background:var(--card); border-bottom:1px solid var(--line);
    position:sticky; top:0; z-index:30; flex-wrap:wrap;
  }
  h1 { font-size:16px; margin:0; font-weight:600; }
  .nav { display:flex; gap:4px; margin-left:8px; }
  .nav button {
    background:transparent; border:1px solid transparent; color:var(--muted);
    padding:6px 12px; border-radius:8px; cursor:pointer; font-size:13px;
  }
  .nav button.active { color:var(--text); background:#21262d; border-color:var(--line); }
  .nav button:hover { color:var(--text); }
  .meta { color:var(--muted); font-size:12px; margin-left:auto; }
  .pill { background:#21262d; border:1px solid var(--line); border-radius:999px; padding:2px 10px; font-size:12px; color:var(--acc); }
  main { padding:16px; max-width:1100px; margin:0 auto; }
  .page { display:none; }
  .page.active { display:block; }
  .card {
    background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:14px 16px; margin-bottom:12px;
  }
  .card h2 { margin:0 0 10px; font-size:14px; font-weight:600; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .tag { font-size:11px; color:var(--muted); border:1px solid var(--line); border-radius:999px; padding:1px 8px; font-weight:500; }
  .tag.now { color:var(--ok); border-color:#238636; }
  .members { display:flex; flex-wrap:wrap; gap:8px; }
  .mem {
    background:#21262d; border:1px solid var(--line); border-radius:10px;
    padding:8px 12px; min-width:120px; cursor:pointer; font-size:13px;
    display:flex; flex-direction:column; gap:4px; transition: border-color .15s;
  }
  .mem:hover { border-color:var(--acc); }
  .mem.active { border-color:var(--ok); background:#15231a; }
  .mem .name { font-weight:500; }
  .mem .delay { font-size:11px; color:var(--muted); font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .mem .delay.ok { color:var(--ok); }
  .mem .delay.bad { color:var(--bad); }
  .actions { display:flex; gap:8px; flex-wrap:wrap; margin-top:10px; }
  .btn {
    background:#21262d; border:1px solid var(--line); color:var(--text);
    border-radius:8px; padding:6px 12px; font-size:12px; cursor:pointer;
  }
  .btn:hover { border-color:var(--acc); color:var(--acc); }
  .btn.primary { background:#1f6feb33; border-color:#1f6feb; color:var(--acc); }
  code, .mono { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }
  .kv { display:grid; grid-template-columns: 140px 1fr; gap:8px 12px; font-size:13px; }
  .kv .k { color:var(--muted); }
  .kv .v { word-break:break-all; }
  .list { margin:0; padding-left:18px; font-size:13px; color:var(--text); }
  .list li { margin:4px 0; }
  .on { color:var(--ok); } .off { color:var(--muted); }

  /* ── connections: card list (zashboard-style) ─────────────── */
  .conn-list { display:flex; flex-direction:column; gap:8px; }
  .conn-card {
    background:var(--card); border:1px solid var(--line); border-radius:12px;
    padding:10px 14px; cursor:pointer; transition:border-color .15s;
  }
  .conn-card:hover { border-color:var(--acc); }
  .conn-top { display:flex; align-items:center; gap:8px; min-width:0; }
  .net { font-size:10px; font-weight:600; border-radius:6px; padding:1px 7px; text-transform:uppercase;
    letter-spacing:.5px; flex-shrink:0; }
  .net.tcp { color:#79c0ff; background:#121d2f; border:1px solid #1f3a5f; }
  .net.udp { color:#d2a8ff; background:#191530; border:1px solid #3c2d6b; }
  .net.quic { color:#ffa657; background:#2a1d10; border:1px solid #6b4720; }
  .conn-host { font-size:14px; font-weight:500; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; min-width:0; }
  .conn-host .port { color:var(--muted); font-size:12px; }
  .chip { font-size:11px; border-radius:999px; padding:2px 10px; border:1px solid var(--line);
    color:var(--muted); flex-shrink:0; max-width:40%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .chip.ob-direct { color:var(--acc); border-color:#1f3a5f; }
  .chip.ob-block { color:var(--bad); border-color:#6b2020; }
  .chip.ob-proxy { color:var(--ok); border-color:#238636; }
  .conn-sub { display:flex; gap:6px 14px; flex-wrap:wrap; margin-top:5px; font-size:11px; color:var(--muted); }
  .conn-sub .rule { color:var(--warn); }
  .conn-sub span { white-space:nowrap; }

  /* ── connection detail modal ──────────────────────────────── */
  .mask {
    display:none; position:fixed; inset:0; background:rgba(0,0,0,.55);
    z-index:100; align-items:center; justify-content:center; padding:16px;
  }
  .mask.open { display:flex; }
  .modal {
    background:var(--card); border:1px solid var(--line); border-radius:14px;
    width:100%; max-width:560px; max-height:85vh; overflow-y:auto; padding:18px 20px;
  }
  .modal-head { display:flex; align-items:flex-start; gap:10px; margin-bottom:14px; }
  .modal-head h2 { margin:0; font-size:15px; font-weight:600; word-break:break-all; flex:1; }
  .modal-head .close { flex-shrink:0; width:28px; height:28px; padding:0; border-radius:8px; font-size:14px; line-height:1; }
  @media (max-width:600px) {
    .kv { grid-template-columns: 1fr; gap:2px 0; }
    .kv .k { margin-top:8px; }
    .modal { max-height:90vh; padding:16px; }
    .chip { max-width:50%; }
  }
</style>
</head>
<body>
<header>
  <h1>ant</h1>
  <nav class="nav">
    <button type="button" data-page="proxies" class="active">代理组</button>
    <button type="button" data-page="connections">连接</button>
    <button type="button" data-page="info">信息</button>
  </nav>
  <span class="pill" id="count" style="display:none">0</span>
  <span class="meta" id="updated">—</span>
</header>
<main>
  <!-- 1. proxy groups -->
  <section id="page-proxies" class="page active">
    <div class="actions" style="margin-bottom:12px">
      <button class="btn primary" type="button" id="btn-test-all">全部测速</button>
      <button class="btn" type="button" id="btn-refresh-proxies">刷新</button>
      <span class="meta mono" id="test-url-label"></span>
    </div>
    <div id="groups"></div>
    <div class="empty" id="groups-empty" style="display:none">暂无代理组</div>
  </section>

  <!-- 2. connections: card list + detail modal -->
  <section id="page-connections" class="page">
    <div class="conn-list" id="conn-list"></div>
    <div class="empty" id="empty" style="display:none">暂无活动连接</div>
  </section>

  <!-- 3. info -->
  <section id="page-info" class="page">
    <div class="card">
      <h2>入站 / 端口</h2>
      <div class="kv" id="info-ports"></div>
    </div>
    <div class="card">
      <h2>DNS</h2>
      <div class="kv" id="info-dns"></div>
    </div>
    <div class="card">
      <h2>TUN</h2>
      <div class="kv" id="info-tun"></div>
    </div>
    <div class="card">
      <h2>规则集 <span class="tag" id="ruleset-count">0</span></h2>
      <ul class="list" id="info-rulesets"></ul>
    </div>
    <div class="card">
      <h2>路由规则 <span class="tag" id="route-count">0</span></h2>
      <ul class="list mono" id="info-routes"></ul>
    </div>
    <div class="card">
      <h2>节点 <span class="tag" id="node-count">0</span></h2>
      <ul class="list mono" id="info-nodes"></ul>
    </div>
  </section>
</main>

<div class="mask" id="conn-mask">
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-head">
      <h2 id="modal-title"></h2>
      <button class="btn close" type="button" id="modal-close">✕</button>
    </div>
    <div class="kv" id="modal-kv"></div>
  </div>
</div>

<script>
const TEST_URL = 'http://www.gstatic.com/generate_204';
const delays = {}; // name -> ms | -1 fail | undefined
let connData = [];  // latest /connections payload (for the detail modal)

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

// tabs
document.querySelectorAll('.nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('page-' + btn.dataset.page).classList.add('active');
    const c = document.getElementById('count');
    c.style.display = btn.dataset.page === 'connections' ? '' : 'none';
    if (btn.dataset.page === 'info') refreshInfo();
    if (btn.dataset.page === 'proxies') refreshProxies();
    if (btn.dataset.page === 'connections') refreshConn();
  });
});

// ── proxies ──────────────────────────────────────────────
async function refreshProxies() {
  try {
    const r = await api('/proxies');
    const data = await r.json();
    const root = document.getElementById('groups');
    const empty = document.getElementById('groups-empty');
    document.getElementById('test-url-label').textContent = TEST_URL;
    if (!data.length) {
      root.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    root.innerHTML = data.map(g => {
      const selectable = g.type === 'select';
      const members = (g.all || []).map(m => {
        const active = m === g.now ? ' active' : '';
        return `<div class="mem${active}" data-group="${esc(g.name)}" data-member="${esc(m)}" data-selectable="${selectable}">
          <span class="name">${esc(m)}</span>
          <span class="delay ${delayClass(m)}">${delayText(m)}</span>
        </div>`;
      }).join('');
      return `<div class="card" data-group-card="${esc(g.name)}">
        <h2>${esc(g.name)} <span class="tag">${esc(g.type)}</span>
          <span class="tag now">now: ${esc(g.now)}</span></h2>
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

async function testOne(name) {
  try {
    const r = await api('/proxies/' + encodeURIComponent(name) + '/delay?url=' + encodeURIComponent(TEST_URL) + '&timeout=5000');
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
  document.querySelectorAll('.mem').forEach(el => names.add(el.dataset.member));
  for (const n of names) await testOne(n); // sequential to avoid stampede
});
document.getElementById('btn-refresh-proxies').addEventListener('click', refreshProxies);

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
function closeConnModal() { document.getElementById('conn-mask').classList.remove('open'); }
document.getElementById('modal-close').addEventListener('click', closeConnModal);
document.getElementById('conn-mask').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeConnModal();
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeConnModal(); });

function row(k, v) { return `<div class="k">${esc(k)}</div><div class="v">${v}</div>`; }

// ── info ─────────────────────────────────────────────────
function yn(v) { return v ? '<span class="on">开启</span>' : '<span class="off">关闭</span>'; }

async function refreshInfo() {
  try {
    const r = await api('/configs');
    const c = await r.json();
    document.getElementById('info-ports').innerHTML = [
      row('mixed-port', c.mixed_port || 0),
      row('tproxy-port', c.tproxy_port || 0),
      row('redir-port', c.redir_port || 0),
      row('api', esc(c.api || '—')),
      row('bind-address', esc(c.bind_address || '—')),
      row('log-level', esc(c.log_level || '—')),
      row('sniff', yn(!!c.sniff)),
      row('api-secret 鉴权', yn(!!c.auth)),
      row('api-connection-record', yn(!!c.api_connection_record)),
    ].join('');
    document.getElementById('info-dns').innerHTML = [
      row('enable', yn(!!c.dns_enable)),
      row('port', c.dns_port == null ? '—' : (c.dns_port || '未监听（仅劫持）')),
      row('mode', esc(c.dns_mode || '—')),
      row('rule-follow-route', yn(!!c.dns_rule_follow_route)),
      row('default-nameserver', '<code>'+esc(c.dns_default_nameserver||'—')+'</code>'),
      row('direct-nameserver', '<code>'+esc(c.dns_direct_nameserver||'—')+'</code>'),
      row('proxy-nameserver', '<code>'+esc(c.dns_proxy_nameserver||'—')+'</code>'),
      row('fakeip-range', esc(c.fakeip_range || '—')),
      row('fakeip6-range', esc(c.fakeip6_range || '—')),
      row('ipv6', yn(!!c.dns_ipv6)),
    ].join('');
    document.getElementById('info-tun').innerHTML = [
      row('enable', yn(!!c.tun_enable)),
      row('stack', esc(c.tun_stack || '—')),
      row('device', esc(c.tun_device || '—')),
      row('auto-route', yn(!!c.tun_auto_route)),
      row('strict-route', yn(!!c.tun_strict_route)),
      row('auto-detect-interface', yn(!!c.tun_auto_detect_interface)),
      row('dns-hijack', (c.tun_dns_hijack||[]).map(esc).join(', ') || '—'),
    ].join('');
    const rs = c.rule_providers || [];
    document.getElementById('ruleset-count').textContent = rs.length;
    document.getElementById('info-rulesets').innerHTML = rs.length
      ? rs.map(x => `<li><code>${esc(x.name)}</code> · ${esc(x.behavior||x.type||'')} · ${esc(x.path||'')}</li>`).join('')
      : '<li class="off">无</li>';
    const routes = c.route || [];
    document.getElementById('route-count').textContent = routes.length;
    document.getElementById('info-routes').innerHTML = routes.length
      ? routes.map(x => `<li>${esc(x)}</li>`).join('')
      : '<li class="off">无</li>';
    const nodes = c.proxies || [];
    document.getElementById('node-count').textContent = nodes.length;
    document.getElementById('info-nodes').innerHTML = nodes.length
      ? nodes.map(x => `<li>${esc(x)}</li>`).join('')
      : '<li class="off">无</li>';
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
  } catch (e) {
    if (String(e) !== 'Error: unauthorized') document.getElementById('updated').textContent = 'error: ' + e;
  }
}

refreshProxies();
refreshConn();
setInterval(() => {
  const page = document.querySelector('.nav button.active')?.dataset.page;
  if (page === 'connections') refreshConn();
  else if (page === 'proxies') { /* keep delays; soft refresh optional */ }
}, 1500);
</script>
</body>
</html>
"#;
