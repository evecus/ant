//! Embedded UI panel HTML (served at `/ui` by the API).
//!
//! Migrated from `src/api/ui.html`. Plain HTML + CSS + vanilla JS polling
//! `/connections` every 1.5s.

pub const UI_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ant connections</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background: #0f1419; color: #e7ecf3;
  }
  header {
    display: flex; align-items: center; gap: 16px; padding: 14px 20px;
    background: #161b22; border-bottom: 1px solid #30363d; position: sticky; top: 0;
  }
  h1 { font-size: 16px; margin: 0; font-weight: 600; letter-spacing: .02em; }
  .meta { color: #8b949e; font-size: 13px; }
  .pill {
    background: #21262d; border: 1px solid #30363d; border-radius: 999px;
    padding: 2px 10px; font-size: 12px; color: #58a6ff;
  }
  main { padding: 16px 20px 40px; overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #21262d; white-space: nowrap; }
  th { color: #8b949e; font-weight: 500; position: sticky; top: 52px; background: #0f1419; }
  tr:hover td { background: #161b22; }
  .ob-proxy { color: #3fb950; }
  .ob-direct { color: #58a6ff; }
  .ob-block { color: #f85149; }
  .rule { color: #d2a8ff; }
  .empty { color: #8b949e; padding: 40px; text-align: center; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>ant</h1>
  <span class="pill" id="count">0</span>
  <span class="meta" id="updated">—</span>
</header>
<main>
  <table>
    <thead>
      <tr>
        <th>源 IP</th>
        <th>源端口</th>
        <th>目标 Host</th>
        <th>目标 IP</th>
        <th>目标端口</th>
        <th>入站</th>
        <th>规则</th>
        <th>出站</th>
        <th>时长</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
  <div class="empty" id="empty" style="display:none">暂无活动连接</div>
</main>
<script>
function fmtAge(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm' + (s % 60) + 's';
  const h = Math.floor(m / 60);
  return h + 'h' + (m % 60) + 'm';
}
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
async function refresh() {
  try {
    const r = await fetch('/connections');
    const data = await r.json();
    const rows = document.getElementById('rows');
    const empty = document.getElementById('empty');
    document.getElementById('count').textContent = data.length + ' connections';
    document.getElementById('updated').textContent = new Date().toLocaleTimeString();
    if (!data.length) {
      rows.innerHTML = '';
      empty.style.display = 'block';
      return;
    }
    empty.style.display = 'none';
    rows.innerHTML = data.map(c => {
      const obClass = 'ob-' + (c.outbound || '');
      return '<tr>' +
        '<td><code>' + esc(c.src_ip) + '</code></td>' +
        '<td>' + c.src_port + '</td>' +
        '<td><code>' + esc(c.dest_host) + '</code></td>' +
        '<td><code>' + esc(c.dest_ip) + '</code></td>' +
        '<td>' + c.dest_port + '</td>' +
        '<td>' + esc(c.inbound) + '</td>' +
        '<td class="rule">' + esc(c.rule) + '</td>' +
        '<td class="' + obClass + '">' + esc(c.outbound) + '</td>' +
        '<td>' + fmtAge(c.age_ms) + '</td>' +
      '</tr>';
    }).join('');
  } catch (e) {
    document.getElementById('updated').textContent = 'error: ' + e;
  }
}
refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"#;
