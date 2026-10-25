package hub

var DashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAHAND MATRIX // Multi-Server Packet & DPI Lab</title>
<style>
  :root {
    --bg: #0B0F19; --card: #111827; --border: #1E293B;
    --cyan: #38BDF8; --emerald: #10B981; --amber: #F59E0B;
    --crimson: #EF4444; --text: #F8FAFC; --muted: #94A3B8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', system-ui, Tahoma, monospace; }
  body { background: var(--bg); color: var(--text); min-height: 100vh; }
  body.rtl { direction: rtl; text-align: right; }
  bdi, .ltr { direction: ltr; unicode-bidi: isolate; display: inline-block; }
  header {
    background: #0D1322; border-bottom: 1px solid var(--border); padding: 10px 18px;
    display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;
    position: sticky; top: 0; z-index: 30;
  }
  .brand { font-size: 15px; font-weight: 700; display: flex; align-items: center; gap: 8px; }
  .controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  select, input {
    background: #070B14; color: var(--text); border: 1px solid var(--border);
    padding: 6px 10px; border-radius: 6px; font-size: 12px;
  }
  .btn {
    padding: 6px 11px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;
    border: 1px solid var(--border); background: var(--card); color: var(--text);
  }
  .btn:hover { filter: brightness(1.15); }
  .btn-start { border-color: var(--emerald); color: var(--emerald); background: rgba(16,185,129,0.12); }
  .btn-stop { border-color: var(--crimson); color: var(--crimson); background: rgba(239,68,68,0.12); }
  .btn-pause { border-color: var(--cyan); color: var(--cyan); background: rgba(56,189,248,0.12); }
  .btn-tab.active { background: var(--cyan); color: #000; border-color: var(--cyan); }
  .pill { font-size: 11px; font-weight: 700; padding: 5px 10px; border-radius: 14px; border: 1px solid var(--amber); color: var(--amber); }
  .pill.live { border-color: var(--emerald); color: var(--emerald); background: rgba(16,185,129,0.1); }
  .wrap { max-width: 1720px; margin: 0 auto; padding: 12px 18px; }

  .toolbar {
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;
    margin-bottom: 10px; font-size: 12px; background: #111827; padding: 8px 14px;
    border-radius: 8px; border: 1px solid var(--border);
  }
  .tool-group { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }

  .cp-row {
    display: grid; grid-template-columns: 1.45fr 1fr; gap: 14px;
    background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--emerald);
    border-radius: 10px; padding: 11px 14px; margin-bottom: 10px; align-items: stretch;
  }
  .cp-row.critical { border-color: var(--crimson); border-left-width: 5px; background: rgba(239,68,68,0.04); }
  .cp-row.warning { border-left-color: var(--amber); }
  .cp-left { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
  .cp-top { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
  .cp-title { font-size: 13px; font-weight: 700; color: var(--cyan); }
  .srv-badge {
    font-size: 11px; font-weight: 700; padding: 2px 7px; border-radius: 4px;
    background: rgba(168,85,247,0.18); color: #E9D5FF; border: 1px solid #A855F7; margin: 0 5px;
  }
  .scroll-lock-badge {
    font-size: 10.5px; font-weight: 700; padding: 2px 7px; border-radius: 4px;
    background: rgba(245,158,11,0.2); color: #FDE68A; border: 1px solid var(--amber); display: none;
  }
  .dpi-badge { font-size: 10.5px; font-weight: 700; padding: 2px 8px; border-radius: 5px; }
  .dpi-badge.crit { background: rgba(239,68,68,0.2); color: #FCA5A5; border: 1px solid var(--crimson); }
  .dpi-badge.safe { background: rgba(16,185,129,0.15); color: var(--emerald); border: 1px solid var(--emerald); }

  .raw-box {
    background: #050811; border: 1px solid #1E293B; border-radius: 6px; padding: 7px 9px;
    font-family: 'Courier New', monospace; font-size: 11.5px;
    height: 135px; min-height: 85px; max-height: 680px;
    overflow-y: auto; resize: vertical; direction: ltr; text-align: left;
  }
  .raw-line {
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding: 2px 4px;
    border-radius: 4px; cursor: pointer; color: #7DD3FC; margin-bottom: 1px;
  }
  .raw-line:hover { background: rgba(255,255,255,0.07); }
  .raw-line.crit { color: #FCA5A5; background: rgba(239,68,68,0.08); }
  .raw-line.warn { color: #FDE68A; background: rgba(245,158,11,0.06); }
  .raw-line.matched { outline: 1px solid var(--amber); background: rgba(245,158,11,0.25) !important; color: #FFF !important; }
  .port-tag { color: #E2E8F0; font-weight: 700; background: #1E293B; padding: 0 4px; border-radius: 3px; margin-right: 4px; }
  .corr-tag { color: #C084FC; font-weight: 700; margin-right: 4px; }
  .copy-btn {
    float: right; font-size: 10px; background: #1E293B; color: #CBD5E1; border: none;
    border-radius: 3px; padding: 0 5px; cursor: pointer; margin-left: 6px;
  }
  .copy-btn:hover { background: var(--cyan); color: #000; }

  .cp-right {
    background: #0A0E19; border: 1px solid #1E293B; border-radius: 8px; padding: 9px 12px;
    display: flex; flex-direction: column; justify-content: space-between; font-size: 11.5px; line-height: 1.42;
  }
  .stat-bar { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px; border-bottom: 1px solid #1E293B; padding-bottom: 5px; margin-bottom: 4px; font-family: monospace; direction: ltr; }
  .avg-bar {
    background: #0F172A; border: 1px solid #1E293B; border-radius: 5px; padding: 5px 8px;
    margin-bottom: 5px; font-family: monospace; font-size: 11px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 4px; direction: ltr;
  }
  .verdict { margin-top: 4px; padding: 5px 8px; border-radius: 5px; background: rgba(56,189,248,0.12); color: #7DD3FC; font-weight: 600; border-left: 3px solid var(--cyan); }
  .verdict.crit { background: rgba(239,68,68,0.18); color: #FECACA; border-left-color: var(--crimson); }
  .verdict.warn { background: rgba(245,158,11,0.16); color: #FDE68A; border-left-color: var(--amber); }

  .srv-grid { display: grid; grid-template-columns: 350px 1fr; gap: 16px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 15px; }
  .form-row { margin-bottom: 9px; display: flex; flex-direction: column; gap: 4px; font-size: 12px; }
  .node-card { background: #0B101D; border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 10px; }
  .prog-track { height: 8px; background: #1E293B; border-radius: 4px; overflow: hidden; margin: 8px 0; }
  .prog-fill { height: 100%; background: var(--emerald); transition: width 0.3s; }
  .log-box { background: #050811; padding: 8px; border-radius: 6px; font-family: monospace; font-size: 11px; height: 80px; overflow-y: auto; color: #A7F3D0; direction: ltr; text-align: left; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <span style="color:var(--cyan)">❖</span> <bdi>SAHAND MATRIX</bdi>
    <button id="tabMatrix" class="btn btn-tab active" onclick="showTab('matrix')">6-Window Matrix</button>
    <button id="tabServers" class="btn btn-tab" onclick="showTab('servers')">🖧 Servers & SSH Deploy</button>
    <button id="langBtn" class="btn" onclick="toggleLang()">🌐 فارسی / EN</button>
  </div>
  <div class="controls">
    <span id="lblS1" style="font-size:11px;color:var(--muted)">Main Server:</span>
    <select id="s1Select" onchange="setPair()"></select>
    <span id="lblS2" style="font-size:11px;color:var(--muted)">➔ Server 2 / 3:</span>
    <select id="s2Select" onchange="setPair()"></select>
    <span id="statePill" class="pill">● STOPPED</span>
    <button id="btnStart" class="btn btn-start" onclick="ctrlCapture('start')">▶ Start Both</button>
    <button id="btnStop" class="btn btn-stop" onclick="ctrlCapture('stop')">■ Stop Both</button>
    <button id="pauseBtn" class="btn btn-pause" onclick="toggleSmartPause()">⏸ 5-Ping Sync Pause</button>
  </div>
</header>

<div class="wrap">
  <div id="viewMatrix">
    <div class="toolbar">
      <div id="pingBanner"><strong>5-Ping Sync (1h Cache):</strong> Click Pause to measure 5 pings & freeze 150 pkts/window</div>
      <div class="tool-group">
        <input id="portFilter" class="ltr" placeholder="Ports (e.g. 443, 8443)" oninput="applyFilters()" style="width:185px;">
        <button id="btnLockP" class="btn btn-pause" onclick="lockSnifferPorts()">🔒 Lock Sniffer Ports</button>
        <button id="btnAllP" class="btn" onclick="unlockSnifferPorts()">🔓 All Ports</button>
        <span id="lockPortBadge" class="ltr" style="font-size:11px;color:var(--emerald);font-weight:700;">[Sniffer: All Ports]</span>
        <label style="cursor:pointer;display:flex;align-items:center;gap:4px;color:#FCA5A5;font-weight:600;">
          <input type="checkbox" id="leaksOnly" onchange="applyFilters()"> <span id="lblRedOnly">🔴 Red Only</span>
        </label>
        <button class="btn" onclick="setAllHeights(125)">Compact</button>
        <button class="btn" onclick="setAllHeights(240)">Tall</button>
        <button class="btn" onclick="setAllHeights(420)">Max</button>
      </div>
    </div>
    <div id="cpList"></div>
  </div>

  <div id="viewServers" style="display:none;">
    <div class="srv-grid">
      <div class="card">
        <h3 id="addSrvTitle" style="font-size:14px;margin-bottom:10px;color:var(--cyan)">+ Add Server 2 / Server 3 (SSH or Sentinel)</h3>
        <div class="form-row"><label>Server Label</label><input id="fName" placeholder="e.g. Server 2 (Relay/Exit)"></div>
        <div class="form-row"><label>Server Role</label>
          <select id="fRole"><option value="kharej">Server 2 / Server 3 (Transit/Exit CP4-CP6)</option><option value="iran">Main Server (Entry CP1-CP3)</option></select>
        </div>
        <div class="form-row"><label>Server IP Address</label><input id="fHost" class="ltr" placeholder="e.g. 203.0.113.10"></div>
        <div class="form-row"><label>SSH Port</label><input id="fPort" class="ltr" type="number" value="22"></div>
        <div class="form-row"><label>SSH Username</label><input id="fUser" class="ltr" value="root"></div>
        <div class="form-row"><label>SSH Password (blank if Sentinel installed)</label><input id="fPass" type="password" placeholder="Root password (or blank)"></div>
        <button class="btn btn-start" style="width:100%;margin-top:4px;" onclick="addServer()">🔗 Save & Connect Server</button>
        <div id="addMsg" style="font-size:11px;margin-top:8px;color:var(--amber)"></div>
      </div>
      <div class="card">
        <h3 style="font-size:14px;margin-bottom:10px;">Connected Server Nodes (Main Server, Server 2, Server 3...)</h3>
        <div id="nodeList"></div>
      </div>
    </div>
  </div>
</div>

<script>
let isPaused = false, selectedTag = '', lastData = null, lastNodeKey = '', domInitialized = false, lang = 'en';
const scrollLocks = {};

const faGuides = {
  1: { t: "پنجره ۱: کارت شبکه ورودی سرور اصلی (کلاینت ➔ <bdi>Main Server</bdi>)", z: "🚨 بررسی DPI در ورودی سرور اصلی", w: "بسته‌های دریافتی از کلاینت شما در ورود به سرور اصلی.", g: "🔵 خطوط آبی: فریم‌های استاندارد <bdi>TLS 1.3 (\\x17\\x03\\x03)</bdi>.", b: "🔴 خطوط قرمز: هدرهای رمزنگاری‌نشده یا جریان بدون هدر <bdi>TLS</bdi>." },
  2: { t: "پنجره ۲: هسته داخلی تانل در سرور اصلی (<bdi>Internal RAM</bdi>)", z: "🔒 غیرقابل دید برای DPI خارجی", w: "انتقال داخلی بسته‌ها در حافظه سرور اصلی پیش از ارسال به تانل.", g: "🔵 خطوط آبی: پردازش ایمن داخلی در حافظه رم سرور اصلی.", b: "بدون ریسک — ایزوله در داخل سرور اصلی." },
  3: { t: "پنجره ۳: خروجی تانل مرزی (<bdi>Main Server ➔ Server 2</bdi>)", z: "🚨 حساس‌ترین نقطه: گیت‌وی مرزی (DPI)", w: "بسته‌های تانل در حال خروج از سرور اصلی به سمت سرور ۲.", g: "🔵 خطوط آبی: فریم‌های معتبر <bdi>TLS/WSS/Reality</bdi> با درصد مخفی‌سازی وزنی بالا.", b: "🔴 خطوط قرمز: پورت‌فوروارد خام یا متن آشکار قابل تشخیص توسط فایروال." },
  4: { t: "پنجره ۴: کارت شبکه ورودی سرور ۲ (<bdi>Main Server ➔ Server 2</bdi>)", z: "👁 لبه دیتاسنتر سرور ۲", w: "بسته‌های تانل که از سرور اصلی به کارت شبکه سرور ۲ می‌رسند.", g: "🔵 خطوط آبی منطبق با تگ‌های <bdi>[TAG:xxxx]</bdi> پنجره ۳ پس از تاخیر <bdi>+RTT/2</bdi>.", b: "🔴 خطوط قرمز یا حذف شدن بسته‌ها در مسیر مرزی." },
  5: { t: "پنجره ۵: هسته رمزگشایی داخلی سرور ۲ (<bdi>Server 2 RAM</bdi>)", z: "🔒 غیرقابل دید برای DPI (حافظه سرور ۲)", w: "جریان رمزگشایی‌شده در داخل سرور ۲ پیش از ارسال به اینترنت.", g: "🔵 خطوط آبی: پردازش داخلی ایمن در سرور ۲.", b: "بدون ریسک — داخل حافظه سرور ۲." },
  6: { t: "پنجره ۶: خروجی اینترنت آزاد (<bdi>Server 2 ➔ Target Web</bdi>)", z: "🌐 خروجی اینترنت مقصد", w: "ترافیک نهایی خروجی از سرور ۲ به سمت وب‌سایت‌های مقصد (<bdi>:443</bdi>).", g: "🔵 خطوط آبی: ارتباط استاندارد <bdi>HTTPS (\\x17\\x03\\x03)</bdi>.", b: "🔴 خطوط قرمز: ترافیک <bdi>HTTP (:80)</bdi> بدون رمزنگاری." }
};

function toggleLang() {
  lang = (lang === 'en') ? 'fa' : 'en';
  document.body.className = (lang === 'fa') ? 'rtl' : '';
  document.getElementById('tabMatrix').innerText = lang==='fa' ? 'ماتریس ۶ پنجره‌ای' : '6-Window Matrix';
  document.getElementById('tabServers').innerText = lang==='fa' ? '🖧 مدیریت سرورها (Main / Server 2)' : '🖧 Servers & SSH Deploy';
  document.getElementById('lblS1').innerText = lang==='fa' ? 'سرور اصلی:' : 'Main Server:';
  document.getElementById('lblS2').innerText = lang==='fa' ? '➔ سرور ۲ / ۳:' : '➔ Server 2 / 3:';
  document.getElementById('btnStart').innerText = lang==='fa' ? '▶ شروع هر دو' : '▶ Start Both';
  document.getElementById('btnStop').innerText = lang==='fa' ? '■ توقف هر دو' : '■ Stop Both';
  document.getElementById('btnLockP').innerText = lang==='fa' ? '🔒 قفل اسنیفر روی پورت' : '🔒 Lock Sniffer Ports';
  document.getElementById('btnAllP').innerText = lang==='fa' ? '🔓 همه پورت‌ها' : '🔓 All Ports';
  document.getElementById('lblRedOnly').innerText = lang==='fa' ? '🔴 فقط خطوط قرمز' : '🔴 Red Only';
  if (lastData) renderMatrix(lastData);
}

function showTab(t) {
  document.getElementById('viewMatrix').style.display = t === 'matrix' ? 'block' : 'none';
  document.getElementById('viewServers').style.display = t === 'servers' ? 'block' : 'none';
  document.getElementById('tabMatrix').className = 'btn btn-tab' + (t === 'matrix' ? ' active' : '');
  document.getElementById('tabServers').className = 'btn btn-tab' + (t === 'servers' ? ' active' : '');
}

function selectTag(tag) { selectedTag = (selectedTag === tag) ? '' : tag; if (lastData) renderMatrix(lastData); }
function copyLine(ev) {
  ev.stopPropagation();
  const btn = ev.target;
  const lineText = btn.parentElement.innerText.replace('📋 Copy', '').replace('✓ Copied', '').trim();
  navigator.clipboard.writeText(lineText);
  btn.innerText = '✓ Copied';
  setTimeout(() => { btn.innerText = '📋 Copy'; }, 1200);
}
function setAllHeights(px) { document.querySelectorAll('.raw-box').forEach(b => { b.style.height = px + 'px'; }); }
function applyFilters() { if (lastData) renderMatrix(lastData); }
async function lockSnifferPorts() { await fetch('api/ports?ports=' + encodeURIComponent(document.getElementById('portFilter').value.trim()), {method:'POST'}); pollState(); }
async function unlockSnifferPorts() { document.getElementById('portFilter').value = ''; await fetch('api/ports?ports=', {method:'POST'}); pollState(); }
function splitPort(addr) { if (!addr) return ['—','—']; const idx = addr.lastIndexOf(':'); return idx > -1 ? [addr.slice(0, idx), addr.slice(idx+1)] : [addr, '—']; }

function onBoxScroll(cpId) {
  const b = document.getElementById('box-' + cpId);
  if (!b) return;
  if ((b.scrollHeight - b.scrollTop - b.clientHeight) < 18) delete scrollLocks[cpId];
  else scrollLocks[cpId] = Date.now() + 20000;
  updateScrollBadge(cpId);
}
function updateScrollBadge(cpId) {
  const badge = document.getElementById('lock-' + cpId);
  if (!badge) return;
  const rem = Math.ceil(((scrollLocks[cpId] || 0) - Date.now()) / 1000);
  badge.style.display = rem > 0 ? 'inline-block' : 'none';
  if (rem > 0) badge.innerText = '⏸ Scroll Locked (' + rem + 's)';
}
setInterval(() => { [1,2,3,4,5,6].forEach(updateScrollBadge); }, 1000);

function ensureSkeleton(guides) {
  if (domInitialized || !guides || !guides.length) return;
  domInitialized = true;
  document.getElementById('cpList').innerHTML = guides.map(g =>
    '<div class="cp-row" id="row-' + g.id + '">' +
      '<div class="cp-left">' +
        '<div class="cp-top">' +
          '<div><span class="cp-title" id="title-' + g.id + '"></span><bdi class="srv-badge" id="srv-' + g.id + '"></bdi> <bdi class="scroll-lock-badge" id="lock-' + g.id + '"></bdi></div>' +
          '<span class="dpi-badge ' + (g.dpi_visible ? 'crit' : 'safe') + '" id="zone-' + g.id + '"></span>' +
        '</div>' +
        '<div class="raw-box" id="box-' + g.id + '"></div>' +
      '</div>' +
      '<div class="cp-right" id="right-' + g.id + '"></div>' +
    '</div>'
  ).join('');
  guides.forEach(g => {
    const b = document.getElementById('box-' + g.id);
    if (b) {
      b.addEventListener('wheel', () => onBoxScroll(g.id), {passive: true});
      b.addEventListener('touchmove', () => onBoxScroll(g.id), {passive: true});
      b.addEventListener('mousedown', () => { scrollLocks[g.id] = Date.now() + 20000; updateScrollBadge(g.id); });
    }
  });
}

async function ctrlCapture(action) { isPaused = false; await fetch('api/control?action=' + action, {method:'POST'}); pollState(); }
async function setPair() {
  const s1 = document.getElementById('s1Select').value, s2 = document.getElementById('s2Select').value;
  await fetch('api/pair?s1=' + encodeURIComponent(s1) + '&s2=' + encodeURIComponent(s2), {method:'POST'});
  pollState();
}
async function toggleSmartPause() {
  const btn = document.getElementById('pauseBtn');
  if (!isPaused) {
    btn.innerText = '⚡ 5-Ping Sync...';
    const res = await fetch('api/pause-burst');
    lastData = await res.json();
    isPaused = true;
    renderMatrix(lastData);
    btn.innerText = lang==='fa' ? '▶ ادامه جریان زنده' : '▶ Resume Live Stream';
  } else {
    isPaused = false;
    btn.innerText = '⏸ 5-Ping Sync Pause';
    pollState();
  }
}

function getServerLabel(d, role) {
  const nodes = d.nodes || [];
  const targetId = role === 'iran' ? d.active_s1 : d.active_s2;
  const found = nodes.find(n => n.id === targetId);
  if (!found) return role === 'iran' ? 'Main Server' : 'Server 2';
  const prefix = role === 'iran' ? 'Main Server: ' : 'Server 2: ';
  return prefix + found.name.replace('Primary Iran Server (Local Hub)', 'Local Hub') + ' (' + found.host + ')';
}

function renderMatrix(d) {
  ensureSkeleton(d.guides);
  const pill = document.getElementById('statePill');
  pill.className = (!isPaused && d.capturing) ? 'pill live' : 'pill';
  pill.innerText = isPaused ? ('⏸ PAUSED (+' + (d.ping ? d.ping.offset_ms.toFixed(1) : '0.0') + 'ms)') : (d.capturing ? '● CAPTURING REAL PACKETS' : '● STOPPED');

  const lp = d.locked_ports || [];
  const lBadge = document.getElementById('lockPortBadge');
  lBadge.innerText = lp.length ? ('[🔒 Ports: ' + lp.join(', ') + ']') : '[Sniffer: All Ports]';
  lBadge.style.color = lp.length ? 'var(--amber)' : 'var(--emerald)';

  const rawTokens = (document.getElementById('portFilter').value || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const leaksOnly = document.getElementById('leaksOnly').checked;

  d.guides.forEach(g => {
    const fg = (lang === 'fa' && faGuides[g.id]) ? faGuides[g.id] : null;
    const allEvs = (d.checkpoints && d.checkpoints[g.id]) || [];
    const evs = allEvs.filter(e => {
      if (leaksOnly && e.dpi.level === 'OPTIMAL') return false;
      if (rawTokens.length > 0) {
        const hay = (e.src_addr + ' ' + e.dst_addr + ' ' + e.correlation_tag + ' ' + e.protocol).toLowerCase();
        if (!rawTokens.some(tok => hay.includes(tok))) return false;
      }
      return true;
    });

    const statList = evs.length ? evs : allEvs;
    let safeCnt = 0, warnCnt = 0, critCnt = 0, sumStealth = 0, weightedSum = 0, totalBytes = 0;
    statList.forEach(e => {
      const b = Math.max(1, e.length || 1);
      sumStealth += e.dpi.stealth_score;
      weightedSum += (e.dpi.stealth_score * b);
      totalBytes += b;
      if (e.dpi.level === 'CRITICAL') critCnt++;
      else if (e.dpi.level === 'WARNING') warnCnt++;
      else safeCnt++;
    });
    const pktAvg = statList.length ? Math.round(sumStealth / statList.length) : 0;
    const bwStealth = totalBytes > 0 ? Math.round(weightedSum / totalBytes) : 0;
    const totalKB = (totalBytes / 1024).toFixed(1);

    const last = evs.length ? evs[evs.length - 1] : (allEvs.length ? allEvs[allEvs.length - 1] : null);
    const isCrit = last && last.dpi.level === 'CRITICAL';
    const isWarn = last && last.dpi.level === 'WARNING';
    const protoColor = isCrit ? 'var(--crimson)' : (isWarn ? 'var(--amber)' : 'var(--cyan)');
    const stealthColor = isCrit ? 'var(--crimson)' : (isWarn ? 'var(--amber)' : 'var(--emerald)');
    const bwColor = bwStealth < 50 ? 'var(--crimson)' : (bwStealth < 80 ? 'var(--amber)' : 'var(--emerald)');
    const sPort = last ? splitPort(last.src_addr)[1] : '—';
    const dPort = last ? splitPort(last.dst_addr)[1] : '—';

    document.getElementById('row-' + g.id).className = 'cp-row ' + (isCrit ? 'critical' : (isWarn ? 'warning' : ''));
    document.getElementById('title-' + g.id).innerHTML = (fg ? fg.t : g.title) + ' <bdi>(' + evs.length + '/' + allEvs.length + ' pkts | ' + totalKB + ' KB)</bdi>';
    document.getElementById('zone-' + g.id).innerHTML = fg ? fg.z : g.dpi_zone;
    document.getElementById('srv-' + g.id).innerText = getServerLabel(d, g.server_role);

    const box = document.getElementById('box-' + g.id);
    const prevTop = box.scrollTop;
    const isLocked = (scrollLocks[g.id] || 0) > Date.now();

    box.innerHTML = evs.length ? evs.map(e => {
      const sp = splitPort(e.src_addr)[1], dp = splitPort(e.dst_addr)[1];
      const cls = (e.dpi.level === 'CRITICAL' ? 'crit' : (e.dpi.level === 'WARNING' ? 'warn' : '')) + (selectedTag && e.correlation_tag === selectedTag ? ' matched' : '');
      return '<div class="raw-line ' + cls + '" onclick="selectTag(\'' + e.correlation_tag + '\')">' +
        '<button class="copy-btn" onclick="copyLine(event)">📋 Copy</button>' +
        '<span class="corr-tag">[' + e.correlation_tag + ']</span>' +
        '<span class="port-tag">Port ' + sp + '➔' + dp + '</span>' +
        '[#' + e.sequence_num + ' ' + e.src_addr + '➔' + e.dst_addr + ' | ' + e.length + 'B] ' + e.raw_byte_log.replace(/</g,'&lt;') + '</div>';
    }).join('') : '<div style="color:#64748B">No matching packets. Click [▶ Start Both] or adjust port filter...</div>';

    if (d.capturing && !isPaused && !isLocked) box.scrollTop = box.scrollHeight;
    else box.scrollTop = prevTop;

    const lblWhat = lang==='fa' ? '👁 آنچه می‌بینید:' : '👁 What you see:';
    const lblGood = lang==='fa' ? '✓ ایمن (آبی):' : '✓ Safe (Blue):';
    const lblBad  = lang==='fa' ? '✗ ریسک (قرمز):' : '✗ Exposed (Red):';

    document.getElementById('right-' + g.id).innerHTML =
      '<div>' +
        '<div class="stat-bar">' +
          '<span>Proto: <strong style="color:' + protoColor + '">' + (last ? last.protocol : '—') + '</strong></span>' +
          '<span>Ports: <strong style="color:#FFF">' + sPort + ' ➔ ' + dPort + '</strong></span>' +
          '<span>Entropy: <strong>' + (last ? last.dpi.shannon_entropy.toFixed(2) + '/8' : '—') + '</strong></span>' +
          '<span>Last Pkt: <strong style="color:' + stealthColor + '">' + (last ? last.dpi.stealth_score + '%' : '—') + '</strong></span>' +
        '</div>' +
        '<div class="avg-bar">' +
          '<span><strong>Byte-Weighted Stealth:</strong> <strong style="color:' + bwColor + ';font-size:12px;">' + (statList.length ? bwStealth + '%' : '—') + '</strong> <span style="color:var(--muted)">(Pkt Avg: ' + pktAvg + '%)</span></span>' +
          '<span><span style="color:#7DD3FC">🔵 ' + safeCnt + '</span> / <span style="color:#FDE68A">🟡 ' + warnCnt + '</span> / <span style="color:#FCA5A5">🔴 ' + critCnt + '</span> (' + totalKB + ' KB)</span>' +
        '</div>' +
        '<div style="color:var(--muted)"><strong>' + lblWhat + '</strong> ' + (fg ? fg.w : g.what_you_see) + '</div>' +
        '<div style="color:#6EE7B7"><strong>' + lblGood + '</strong> ' + (fg ? fg.g : g.good_for_dpi) + '</div>' +
        '<div style="color:#FCA5A5"><strong>' + lblBad + '</strong> ' + (fg ? fg.b : g.bad_for_dpi) + '</div>' +
      '</div>' +
      '<div class="verdict ' + (isCrit ? 'crit' : (isWarn ? 'warn' : '')) + '"><bdi>' + (last ? (last.dpi.color_meaning + ' — ' + last.dpi.explanation) : 'Idle — Waiting for real packet stream.') + '</bdi></div>';
  });
}

function renderNodes(nodes, activeS1, activeS2) {
  const key = nodes.map(n => n.id).join(',');
  if (key !== lastNodeKey) {
    lastNodeKey = key;
    const opts = nodes.map((n, idx) => {
      const cleanName = n.id === 'local-s1' ? 'Main Server (Local Hub)' : n.name;
      return '<option value="'+n.id+'">'+cleanName+' ('+n.host+')</option>';
    }).join('');
    document.getElementById('s1Select').innerHTML = opts;
    document.getElementById('s2Select').innerHTML = opts;
  }
  if (activeS1) document.getElementById('s1Select').value = activeS1;
  if (activeS2) document.getElementById('s2Select').value = activeS2;

  document.getElementById('nodeList').innerHTML = nodes.map((n, idx) => {
    const logs = (n.deploy_logs || []).map(l => '<div>' + l + '</div>').join('');
    const delBtn = n.id !== 'local-s1' ? '<button class="btn btn-stop" onclick="deleteNode(\'' + n.id + '\')">🗑 Delete</button>' : '';
    const roleTag = n.role === 'iran' ? 'MAIN SERVER' : ('SERVER ' + (idx + 1));
    return '<div class="node-card">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;">' +
        '<div><strong><bdi>' + (n.id==='local-s1'?'Main Server (Local Hub)':n.name) + '</bdi></strong> <bdi style="color:var(--cyan)">[' + roleTag + ' - ' + n.host + ']</bdi></div>' +
        '<div style="display:flex;gap:6px;">' +
          '<a href="http://' + n.host + ':9444/" target="_blank" class="btn" style="text-decoration:none;">↗ 3-Window Sentinel</a>' +
          '<button class="btn btn-pause" onclick="deployNode(\'' + n.id + '\')">🚀 Deploy (' + n.deploy_pct + '%)</button>' +
          delBtn +
        '</div>' +
      '</div>' +
      '<div class="prog-track"><div class="prog-fill" style="width:' + n.deploy_pct + '%"></div></div>' +
      '<div class="log-box">' + logs + '</div></div>';
  }).join('');
}

async function addServer() {
  const msg = document.getElementById('addMsg');
  msg.innerText = 'Verifying node...';
  const res = await fetch('api/nodes/add', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      name: document.getElementById('fName').value || 'Server 2',
      role: document.getElementById('fRole').value,
      host: document.getElementById('fHost').value,
      ssh_port: parseInt(document.getElementById('fPort').value || '22'),
      ssh_user: document.getElementById('fUser').value || 'root',
      password: document.getElementById('fPass').value
    })
  });
  const d = await res.json();
  msg.innerText = d.error ? ('Error: ' + d.error) : '✓ Server saved!';
  pollState();
}

async function deployNode(id) { await fetch('api/nodes/deploy?id=' + encodeURIComponent(id), {method:'POST'}); pollState(); }
async function deleteNode(id) { await fetch('api/nodes/delete?id=' + encodeURIComponent(id), {method:'POST'}); pollState(); }

async function pollState() {
  if (isPaused) return;
  try {
    const res = await fetch('api/state');
    lastData = await res.json();
    renderMatrix(lastData);
    renderNodes(lastData.nodes || [], lastData.active_s1, lastData.active_s2);
  } catch (e) {}
}
setInterval(pollState, 900); pollState();
</script>
</body>
</html>`
