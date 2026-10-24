package hub

var DashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAHAND MATRIX // Real Packet & Iran DPI Lab</title>
<style>
  :root {
    --bg: #0B0F19; --card: #111827; --border: #1E293B;
    --cyan: #38BDF8; --emerald: #10B981; --amber: #F59E0B;
    --crimson: #EF4444; --text: #F8FAFC; --muted: #94A3B8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', system-ui, monospace; }
  body { background: var(--bg); color: var(--text); min-height: 100vh; }
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
  .tool-group { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

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
    overflow-y: auto; resize: vertical;
  }
  .raw-line {
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; padding: 2px 4px;
    border-radius: 4px; cursor: pointer; color: #7DD3FC; margin-bottom: 1px;
  }
  .raw-line:hover { background: rgba(255,255,255,0.07); }
  .raw-line.crit { color: #FCA5A5; background: rgba(239,68,68,0.08); }
  .raw-line.warn { color: #FDE68A; }
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
    display: flex; flex-direction: column; justify-content: space-between; font-size: 11.5px; line-height: 1.38;
  }
  .stat-bar { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 6px; border-bottom: 1px solid #1E293B; padding-bottom: 5px; margin-bottom: 4px; font-family: monospace; }
  .avg-bar {
    background: #0F172A; border: 1px solid #1E293B; border-radius: 5px; padding: 4px 8px;
    margin-bottom: 5px; font-family: monospace; font-size: 11px; display: flex; justify-content: space-between; flex-wrap: wrap;
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
  .log-box { background: #050811; padding: 8px; border-radius: 6px; font-family: monospace; font-size: 11px; height: 80px; overflow-y: auto; color: #A7F3D0; }
</style>
</head>
<body>
<header>
  <div class="brand">
    <span style="color:var(--cyan)">❖</span> SAHAND MATRIX
    <button id="tabMatrix" class="btn btn-tab active" onclick="showTab('matrix')">6-Window Matrix</button>
    <button id="tabServers" class="btn btn-tab" onclick="showTab('servers')">🖧 Servers & SSH Deploy</button>
  </div>
  <div class="controls">
    <span style="font-size:11px;color:var(--muted)">S1 (Iran):</span>
    <select id="s1Select" onchange="setPair()"></select>
    <span style="font-size:11px;color:var(--muted)">➔ S2 (Kharej):</span>
    <select id="s2Select" onchange="setPair()"></select>
    <span id="statePill" class="pill">● STOPPED (IDLE)</span>
    <button class="btn btn-start" onclick="ctrlCapture('start')">▶ Start Both</button>
    <button class="btn btn-stop" onclick="ctrlCapture('stop')">■ Stop Both</button>
    <button id="pauseBtn" class="btn btn-pause" onclick="toggleSmartPause()">⏸ 5-Ping Sync Pause</button>
  </div>
</header>

<div class="wrap">
  <div id="viewMatrix">
    <div class="toolbar">
      <div id="pingBanner"><strong>5-Ping Sync (1h Cache):</strong> Click Pause to measure 5 pings & freeze up to 150 packets/window</div>
      <div class="tool-group">
        <input id="portFilter" placeholder="🔍 Filter Port or IP (e.g. 44995)" oninput="applyFilters()" style="width:195px;">
        <label style="cursor:pointer;display:flex;align-items:center;gap:4px;color:#FCA5A5;font-weight:600;">
          <input type="checkbox" id="leaksOnly" onchange="applyFilters()"> 🔴 Show Flagged/Red Only
        </label>
        <span style="color:var(--muted)">| Window Size:</span>
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
        <h3 style="font-size:14px;margin-bottom:10px;color:var(--cyan)">+ Add Server (SSH or Manual Agent)</h3>
        <div class="form-row"><label>Server Name</label><input id="fName" placeholder="e.g. Ireland Kharej S2"></div>
        <div class="form-row"><label>Server Role</label>
          <select id="fRole"><option value="kharej">S2: Kharej Server (CP4-CP6)</option><option value="iran">S1: Iran Server (CP1-CP3)</option></select>
        </div>
        <div class="form-row"><label>Server IP Address</label><input id="fHost" placeholder="e.g. 205.234.152.182"></div>
        <div class="form-row"><label>SSH Port</label><input id="fPort" type="number" value="22"></div>
        <div class="form-row"><label>SSH Username</label><input id="fUser" value="root"></div>
        <div class="form-row"><label>SSH Password (blank if agent installed)</label><input id="fPass" type="password" placeholder="Root password (or blank)"></div>
        <button class="btn btn-start" style="width:100%;margin-top:4px;" onclick="addServer()">🔗 Save & Connect Server</button>
        <div id="addMsg" style="font-size:11px;margin-top:8px;color:var(--amber)"></div>
      </div>
      <div class="card">
        <h3 style="font-size:14px;margin-bottom:10px;">Connected Server Nodes</h3>
        <div id="nodeList"></div>
      </div>
    </div>
  </div>
</div>

<script>
let isPaused = false;
let selectedTag = '';
let lastData = null;
let lastNodeKey = '';
let domInitialized = false;
const scrollLocks = {};

function showTab(t) {
  document.getElementById('viewMatrix').style.display = t === 'matrix' ? 'block' : 'none';
  document.getElementById('viewServers').style.display = t === 'servers' ? 'block' : 'none';
  document.getElementById('tabMatrix').className = 'btn btn-tab' + (t === 'matrix' ? ' active' : '');
  document.getElementById('tabServers').className = 'btn btn-tab' + (t === 'servers' ? ' active' : '');
}

function selectTag(tag) {
  selectedTag = (selectedTag === tag) ? '' : tag;
  if (lastData) renderMatrix(lastData);
}

function copyLine(ev) {
  ev.stopPropagation();
  const btn = ev.target;
  const lineText = btn.parentElement.innerText.replace('📋 Copy', '').replace('✓ Copied', '').trim();
  navigator.clipboard.writeText(lineText);
  btn.innerText = '✓ Copied';
  setTimeout(() => { btn.innerText = '📋 Copy'; }, 1200);
}

function setAllHeights(px) {
  document.querySelectorAll('.raw-box').forEach(b => { b.style.height = px + 'px'; });
}

function applyFilters() {
  if (lastData) renderMatrix(lastData);
}

function splitPort(addr) {
  if (!addr) return ['—','—'];
  const idx = addr.lastIndexOf(':');
  return idx > -1 ? [addr.slice(0, idx), addr.slice(idx+1)] : [addr, '—'];
}

function onBoxScroll(cpId) {
  const b = document.getElementById('box-' + cpId);
  if (!b) return;
  const atBottom = (b.scrollHeight - b.scrollTop - b.clientHeight) < 18;
  if (atBottom) {
    delete scrollLocks[cpId];
  } else {
    scrollLocks[cpId] = Date.now() + 20000;
  }
  updateScrollBadge(cpId);
}

function updateScrollBadge(cpId) {
  const badge = document.getElementById('lock-' + cpId);
  if (!badge) return;
  const exp = scrollLocks[cpId] || 0;
  const rem = Math.ceil((exp - Date.now()) / 1000);
  if (rem > 0) {
    badge.style.display = 'inline-block';
    badge.innerText = '⏸ Scroll Locked (' + rem + 's)';
  } else {
    badge.style.display = 'none';
  }
}

setInterval(() => { [1,2,3,4,5,6].forEach(updateScrollBadge); }, 1000);

function ensureSkeleton(guides) {
  if (domInitialized || !guides || !guides.length) return;
  domInitialized = true;
  document.getElementById('cpList').innerHTML = guides.map(g =>
    '<div class="cp-row" id="row-' + g.id + '">' +
      '<div class="cp-left">' +
        '<div class="cp-top">' +
          '<div><span class="cp-title" id="title-' + g.id + '">' + g.title + '</span> <span class="scroll-lock-badge" id="lock-' + g.id + '"></span></div>' +
          '<span class="dpi-badge ' + (g.dpi_visible ? 'crit' : 'safe') + '">' + g.dpi_zone + '</span>' +
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

async function ctrlCapture(action) {
  isPaused = false;
  document.getElementById('pauseBtn').innerText = '⏸ 5-Ping Sync Pause';
  await fetch('api/control?action=' + action, {method:'POST'});
  pollState();
}

async function setPair() {
  const s1 = document.getElementById('s1Select').value;
  const s2 = document.getElementById('s2Select').value;
  await fetch('api/pair?s1=' + encodeURIComponent(s1) + '&s2=' + encodeURIComponent(s2), {method:'POST'});
  pollState();
}

async function toggleSmartPause() {
  const btn = document.getElementById('pauseBtn');
  if (!isPaused) {
    btn.innerText = '⚡ Checking 5 Pings (or 1h Cache)...';
    const res = await fetch('api/pause-burst');
    lastData = await res.json();
    isPaused = true;
    renderMatrix(lastData);
    btn.innerText = '▶ Resume Live Stream';
  } else {
    isPaused = false;
    btn.innerText = '⏸ 5-Ping Sync Pause';
    pollState();
  }
}

function renderMatrix(d) {
  ensureSkeleton(d.guides);
  const pill = document.getElementById('statePill');
  pill.className = (!isPaused && d.capturing) ? 'pill live' : 'pill';
  pill.innerText = isPaused ? ('⏸ PAUSED (+' + (d.ping ? d.ping.offset_ms.toFixed(1) : '0.0') + 'ms)') : (d.capturing ? '● CAPTURING REAL PACKETS' : '● STOPPED (PRESS START)');

  if (d.ping && d.ping.average_ms > 0) {
    const src = d.ping.used_cached ? 'Cached <1h' : 'Fresh 5-Ping';
    document.getElementById('pingBanner').innerHTML =
      '<strong>5-Ping (' + src + '):</strong> [' + d.ping.samples_ms.map(x=>x.toFixed(1)).join(', ') + '] ms ➔ <strong>Avg: ' + d.ping.average_ms.toFixed(1) + 'ms | Offset: +' + d.ping.offset_ms.toFixed(1) + 'ms</strong>';
  }

  const pFilter = (document.getElementById('portFilter').value || '').trim().toLowerCase();
  const leaksOnly = document.getElementById('leaksOnly').checked;

  d.guides.forEach(g => {
    const allEvs = (d.checkpoints && d.checkpoints[g.id]) || [];
    let safeCnt = 0, warnCnt = 0, critCnt = 0, sumStealth = 0;
    allEvs.forEach(e => {
      sumStealth += e.dpi.stealth_score;
      if (e.dpi.level === 'CRITICAL') critCnt++;
      else if (e.dpi.level === 'WARNING') warnCnt++;
      else safeCnt++;
    });
    const avgStealth = allEvs.length ? Math.round(sumStealth / allEvs.length) : 0;

    const evs = allEvs.filter(e => {
      if (leaksOnly && e.dpi.level === 'OPTIMAL') return false;
      if (pFilter && !(e.src_addr.toLowerCase().includes(pFilter) || e.dst_addr.toLowerCase().includes(pFilter) || e.correlation_tag.toLowerCase().includes(pFilter))) return false;
      return true;
    });

    const last = evs.length ? evs[evs.length - 1] : (allEvs.length ? allEvs[allEvs.length - 1] : null);
    const isCrit = last && last.dpi.level === 'CRITICAL';
    const isWarn = last && last.dpi.level === 'WARNING';
    const protoColor = isCrit ? 'var(--crimson)' : (isWarn ? 'var(--amber)' : 'var(--cyan)');
    const stealthColor = isCrit ? 'var(--crimson)' : (isWarn ? 'var(--amber)' : 'var(--emerald)');
    const avgColor = avgStealth < 50 ? 'var(--crimson)' : (avgStealth < 80 ? 'var(--amber)' : 'var(--emerald)');
    const sPort = last ? splitPort(last.src_addr)[1] : '—';
    const dPort = last ? splitPort(last.dst_addr)[1] : '—';

    document.getElementById('row-' + g.id).className = 'cp-row ' + (isCrit ? 'critical' : (isWarn ? 'warning' : ''));
    document.getElementById('title-' + g.id).innerText = g.title + ' (' + evs.length + '/' + allEvs.length + ' pkts)';

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
    }).join('') : '<div style="color:#64748B">No matching packets. Click [▶ Start Both] or clear filters...</div>';

    if (d.capturing && !isPaused && !isLocked) {
      box.scrollTop = box.scrollHeight;
    } else {
      box.scrollTop = prevTop;
    }

    document.getElementById('right-' + g.id).innerHTML =
      '<div>' +
        '<div class="stat-bar">' +
          '<span>Proto: <strong style="color:' + protoColor + '">' + (last ? last.protocol : '—') + '</strong></span>' +
          '<span>Ports: <strong style="color:#FFF">' + sPort + ' ➔ ' + dPort + '</strong></span>' +
          '<span>Entropy: <strong>' + (last ? last.dpi.shannon_entropy.toFixed(2) + '/8' : '—') + '</strong></span>' +
          '<span>Last: <strong style="color:' + stealthColor + '">' + (last ? last.dpi.stealth_score + '%' : '—') + '</strong></span>' +
        '</div>' +
        '<div class="avg-bar">' +
          '<span><strong>Avg Stealth:</strong> <strong style="color:' + avgColor + '">' + (allEvs.length ? avgStealth + '%' : '—') + '</strong></span>' +
          '<span><span style="color:#7DD3FC">🔵 ' + safeCnt + ' Safe</span> / <span style="color:#FDE68A">🟡 ' + warnCnt + ' Warn</span> / <span style="color:#FCA5A5">🔴 ' + critCnt + ' Red</span> (of ' + allEvs.length + ')</span>' +
        '</div>' +
        '<div style="color:var(--muted)"><strong>👁 What you see:</strong> ' + g.what_you_see + '</div>' +
        '<div style="color:#6EE7B7"><strong>✓ Safe (Blue):</strong> ' + g.good_for_dpi + '</div>' +
        '<div style="color:#FCA5A5"><strong>✗ Exposed (Red):</strong> ' + g.bad_for_dpi + '</div>' +
      '</div>' +
      '<div class="verdict ' + (isCrit ? 'crit' : (isWarn ? 'warn' : '')) + '">' + (last ? (last.dpi.color_meaning + ' — ' + last.dpi.explanation) : 'Idle — Waiting for real packet stream.') + '</div>';
  });
}

function renderNodes(nodes, activeS1, activeS2) {
  const key = nodes.map(n => n.id).join(',');
  if (key !== lastNodeKey) {
    lastNodeKey = key;
    const opts = nodes.map(n => '<option value="'+n.id+'">'+n.name+' ('+n.host+')</option>').join('');
    document.getElementById('s1Select').innerHTML = opts;
    document.getElementById('s2Select').innerHTML = opts;
  }
  if (activeS1) document.getElementById('s1Select').value = activeS1;
  if (activeS2) document.getElementById('s2Select').value = activeS2;

  document.getElementById('nodeList').innerHTML = nodes.map(n => {
    const logs = (n.deploy_logs || []).map(l => '<div>' + l + '</div>').join('');
    const delBtn = n.id !== 'local-s1' ? '<button class="btn btn-stop" onclick="deleteNode(\'' + n.id + '\')">🗑 Delete</button>' : '';
    return '<div class="node-card">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;">' +
        '<div><strong>' + n.name + '</strong> <span style="color:var(--cyan)">[' + n.role.toUpperCase() + ' - ' + n.host + ']</span></div>' +
        '<div style="display:flex;gap:6px;">' +
          '<a href="http://' + n.host + ':9444/" target="_blank" class="btn" style="text-decoration:none;">↗ 3-Window View</a>' +
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
      name: document.getElementById('fName').value || 'Kharej Node',
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
