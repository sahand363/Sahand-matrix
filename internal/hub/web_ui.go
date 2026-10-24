package hub

const DashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAHAND MATRIX // Real Packet & Iran DPI Lab</title>
<style>
  :root {
    --bg: #0B0F19; --card: #111827; --border: #1E293B;
    --cyan: #38BDF8; --purple: #A855F7; --emerald: #10B981;
    --amber: #F59E0B; --crimson: #EF4444; --text: #F8FAFC; --muted: #94A3B8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', system-ui, monospace; }
  body { background: var(--bg); color: var(--text); min-height: 100vh; }
  header {
    background: #0D1322; border-bottom: 1px solid var(--border); padding: 10px 20px;
    display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;
    position: sticky; top: 0; z-index: 30;
  }
  .brand { font-size: 16px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
  .controls { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  select, input {
    background: #070B14; color: var(--text); border: 1px solid var(--border);
    padding: 6px 10px; border-radius: 6px; font-size: 12px;
  }
  .btn {
    padding: 7px 13px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;
    border: 1px solid var(--border); background: var(--card); color: var(--text);
  }
  .btn-start { border-color: var(--emerald); color: var(--emerald); background: rgba(16,185,129,0.12); }
  .btn-stop { border-color: var(--crimson); color: var(--crimson); background: rgba(239,68,68,0.12); }
  .btn-pause { border-color: var(--cyan); color: var(--cyan); background: rgba(56,189,248,0.12); }
  .btn-tab.active { background: var(--cyan); color: #000; border-color: var(--cyan); }
  .pill { font-size: 11px; font-weight: 700; padding: 5px 10px; border-radius: 14px; border: 1px solid var(--amber); color: var(--amber); }
  .pill.live { border-color: var(--emerald); color: var(--emerald); background: rgba(16,185,129,0.1); }
  .wrap { max-width: 1650px; margin: 0 auto; padding: 14px 20px; }

  /* Single-Column Stacked 6-Window List */
  .cp-row {
    display: grid; grid-template-columns: 1.35fr 1fr; gap: 14px;
    background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--emerald);
    border-radius: 10px; padding: 12px 14px; margin-bottom: 10px; align-items: stretch;
  }
  .cp-row.critical { border-color: var(--crimson); border-left-width: 5px; background: rgba(239,68,68,0.05); }
  .cp-left { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
  .cp-top { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
  .cp-title { font-size: 13.5px; font-weight: 700; color: var(--cyan); }
  .dpi-badge { font-size: 10.5px; font-weight: 700; padding: 2px 8px; border-radius: 5px; }
  .dpi-badge.crit { background: rgba(239,68,68,0.2); color: #FCA5A5; border: 1px solid var(--crimson); }
  .dpi-badge.safe { background: rgba(16,185,129,0.15); color: var(--emerald); border: 1px solid var(--emerald); }
  .raw-box {
    background: #050811; border: 1px solid #1E293B; border-radius: 6px; padding: 8px 10px;
    font-family: 'Courier New', monospace; font-size: 11.5px; height: 96px; overflow-y: auto; color: #7DD3FC;
  }
  .raw-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-bottom: 2px; }
  .raw-line.crit { color: #FCA5A5; }

  /* Right Side Metadata & Educational Guide */
  .cp-right {
    background: #0A0E19; border: 1px solid #1E293B; border-radius: 8px; padding: 9px 12px;
    display: flex; flex-direction: column; justify-content: space-between; font-size: 11.5px; line-height: 1.4;
  }
  .stat-bar { display: flex; justify-content: space-between; border-bottom: 1px solid #1E293B; padding-bottom: 5px; margin-bottom: 5px; font-family: monospace; }
  .guide-line { color: var(--muted); margin-bottom: 3px; }
  .guide-good { color: #6EE7B7; }
  .guide-bad { color: #FCA5A5; }
  .verdict { margin-top: 4px; padding: 4px 8px; border-radius: 5px; background: rgba(16,185,129,0.1); color: #A7F3D0; font-weight: 600; }
  .verdict.crit { background: rgba(239,68,68,0.18); color: #FECACA; }

  /* Servers & SSH Deployment Page */
  .srv-grid { display: grid; grid-template-columns: 360px 1fr; gap: 16px; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; }
  .form-row { margin-bottom: 10px; display: flex; flex-direction: column; gap: 4px; font-size: 12px; }
  .node-card { background: #0B101D; border: 1px solid var(--border); border-radius: 8px; padding: 12px; margin-bottom: 12px; }
  .prog-track { height: 8px; background: #1E293B; border-radius: 4px; overflow: hidden; margin: 8px 0; }
  .prog-fill { height: 100%; background: var(--cyan); transition: width 0.3s; }
  .log-box { background: #050811; padding: 8px; border-radius: 6px; font-family: monospace; font-size: 11px; height: 85px; overflow-y: auto; color: #A7F3D0; }
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
  <!-- TAB 1: 6-WINDOW COMPACT VERTICAL LIST -->
  <div id="viewMatrix">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;font-size:12px;background:#111827;padding:8px 14px;border-radius:8px;border:1px solid var(--border);">
      <div id="pingBanner"><strong>5-Ping Sync Cache (1h TTL):</strong> Not measured yet — Click Pause to run 5-ping calibration</div>
      <div style="color:var(--muted)">Flow: PC (Iran) ➔ S1 (CP1..CP3) ➔ S2 (CP4..CP6) ➔ YouTube/Telegram</div>
    </div>
    <div id="cpList"></div>
  </div>

  <!-- TAB 2: SSH SERVER ADD & LIVE DEPLOYMENT MANAGER -->
  <div id="viewServers" style="display:none;">
    <div class="srv-grid">
      <div class="card">
        <h3 style="font-size:14px;margin-bottom:12px;color:var(--cyan)">+ Add Server via SSH</h3>
        <div class="form-row"><label>Server Name</label><input id="fName" placeholder="e.g. Germany Hetzner S2"></div>
        <div class="form-row"><label>Server Role</label>
          <select id="fRole"><option value="kharej">S2: Kharej Server (CP4-CP6)</option><option value="iran">S1: Iran Server (CP1-CP3)</option></select>
        </div>
        <div class="form-row"><label>Server IP Address</label><input id="fHost" placeholder="e.g. 94.184.6.138"></div>
        <div class="form-row"><label>SSH Port</label><input id="fPort" type="number" value="22"></div>
        <div class="form-row"><label>SSH Username</label><input id="fUser" value="root"></div>
        <div class="form-row"><label>SSH Password</label><input id="fPass" type="password" placeholder="Root password"></div>
        <button id="addBtn" class="btn btn-start" style="width:100%;margin-top:6px;" onclick="addServer()">🔗 Connect & Add Server Card</button>
        <div id="addMsg" style="font-size:11px;margin-top:8px;color:var(--amber)"></div>
      </div>
      <div class="card">
        <h3 style="font-size:14px;margin-bottom:12px;">Connected Server Nodes & Agent Deployment</h3>
        <div id="nodeList"></div>
      </div>
    </div>
  </div>
</div>

<script>
let isPaused = false;
let frozenData = null;

function showTab(t) {
  document.getElementById('viewMatrix').style.display = t === 'matrix' ? 'block' : 'none';
  document.getElementById('viewServers').style.display = t === 'servers' ? 'block' : 'none';
  document.getElementById('tabMatrix').className = 'btn btn-tab' + (t === 'matrix' ? ' active' : '');
  document.getElementById('tabServers').className = 'btn btn-tab' + (t === 'servers' ? ' active' : '');
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
    frozenData = await res.json();
    isPaused = true;
    renderMatrix(frozenData);
    btn.innerText = '▶ Resume Live View';
  } else {
    isPaused = false;
    frozenData = null;
    btn.innerText = '⏸ 5-Ping Sync Pause';
    pollState();
  }
}

function renderMatrix(d) {
  const pill = document.getElementById('statePill');
  if (isPaused) {
    pill.className = 'pill';
    pill.innerText = '⏸ PAUSED (OFFSET +' + d.ping.offset_ms.toFixed(1) + 'ms)';
  } else if (d.capturing) {
    pill.className = 'pill live';
    pill.innerText = '● CAPTURING REAL PACKETS';
  } else {
    pill.className = 'pill';
    pill.innerText = '● STOPPED (PRESS START)';
  }

  if (d.ping && d.ping.average_ms > 0) {
    const src = d.ping.used_cached ? 'Reused <1h Cache' : 'Fresh 5-Ping Burst';
    const s = d.ping.samples_ms.map(x => x.toFixed(1)).join(', ');
    document.getElementById('pingBanner').innerHTML =
      '<strong>5-Ping Sync (' + src + '):</strong> [' + s + '] ms ➔ <strong>Avg: ' + d.ping.average_ms.toFixed(1) + 'ms | S2 Window Offset: +' + d.ping.offset_ms.toFixed(1) + 'ms</strong>';
  }

  const list = document.getElementById('cpList');
  list.innerHTML = d.guides.map(g => {
    const evs = (d.checkpoints && d.checkpoints[g.id]) || [];
    const last = evs.length ? evs[evs.length - 1] : null;
    const isCrit = last && last.dpi.level === 'CRITICAL';
    const offset = g.server_role === 'kharej' ? (d.ping ? d.ping.offset_ms : 0) : 0;

    const logs = evs.length ? evs.map(e =>
      '<div class="raw-line ' + (e.dpi.level === 'CRITICAL' ? 'crit' : '') + '">[#' + e.sequence_num + ' ' + e.src_addr + '➔' + e.dst_addr + ' | ' + e.length + 'B] ' + e.raw_byte_log.replace(/</g,'&lt;') + '</div>'
    ).join('') : '<div style="color:#64748B">No packets captured yet. Click [▶ Start Both] and generate traffic...</div>';

    return '<div class="cp-row ' + (isCrit ? 'critical' : '') + '">' +
      '<div class="cp-left">' +
        '<div class="cp-top">' +
          '<span class="cp-title">' + g.title + ' (Offset: +' + offset.toFixed(1) + 'ms)</span>' +
          '<span class="dpi-badge ' + (g.dpi_visible ? 'crit' : 'safe') + '">' + g.dpi_zone + '</span>' +
        '</div>' +
        '<div class="raw-box">' + logs + '</div>' +
      '</div>' +
      '<div class="cp-right">' +
        '<div class="stat-bar">' +
          '<span>Proto: <strong style="color:var(--cyan)">' + (last ? last.protocol : '—') + '</strong></span>' +
          '<span>SNI: <strong>' + (last && last.tls.sni ? last.tls.sni : '—') + '</strong></span>' +
          '<span>Entropy: <strong>' + (last ? last.dpi.shannon_entropy.toFixed(2) + '/8.00' : '—') + '</strong></span>' +
          '<span>Stealth: <strong style="color:' + (isCrit ? 'var(--crimson)' : 'var(--emerald)') + '">' + (last ? last.dpi.stealth_score + '%' : '—') + '</strong></span>' +
        '</div>' +
        '<div class="guide-line"><strong>👁 What you see:</strong> ' + g.what_you_see + '</div>' +
        '<div class="guide-good"><strong>✓ Secure / Good:</strong> ' + g.good_for_dpi + '</div>' +
        '<div class="guide-bad"><strong>✗ Bad for DPI:</strong> ' + g.bad_for_dpi + '</div>' +
        '<div class="verdict ' + (isCrit ? 'crit' : '') + '">' + (last ? last.dpi.explanation : 'Idle — Waiting for real packet stream.') + '</div>' +
      '</div>' +
    '</div>';
  }).join('');
}

function renderNodes(nodes, activeS1, activeS2) {
  const s1El = document.getElementById('s1Select');
  const s2El = document.getElementById('s2Select');
  if (s1El.options.length !== nodes.length) {
    s1El.innerHTML = nodes.map(n => '<option value="'+n.id+'">'+n.name+' ('+n.host+')</option>').join('');
    s2El.innerHTML = nodes.map(n => '<option value="'+n.id+'">'+n.name+' ('+n.host+')</option>').join('');
  }
  if (activeS1) s1El.value = activeS1;
  if (activeS2) s2El.value = activeS2;

  document.getElementById('nodeList').innerHTML = nodes.map(n => {
    const logs = (n.deploy_logs || []).map(l => '<div>' + l + '</div>').join('');
    return '<div class="node-card">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;">' +
        '<div><strong>' + n.name + '</strong> <span style="color:var(--cyan)">[' + n.role.toUpperCase() + ' - ' + n.host + ']</span></div>' +
        '<div style="display:flex;gap:8px;">' +
          '<a href="http://' + n.host + ':9444/" target="_blank" class="btn" style="text-decoration:none;">↗ Open 3-Window Node Page</a>' +
          '<button class="btn btn-pause" onclick="deployNode(\'' + n.id + '\')">🚀 Deploy sahand-agent (' + n.deploy_pct + '%)</button>' +
        '</div>' +
      '</div>' +
      '<div class="prog-track"><div class="prog-fill" style="width:' + n.deploy_pct + '%"></div></div>' +
      '<div class="log-box">' + logs + '</div>' +
    '</div>';
  }).join('');
}

async function addServer() {
  const msg = document.getElementById('addMsg');
  msg.innerText = 'Connecting via SSH...';
  const res = await fetch('api/nodes/add', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      name: document.getElementById('fName').value || 'Kharej Server',
      role: document.getElementById('fRole').value,
      host: document.getElementById('fHost').value,
      ssh_port: parseInt(document.getElementById('fPort').value || '22'),
      ssh_user: document.getElementById('fUser').value || 'root',
      password: document.getElementById('fPass').value
    })
  });
  const d = await res.json();
  msg.innerText = d.error ? ('Error: ' + d.error) : '✓ SSH Verified & Server Card Added!';
  pollState();
}

async function deployNode(id) {
  await fetch('api/nodes/deploy?id=' + encodeURIComponent(id), {method:'POST'});
  pollState();
}

async function pollState() {
  if (isPaused) return;
  try {
    const res = await fetch('api/state');
    const d = await res.json();
    renderMatrix(d);
    renderNodes(d.nodes || [], d.active_s1, d.active_s2);
  } catch (e) {}
}

setInterval(pollState, 850);
pollState();
</script>
</body>
</html>`
