package hub

// DashboardHTML contains the single-page Netview Pro dark UI with 6-Checkpoint Raw Byte Streams.
const DashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAHAND MATRIX PRO // 6-Checkpoint Iran DPI Lab</title>
<style>
  :root {
    --bg-dark: #0B0F19; --bg-card: #111827; --border: #1E293B;
    --cyan: #38BDF8; --purple: #A855F7; --emerald: #10B981;
    --amber: #F59E0B; --crimson: #EF4444; --text-main: #F8FAFC; --text-muted: #94A3B8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, monospace; }
  body { background: var(--bg-dark); color: var(--text-main); display: flex; flex-direction: column; min-height: 100vh; }
  header {
    height: 62px; border-bottom: 1px solid var(--border); display: flex; align-items: center;
    justify-content: space-between; padding: 0 20px; background: #0D1322; position: sticky; top: 0; z-index: 20;
  }
  .brand { font-size: 17px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
  .controls { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
  select.tunnel-select {
    background: #090D16; color: var(--cyan); border: 1px solid var(--cyan);
    padding: 7px 12px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;
  }
  .status-pill {
    font-size: 12px; font-weight: 700; padding: 6px 12px; border-radius: 20px;
    background: rgba(16, 185, 129, 0.12); border: 1px solid var(--emerald); color: var(--emerald);
  }
  .status-pill.paused { background: rgba(245, 158, 11, 0.15); border-color: var(--amber); color: var(--amber); }
  .btn {
    padding: 7px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;
    border: 1px solid var(--border); background: var(--bg-card); color: var(--text-main);
  }
  .btn-primary { background: rgba(56, 189, 248, 0.15); border-color: var(--cyan); color: var(--cyan); }
  .btn-purple { background: rgba(168, 85, 247, 0.15); border-color: var(--purple); color: var(--purple); }
  .container { padding: 18px 20px; display: flex; flex-direction: column; gap: 16px; max-width: 1750px; margin: 0 auto; width: 100%; }
  .banner {
    background: #111827; border: 1px solid var(--border); border-left: 4px solid var(--cyan);
    border-radius: 10px; padding: 12px 16px; display: flex; justify-content: space-between; align-items: center;
  }
  .cp-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
  @media (max-width: 1200px) { .cp-grid { grid-template-columns: repeat(2, 1fr); } }
  @media (max-width: 800px) { .cp-grid { grid-template-columns: 1fr; } }
  .cp-card {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px; display: flex; flex-direction: column; gap: 10px; transition: 0.2s;
  }
  .cp-card.optimal { border-top: 3px solid var(--emerald); }
  .cp-card.warning { border-top: 3px solid var(--amber); }
  .cp-card.critical {
    border: 2px solid var(--crimson); background: rgba(239, 68, 68, 0.06);
    box-shadow: 0 0 18px rgba(239, 68, 68, 0.22);
  }
  .cp-head { display: flex; justify-content: space-between; align-items: flex-start; }
  .cp-title { font-size: 14px; font-weight: 700; color: var(--text-main); }
  .cp-sub { font-size: 11px; color: var(--text-muted); margin-top: 2px; }
  .dpi-tag { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px; }
  .dpi-tag.visible { background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.4); }
  .dpi-tag.iran-edge { background: rgba(239, 68, 68, 0.18); color: #FCA5A5; border: 1px solid var(--crimson); }
  .dpi-tag.hidden { background: rgba(16, 185, 129, 0.12); color: var(--emerald); border: 1px solid rgba(16, 185, 129, 0.3); }
  .metrics-strip {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px;
    background: #0B101B; padding: 8px 10px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.05);
  }
  .m-lbl { font-size: 10px; color: var(--text-muted); text-transform: uppercase; }
  .m-val { font-size: 13px; font-weight: 700; font-family: monospace; margin-top: 2px; }
  .raw-stream-box {
    background: #060911; border: 1px solid #1E293B; border-radius: 8px; padding: 8px 10px;
    font-family: 'Courier New', monospace; font-size: 11.5px; line-height: 1.45;
    height: 115px; overflow-y: auto; color: #CBD5E1;
  }
  .raw-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .raw-line.danger { color: #FCA5A5; }
  .raw-line.safe { color: #7DD3FC; }
  .explain-box {
    font-size: 12px; line-height: 1.4; padding: 8px 10px; border-radius: 8px;
    background: rgba(16, 185, 129, 0.08); border-left: 3px solid var(--emerald); color: #D1FAE5;
  }
  .explain-box.critical {
    background: rgba(239, 68, 68, 0.15); border-left-color: var(--crimson); color: #FECACA; font-weight: 600;
  }
  .kpi-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
  .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px; }
  .kpi-val { font-size: 22px; font-weight: 700; margin: 6px 0 2px 0; }
  #agentModal {
    display: none; position: fixed; inset: 0; background: rgba(6, 10, 19, 0.85);
    align-items: center; justify-content: center; z-index: 50;
  }
  .modal-card { background: var(--bg-card); border: 1px solid var(--cyan); border-radius: 14px; width: 650px; padding: 22px; }
  pre.cmd { background: #060911; padding: 10px; border-radius: 8px; color: var(--cyan); font-size: 12px; overflow-x: auto; margin: 8px 0 14px 0; }
</style>
</head>
<body>
<header>
  <div class="brand"><span style="color:var(--cyan)">❖</span> SAHAND MATRIX <span style="color:var(--text-muted);font-weight:400">// IRAN DPI & TUNNEL LAB</span></div>
  <div class="controls">
    <label style="font-size:12px;color:var(--text-muted)">Active Tunnel:</label>
    <select id="tunnelSelect" class="tunnel-select" onchange="changeTunnel(this.value)">
      <option value="wss">WSS (WebSocket + TLS 1.3)</option>
      <option value="reality">VLESS + XTLS-Reality</option>
      <option value="grpc">gRPC + TLS 1.3 (HTTP/2)</option>
      <option value="shadowsocks">Shadowsocks-2022 (Raw Encrypted - High Entropy Alert!)</option>
      <option value="raw_tcp">Raw Unmasked TCP (Plaintext Leak - RED Alert!)</option>
    </select>
    <div id="statusBadge" class="status-pill">● LIVE STREAM (6/6 SYNCED)</div>
    <button id="pauseBtn" class="btn btn-primary" onclick="toggleSmartPause()">⏸ 5-Ping Sync Pause</button>
    <button class="btn btn-purple" onclick="toggleModal()">🚀 Deploy Agent</button>
  </div>
</header>

<div class="container">
  <div class="banner">
    <div>
      <strong id="tunnelTitle" style="color:var(--cyan);font-size:14px;">WSS (WebSocket + TLS 1.3)</strong>
      <div id="tunnelDesc" style="font-size:12px;color:var(--text-muted);margin-top:3px;">
        Wraps proxy frames inside HTTP/1.1 WebSocket Upgrade + TLS 1.3 (\x17\x03\x03). Looks like standard Web/CDN traffic to Iran DPI.
      </div>
    </div>
    <div style="text-align:right;font-size:12px;font-family:monospace;">
      <div id="pingSummary" style="color:var(--emerald)">5-Ping Avg: 48.0ms | Offset: +24.0ms</div>
      <div style="color:var(--text-muted)">Click Pause to freeze all 6 windows on the exact same packet</div>
    </div>
  </div>

  <div id="cpGrid" class="cp-grid"></div>

  <div class="kpi-row">
    <div class="kpi-card">
      <div class="m-lbl">5-PING BURST SAMPLES</div>
      <div class="kpi-val" id="kpiSamples" style="font-size:15px;font-family:monospace;">46.7 | 48.0 | 49.3 | 47.4 | 48.7 ms</div>
      <div class="cp-sub" id="kpiOffset">Calculated Window Offset: +24.0 ms (RTT/2)</div>
    </div>
    <div class="kpi-card">
      <div class="m-lbl">CHECKPOINT 5 (IRAN DOMESTIC DPI) STEALTH</div>
      <div class="kpi-val" id="kpiStealth" style="color:var(--emerald)">88% SAFE</div>
      <div class="cp-sub" id="kpiTriggers">0 Leaks Detected on Domestic Egress</div>
    </div>
    <div class="kpi-card">
      <div class="m-lbl">CHECKPOINT 5 SHANNON ENTROPY</div>
      <div class="kpi-val" id="kpiEntropy">5.88 / 8.00</div>
      <div class="cp-sub">Framed inside TLS 1.3 (\x17\x03\x03)</div>
    </div>
    <div class="kpi-card">
      <div class="m-lbl">DPI VISIBILITY MAP</div>
      <div class="kpi-val" style="font-size:16px;color:var(--amber)">4 Exposed / 2 Internal</div>
      <div class="cp-sub">CP1, CP3, CP4, CP5 visible to ISP/DPI</div>
    </div>
  </div>
</div>

<div id="agentModal">
  <div class="modal-card">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
      <strong>🚀 Deploy Lightweight sahand-agent on 2nd Server</strong>
      <button class="btn" onclick="toggleModal()">✕</button>
    </div>
    <div class="cp-sub">1. Ubuntu Setup Menu One-Liner:</div>
    <pre class="cmd">bash &lt;(curl -Ls https://raw.githubusercontent.com/sahand363/sahand-matrix/main/scripts/setup.sh)</pre>
    <div class="cp-sub">2. Direct Agent Connect Command:</div>
    <pre class="cmd" id="agentCmd">Loading...</pre>
  </div>
</div>

<script>
let isPaused = false;
let currentTunnel = 'wss';
const logHistory = {1:[], 2:[], 3:[], 4:[], 5:[], 6:[]};

async function changeTunnel(val) {
  currentTunnel = val;
  for (let k = 1; k <= 6; k++) logHistory[k] = [];
  await fetch('api/tunnel?type=' + encodeURIComponent(val), {method:'POST'});
  if (isPaused) toggleSmartPause();
  else pollState();
}

function renderDashboard(data) {
  if (data.active_tunnel_info) {
    document.getElementById('tunnelTitle').innerText = data.active_tunnel_info.name;
    document.getElementById('tunnelDesc').innerText = data.active_tunnel_info.description;
    document.getElementById('tunnelSelect').value = data.active_tunnel_info.id;
  }
  const p = data.five_ping_burst_ms.map(x => x.toFixed(1)).join(' | ') + ' ms';
  document.getElementById('kpiSamples').innerText = p;
  document.getElementById('kpiOffset').innerText = 'Calculated Window Offset: +' + data.window_offset_ms.toFixed(1) + ' ms (RTT/2)';
  document.getElementById('pingSummary').innerText = '5-Ping Avg: ' + data.average_rtt_ms.toFixed(1) + 'ms | Offset: +' + data.window_offset_ms.toFixed(1) + 'ms';
  document.getElementById('agentCmd').innerText = 'sahand-agent --hub ' + data.hub_host + ' --token ' + (data.agent_token || 'TOKEN') + ' --role iran';

  const grid = document.getElementById('cpGrid');
  grid.innerHTML = data.checkpoints.map(cp => {
    const hist = logHistory[cp.checkpoint] || [];
    const linePrefix = '[#' + cp.sequence_num + ' +' + cp.offset_ms.toFixed(1) + 'ms] ';
    if (!isPaused) {
      hist.push(linePrefix + cp.raw_byte_log);
      if (hist.length > 7) hist.shift();
      logHistory[cp.checkpoint] = hist;
    }
    const isCrit = cp.dpi.level === 'CRITICAL';
    const cardCls = isCrit ? 'critical' : (cp.dpi.level === 'WARNING' ? 'warning' : 'optimal');
    let tagCls = cp.dpi_visible ? (cp.checkpoint === 5 ? 'iran-edge' : 'visible') : 'hidden';

    if (cp.checkpoint === 5) {
      const stEl = document.getElementById('kpiStealth');
      stEl.innerText = cp.dpi.stealth_score + '% (' + cp.dpi.level + ')';
      stEl.style.color = isCrit ? 'var(--crimson)' : 'var(--emerald)';
      document.getElementById('kpiEntropy').innerText = cp.dpi.shannon_entropy.toFixed(2) + ' / 8.00';
      document.getElementById('kpiTriggers').innerText = (cp.dpi.triggers && cp.dpi.triggers.length) ? 'Triggers: ' + cp.dpi.triggers.join(', ') : '0 Leaks Detected on Domestic Egress';
    }

    const logsHtml = hist.map(l => '<div class="raw-line ' + (isCrit ? 'danger' : 'safe') + '">' + l.replace(/</g,'&lt;') + '</div>').join('');
    return '<div class="cp-card ' + cardCls + '">' +
      '<div class="cp-head">' +
        '<div><div class="cp-title">' + cp.checkpoint_title + '</div><div class="cp-sub">' + cp.node_name + ' (Offset: +' + cp.offset_ms.toFixed(1) + 'ms)</div></div>' +
        '<span class="dpi-tag ' + tagCls + '">' + cp.dpi_zone + '</span>' +
      '</div>' +
      '<div class="metrics-strip">' +
        '<div><div class="m-lbl">Packet</div><div class="m-val">#' + cp.sequence_num + '</div></div>' +
        '<div><div class="m-lbl">Protocol</div><div class="m-val" style="color:var(--cyan)">' + cp.protocol + '</div></div>' +
        '<div><div class="m-lbl">Entropy H(X)</div><div class="m-val">' + cp.dpi.shannon_entropy.toFixed(2) + ' / 8</div></div>' +
        '<div><div class="m-lbl">Stealth</div><div class="m-val" style="color:' + (isCrit ? 'var(--crimson)' : 'var(--emerald)') + '">' + cp.dpi.stealth_score + '%</div></div>' +
      '</div>' +
      '<div class="raw-stream-box">' + logsHtml + '</div>' +
      '<div class="explain-box ' + (isCrit ? 'critical' : '') + '">' + cp.dpi.explanation + '</div>' +
    '</div>';
  }).join('');
}

async function pollState() {
  if (isPaused) return;
  try {
    const res = await fetch('api/state');
    renderDashboard(await res.json());
  } catch (e) {}
}

async function toggleSmartPause() {
  const btn = document.getElementById('pauseBtn');
  const badge = document.getElementById('statusBadge');
  if (!isPaused) {
    btn.innerText = '⚡ 5-Ping Calibrating...';
    const res = await fetch('api/pause-burst');
    const data = await res.json();
    isPaused = true;
    renderDashboard(data);
    btn.innerText = '▶ Resume All 6 Streams';
    badge.className = 'status-pill paused';
    badge.innerText = '⏸ PAUSED @ PACKET #' + data.sequence_num + ' (+' + data.window_offset_ms.toFixed(1) + 'ms SYNC)';
  } else {
    isPaused = false;
    btn.innerText = '⏸ 5-Ping Sync Pause';
    badge.className = 'status-pill';
    badge.innerText = '● LIVE STREAM (6/6 SYNCED)';
    pollState();
  }
}

function toggleModal() {
  const m = document.getElementById('agentModal');
  m.style.display = (m.style.display === 'flex') ? 'none' : 'flex';
}

setInterval(pollState, 750);
pollState();
</script>
</body>
</html>`
