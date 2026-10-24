package hub

// DashboardHTML combines the layout/CSS with the interactive JS engine from web_js.go.
var DashboardHTML = dashboardHeadHTML + DashboardScriptJS + "</body></html>"

const dashboardHeadHTML = `<!DOCTYPE html>
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

  /* Resizable Raw Stream Box */
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
`
