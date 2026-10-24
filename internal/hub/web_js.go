package hub

const DashboardScriptJS = `<script>
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
</script>`
