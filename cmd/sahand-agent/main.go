package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"sahand-matrix/internal/agent"
	"sahand-matrix/internal/analyzer"
)

func main() {
	role := flag.String("role", "kharej", "Node role: 'iran' (Main Server CP1-CP3) or 'kharej' (Server 2 CP4-CP6)")
	serverID := flag.String("id", "server-2", "Unique Server Node ID")
	peerIP := flag.String("peer", "", "Peer Server IP to classify CP3/CP4 transit traffic")
	token := flag.String("token", "", "Optional shared token for Hub API calls")
	secretPath := flag.String("secret", "", "Optional persistent secret URL path for Sentinel Web UI")
	authUser := flag.String("auth-user", "", "Optional HTTP Basic Auth username (blank = disabled)")
	authPass := flag.String("auth-pass", "", "Optional HTTP Basic Auth password (blank = disabled)")
	listenAddr := flag.String("listen", ":9444", "Sentinel API & 3-Window Web UI port")
	flag.Parse()

	sniffer := agent.NewRealSniffer(*role, *serverID, *peerIP, 9444)

	go func() {
		if err := sniffer.RunCaptureLoop(); err != nil {
			log.Printf("[sahand-sentinel] Raw socket warning: %v", err)
		}
	}()

	apiGuard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if *token != "" {
				qTok := r.URL.Query().Get("token")
				hTok := r.Header.Get("X-Sahand-Token")
				if qTok != "" && qTok != *token && hTok != *token {
					http.Error(w, "Unauthorized token", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}

	uiGuard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if *authUser != "" && *authPass != "" {
				u, p, ok := r.BasicAuth()
				uMatch := subtle.ConstantTimeCompare([]byte(u), []byte(*authUser)) == 1
				pMatch := subtle.ConstantTimeCompare([]byte(p), []byte(*authPass)) == 1
				if !ok || !uMatch || !pMatch {
					w.Header().Set("WWW-Authenticate", `Basic realm="Sahand Sentinel 3-Window Lab"`)
					http.Error(w, "Authentication required", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}

	http.HandleFunc("/api/ping", apiGuard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_id":      *serverID,
			"role":           *role,
			"capturing":      sniffer.IsRunning(),
			"timestamp_nano": time.Now().UTC().UnixNano(),
		})
	}))

	http.HandleFunc("/api/control", apiGuard(func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("action")
		if peer := r.URL.Query().Get("peer"); peer != "" {
			sniffer.SetPeerIP(peer)
		}
		if r.URL.Query().Has("ports") {
			sniffer.SetPortFilterCSV(r.URL.Query().Get("ports"))
		}
		if action == "start" {
			sniffer.Start()
		} else if action == "stop" {
			sniffer.Stop()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"capturing":    sniffer.IsRunning(),
			"role":         *role,
			"locked_ports": sniffer.GetLockedPorts(),
		})
	}))

	http.HandleFunc("/api/snapshot", apiGuard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_id":    *serverID,
			"role":         *role,
			"capturing":    sniffer.IsRunning(),
			"locked_ports": sniffer.GetLockedPorts(),
			"checkpoints":  sniffer.GetSnapshot(),
			"guides":       analyzer.AllCheckpointGuides(),
		})
	}))

	uiPath := "/"
	if s := strings.Trim(*secretPath, "/"); s != "" {
		uiPath = "/sentinel/" + s + "/"
	}
	http.HandleFunc(uiPath, uiGuard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, agentSentinelHTML)
	}))

	log.Printf("[sahand-sentinel] (%s) active on %s%s [Default: STOPPED]", *role, *listenAddr, uiPath)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}

const agentSentinelHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>SAHAND SENTINEL // 3-Window Node Lab</title>
<style>
  :root { --bg:#0B0F19; --card:#111827; --border:#1E293B; --cyan:#38BDF8; --emerald:#10B981; --amber:#F59E0B; --crimson:#EF4444; --text:#F8FAFC; --muted:#94A3B8; --left-col:60%; }
  * { box-sizing:border-box; margin:0; padding:0; font-family:'Inter',system-ui,Tahoma,monospace; }
  body { background:var(--bg); color:var(--text); min-height:100vh; }
  body.rtl { direction:rtl; text-align:right; }
  bdi, .ltr { direction:ltr; unicode-bidi:isolate; display:inline-block; }
  header { background:#0D1322; border-bottom:1px solid var(--border); padding:10px 18px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; position:sticky; top:0; z-index:30; }
  .wrap { max-width:1860px; margin:0 auto; padding:12px 16px; }
  .toolbar { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; margin-bottom:10px; font-size:12px; background:#111827; padding:8px 14px; border-radius:8px; border:1px solid var(--border); }
  .btn { padding:6px 10px; border-radius:6px; border:1px solid var(--border); background:var(--card); color:var(--text); cursor:pointer; font-size:12px; font-weight:600; }
  .btn:hover { filter:brightness(1.15); }
  .btn-start { border-color:var(--emerald); color:var(--emerald); background:rgba(16,185,129,0.12); }
  .btn-stop { border-color:var(--crimson); color:var(--crimson); background:rgba(239,68,68,0.12); }
  input { background:#070B14; color:var(--text); border:1px solid var(--border); padding:6px 10px; border-radius:6px; font-size:12px; }
  .cp-row { display:flex; gap:0; align-items:flex-start; background:var(--card); border:1px solid var(--border); border-left:4px solid var(--emerald); border-radius:10px; padding:11px 14px; margin-bottom:10px; }
  .cp-row.critical { border-color:var(--crimson); border-left-width:5px; background:rgba(239,68,68,0.04); }
  .cp-left { width:var(--left-col); min-width:30%; max-width:85%; display:flex; flex-direction:column; gap:6px; flex-shrink:0; }
  .splitter { width:10px; align-self:stretch; cursor:col-resize; display:flex; align-items:center; justify-content:center; margin:0 5px; border-radius:4px; background:rgba(255,255,255,0.03); color:#64748B; font-size:11px; user-select:none; }
  .splitter:hover { background:rgba(56,189,248,0.25); color:#FFF; }
  .cp-right { flex:1; min-width:180px; background:#0A0E19; border:1px solid var(--border); border-radius:8px; padding:9px 12px; display:flex; flex-direction:column; justify-content:flex-start; gap:6px; font-size:11.5px; line-height:1.42; }
  .raw-box { background:#050811; border:1px solid var(--border); border-radius:6px; padding:7px 9px; font-family:'Courier New',monospace; font-size:11.5px; height:140px; min-height:85px; max-height:700px; overflow-y:auto; overflow-x:auto; resize:vertical; direction:ltr; text-align:left; }
  .raw-line { white-space:pre; width:max-content; min-width:100%; padding:2px 6px; border-radius:4px; color:#7DD3FC; margin-bottom:1px; }
  body.wrap-lines .raw-line { white-space:pre-wrap; word-break:break-all; width:100%; }
  .raw-line.crit { color:#FCA5A5; background:rgba(239,68,68,0.08); }
  .raw-line.warn { color:#FDE68A; background:rgba(245,158,11,0.06); }
  .port-tag { color:#E2E8F0; font-weight:700; background:#1E293B; padding:0 4px; border-radius:3px; margin-right:4px; }
  .corr-tag { color:#C084FC; font-weight:700; margin-right:4px; }
  .copy-btn { font-size:10px; background:#1E293B; color:#CBD5E1; border:none; border-radius:3px; padding:0 5px; cursor:pointer; margin-right:6px; }
  .stat-bar, .avg-bar { display:flex; justify-content:space-between; flex-wrap:wrap; gap:6px; font-family:monospace; direction:ltr; }
  .avg-bar { background:#0F172A; border:1px solid var(--border); border-radius:5px; padding:5px 8px; }
  .verdict { margin-top:2px; padding:5px 8px; border-radius:5px; background:rgba(56,189,248,0.12); color:#7DD3FC; font-weight:600; border-left:3px solid var(--cyan); }
  .verdict.crit { background:rgba(239,68,68,0.18); color:#FECACA; border-left-color:var(--crimson); }
</style></head><body>
<header>
  <div><strong id="hdr" style="color:var(--cyan);font-size:15px;">❖ SAHAND SENTINEL // 3-WINDOW NODE</strong> <span id="lockBadge" style="font-size:11px;color:var(--emerald)">[All Ports]</span></div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <button class="btn btn-start" onclick="ctrl('start')">▶ Start Capture</button>
    <button class="btn btn-stop" onclick="ctrl('stop')">■ Stop Capture</button>
    <button class="btn" onclick="toggleLang()">🌐 فارسی / EN</button>
  </div>
</header>
<div class="wrap">
  <div class="toolbar">
    <div><strong>Drag ⋮ bar</strong> between columns to widen packet lines, or scroll horizontally</div>
    <div style="display:flex;gap:7px;align-items:center;flex-wrap:wrap;">
      <input id="pInp" class="ltr" placeholder="Ports (e.g. 443, 8443)" style="width:165px">
      <button class="btn" onclick="lockP()">🔒 Lock Ports</button>
      <button class="btn" onclick="unlockP()">🔓 All</button>
      <button class="btn" onclick="resetCum()">↺ Reset Stats</button>
      <button class="btn" onclick="document.body.classList.toggle('wrap-lines')">↩ Wrap Lines</button>
      <button class="btn" onclick="setH(135)">Compact</button>
      <button class="btn" onclick="setH(260)">Tall</button>
      <button class="btn" onclick="setH(440)">Max</button>
    </div>
  </div>
  <div id="list"></div>
</div>
<script>
let lang = 'en', init = false, drag = false;
const locks = {}, cum = {};
document.addEventListener('mousemove', e => {
  if (!drag) return;
  const w = document.querySelector('.wrap').getBoundingClientRect();
  let p = ((e.clientX - w.left) / w.width) * 100;
  if (document.body.classList.contains('rtl')) p = ((w.right - e.clientX) / w.width) * 100;
  document.documentElement.style.setProperty('--left-col', Math.max(32, Math.min(84, p)).toFixed(1) + '%');
});
document.addEventListener('mouseup', () => { drag = false; });
function setH(px) { document.querySelectorAll('.raw-box').forEach(b => { b.style.height = px + 'px'; }); }
function resetCum() { Object.keys(cum).forEach(k => delete cum[k]); poll(); }
function toggleLang() { lang = lang==='en'?'fa':'en'; document.body.classList.toggle('rtl', lang==='fa'); poll(); }
function copyLine(ev) { ev.stopPropagation(); const b=ev.target; navigator.clipboard.writeText(b.parentElement.innerText.replace('📋 Copy','').trim()); b.innerText='✓'; setTimeout(()=>b.innerText='📋 Copy',1000); }
function spPort(a) { if(!a) return '—'; const i=a.lastIndexOf(':'); return i>-1?a.slice(i+1):'—'; }
async function ctrl(a) { await fetch('/api/control?action='+a); poll(); }
async function lockP() { resetCum(); await fetch('/api/control?ports='+encodeURIComponent(document.getElementById('pInp').value)); poll(); }
async function unlockP() { document.getElementById('pInp').value=''; resetCum(); await fetch('/api/control?ports='); poll(); }
async function poll() {
  const res = await fetch('/api/snapshot');
  const d = await res.json();
  const roleName = d.role === 'iran' ? (lang==='fa'?'سرور اصلی (Main Server)':'Main Server (S1)') : (lang==='fa'?'سرور ۲ (Server 2)':'Server 2 (S2)');
  document.getElementById('hdr').innerHTML = '❖ SAHAND SENTINEL // <bdi>' + d.server_id + '</bdi> — ' + roleName;
  const lp = d.locked_ports || [];
  document.getElementById('lockBadge').innerText = lp.length ? ('[🔒 Ports: '+lp.join(',')+']') : '[All Ports]';
  const guides = (d.guides || []).filter(g => g.server_role === d.role);
  if (!init && guides.length) {
    init = true;
    document.getElementById('list').innerHTML = guides.map(g =>
      '<div class="cp-row" id="r-'+g.id+'"><div class="cp-left"><div style="display:flex;justify-content:space-between;"><strong id="t-'+g.id+'" style="color:var(--cyan);font-size:13px;"></strong> <span id="lk-'+g.id+'" style="color:var(--amber);font-size:11px"></span></div><div class="raw-box" id="b-'+g.id+'"></div></div><div class="splitter" onmousedown="drag=true">⋮</div><div class="cp-right" id="ri-'+g.id+'"></div></div>'
    ).join('');
    guides.forEach(g => {
      const b = document.getElementById('b-'+g.id);
      b.addEventListener('wheel', () => { locks[g.id] = Date.now()+20000; }, {passive:true});
    });
  }
  guides.forEach(g => {
    const evs = (d.checkpoints && d.checkpoints[g.id]) || [];
    if (!cum[g.id]) cum[g.id] = { maxSeq:0, wSum:0, bytes:0, safe:0, warn:0, crit:0 };
    const cs = cum[g.id];
    evs.forEach(e => {
      if (e.sequence_num > cs.maxSeq) {
        const b = Math.max(1, e.length||1);
        cs.maxSeq = e.sequence_num; cs.wSum += e.dpi.stealth_score*b; cs.bytes += b;
        if(e.dpi.level==='CRITICAL') cs.crit++; else if(e.dpi.level==='WARNING') cs.warn++; else cs.safe++;
      }
    });
    const bw = cs.bytes ? Math.round(cs.wSum/cs.bytes) : 0;
    const totalMB = cs.bytes >= 1048576 ? (cs.bytes/1048576).toFixed(2)+' MB' : (cs.bytes/1024).toFixed(1)+' KB';
    const last = evs[evs.length-1];
    const isCrit = last && last.dpi.level==='CRITICAL';
    document.getElementById('r-'+g.id).className = 'cp-row' + (isCrit?' critical':'');
    document.getElementById('t-'+g.id).innerHTML = '<bdi>'+g.title+' ('+evs.length+' in buf | '+totalMB+' analyzed)</bdi>';
    const rem = Math.ceil(((locks[g.id]||0)-Date.now())/1000);
    document.getElementById('lk-'+g.id).innerText = rem>0 ? ('⏸ Scroll Locked ('+rem+'s)') : '';
    const box = document.getElementById('b-'+g.id);
    const top = box.scrollTop, left = box.scrollLeft;
    box.innerHTML = evs.length ? evs.map(e => '<div class="raw-line '+(e.dpi.level==='CRITICAL'?'crit':(e.dpi.level==='WARNING'?'warn':''))+'"><button class="copy-btn" onclick="copyLine(event)">📋 Copy</button><span class="corr-tag">['+e.correlation_tag+']</span><span class="port-tag">Port '+spPort(e.src_addr)+'➔'+spPort(e.dst_addr)+'</span>[#'+e.sequence_num+' '+e.src_addr+'➔'+e.dst_addr+' | '+e.length+'B] '+e.raw_byte_log.replace(/</g,'&lt;')+'</div>').join('') : '<div style="color:#64748B">Waiting for packets...</div>';
    if (d.capturing && rem<=0) box.scrollTop = box.scrollHeight; else box.scrollTop = top;
    box.scrollLeft = left;
    document.getElementById('ri-'+g.id).innerHTML = '<div><div class="stat-bar"><span>Proto: <strong>'+(last?last.protocol:'—')+'</strong></span><span>Entropy: <strong>'+(last?last.dpi.shannon_entropy.toFixed(2)+'/8':'—')+'</strong></span></div><div class="avg-bar"><span><strong>Session Stealth: <bdi style="color:var(--emerald)">'+bw+'%</bdi></strong></span><span><bdi>🔵 '+cs.safe+' / 🟡 '+cs.warn+' / 🔴 '+cs.crit+' ('+totalMB+')</bdi></span></div><div style="margin-top:6px;color:var(--muted)">'+g.what_you_see+'</div><div style="color:#6EE7B7">'+g.good_for_dpi+'</div><div style="color:#FCA5A5">'+g.bad_for_dpi+'</div></div><div class="verdict '+(isCrit?'crit':'')+'"><bdi>'+(last?last.dpi.explanation:'Idle — Waiting for real packet stream.')+'</bdi></div>';
  });
}
setInterval(poll, 900); poll();
</script></body></html>`
