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
  :root { --bg:#0B0F19; --card:#111827; --border:#1E293B; --cyan:#38BDF8; --emerald:#10B981; --amber:#F59E0B; --crimson:#EF4444; --text:#F8FAFC; --muted:#94A3B8; }
  * { box-sizing:border-box; margin:0; padding:0; font-family:'Inter',system-ui,Tahoma,monospace; }
  body { background:var(--bg); color:var(--text); padding:14px 20px; }
  body.rtl { direction:rtl; text-align:right; }
  bdi, .ltr { direction:ltr; unicode-bidi:isolate; display:inline-block; }
  .bar { display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px; background:#0D1322; padding:12px 16px; border-radius:10px; border:1px solid var(--border); margin-bottom:12px; }
  .btn { padding:6px 12px; border-radius:6px; border:1px solid var(--border); background:var(--card); color:var(--text); cursor:pointer; font-size:12px; font-weight:600; }
  .btn-start { border-color:var(--emerald); color:var(--emerald); }
  .btn-stop { border-color:var(--crimson); color:var(--crimson); }
  input { background:#070B14; color:var(--text); border:1px solid var(--border); padding:6px 10px; border-radius:6px; font-size:12px; }
  .cp-row { display:grid; grid-template-columns:1.45fr 1fr; gap:14px; background:var(--card); border:1px solid var(--border); border-left:4px solid var(--emerald); border-radius:10px; padding:12px; margin-bottom:10px; }
  .cp-row.critical { border-color:var(--crimson); border-left-width:5px; }
  .raw-box { background:#050811; border:1px solid var(--border); border-radius:6px; padding:8px; font-family:monospace; font-size:11.5px; height:145px; overflow-y:auto; resize:vertical; direction:ltr; text-align:left; margin-top:6px; }
  .raw-line { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; padding:2px 4px; color:#7DD3FC; }
  .raw-line.crit { color:#FCA5A5; background:rgba(239,68,68,0.08); }
  .raw-line.warn { color:#FDE68A; }
  .cp-right { background:#0A0E19; border:1px solid var(--border); border-radius:8px; padding:10px; font-size:11.5px; line-height:1.45; display:flex; flex-direction:column; justify-content:space-between; }
  .verdict { margin-top:6px; padding:6px 8px; border-radius:5px; background:rgba(56,189,248,0.12); color:#7DD3FC; font-weight:600; border-left:3px solid var(--cyan); }
  .verdict.crit { background:rgba(239,68,68,0.18); color:#FECACA; border-left-color:var(--crimson); }
</style></head><body>
<div class="bar">
  <div><strong id="hdr" style="color:var(--cyan)">❖ SAHAND SENTINEL // 3-WINDOW NODE</strong> <span id="lockBadge" style="font-size:11px;color:var(--emerald)">[All Ports]</span></div>
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <input id="pInp" placeholder="Ports (e.g. 443, 8443)" style="width:165px">
    <button class="btn" onclick="lockP()">🔒 Lock Ports</button>
    <button class="btn" onclick="unlockP()">🔓 All</button>
    <button class="btn btn-start" onclick="ctrl('start')">▶ Start</button>
    <button class="btn btn-stop" onclick="ctrl('stop')">■ Stop</button>
    <button class="btn" onclick="toggleLang()" id="langBtn">🌐 فارسی / EN</button>
  </div>
</div>
<div id="list"></div>
<script>
let lang = 'en', init = false;
const locks = {};
function toggleLang() { lang = lang==='en'?'fa':'en'; document.body.className = lang==='fa'?'rtl':''; poll(); }
async function ctrl(a) { await fetch('/api/control?action='+a); poll(); }
async function lockP() { await fetch('/api/control?ports='+encodeURIComponent(document.getElementById('pInp').value)); poll(); }
async function unlockP() { document.getElementById('pInp').value=''; await fetch('/api/control?ports='); poll(); }
async function poll() {
  const res = await fetch('/api/snapshot');
  const d = await res.json();
  const roleName = d.role === 'iran' ? (lang==='fa'?'سرور اصلی (S1)':'Main Server (S1)') : (lang==='fa'?'سرور ۲ (S2)':'Server 2 (S2)');
  document.getElementById('hdr').innerHTML = '❖ SAHAND SENTINEL // <bdi>' + d.server_id + '</bdi> — ' + roleName;
  const lp = d.locked_ports || [];
  document.getElementById('lockBadge').innerText = lp.length ? ('[🔒 Ports: '+lp.join(',')+']') : '[All Ports]';
  const guides = (d.guides || []).filter(g => g.server_role === d.role);
  if (!init && guides.length) {
    init = true;
    document.getElementById('list').innerHTML = guides.map(g =>
      '<div class="cp-row" id="r-'+g.id+'"><div><strong id="t-'+g.id+'" style="color:var(--cyan)"></strong> <span id="lk-'+g.id+'" style="color:var(--amber);font-size:11px"></span><div class="raw-box" id="b-'+g.id+'"></div></div><div class="cp-right" id="ri-'+g.id+'"></div></div>'
    ).join('');
    guides.forEach(g => {
      const b = document.getElementById('b-'+g.id);
      b.addEventListener('wheel', () => { locks[g.id] = Date.now()+20000; });
    });
  }
  guides.forEach(g => {
    const evs = (d.checkpoints && d.checkpoints[g.id]) || [];
    let wSum = 0, tBytes = 0, sCnt = 0, wCnt = 0, cCnt = 0;
    evs.forEach(e => { const b = Math.max(1, e.length||1); wSum += e.dpi.stealth_score*b; tBytes += b; if(e.dpi.level==='CRITICAL') cCnt++; else if(e.dpi.level==='WARNING') wCnt++; else sCnt++; });
    const bw = tBytes ? Math.round(wSum/tBytes) : 0;
    const last = evs[evs.length-1];
    const isCrit = last && last.dpi.level==='CRITICAL';
    document.getElementById('r-'+g.id).className = 'cp-row' + (isCrit?' critical':'');
    document.getElementById('t-'+g.id).innerHTML = '<bdi>'+g.title+'</bdi> (<bdi>'+evs.length+' pkts</bdi>)';
    const rem = Math.ceil(((locks[g.id]||0)-Date.now())/1000);
    document.getElementById('lk-'+g.id).innerText = rem>0 ? ('⏸ Lock '+rem+'s') : '';
    const box = document.getElementById('b-'+g.id);
    const top = box.scrollTop;
    box.innerHTML = evs.length ? evs.map(e => '<div class="raw-line '+(e.dpi.level==='CRITICAL'?'crit':(e.dpi.level==='WARNING'?'warn':''))+'">[#'+e.sequence_num+' '+e.src_addr+'➔'+e.dst_addr+' | '+e.length+'B] '+e.raw_byte_log.replace(/</g,'&lt;')+'</div>').join('') : '<div style="color:#64748B">Waiting for packets...</div>';
    if (d.capturing && rem<=0) box.scrollTop = box.scrollHeight; else box.scrollTop = top;
    document.getElementById('ri-'+g.id).innerHTML = '<div><div><strong>Byte-Weighted Stealth: <bdi style="color:var(--emerald)">'+bw+'%</bdi></strong> | <bdi>🔵 '+sCnt+' / 🟡 '+wCnt+' / 🔴 '+cCnt+'</bdi></div><div style="margin-top:6px;color:var(--muted)">'+g.what_you_see+'</div><div style="color:#6EE7B7">'+g.good_for_dpi+'</div><div style="color:#FCA5A5">'+g.bad_for_dpi+'</div></div><div class="verdict '+(isCrit?'crit':'')+'"><bdi>'+(last?last.dpi.explanation:'Idle')+'</bdi></div>';
  });
}
setInterval(poll, 900); poll();
</script></body></html>`
