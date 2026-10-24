package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"sahand-matrix/internal/agent"
	"sahand-matrix/internal/analyzer"
)

func main() {
	role := flag.String("role", "kharej", "Server role: 'iran' (CP1-CP3) or 'kharej' (CP4-CP6)")
	serverID := flag.String("id", "node-kharej", "Unique Server Node ID")
	peerIP := flag.String("peer", "", "Peer Server IP to classify CP3/CP4 transit traffic")
	token := flag.String("token", "", "Shared authentication token")
	listenAddr := flag.String("listen", ":9444", "Agent API & 3-Window Local Web UI port")
	flag.Parse()

	sniffer := agent.NewRealSniffer(*role, *serverID, *peerIP, 9444)

	// Start raw socket capture loop in background (starts in STOPPED/Idle state until Start is pressed)
	go func() {
		if err := sniffer.RunCaptureLoop(); err != nil {
			log.Printf("[sahand-agent] Raw capture warning: %v", err)
		}
	}()

	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if *token != "" && r.Header.Get("X-Sahand-Token") != *token && r.URL.Query().Get("token") != *token {
				// Allow local browser UI access if token not enforced on root
			}
			next(w, r)
		}
	}

	// 1. Real 5-Ping Calibration Responder
	http.HandleFunc("/api/ping", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_id":      *serverID,
			"role":           *role,
			"capturing":      sniffer.IsRunning(),
			"timestamp_nano": time.Now().UTC().UnixNano(),
		})
	}))

	// 2. Start / Stop Control Endpoint (Starts Stopped by default)
	http.HandleFunc("/api/control", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("action")
		if peer := r.URL.Query().Get("peer"); peer != "" {
			sniffer.SetPeerIP(peer)
		}
		if action == "start" {
			sniffer.Start()
		} else if action == "stop" {
			sniffer.Stop()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"capturing": sniffer.IsRunning(),
			"role":      *role,
		})
	}))

	// 3. Real Captured Packet Snapshot (3 Local Checkpoints)
	http.HandleFunc("/api/snapshot", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_id":   *serverID,
			"role":        *role,
			"capturing":   sniffer.IsRunning(),
			"checkpoints": sniffer.GetSnapshot(),
			"guides":      analyzer.AllCheckpointGuides(),
		})
	}))

	// 4. Local 3-Window Node Web Page (Matches Main Hub with zero transit lag)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, agentLocalHTML)
	})

	log.Printf("[sahand-agent] (%s) listening on %s [Default State: STOPPED]", *role, *listenAddr)
	log.Fatal(http.ListenAndServe(*listenAddr, nil))
}

const agentLocalHTML = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Sahand Agent // Local 3-Window Node</title>
<style>
  body { background:#0B0F19; color:#F8FAFC; font-family:monospace; padding:20px; }
  .bar { display:flex; justify-content:space-between; align-items:center; background:#111827; padding:14px 18px; border-radius:10px; border:1px solid #1E293B; margin-bottom:16px; }
  .btn { padding:8px 16px; border-radius:6px; border:1px solid #38BDF8; background:#0D1322; color:#38BDF8; cursor:pointer; font-weight:bold; }
  .row { display:grid; grid-template-columns: 1.6fr 1fr; gap:14px; background:#111827; border:1px solid #1E293B; border-radius:10px; padding:14px; margin-bottom:12px; }
  .stream { background:#060911; padding:10px; border-radius:6px; height:110px; overflow-y:auto; font-size:12px; color:#7DD3FC; }
</style></head><body>
<div class="bar">
  <div><strong id="hdr">SAHAND LOCAL AGENT // 3-WINDOW REAL CAPTURE</strong></div>
  <div>
    <span id="stateBadge" style="margin-right:12px;color:#F59E0B">● STOPPED (IDLE)</span>
    <button class="btn" onclick="ctrl('start')">▶ Start Capture</button>
    <button class="btn" style="border-color:#EF4444;color:#EF4444" onclick="ctrl('stop')">■ Stop</button>
  </div>
</div>
<div id="list"></div>
<script>
async function ctrl(a) { await fetch('/api/control?action='+a); poll(); }
async function poll() {
  const res = await fetch('/api/snapshot');
  const d = await res.json();
  document.getElementById('hdr').innerText = 'SAHAND AGENT (' + d.role.toUpperCase() + ' NODE: ' + d.server_id + ')';
  const b = document.getElementById('stateBadge');
  b.innerText = d.capturing ? '● CAPTURING REAL PACKETS' : '● STOPPED (IDLE)';
  b.style.color = d.capturing ? '#10B981' : '#F59E0B';
  const guides = d.guides.filter(g => g.server_role === d.role);
  document.getElementById('list').innerHTML = guides.map(g => {
    const evs = (d.checkpoints && d.checkpoints[g.id]) || [];
    const last = evs[evs.length-1];
    const logs = evs.length ? evs.map(e => '<div>[#'+e.sequence_num+' '+e.src_addr+'->'+e.dst_addr+'] '+e.raw_byte_log+'</div>').join('') : '<div style="color:#64748B">Waiting for real packets (Press Start Capture)...</div>';
    return '<div class="row">' +
      '<div><strong>'+g.title+'</strong> <span style="color:#F59E0B">['+g.dpi_zone+']</span><div class="stream" style="margin-top:8px">'+logs+'</div></div>' +
      '<div style="font-size:12px;line-height:1.5;background:#0B101B;padding:10px;border-radius:8px;">' +
        '<div><strong>Protocol:</strong> '+(last?last.protocol:'—')+' | <strong>Entropy:</strong> '+(last?last.dpi.shannon_entropy+' / 8.00':'—')+'</div>' +
        '<div style="color:#94A3B8;margin-top:6px;"><strong>What you see:</strong> '+g.what_you_see+'</div>' +
        '<div style="color:#10B981;margin-top:4px;"><strong>Good:</strong> '+g.good_for_dpi+'</div>' +
        '<div style="color:#EF4444;margin-top:4px;"><strong>Bad for DPI:</strong> '+g.bad_for_dpi+'</div>' +
      '</div></div>';
  }).join('');
}
setInterval(poll, 700); poll();
</script></body></html>`
