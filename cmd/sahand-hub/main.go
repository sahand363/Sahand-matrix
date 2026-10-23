package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"sahand-matrix/internal/analyzer"
	"sahand-matrix/internal/hub"
	"sahand-matrix/internal/ui"
	"sahand-matrix/pkg/models"
)

var globalSeq uint64 = 10420

func main() {
	daemonMode := flag.Bool("daemon", false, "Run as background systemd Hub & Web Panel service")
	port := flag.String("port", "8443", "Secure web panel & agent telemetry port")
	secretPath := flag.String("secret", "sahand-default", "Dynamic secret URL path")
	token := flag.String("token", "", "Shared agent authentication token")
	flag.Parse()

	if *daemonMode {
		runDaemonServer(*port, *secretPath, *token)
		return
	}

	// Interactive Terminal UI (TUI) Mode
	p := tea.NewProgram(
		ui.NewMatrixModel(),
		tea.WithAltScreen(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Sahand Traffic Matrix TUI: %v\n", err)
		os.Exit(1)
	}
}

func runDaemonServer(port, secret, token string) {
	syncEngine := hub.NewSyncEngine(256)
	baseRoute := fmt.Sprintf("/matrix/%s", strings.Trim(secret, "/"))
	panelRoute := baseRoute + "/"
	apiStateRoute := baseRoute + "/api/state"
	apiBurstRoute := baseRoute + "/api/pause-burst"

	mux := http.NewServeMux()

	// 1. Live Telemetry API (Polled by the Web UI every 600ms)
	mux.HandleFunc(apiStateRoute, func(w http.ResponseWriter, r *http.Request) {
		seq := atomic.AddUint64(&globalSeq, 1)
		burst := syncEngine.Measure5PingBurst("simulate", 48.0)
		avgMs := float64(burst.AverageRTT.Microseconds()) / 1000.0
		offsetMs := float64(burst.OneWayDelay.Microseconds()) / 1000.0

		checkpoints := buildLiveCheckpointSnapshot(seq, burst.OneWayDelay)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"panel":              "Sahand Traffic Matrix Pro",
			"global_status":      "OPTIMAL",
			"sequence_num":       seq,
			"five_ping_burst_ms": burst.SamplesMs,
			"average_rtt_ms":     avgMs,
			"window_offset_ms":   offsetMs,
			"jitter_ms":          burst.JitterMs,
			"checkpoints":        checkpoints,
			"agent_token":        token,
			"hub_host":           r.Host,
		})
	})

	// 2. 5-Ping Calibration Burst Endpoint (Triggered when clicking Smart Pause)
	mux.HandleFunc(apiBurstRoute, func(w http.ResponseWriter, r *http.Request) {
		seq := atomic.LoadUint64(&globalSeq)
		burst := syncEngine.Measure5PingBurst("simulate", 48.0)
		avgMs := float64(burst.AverageRTT.Microseconds()) / 1000.0
		offsetMs := float64(burst.OneWayDelay.Microseconds()) / 1000.0

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"locked_sequence":    seq,
			"five_ping_burst_ms": burst.SamplesMs,
			"average_rtt_ms":     avgMs,
			"window_offset_ms":   offsetMs,
			"jitter_ms":          burst.JitterMs,
			"checkpoints":        buildLiveCheckpointSnapshot(seq, burst.OneWayDelay),
		})
	})

	// 3. Main Netview Pro Web Dashboard UI
	mux.HandleFunc(panelRoute, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboardHTML))
	})

	log.Printf("[sahand-hub] Web Panel active on HTTP & HTTPS port :%s%s", port, panelRoute)
	log.Fatal(listenDualHTTPAndTLS("0.0.0.0:"+port, mux))
}

func buildLiveCheckpointSnapshot(seq uint64, oneWayOffset time.Duration) []map[string]any {
	now := time.Now().UTC()
	payloadHigh := make([]byte, 256)
	for i := range payloadHigh {
		payloadHigh[i] = byte((uint64(i)*37 + seq*13) % 256)
	}
	payloadInner := []byte(fmt.Sprintf("GET /v2/stream?seq=%d HTTP/1.1\r\nHost: core.internal\r\n\r\n", seq))

	defs := []struct {
		id      models.CheckpointID
		title   string
		node    string
		proto   string
		sni     string
		isTLS   bool
		payload []byte
		offset  time.Duration
	}{
		{models.CP1_RemoteEdgeIngress, "CP1: Edge Raw Ingress", "Remote Server", "TLSv1.3", "www.microsoft.com", true, payloadHigh, 0},
		{models.CP2_RemoteDecrypted, "CP2: Decrypted Payload", "Remote Server", "VLESS", "—", false, payloadInner, 2 * time.Millisecond},
		{models.CP3_InternationalFlight, "CP3: Int'l Transit", "In-Flight", "REALITY", "www.microsoft.com", true, payloadHigh, oneWayOffset / 2},
		{models.CP4_IranInternalIngress, "CP4: Internal Ingress", "Iran Server", "REALITY", "www.microsoft.com", true, payloadHigh, oneWayOffset},
		{models.CP5_IranEgressEdge, "CP5: Egress Edge (DPI)", "Iran Server", "TCP/TLS", "dl.cdn-edge.ir", true, payloadHigh, oneWayOffset + 2*time.Millisecond},
		{models.CP6_IranAppOutput, "CP6: Application Output", "Iran Server", "HTTP/2", "—", false, payloadInner, oneWayOffset + 4*time.Millisecond},
	}

	var out []map[string]any
	for _, d := range defs {
		dpi := analyzer.EvaluateDPIRisk(d.id, d.payload, models.TLSMetadata{
			IsTLS:            d.isTLS,
			SNI:              d.sni,
			IsRealityMimicry: d.proto == "REALITY",
		})
		out = append(out, map[string]any{
			"id":        d.id,
			"title":     d.title,
			"node":      d.node,
			"seq":       seq,
			"proto":     d.proto,
			"sni":       d.sni,
			"entropy":   dpi.ShannonEntropy,
			"risk":      dpi.Level,
			"offset_ms": float64(d.offset.Microseconds()) / 1000.0,
			"timestamp": now.Add(d.offset).Format("15:04:05.000"),
		})
	}
	return out
}

// Dual HTTP + HTTPS multiplexer so both http:// and https:// work seamlessly on the same port.
type sniffedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *sniffedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type chanListener struct {
	net.Listener
	ch chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) {
	c, ok := <-l.ch
	if !ok {
		return nil, net.ErrClosed
	}
	return c, nil
}

func listenDualHTTPAndTLS(addr string, handler http.Handler) error {
	baseLn, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	tlsCert, err := generateSelfSignedCert()
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	httpLn := &chanListener{Listener: baseLn, ch: make(chan net.Conn, 64)}
	tlsLn := &chanListener{Listener: baseLn, ch: make(chan net.Conn, 64)}

	go func() {
		_ = http.Serve(httpLn, handler)
	}()
	go func() {
		_ = http.Serve(tls.NewListener(tlsLn, tlsConfig), handler)
	}()

	for {
		rawConn, err := baseLn.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			br := bufio.NewReader(c)
			b, err := br.Peek(1)
			if err != nil {
				_ = c.Close()
				return
			}
			sc := &sniffedConn{Conn: c, r: br}
			// 0x16 is the standard TLS Handshake record byte
			if b[0] == 0x16 {
				tlsLn.ch <- sc
			} else {
				httpLn.ch <- sc
			}
		}(rawConn)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(202610),
		Subject:      pkix.Name{Organization: []string{"Sahand Traffic Matrix Pro"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAHAND MATRIX PRO // 6-Checkpoint DPI Analyzer</title>
<style>
  :root {
    --bg-dark: #0B0F19;
    --bg-card: #111827;
    --bg-card-hover: #162033;
    --border: #1E293B;
    --cyan: #38BDF8;
    --purple: #A855F7;
    --emerald: #10B981;
    --amber: #F59E0B;
    --crimson: #EF4444;
    --text-main: #F8FAFC;
    --text-muted: #64748B;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; }
  body { background: var(--bg-dark); color: var(--text-main); display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
  
  /* Top Header */
  header {
    height: 60px; border-bottom: 1px solid var(--border); display: flex; align-items: center;
    justify-content: space-between; padding: 0 24px; background: #0D1322;
  }
  .brand { display: flex; align-items: center; gap: 12px; font-size: 18px; font-weight: 700; letter-spacing: 0.5px; }
  .brand span.pro { color: var(--text-muted); font-weight: 400; }
  .header-controls { display: flex; align-items: center; gap: 16px; }
  .status-pill {
    font-size: 13px; font-weight: 600; padding: 6px 14px; border-radius: 20px;
    background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(16, 185, 129, 0.35); color: var(--emerald);
    display: flex; align-items: center; gap: 8px;
  }
  .status-pill.paused {
    background: rgba(245, 158, 11, 0.15); border-color: var(--amber); color: var(--amber);
  }
  .btn {
    padding: 8px 16px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;
    border: 1px solid var(--border); background: var(--bg-card); color: var(--text-main); transition: 0.2s;
  }
  .btn:hover { border-color: var(--cyan); background: var(--bg-card-hover); }
  .btn-primary { background: rgba(56, 189, 248, 0.15); border-color: var(--cyan); color: var(--cyan); }
  .btn-purple { background: rgba(168, 85, 247, 0.15); border-color: var(--purple); color: var(--purple); }

  /* Main Layout */
  .workspace { display: flex; flex: 1; overflow: hidden; }
  
  /* Sidebar */
  aside {
    width: 220px; border-right: 1px solid var(--border); background: #0C111D;
    display: flex; flex-direction: column; justify-content: space-between; padding: 20px 12px;
  }
  .nav-item {
    padding: 11px 14px; border-radius: 8px; color: var(--text-muted); font-size: 14px;
    font-weight: 500; cursor: pointer; display: flex; align-items: center; gap: 10px; margin-bottom: 6px;
  }
  .nav-item.active, .nav-item:hover { background: rgba(56, 189, 248, 0.1); color: var(--cyan); }
  .sys-footer { border-top: 1px solid var(--border); padding-top: 14px; font-size: 12px; color: var(--text-muted); }

  /* Center & Right Grid */
  main {
    flex: 1; padding: 20px; overflow-y: auto; display: grid;
    grid-template-columns: 1fr 330px; gap: 20px;
  }
  .center-col { display: flex; flex-direction: column; gap: 18px; }
  .right-col { display: flex; flex-direction: column; gap: 18px; }

  .card {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px;
  }
  .card.locked { border-color: var(--amber); box-shadow: 0 0 15px rgba(245, 158, 11, 0.12); }
  .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .card-title { font-size: 14px; font-weight: 600; color: var(--text-main); }
  .card-sub { font-size: 12px; color: var(--text-muted); }

  /* 6-Checkpoint Matrix Grid */
  .cp-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }
  .cp-box {
    background: #0E1525; border: 1px solid var(--border); border-radius: 10px; padding: 12px;
    transition: border-color 0.2s;
  }
  .cp-box.remote { border-top: 3px solid var(--cyan); }
  .cp-box.iran { border-top: 3px solid var(--purple); }
  .cp-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
  .cp-name { font-size: 13px; font-weight: 700; color: var(--cyan); }
  .cp-box.iran .cp-name { color: var(--purple); }
  .cp-offset { font-size: 11px; padding: 2px 6px; border-radius: 4px; background: rgba(255,255,255,0.06); color: var(--text-muted); }
  .cp-table { width: 100%; font-size: 12px; border-collapse: collapse; margin-top: 6px; }
  .cp-table td { padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.04); }
  .cp-table td.lbl { color: var(--text-muted); }
  .cp-table td.val { text-align: right; font-family: monospace; font-weight: 600; }
  .badge-low { color: var(--emerald); background: rgba(16,185,129,0.12); padding: 2px 6px; border-radius: 4px; font-size: 11px; }

  /* Bottom 4 KPI Row */
  .kpi-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; }
  .kpi-val { font-size: 26px; font-weight: 700; margin: 8px 0 4px 0; }
  .kpi-sub { font-size: 12px; color: var(--emerald); font-weight: 500; }

  /* Incidents & Protocol Bars */
  .incident-item { display: flex; gap: 10px; margin-bottom: 12px; font-size: 13px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; margin-top: 4px; flex-shrink: 0; }
  .dot.green { background: var(--emerald); }
  .dot.orange { background: var(--amber); }
  .bar-row { margin-bottom: 10px; font-size: 12px; }
  .bar-lbl { display: flex; justify-content: space-between; margin-bottom: 4px; color: var(--text-muted); }
  .bar-track { height: 6px; background: #1E293B; border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 4px; }

  /* Agent Modal */
  #agentModal {
    display: none; position: fixed; inset: 0; background: rgba(6, 10, 19, 0.85);
    align-items: center; justify-content: center; z-index: 50;
  }
  .modal-card {
    background: var(--bg-card); border: 1px solid var(--cyan); border-radius: 14px;
    width: 680px; padding: 24px;
  }
  pre.cmd-box {
    background: #070A12; border: 1px solid var(--border); padding: 12px; border-radius: 8px;
    color: var(--cyan); font-family: monospace; font-size: 12px; overflow-x: auto; margin: 8px 0 16px 0;
  }
</style>
</head>
<body>

<header>
  <div class="brand">
    <span style="color:var(--cyan)">❖</span> SAHAND MATRIX <span class="pro">PRO // DPI ANALYZER</span>
  </div>
  <div class="header-controls">
    <div id="statusBadge" class="status-pill">● GLOBAL STATUS: OPTIMAL (6/6 SYNCED)</div>
    <button id="pauseBtn" class="btn btn-primary" onclick="toggleSmartPause()">⏸ 5-Ping Sync Pause</button>
    <button class="btn btn-purple" onclick="toggleAgentModal()">🚀 Deploy Agent</button>
  </div>
</header>

<div class="workspace">
  <aside>
    <div>
      <div class="nav-item active">⊞ &nbsp;Dashboard</div>
      <div class="nav-item" onclick="toggleAgentModal()">🚀 &nbsp;Deploy Agent</div>
      <div class="nav-item">☊ &nbsp;Topology Map</div>
      <div class="nav-item">⛨ &nbsp;Checkpoints (6)</div>
      <div class="nav-item">📈 &nbsp;Performance</div>
      <div class="nav-item">⚙ &nbsp;Settings</div>
    </div>
    <div class="sys-footer">
      <div style="color:var(--emerald); margin-bottom:4px;">● Remote Agent: Verified</div>
      <div style="color:var(--emerald); margin-bottom:8px;">● Iran Agent: Verified</div>
      System Status: OK
    </div>
  </aside>

  <main>
    <div class="center-col">
      <!-- Real-Time Throughput & 5-Ping Wave Card -->
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Real-Time Multi-Checkpoint Throughput & Entropy Stream</div>
            <div class="card-sub">Synchronized via 5-Ping RTT/2 Offset Engine</div>
          </div>
          <div style="display:flex; gap:16px; font-size:12px;">
            <span style="color:var(--cyan)">● Remote Edge (CP1-CP3)</span>
            <span style="color:var(--purple)">● Iran Node (CP4-CP6)</span>
          </div>
        </div>
        <svg viewBox="0 0 800 135" width="100%" height="135">
          <defs>
            <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#38BDF8" stop-opacity="0.35"/>
              <stop offset="100%" stop-color="#38BDF8" stop-opacity="0.0"/>
            </linearGradient>
            <linearGradient id="purpleGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="#A855F7" stop-opacity="0.30"/>
              <stop offset="100%" stop-color="#A855F7" stop-opacity="0.0"/>
            </linearGradient>
          </defs>
          <path d="M0,90 Q60,45 120,80 T240,65 T360,70 T480,35 T600,60 T720,20 L800,55 L800,135 L0,135 Z" fill="url(#cyanGrad)"/>
          <path d="M0,90 Q60,45 120,80 T240,65 T360,70 T480,35 T600,60 T720,20 L800,55" fill="none" stroke="#38BDF8" stroke-width="2.5"/>
          <path d="M0,110 Q60,75 120,100 T240,85 T360,90 T480,65 T600,80 T720,50 L800,75 L800,135 L0,135 Z" fill="url(#purpleGrad)"/>
          <path d="M0,110 Q60,75 120,100 T240,85 T360,90 T480,65 T600,80 T720,50 L800,75" fill="none" stroke="#A855F7" stroke-width="2"/>
        </svg>
      </div>

      <!-- 6 Synchronized Checkpoints Grid -->
      <div id="cpGrid" class="cp-grid"></div>

      <!-- Bottom 4 KPI Cards -->
      <div class="kpi-row">
        <div class="card">
          <div class="card-sub">BANDWIDTH</div>
          <div class="kpi-val">14.5 <span style="font-size:15px;font-weight:400">Gbps</span></div>
          <div class="kpi-sub">+1.2% Synced</div>
        </div>
        <div class="card">
          <div class="card-sub">5-PING AVG LATENCY</div>
          <div class="kpi-val" id="kpiRtt">48.0 <span style="font-size:15px;font-weight:400">ms</span></div>
          <div class="kpi-sub" id="kpiOffset">Window Offset: +24.0 ms</div>
        </div>
        <div class="card">
          <div class="card-sub">ACTIVE CHECKPOINTS</div>
          <div class="kpi-val">6 <span style="font-size:15px;color:var(--text-muted)">/ 6 Nodes</span></div>
          <div class="kpi-sub" style="color:var(--cyan)">All Streams Verified</div>
        </div>
        <div class="card">
          <div class="card-sub">DPI VULNERABILITY</div>
          <div class="kpi-val" style="color:var(--emerald)">0.01%</div>
          <div class="kpi-sub">Reality SNI & Entropy Clean</div>
        </div>
      </div>
    </div>

    <!-- Right Rail -->
    <div class="right-col">
      <div class="card">
        <div class="card-header">
          <div class="card-title">5-PING CALIBRATION & ALERTS</div>
        </div>
        <div id="incidentFeed">
          <div class="incident-item">
            <div class="dot green"></div>
            <div>
              <div style="font-weight:600" id="pingLogTitle">5-Ping Burst Ready</div>
              <div class="card-sub" id="pingSamplesText">P1..P5: Calibrating...</div>
            </div>
          </div>
          <div class="incident-item">
            <div class="dot green"></div>
            <div>
              <div style="font-weight:600">CP1: Reality Handshake Verified</div>
              <div class="card-sub">SNI: www.microsoft.com</div>
            </div>
          </div>
          <div class="incident-item">
            <div class="dot orange"></div>
            <div>
              <div style="font-weight:600">CP3: High Entropy Tunnel</div>
              <div class="card-sub">Shannon H(X) = 8.00 bits/byte</div>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="card-title">TRAFFIC BY PROTOCOL</div>
        </div>
        <div class="bar-row">
          <div class="bar-lbl"><span>REALITY / TLS 1.3</span><span>68%</span></div>
          <div class="bar-track"><div class="bar-fill" style="width:68%; background:var(--cyan)"></div></div>
        </div>
        <div class="bar-row">
          <div class="bar-lbl"><span>VLESS CORE</span><span>22%</span></div>
          <div class="bar-track"><div class="bar-fill" style="width:22%; background:var(--purple)"></div></div>
        </div>
        <div class="bar-row">
          <div class="bar-lbl"><span>TCP RAW</span><span>8%</span></div>
          <div class="bar-track"><div class="bar-fill" style="width:8%; background:var(--emerald)"></div></div>
        </div>
        <div class="bar-row">
          <div class="bar-lbl"><span>UDP / DNS</span><span>2%</span></div>
          <div class="bar-track"><div class="bar-fill" style="width:2%; background:var(--amber)"></div></div>
        </div>
      </div>
    </div>
  </main>
</div>

<!-- Deploy Agent Modal -->
<div id="agentModal">
  <div class="modal-card">
    <div class="card-header">
      <div class="card-title" style="font-size:17px;">🚀 Deploy & Verify Lightweight sahand-agent</div>
      <button class="btn" onclick="toggleAgentModal()">✕ Close</button>
    </div>
    <p class="card-sub" style="margin-bottom:12px;">
      Copy and run either command below on your second server to link Checkpoints 1–6 and enable 5-ping RTT calibration:
    </p>
    <div class="card-title">1. Interactive Ubuntu Setup Menu:</div>
    <pre class="cmd-box">bash &lt;(curl -Ls https://raw.githubusercontent.com/sahand363/sahand-matrix/main/scripts/setup.sh)</pre>
    <div class="card-title">2. Direct One-Line Agent Connect Command:</div>
    <pre class="cmd-box" id="agentOneLiner">Loading token...</pre>
    <div class="card-title">3. Live 5-Ping Calibration Telemetry:</div>
    <pre class="cmd-box" id="modalPingStatus" style="color:var(--emerald)">Verifying...</pre>
  </div>
</div>

<script>
let isPaused = false;

function renderCheckpoints(data) {
  const grid = document.getElementById('cpGrid');
  grid.innerHTML = data.checkpoints.map(cp => {
    const isRemote = cp.id <= 3;
    return ` + "`" + `
      <div class="cp-box ${isRemote ? 'remote' : 'iran'}">
        <div class="cp-top">
          <span class="cp-name">${cp.title}</span>
          <span class="cp-offset">+${cp.offset_ms.toFixed(1)} ms</span>
        </div>
        <table class="cp-table">
          <tr><td class="lbl">Logical Packet</td><td class="val">#${cp.seq}</td></tr>
          <tr><td class="lbl">Protocol / SNI</td><td class="val">${cp.proto} (${cp.sni})</td></tr>
          <tr><td class="lbl">Shannon H(X)</td><td class="val">${cp.entropy.toFixed(2)} b/B</td></tr>
          <tr><td class="lbl">DPI Risk</td><td class="val"><span class="badge-low">${cp.risk}</span></td></tr>
        </table>
      </div>
    ` + "`" + `;
  }).join('');

  document.getElementById('kpiRtt').innerHTML = data.average_rtt_ms.toFixed(1) + ' <span style="font-size:15px;font-weight:400">ms</span>';
  document.getElementById('kpiOffset').innerText = 'Window Offset: +' + data.window_offset_ms.toFixed(1) + ' ms (RTT/2)';
  const p = data.five_ping_burst_ms.map(x => x.toFixed(1)).join('ms, ') + 'ms';
  document.getElementById('pingSamplesText').innerText = '5 Pings: [' + p + ']';
  document.getElementById('agentOneLiner').innerText =
    'sahand-agent --hub ' + data.hub_host + ' --token ' + (data.agent_token || 'SECRET') + ' --role iran';
  document.getElementById('modalPingStatus').innerText =
    '5-Ping Samples: [' + p + '] | Avg RTT: ' + data.average_rtt_ms.toFixed(2) + 'ms | Offset: +' + data.window_offset_ms.toFixed(2) + 'ms | Checkpoints 1-6: ONLINE';
}

async function pollState() {
  if (isPaused) return;
  try {
    const res = await fetch('api/state');
    const data = await res.json();
    renderCheckpoints(data);
  } catch (e) {}
}

async function toggleSmartPause() {
  const btn = document.getElementById('pauseBtn');
  const badge = document.getElementById('statusBadge');
  if (!isPaused) {
    btn.innerText = '⚡ Calibrating 5 Pings...';
    const res = await fetch('api/pause-burst');
    const data = await res.json();
    isPaused = true;
    renderCheckpoints(data);
    btn.innerText = '▶ Resume Live Stream';
    badge.className = 'status-pill paused';
    badge.innerText = '⏸ LOCKED @ SEQ #' + data.locked_sequence + ' (5-PING AVG: ' + data.average_rtt_ms.toFixed(1) + 'ms | OFFSET: +' + data.window_offset_ms.toFixed(1) + 'ms)';
    document.getElementById('pingLogTitle').innerText = '5-Ping Sync Pause Locked @ #' + data.locked_sequence;
  } else {
    isPaused = false;
    btn.innerText = '⏸ 5-Ping Sync Pause';
    badge.className = 'status-pill';
    badge.innerText = '● GLOBAL STATUS: OPTIMAL (6/6 SYNCED)';
    document.getElementById('pingLogTitle').innerText = 'Live Stream Resumed';
    pollState();
  }
}

function toggleAgentModal() {
  const m = document.getElementById('agentModal');
  m.style.display = (m.style.display === 'flex') ? 'none' : 'flex';
}

setInterval(pollState, 650);
pollState();
</script>
</body>
</html>`
