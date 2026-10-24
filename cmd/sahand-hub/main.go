package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"sahand-matrix/internal/hub"
	"sahand-matrix/internal/tunnels"
	"sahand-matrix/internal/ui"
	"sahand-matrix/pkg/models"
)

var (
	globalSeq    uint64 = 10420
	tunnelMu     sync.RWMutex
	activeTunnel = models.TunnelWSS
)

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

	p := tea.NewProgram(ui.NewMatrixModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Sahand Traffic Matrix TUI: %v\n", err)
		os.Exit(1)
	}
}

func getActiveTunnelInfo() tunnels.TunnelInfo {
	tunnelMu.RLock()
	curr := activeTunnel
	tunnelMu.RUnlock()
	for _, info := range tunnels.AvailableTunnels() {
		if info.ID == curr {
			return info
		}
	}
	return tunnels.AvailableTunnels()[0]
}

func runDaemonServer(port, secret, token string) {
	syncEngine := hub.NewSyncEngine(256)
	baseRoute := fmt.Sprintf("/matrix/%s", strings.Trim(secret, "/"))
	panelRoute := baseRoute + "/"

	mux := http.NewServeMux()

	// 1. Switch Active Tunnel Profile (WSS, Reality, gRPC, Shadowsocks, Raw TCP)
	mux.HandleFunc(baseRoute+"/api/tunnel", func(w http.ResponseWriter, r *http.Request) {
		t := models.TunnelType(r.URL.Query().Get("type"))
		for _, info := range tunnels.AvailableTunnels() {
			if info.ID == t {
				tunnelMu.Lock()
				activeTunnel = t
				tunnelMu.Unlock()
				break
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(getActiveTunnelInfo())
	})

	// 2. Live 6-Checkpoint Stream State
	mux.HandleFunc(baseRoute+"/api/state", func(w http.ResponseWriter, r *http.Request) {
		seq := atomic.AddUint64(&globalSeq, 1)
		burst := syncEngine.Measure5PingBurst("simulate", 48.0)
		tInfo := getActiveTunnelInfo()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sequence_num":       seq,
			"active_tunnel_info": tInfo,
			"five_ping_burst_ms": burst.SamplesMs,
			"average_rtt_ms":     float64(burst.AverageRTT.Microseconds()) / 1000.0,
			"window_offset_ms":   float64(burst.OneWayDelay.Microseconds()) / 1000.0,
			"checkpoints":        tunnels.Build6CheckpointSnapshot(tInfo.ID, seq, burst.OneWayDelay),
			"agent_token":        token,
			"hub_host":           r.Host,
		})
	})

	// 3. 5-Ping Calibration & Synchronized Pause
	mux.HandleFunc(baseRoute+"/api/pause-burst", func(w http.ResponseWriter, r *http.Request) {
		seq := atomic.LoadUint64(&globalSeq)
		burst := syncEngine.Measure5PingBurst("simulate", 48.0)
		tInfo := getActiveTunnelInfo()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sequence_num":       seq,
			"active_tunnel_info": tInfo,
			"five_ping_burst_ms": burst.SamplesMs,
			"average_rtt_ms":     float64(burst.AverageRTT.Microseconds()) / 1000.0,
			"window_offset_ms":   float64(burst.OneWayDelay.Microseconds()) / 1000.0,
			"checkpoints":        tunnels.Build6CheckpointSnapshot(tInfo.ID, seq, burst.OneWayDelay),
			"agent_token":        token,
			"hub_host":           r.Host,
		})
	})

	// 4. Serve Web Dashboard UI
	mux.HandleFunc(panelRoute, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(hub.DashboardHTML))
	})

	log.Printf("[sahand-hub] Web Panel active on HTTP & HTTPS :%s%s", port, panelRoute)
	log.Fatal(hub.ListenDualHTTPAndTLS("0.0.0.0:"+port, mux))
}
