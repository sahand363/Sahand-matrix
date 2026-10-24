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
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"sahand-matrix/internal/agent"
	"sahand-matrix/internal/analyzer"
	"sahand-matrix/internal/hub"
	"sahand-matrix/internal/ui"
	"sahand-matrix/pkg/models"
)

type HubCoordinator struct {
	mu         sync.RWMutex
	localSniff *agent.RealSniffer
	syncEngine *hub.SyncEngine
	nodeMgr    *hub.NodeManager
	activeS1   string
	activeS2   string
	lastPing   hub.PingBurstReport
	token      string
	httpClient *http.Client
}

func main() {
	daemonMode := flag.Bool("daemon", false, "Run as background systemd Hub & Web Panel service")
	port := flag.String("port", "8443", "Secure web panel port")
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

func runDaemonServer(port, secret, token string) {
	sniffer := agent.NewRealSniffer("iran", "local-s1", "", 8443)
	go func() {
		if err := sniffer.RunCaptureLoop(); err != nil {
			log.Printf("[sahand-hub] Local raw socket notice: %v", err)
		}
	}()

	hc := &HubCoordinator{
		localSniff: sniffer,
		syncEngine: hub.NewSyncEngine(256),
		nodeMgr:    hub.NewNodeManager("127.0.0.1"),
		activeS1:   "local-s1",
		activeS2:   "local-s1",
		token:      token,
		httpClient: &http.Client{Timeout: 1800 * time.Millisecond},
	}

	baseRoute := fmt.Sprintf("/matrix/%s", strings.Trim(secret, "/"))
	mux := http.NewServeMux()

	// 1. Start / Stop Both Servers
	mux.HandleFunc(baseRoute+"/api/control", func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("action")
		if action == "start" {
			hc.localSniff.Start()
		} else {
			hc.localSniff.Stop()
		}
		hc.forwardRemoteControl(action)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"capturing": hc.localSniff.IsRunning()})
	})

	// 2. Select Active S1 (Iran) & S2 (Kharej) Server Pair
	mux.HandleFunc(baseRoute+"/api/pair", func(w http.ResponseWriter, r *http.Request) {
		hc.mu.Lock()
		if s1 := r.URL.Query().Get("s1"); s1 != "" {
			hc.activeS1 = s1
		}
		if s2 := r.URL.Query().Get("s2"); s2 != "" {
			hc.activeS2 = s2
			if n, ok := hc.nodeMgr.GetNode(s2); ok {
				hc.localSniff.SetPeerIP(n.Host)
			}
		}
		hc.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	// 3. Add Remote Server via SSH (or Manual IP if password left blank)
	mux.HandleFunc(baseRoute+"/api/nodes/add", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name     string `json:"name"`
			Role     string `json:"role"`
			Host     string `json:"host"`
			SSHPort  int    `json:"ssh_port"`
			SSHUser  string `json:"ssh_user"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := fmt.Sprintf("node-%d", time.Now().Unix()%10000)
		node, err := hc.nodeMgr.AddAndVerifySSH(id, req.Name, req.Role, strings.TrimSpace(req.Host), req.SSHPort, req.SSHUser, req.Password)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		hc.mu.Lock()
		if req.Role == "kharej" {
			hc.activeS2 = node.ID
			hc.localSniff.SetPeerIP(node.Host)
		}
		hc.mu.Unlock()
		_ = json.NewEncoder(w).Encode(node)
	})

	// 4. Delete Server Card from List
	mux.HandleFunc(baseRoute+"/api/nodes/delete", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		hc.nodeMgr.DeleteNode(id)
		hc.mu.Lock()
		if hc.activeS2 == id {
			hc.activeS2 = "local-s1"
		}
		hc.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	// 5. Trigger Automated SSH Binary Deployment (0% -> 100%)
	mux.HandleFunc(baseRoute+"/api/nodes/deploy", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		hubHost := strings.Split(r.Host, ":")[0]
		hc.nodeMgr.DeployAgentAsync(id, hubHost, hc.token)
		w.WriteHeader(http.StatusOK)
	})

	// 6. Smart 5-Ping Pause (Uses 1-Hour Cache or Runs 5 Real Pings)
	mux.HandleFunc(baseRoute+"/api/pause-burst", func(w http.ResponseWriter, r *http.Request) {
		targetHost := hc.getS2HostPort()
		report := hc.syncEngine.GetOrMeasure5Pings(targetHost, hc.token, false)
		hc.mu.Lock()
		hc.lastPing = report
		hc.mu.Unlock()
		hc.writeMergedState(w)
	})

	// 7. Live Merged 6-Checkpoint Real Packet State
	mux.HandleFunc(baseRoute+"/api/state", func(w http.ResponseWriter, r *http.Request) {
		hc.writeMergedState(w)
	})

	// 8. Serve Main Dashboard
	mux.HandleFunc(baseRoute+"/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(hub.DashboardHTML))
	})

	log.Printf("[sahand-hub] Real Packet Lab active on :%s%s/", port, baseRoute)
	log.Fatal(hub.ListenDualHTTPAndTLS("0.0.0.0:"+port, mux))
}

func (hc *HubCoordinator) getS2HostPort() string {
	hc.mu.RLock()
	s2ID := hc.activeS2
	hc.mu.RUnlock()
	if n, ok := hc.nodeMgr.GetNode(s2ID); ok && n.Host != "" {
		return fmt.Sprintf("%s:%d", n.Host, n.AgentPort)
	}
	return "127.0.0.1:9444"
}

func (hc *HubCoordinator) forwardRemoteControl(action string) {
	for _, n := range hc.nodeMgr.ListNodes() {
		if n.ID == "local-s1" {
			continue
		}
		url := fmt.Sprintf("http://%s:%d/api/control?action=%s", n.Host, n.AgentPort, action)
		go func(u string) {
			resp, err := hc.httpClient.Get(u)
			if err == nil {
				_ = resp.Body.Close()
			}
		}(url)
	}
}

func (hc *HubCoordinator) writeMergedState(w http.ResponseWriter) {
	merged := hc.localSniff.GetSnapshot()

	hc.mu.RLock()
	s1, s2, ping := hc.activeS1, hc.activeS2, hc.lastPing
	hc.mu.RUnlock()

	if n, ok := hc.nodeMgr.GetNode(s2); ok && n.ID != "local-s1" {
		resp, err := hc.httpClient.Get(fmt.Sprintf("http://%s:%d/api/snapshot", n.Host, n.AgentPort))
		if err == nil {
			var remoteSnap struct {
				Checkpoints map[models.CheckpointID][]models.PacketEvent `json:"checkpoints"`
			}
			if json.NewDecoder(resp.Body).Decode(&remoteSnap) == nil {
				hc.nodeMgr.MarkNodeOnline(s2)
				for cpID, evs := range remoteSnap.Checkpoints {
					merged[cpID] = evs
				}
			}
			_ = resp.Body.Close()
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"capturing":   hc.localSniff.IsRunning(),
		"checkpoints": merged,
		"guides":      analyzer.AllCheckpointGuides(),
		"nodes":       hc.nodeMgr.ListNodes(),
		"active_s1":   s1,
		"active_s2":   s2,
		"ping":        ping,
	})
}
