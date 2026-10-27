package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
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
	lastRemote map[models.CheckpointID][]models.PacketEvent
	token      string
	httpClient *http.Client
}

func main() {
	daemonMode := flag.Bool("daemon", false, "Run as background systemd Hub & Web Panel service")
	port := flag.String("port", "8443", "Secure web panel port")
	secretPath := flag.String("secret", "sahand-default", "Persistent secret URL path")
	token := flag.String("token", "", "Shared agent authentication token")
	authUser := flag.String("auth-user", "", "Optional HTTP Basic Auth username (blank = disabled)")
	authPass := flag.String("auth-pass", "", "Optional HTTP Basic Auth password (blank = disabled)")
	flag.Parse()

	if *daemonMode {
		runDaemonServer(*port, *secretPath, *token, *authUser, *authPass)
		return
	}

	p := tea.NewProgram(ui.NewMatrixModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Sahand Traffic Matrix TUI: %v\n", err)
		os.Exit(1)
	}
}

func runDaemonServer(port, secret, token, authUser, authPass string) {
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
		lastRemote: make(map[models.CheckpointID][]models.PacketEvent),
		token:      token,
		httpClient: &http.Client{Timeout: 2500 * time.Millisecond},
	}

	// Background poller for Server 2 (CP4-CP6) so UI never blocks or flashes empty on border lag
	go hc.pollRemoteLoop()

	guard := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if authUser != "" && authPass != "" {
				u, p, ok := r.BasicAuth()
				uOk := subtle.ConstantTimeCompare([]byte(u), []byte(authUser)) == 1
				pOk := subtle.ConstantTimeCompare([]byte(p), []byte(authPass)) == 1
				if !ok || !uOk || !pOk {
					w.Header().Set("WWW-Authenticate", `Basic realm="Sahand Matrix Hub"`)
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}

	baseRoute := fmt.Sprintf("/matrix/%s", strings.Trim(secret, "/"))
	mux := http.NewServeMux()

	mux.HandleFunc(baseRoute+"/api/control", guard(func(w http.ResponseWriter, r *http.Request) {
		action := r.URL.Query().Get("action")
		if action == "start" {
			hc.localSniff.Start()
		} else {
			hc.localSniff.Stop()
		}
		hc.forwardRemoteQuery("action=" + url.QueryEscape(action))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"capturing": hc.localSniff.IsRunning()})
	}))

	mux.HandleFunc(baseRoute+"/api/ports", guard(func(w http.ResponseWriter, r *http.Request) {
		portsCSV := r.URL.Query().Get("ports")
		locked := hc.localSniff.SetPortFilterCSV(portsCSV)
		hc.mu.Lock()
		hc.lastRemote = make(map[models.CheckpointID][]models.PacketEvent)
		hc.mu.Unlock()
		hc.forwardRemoteQuery("ports=" + url.QueryEscape(portsCSV))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"locked_ports": locked})
	}))

	mux.HandleFunc(baseRoute+"/api/pair", guard(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	mux.HandleFunc(baseRoute+"/api/nodes/add", guard(func(w http.ResponseWriter, r *http.Request) {
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
	}))

	mux.HandleFunc(baseRoute+"/api/nodes/delete", guard(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		hc.nodeMgr.DeleteNode(id)
		hc.mu.Lock()
		if hc.activeS2 == id {
			hc.activeS2 = "local-s1"
		}
		hc.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})) // <-- ensure this closing brace and parenthesis are followed by a comma if needed, or closed properly

	mux.HandleFunc(baseRoute+"/api/nodes/deploy", guard(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		hubHost := strings.Split(r.Host, ":")[0]
		hc.nodeMgr.DeployAgentAsync(id, hubHost, hc.token)
		w.WriteHeader(http.StatusOK)
	}))

	mux.HandleFunc(baseRoute+"/api/pause-burst", guard(func(w http.ResponseWriter, r *http.Request) {
		targetHost := hc.getS2HostPort()
		report := hc.syncEngine.GetOrMeasure5Pings(targetHost, hc.token, false)
		hc.mu.Lock()
		hc.lastPing = report
		hc.mu.Unlock()
		hc.writeMergedState(w)
	}))

	mux.HandleFunc(baseRoute+"/api/state", guard(func(w http.ResponseWriter, r *http.Request) {
		hc.writeMergedState(w)
	}))

	mux.HandleFunc(baseRoute+"/", guard(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(hub.DashboardHTML))
	}))

	log.Printf("[sahand-hub] Main Server Lab active on :%s%s/", port, baseRoute)
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

func (hc *HubCoordinator) forwardRemoteQuery(query string) {
	for _, n := range hc.nodeMgr.ListNodes() {
		if n.ID == "local-s1" {
			continue
		}
		u := fmt.Sprintf("http://%s:%d/api/control?%s", n.Host, n.AgentPort, query)
		go func(target string) {
			resp, err := hc.httpClient.Get(target)
			if err == nil {
				_ = resp.Body.Close()
			}
		}(u)
	}
}

func (hc *HubCoordinator) pollRemoteLoop() {
	for {
		time.Sleep(850 * time.Millisecond)
		hc.mu.RLock()
		s2 := hc.activeS2
		hc.mu.RUnlock()

		// Auto-select first remote node if activeS2 is still local-s1
		if s2 == "local-s1" {
			for _, n := range hc.nodeMgr.ListNodes() {
				if n.ID != "local-s1" {
					s2 = n.ID
					hc.mu.Lock()
					hc.activeS2 = s2
					hc.localSniff.SetPeerIP(n.Host)
					hc.mu.Unlock()
					break
				}
			}
		}

		if n, ok := hc.nodeMgr.GetNode(s2); ok && n.ID != "local-s1" {
			u := fmt.Sprintf("http://%s:%d/api/snapshot", n.Host, n.AgentPort)
			resp, err := hc.httpClient.Get(u)
			if err == nil {
				var remoteSnap struct {
					Checkpoints map[models.CheckpointID][]models.PacketEvent `json:"checkpoints"`
				}
				if json.NewDecoder(resp.Body).Decode(&remoteSnap) == nil && len(remoteSnap.Checkpoints) > 0 {
					hc.nodeMgr.MarkNodeOnline(s2)
					hc.mu.Lock()
					for cpID, evs := range remoteSnap.Checkpoints {
						hc.lastRemote[cpID] = evs
					}
					hc.mu.Unlock()
				}
				_ = resp.Body.Close()
			}
		}
	}
}

func (hc *HubCoordinator) writeMergedState(w http.ResponseWriter) {
	merged := hc.localSniff.GetSnapshot()
	hc.mu.RLock()
	s1, s2, ping := hc.activeS1, hc.activeS2, hc.lastPing
	for cpID, evs := range hc.lastRemote {
		merged[cpID] = evs
	}
	hc.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"capturing":    hc.localSniff.IsRunning(),
		"locked_ports": hc.localSniff.GetLockedPorts(),
		"checkpoints":  merged,
		"guides":       analyzer.AllCheckpointGuides(),
		"nodes":        hc.nodeMgr.ListNodes(),
		"active_s1":    s1,
		"active_s2":    s2,
		"ping":         ping,
	})
}
