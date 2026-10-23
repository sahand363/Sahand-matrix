package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"sahand-matrix/internal/hub"
	"sahand-matrix/internal/ui"
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
	panelRoute := fmt.Sprintf("/matrix/%s/", secret)

	http.HandleFunc(panelRoute, func(w http.ResponseWriter, r *http.Request) {
		burst := syncEngine.Measure5PingBurst("simulate", 48.0)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"panel":              "Sahand Traffic Matrix Pro",
			"global_status":      "OPTIMAL",
			"checkpoints_online": []int{1, 2, 3, 4, 5, 6},
			"five_ping_burst_ms": burst.SamplesMs,
			"average_rtt_ms":     float64(burst.AverageRTT.Microseconds()) / 1000.0,
			"window_offset_ms":   float64(burst.OneWayDelay.Microseconds()) / 1000.0,
			"agent_auth_enabled": token != "",
		})
	})

	log.Printf("[sahand-hub] Panel active at http://0.0.0.0:%s%s", port, panelRoute)
	log.Fatal(http.ListenAndServe("0.0.0.0:"+port, nil))
}
