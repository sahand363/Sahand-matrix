package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"sahand-matrix/internal/analyzer"
	"sahand-matrix/pkg/models"
)

func main() {
	hubAddr := flag.String("hub", "127.0.0.1:8443", "Central Sahand Hub address (IP:Port)")
	token := flag.String("token", "", "Agent authentication token")
	role := flag.String("role", "iran", "Server role: 'remote' (CP1-CP3) or 'iran' (CP4-CP6)")
	listenPort := flag.String("listen", ":9444", "Local port for 5-ping calibration probes")
	flag.Parse()

	log.Printf("[sahand-agent] Starting lightweight agent (Role: %s) -> Hub: %s", *role, *hubAddr)

	// 1. Expose low-overhead ping responder for 5-sample RTT calibration bursts
	http.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		if *token != "" && r.Header.Get("X-Sahand-Token") != *token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"role":           *role,
			"timestamp_nano": time.Now().UTC().UnixNano(),
			"status":         "VERIFIED",
		})
	})

	go func() {
		log.Printf("[sahand-agent] Listening on %s for 5-ping sync calibration...", *listenPort)
		if err := http.ListenAndServe(*listenPort, nil); err != nil {
			log.Fatalf("[sahand-agent] Listener error: %v", err)
		}
	}()

	// 2. Continuous checkpoint heartbeat & entropy sampling loop
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var seq uint64 = 1
	for t := range ticker.C {
		seq++
		samplePayload := []byte(fmt.Sprintf("SAHAND-VERIFY-%s-SEQ-%d-%d", *role, seq, t.UnixNano()))
		cp := models.CP4_IranInternalIngress
		if *role == "remote" {
			cp = models.CP1_RemoteEdgeIngress
		}
		assessment := analyzer.EvaluateDPIRisk(cp, samplePayload, models.TLSMetadata{
			IsTLS: true,
			SNI:   "www.microsoft.com",
		})
		log.Printf("[sahand-agent] [%s] Checkpoint %d verified | Seq #%d | H(X)=%.3f | Risk=%s",
			*role, cp, seq, assessment.ShannonEntropy, assessment.Level)
	}
}
