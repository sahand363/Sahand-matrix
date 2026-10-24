package hub

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PingBurstReport holds the 5 real RTT measurements between S1 (Iran) and S2 (Kharej).
type PingBurstReport struct {
	TargetHost  string        `json:"target_host"`
	SamplesMs   [5]float64    `json:"samples_ms"`
	AverageMs   float64       `json:"average_ms"`
	OffsetMs    float64       `json:"offset_ms"` // AverageMs / 2
	JitterMs    float64       `json:"jitter_ms"`
	UsedCached  bool          `json:"used_cached"`
	MeasuredAt  time.Time     `json:"measured_at"`
	ExpiresAt   time.Time     `json:"expires_at"`
}

type SyncEngine struct {
	mu          sync.RWMutex
	cachedBurst map[string]PingBurstReport // keyed by TargetHost
	httpClient  *http.Client
}

func NewSyncEngine(_ int) *SyncEngine {
	return &SyncEngine{
		cachedBurst: make(map[string]PingBurstReport),
		httpClient: &http.Client{
			Timeout: 2500 * time.Millisecond,
		},
	}
}

// GetOrMeasure5Pings returns the cached 5-ping report if measured within the last 1 hour,
// or executes 5 live network probes against targetHost (IP:Port) if expired or force==true.
func (s *SyncEngine) GetOrMeasure5Pings(targetHost string, token string, force bool) PingBurstReport {
	targetHost = strings.TrimSpace(targetHost)
	if targetHost == "" {
		targetHost = "127.0.0.1:9444"
	}

	s.mu.RLock()
	cached, exists := s.cachedBurst[targetHost]
	s.mu.RUnlock()

	if !force && exists && time.Now().UTC().Before(cached.ExpiresAt) {
		cached.UsedCached = true
		return cached
	}

	var samples [5]float64
	var sum float64
	validCount := 0

	for i := 0; i < 5; i++ {
		rttMs := s.probeSingleRTT(targetHost, token)
		samples[i] = math.Round(rttMs*100) / 100
		if rttMs > 0 {
			sum += samples[i]
			validCount++
		}
		time.Sleep(35 * time.Millisecond)
	}

	avgMs := 0.0
	if validCount > 0 {
		avgMs = math.Round((sum/float64(validCount))*100) / 100
	}

	var varianceSum float64
	for _, v := range samples {
		if v > 0 {
			diff := v - avgMs
			varianceSum += diff * diff
		}
	}
	jitter := 0.0
	if validCount > 0 {
		jitter = math.Round(math.Sqrt(varianceSum/float64(validCount))*100) / 100
	}

	now := time.Now().UTC()
	report := PingBurstReport{
		TargetHost: targetHost,
		SamplesMs:  samples,
		AverageMs:  avgMs,
		OffsetMs:   math.Round((avgMs/2.0)*100) / 100,
		JitterMs:   jitter,
		UsedCached: false,
		MeasuredAt: now,
		ExpiresAt:  now.Add(1 * time.Hour),
	}

	s.mu.Lock()
	s.cachedBurst[targetHost] = report
	s.mu.Unlock()

	return report
}

func (s *SyncEngine) probeSingleRTT(hostPort, token string) float64 {
	if !strings.Contains(hostPort, ":") {
		hostPort = hostPort + ":9444"
	}
	start := time.Now()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/api/ping", hostPort), nil)
	if err == nil {
		if token != "" {
			req.Header.Set("X-Sahand-Token", token)
		}
		resp, err := s.httpClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return float64(time.Since(start).Microseconds()) / 1000.0
		}
	}

	// Fallback to raw TCP handshake RTT if HTTP endpoint isn't reachable yet
	startTCP := time.Now()
	conn, err := net.DialTimeout("tcp", hostPort, 2*time.Second)
	if err != nil {
		return 0.0
	}
	_ = conn.Close()
	return float64(time.Since(startTCP).Microseconds()) / 1000.0
}
