package hub

import (
	"sync"
	"time"
	"sahand-matrix/pkg/models"
)

type NodeClockOffset struct {
	NodeID     string
	RTT        time.Duration // Continuously measured via Hub <-> Agent heartbeat
	OneWayLag  time.Duration // RTT / 2
	ClockDrift time.Duration // NTP/Cristian's algorithm delta relative to Hub
}

type SyncEngine struct {
	mu           sync.RWMutex
	isPaused     bool
	freezeAnchor time.Time
	offsets      map[string]NodeClockOffset
	ringBuffers  map[models.CheckpointID][]models.PacketEvent
	bufferLimit  int
}

func NewSyncEngine(bufferLimit int) *SyncEngine {
	return &SyncEngine{
		offsets:     make(map[string]NodeClockOffset),
		ringBuffers: make(map[models.CheckpointID][]models.PacketEvent),
		bufferLimit: bufferLimit,
	}
}

// UpdateNodeLatency recalculates the one-way transit delay (Ping / 2) between nodes.
func (s *SyncEngine) UpdateNodeLatency(nodeID string, rtt time.Duration, drift time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offsets[nodeID] = NodeClockOffset{
		NodeID:     nodeID,
		RTT:        rtt,
		OneWayLag:  rtt / 2,
		ClockDrift: drift,
	}
}

// TriggerSmartPause freezes all 6 windows aligned to the exact logical packet transit time.
// For downstream checkpoints (CP4-CP6 on Iran Server), it waits or slices the buffer at
// FreezeTime + OneWayTransitDelay so the exact same packet aligns across all 6 panes.
func (s *SyncEngine) TriggerSmartPause(interNodeRTT time.Duration) map[models.CheckpointID][]models.PacketEvent {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.isPaused = true
	s.freezeAnchor = time.Now().UTC()
	transitOffset := interNodeRTT / 2

	alignedSnapshot := make(map[models.CheckpointID][]models.PacketEvent)

	for cp, events := range s.ringBuffers {
		var cutoff time.Time
		switch cp {
		case models.CP1_RemoteEdgeIngress, models.CP2_RemoteDecrypted:
			// Origin server: freeze at base anchor T_0
			cutoff = s.freezeAnchor
		case models.CP3_InternationalFlight:
			// Mid-flight transit: freeze at T_0 + (RTT / 4)
			cutoff = s.freezeAnchor.Add(transitOffset / 2)
		case models.CP4_IranInternalIngress, models.CP5_IranEgressEdge, models.CP6_IranAppOutput:
			// Destination server: offset by (RTT / 2) so the in-flight packet has arrived
			cutoff = s.freezeAnchor.Add(transitOffset)
		}

		var windowSlice []models.PacketEvent
		for _, ev := range events {
			if !ev.LogicalTime.After(cutoff) {
				windowSlice = append(windowSlice, ev)
			}
		}
		alignedSnapshot[cp] = windowSlice
	}

	return alignedSnapshot
}
