package models

import (
	"time"
)

// CheckpointID strictly defines the 6 logical observation stages.
type CheckpointID uint8

const (
	CP1_RemoteEdgeIngress   CheckpointID = 1 // Raw NIC arrival on Remote Server (Pre-decryption)
	CP2_RemoteDecrypted     CheckpointID = 2 // Post-X-UI/Reality core decryption on Remote Server
	CP3_InternationalFlight CheckpointID = 3 // In-flight transit envelope between Remote & Iran
	CP4_IranInternalIngress CheckpointID = 4 // Raw arrival at Iran Server interface
	CP5_IranEgressEdge      CheckpointID = 5 // Outbound domestic interface (Leak/DPI inspection point)
	CP6_IranAppOutput       CheckpointID = 6 // Final payload delivered to local target service
)

// RiskLevel mirrors the visual status indicators (Green, Orange, Red) from the UI design.
type RiskLevel string

const (
	RiskOptimal  RiskLevel = "OPTIMAL"  // Emerald Green (#10B981)
	RiskWarning  RiskLevel = "WARNING"  // Amber Orange (#F59E0B)
	RiskCritical RiskLevel = "CRITICAL" // Crimson Red (#EF4444)
)

// TLSMetadata stores unencrypted handshake artifacts visible to passive DPI.
type TLSMetadata struct {
	IsTLS            bool     `json:"is_tls"`
	Version          uint16   `json:"version"`
	SNI              string   `json:"sni,omitempty"`
	ALPN             []string `json:"alpn,omitempty"`
	JA3Hash          string   `json:"ja3_hash,omitempty"`
	IsRealityMimicry bool     `json:"is_reality_mimicry"`
}

// DPIAssessment holds the calculated vulnerability metrics for a single packet or burst.
type DPIAssessment struct {
	ShannonEntropy float64   `json:"shannon_entropy"` // 0.000 to 8.000 bits/byte
	RiskScore      int       `json:"risk_score"`      // 0 to 100
	Level          RiskLevel `json:"level"`
	Triggers       []string  `json:"triggers,omitempty"` // e.g., ["HIGH_ENTROPY_NON_TLS", "SNI_MISMATCH"]
}

// PacketEvent is the fundamental unit streamed from Agents to the Hub.
type PacketEvent struct {
	FlowID        string        `json:"flow_id"`        // Deterministic hash or 5-tuple + correlation tag
	SequenceNum   uint64        `json:"sequence_num"`   // Logical packet order within the flow
	Checkpoint    CheckpointID  `json:"checkpoint"`     // 1 through 6
	TimestampNano int64         `json:"timestamp_nano"` // Local capture monotonic-adjusted UTC timestamp
	LogicalTime   time.Time     `json:"logical_time"`   // Normalized by Hub using (Ping / 2) offset
	Length        uint32        `json:"length"`
	Protocol      string        `json:"protocol"`       // TCP, UDP, TLSv1.3, VLESS, etc.
	PayloadSample []byte        `json:"payload_sample"` // First N bytes for hex/ASCII TUI inspection
	TLS           TLSMetadata   `json:"tls"`
	DPI           DPIAssessment `json:"dpi"`
}
