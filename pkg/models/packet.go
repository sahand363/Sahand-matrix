package models

import "time"

type CheckpointID uint8

const (
	CP1_RemoteEdgeIngress   CheckpointID = 1 // Remote Server NIC (Visible to Int'l Edge DPI)
	CP2_RemoteDecrypted     CheckpointID = 2 // Remote Server Core (Invisible - Inside Server)
	CP3_InternationalFlight CheckpointID = 3 // Cross-Border Transit (Visible to Transit/GCI DPI)
	CP4_IranInternalIngress CheckpointID = 4 // Iran Server Arrival (Visible to Domestic Ingress DPI)
	CP5_IranEgressEdge      CheckpointID = 5 // Iran Server Domestic NIC (CRITICAL: Iran Domestic DPI)
	CP6_IranAppOutput       CheckpointID = 6 // Final App Payload (Invisible - Inside Server)
)

type RiskLevel string

const (
	RiskOptimal  RiskLevel = "OPTIMAL"  // Green: Safe
	RiskWarning  RiskLevel = "WARNING"  // Amber: Suspicious
	RiskCritical RiskLevel = "CRITICAL" // Red: Blocked by DPI
)

type TunnelType string

const (
	TunnelWSS         TunnelType = "wss"         // VMess/VLESS over WSS (WS + TLS 1.3)
	TunnelReality     TunnelType = "reality"     // VLESS + XTLS-Reality
	TunnelShadowsocks TunnelType = "shadowsocks" // Shadowsocks-2022 AEAD
	TunnelGRPC        TunnelType = "grpc"        // HTTP/2 gRPC + TLS
	TunnelRawTCP      TunnelType = "raw_tcp"     // Unmasked Raw TCP (Triggers Red DPI Alert)
)

type TLSMetadata struct {
	IsTLS            bool     `json:"is_tls"`
	Version          uint16   `json:"version"`
	SNI              string   `json:"sni,omitempty"`
	ALPN             []string `json:"alpn,omitempty"`
	JA3Hash          string   `json:"ja3_hash,omitempty"`
	IsRealityMimicry bool     `json:"is_reality_mimicry"`
}

type DPIAssessment struct {
	ShannonEntropy float64   `json:"shannon_entropy"` // 0.00 to 8.00 bits/byte
	StealthScore   int       `json:"stealth_score"`   // 0% to 100% stealth
	RiskScore      int       `json:"risk_score"`      // 0 to 100 danger
	Level          RiskLevel `json:"level"`
	Triggers       []string  `json:"triggers,omitempty"`
	Explanation    string    `json:"explanation"` // Plain-English explanation of what DPI sees
}

type PacketEvent struct {
	FlowID        string        `json:"flow_id"`
	SequenceNum   uint64        `json:"sequence_num"`
	Checkpoint    CheckpointID  `json:"checkpoint"`
	CheckpointTitle string      `json:"checkpoint_title"`
	NodeName      string        `json:"node_name"`
	DPIVisible    bool          `json:"dpi_visible"` // True if DPI has physical access here
	DPIZone       string        `json:"dpi_zone"`    // e.g. "IRAN DOMESTIC DPI (TCI/MCI)"
	TimestampNano int64         `json:"timestamp_nano"`
	LogicalTime   time.Time     `json:"logical_time"`
	OffsetMs      float64       `json:"offset_ms"`
	Length        uint32        `json:"length"`
	Protocol      string        `json:"protocol"`
	PayloadSample []byte        `json:"payload_sample"`
	RawByteLog    string        `json:"raw_byte_log"` // e.g. "[!] Raw Data: b'\x17\x03\x03...'"
	TLS           TLSMetadata   `json:"tls"`
	DPI           DPIAssessment `json:"dpi"`
}
