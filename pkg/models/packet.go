package models

import "time"

type CheckpointID uint8

const (
	// S1: IRAN SERVER (Checkpoints 1, 2, 3)
	CP1_IranClientIngress CheckpointID = 1 // CRITICAL: Client (Iran) -> Iran Server NIC (Domestic ISP DPI)
	CP2_IranTunnelCore    CheckpointID = 2 // Internal: Inside Iran Server (Tunnel Encapsulation / Handoff)
	CP3_IranBorderEgress  CheckpointID = 3 // CRITICAL: Iran Server -> Kharej Transit (Border GCI DPI)

	// S2: KHAREJ SERVER (Checkpoints 4, 5, 6)
	CP4_KharejTransitIn   CheckpointID = 4 // Kharej NIC Arrival from Iran Server
	CP5_KharejDecrypted   CheckpointID = 5 // Internal: Inside Kharej Server (X-UI/Core Decryption)
	CP6_KharejInternetOut CheckpointID = 6 // Kharej Egress -> Open Internet (YouTube / Telegram)
)

type RiskLevel string

const (
	RiskOptimal  RiskLevel = "OPTIMAL"  // Cyan/Blue: Safe TLS/Encrypted framing
	RiskWarning  RiskLevel = "WARNING"  // Amber: Noticeable anomaly or visible SNI
	RiskCritical RiskLevel = "CRITICAL" // Red: Exposed Plaintext or Unframed High-Entropy
)

type TLSMetadata struct {
	IsTLS      bool   `json:"is_tls"`
	RecordType string `json:"record_type,omitempty"`
	Version    string `json:"version,omitempty"`
	SNI        string `json:"sni,omitempty"`
}

type DPIAssessment struct {
	ShannonEntropy float64   `json:"shannon_entropy"` // 0.00 to 8.00 bits/byte
	StealthScore   int       `json:"stealth_score"`   // 0% to 100%
	RiskScore      int       `json:"risk_score"`      // 0 to 100
	Level          RiskLevel `json:"level"`
	ColorMeaning   string    `json:"color_meaning"` // Exact explanation of why this packet is Blue/Amber/Red
	Triggers       []string  `json:"triggers,omitempty"`
	Explanation    string    `json:"explanation"`
}

type CheckpointGuide struct {
	ID         CheckpointID `json:"id"`
	Title      string       `json:"title"`
	ServerRole string       `json:"server_role"` // "iran" (S1) or "kharej" (S2)
	DPIVisible bool         `json:"dpi_visible"`
	DPIZone    string       `json:"dpi_zone"`
	WhatYouSee string       `json:"what_you_see"`
	GoodForDPI string       `json:"good_for_dpi"`
	BadForDPI  string       `json:"bad_for_dpi"`
}

type PacketEvent struct {
	SequenceNum    uint64        `json:"sequence_num"`
	CorrelationTag string        `json:"correlation_tag"` // Time+Size fingerprint to trace across windows
	Checkpoint     CheckpointID  `json:"checkpoint"`
	ServerID       string        `json:"server_id"`
	TimestampNano  int64         `json:"timestamp_nano"`
	LogicalTime    time.Time     `json:"logical_time"`
	TimeStr        string        `json:"time_str"` // HH:MM:SS.mmm for visual cross-window matching
	OffsetMs       float64       `json:"offset_ms"`
	SrcAddr        string        `json:"src_addr"`
	DstAddr        string        `json:"dst_addr"`
	Length         uint32        `json:"length"`
	Protocol       string        `json:"protocol"`
	RawByteLog     string        `json:"raw_byte_log"`
	TLS            TLSMetadata   `json:"tls"`
	DPI            DPIAssessment `json:"dpi"`
}

type ServerNode struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Role        string    `json:"role"` // "iran" (S1) or "kharej" (S2)
	Host        string    `json:"host"`
	SSHPort     int       `json:"ssh_port"`
	SSHUser     string    `json:"ssh_user"`
	AgentPort   int       `json:"agent_port"`
	Connected   bool      `json:"connected"`
	Capturing   bool      `json:"capturing"`
	DeployState string    `json:"deploy_state"` // "READY", "DEPLOYING", "ERROR"
	DeployPct   int       `json:"deploy_pct"`
	DeployLogs  []string  `json:"deploy_logs"`
	UpdatedAt   time.Time `json:"updated_at"`
}
