package models

import "time"

type CheckpointID uint8

const (
	CP1_IranClientIngress CheckpointID = 1
	CP2_IranTunnelCore    CheckpointID = 2
	CP3_IranBorderEgress  CheckpointID = 3
	CP4_KharejTransitIn   CheckpointID = 4
	CP5_KharejDecrypted   CheckpointID = 5
	CP6_KharejInternetOut CheckpointID = 6
)

type RiskLevel string

const (
	RiskOptimal  RiskLevel = "OPTIMAL"
	RiskWarning  RiskLevel = "WARNING"
	RiskCritical RiskLevel = "CRITICAL"
)

type TLSMetadata struct {
	IsTLS      bool   `json:"is_tls"`
	RecordType string `json:"record_type,omitempty"`
	Version    string `json:"version,omitempty"`
	SNI        string `json:"sni,omitempty"`
}

type DPIAssessment struct {
	ShannonEntropy float64   `json:"shannon_entropy"`
	StealthScore   int       `json:"stealth_score"`
	RiskScore      int       `json:"risk_score"`
	Level          RiskLevel `json:"level"`
	ColorMeaning   string    `json:"color_meaning"`
	Triggers       []string  `json:"triggers,omitempty"`
	Explanation    string    `json:"explanation"`
}

type CheckpointGuide struct {
	ID         CheckpointID `json:"id"`
	Title      string       `json:"title"`
	ServerRole string       `json:"server_role"`
	DPIVisible bool         `json:"dpi_visible"`
	DPIZone    string       `json:"dpi_zone"`
	WhatYouSee string       `json:"what_you_see"`
	GoodForDPI string       `json:"good_for_dpi"`
	BadForDPI  string       `json:"bad_for_dpi"`
}

type PacketEvent struct {
	SequenceNum    uint64        `json:"sequence_num"`
	CorrelationTag string        `json:"correlation_tag"`
	Checkpoint     CheckpointID  `json:"checkpoint"`
	ServerID       string        `json:"server_id"`
	TimestampNano  int64         `json:"timestamp_nano"`
	LogicalTime    time.Time     `json:"logical_time"`
	TimeStr        string        `json:"time_str"`
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
	Role        string    `json:"role"`
	Host        string    `json:"host"`
	SSHPort     int       `json:"ssh_port"`
	SSHUser     string    `json:"ssh_user"`
	AgentPort   int       `json:"agent_port"`
	Connected   bool      `json:"connected"`
	Capturing   bool      `json:"capturing"`
	DeployState string    `json:"deploy_state"`
	DeployPct   int       `json:"deploy_pct"`
	DeployLogs  []string  `json:"deploy_logs"`
	UpdatedAt   time.Time `json:"updated_at"`
}
