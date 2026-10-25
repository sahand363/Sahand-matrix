package analyzer

import (
	"fmt"
	"math"

	"sahand-matrix/pkg/models"
)

// CalculateShannonEntropy computes Shannon entropy H(X) in bits per byte [0.00 - 8.00].
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	total := float64(len(data))
	var entropy float64
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / total
			entropy -= p * math.Log2(p)
		}
	}
	return math.Round(entropy*100) / 100
}

// EvaluateDPIRisk scores real packet payloads against network DPI heuristics.
func EvaluateDPIRisk(cp models.CheckpointID, payload []byte, tls models.TLSMetadata) models.DPIAssessment {
	h := CalculateShannonEntropy(payload)
	size := len(payload)

	// Internal loopback/core checkpoints (CP2 & CP5) are isolated inside server RAM.
	if cp == models.CP2_IranTunnelCore || cp == models.CP5_KharejDecrypted {
		return models.DPIAssessment{
			ShannonEntropy: h,
			StealthScore:   100,
			RiskScore:      0,
			Level:          models.RiskOptimal,
			ColorMeaning:   "🔵 BLUE LINE = Safe Internal Handoff (Invisible to External DPI)",
			Explanation:    "SAFE (Internal Server RAM): Traffic inside loopback/tunnel core. External ISP DPI cannot see this window.",
		}
	}

	// 1. Valid TLS 1.2 / 1.3 Framing (\x16\x03 or \x17\x03\x03)
	if tls.IsTLS {
		if tls.SNI != "" && isBlockedSNI(tls.SNI) {
			return models.DPIAssessment{
				ShannonEntropy: h,
				StealthScore:   15,
				RiskScore:      85,
				Level:          models.RiskCritical,
				ColorMeaning:   "🔴 RED LINE = Restricted SNI Exposed in ClientHello!",
				Explanation:    fmt.Sprintf("CRITICAL LEAK: Cleartext SNI '%s' is visible to deep packet inspection!", tls.SNI),
			}
		}
		score := 95
		if h >= 6.8 && h <= 7.95 {
			score = 98
		}
		return models.DPIAssessment{
			ShannonEntropy: h,
			StealthScore:   score,
			RiskScore:      0,
			Level:          models.RiskOptimal,
			ColorMeaning:   "🔵 BLUE LINE = Safe Encrypted TLS Frame (\\x17\\x03\\x03)",
			Explanation:    fmt.Sprintf("SAFE FOR DPI (Blue): Wrapped inside valid TLS record (\\x17\\x03\\x03) with Entropy %.2f/8.00. Looks like standard HTTPS.", h),
		}
	}

	// 2. Tiny TCP Multiplexer Keep-Alives / Control Ticks (<= 16 bytes)
	if size <= 16 {
		return models.DPIAssessment{
			ShannonEntropy: h,
			StealthScore:   75,
			RiskScore:      20,
			Level:          models.RiskWarning,
			ColorMeaning:   "🟡 YELLOW LINE = Tiny Tunnel Keep-Alive / Control Frame (<=16B)",
			Explanation:    fmt.Sprintf("LOW-VOLUME CONTROL (%dB, H=%.2f): Small multiplexer heartbeat or ACK tick. Normal in moderation.", size, h),
		}
	}

	// 3. Large High-Entropy TCP Continuation Chunks (MTU fragmented TLS records without header at byte 0)
	if size >= 256 && h >= 7.05 {
		return models.DPIAssessment{
			ShannonEntropy: h,
			StealthScore:   70,
			RiskScore:      25,
			Level:          models.RiskWarning,
			ColorMeaning:   "🟡 YELLOW LINE = High-Entropy TCP Continuation Segment (No TLS Header at Byte 0)",
			Explanation:    fmt.Sprintf("FRAGMENTED CIPHERTEXT (%dB, H=%.2f): TCP continuation segment of a larger TLS record or unframed stream.", size, h),
		}
	}

	// 4. Unframed High-Entropy Small/Medium Stream
	if h > 7.1 {
		return models.DPIAssessment{
			ShannonEntropy: h,
			StealthScore:   18,
			RiskScore:      80,
			Level:          models.RiskCritical,
			ColorMeaning:   "🔴 RED LINE = Unframed High-Entropy Stream (No \\x17\\x03\\x03 TLS Header!)",
			Explanation:    fmt.Sprintf("EXPOSED TO DPI (Red): High entropy (%.2f/8.00) WITHOUT a TLS header! Deep packet inspection flags unframed encrypted tunnels.", h),
		}
	}

	// 5. Unencrypted Plaintext or Low-Entropy Control Headers (> 16 bytes)
	return models.DPIAssessment{
		ShannonEntropy: h,
		StealthScore:   8,
		RiskScore:      95,
		Level:          models.RiskCritical,
		ColorMeaning:   "🔴 RED LINE = Unencrypted Plaintext / Raw Control Bytes Exposed!",
		Explanation:    fmt.Sprintf("CRITICAL LEAK (Red): Unencrypted/low-entropy raw data (%dB, H=%.2f) without TLS! Directly readable on the wire.", size, h),
	}
}

func isBlockedSNI(sni string) bool {
	blocked := []string{"youtube.com", "googlevideo.com", "t.me", "telegram.org", "twitter.com", "x.com", "facebook.com", "instagram.com"}
	for _, b := range blocked {
		if len(sni) >= len(b) && (sni == b || sni[len(sni)-len(b):] == b) {
			return true
		}
	}
	return false
}

// AllCheckpointGuides returns the 6 neutral checkpoint definitions (Main Server S1 & Server 2 S2).
func AllCheckpointGuides() []models.CheckpointGuide {
	return []models.CheckpointGuide{
		{
			ID: models.CP1_IranClientIngress, ServerRole: "iran",
			Title: "CP1: Main Server Ingress NIC (Client ➔ Main Server)", DPIZone: "🚨 ENTRY ISP DPI ZONE", DPIVisible: true,
			WhatYouSee: "Packets arriving at your Main Server from the client device.",
			GoodForDPI: "🔵 Blue lines: TLS 1.3 frames (\\x17\\x03\\x03) or clean SNI.",
			BadForDPI:  "🔴 Red lines: Plaintext headers or unframed high-entropy streams.",
		},
		{
			ID: models.CP2_IranTunnelCore, ServerRole: "iran",
			Title: "CP2: Main Server Tunnel Core (Internal Loopback)", DPIZone: "🔒 INVISIBLE TO DPI (Main Server RAM)", DPIVisible: false,
			WhatYouSee: "Internal loopback & relay handoff inside Main Server as your tunnel packages the stream.",
			GoodForDPI: "🔵 Blue lines: Internal proxy/tunnel frames inside Main Server RAM.",
			BadForDPI:  "N/A — Isolated inside Main Server memory.",
		},
		{
			ID: models.CP3_IranBorderEgress, ServerRole: "iran",
			Title: "CP3: Border Transit Egress (Main Server ➔ Server 2)", DPIZone: "🚨 CRITICAL: BORDER GATEWAY DPI", DPIVisible: true,
			WhatYouSee: "Tunnel packets leaving your Main Server toward Server 2.",
			GoodForDPI: "🔵 Blue lines: Valid TLS/WSS/Reality frames (\\x17\\x03\\x03) with high byte-weighted stealth.",
			BadForDPI:  "🔴 Red lines: Unmasked raw port-forwarding or plaintext sync strings.",
		},
		{
			ID: models.CP4_KharejTransitIn, ServerRole: "kharej",
			Title: "CP4: Server 2 Ingress NIC (Main Server ➔ Server 2 Arrival)", DPIZone: "👁 TRANSIT DATACENTER EDGE", DPIVisible: true,
			WhatYouSee: "Tunnel packets arriving at Server 2's network interface from Main Server.",
			GoodForDPI: "🔵 Blue lines matching CP3's [TAG:xxxx] burst after +RTT/2 delay.",
			BadForDPI:  "🔴 Red lines or missing tags (indicates border packet dropping/tampering).",
		},
		{
			ID: models.CP5_KharejDecrypted, ServerRole: "kharej",
			Title: "CP5: Server 2 Decryption Core (Internal Loopback)", DPIZone: "🔒 INVISIBLE TO DPI (Server 2 RAM)", DPIVisible: false,
			WhatYouSee: "Decrypted inner stream inside Server 2 before heading to target destination.",
			GoodForDPI: "🔵 Blue lines: Clean decrypted payloads inside Server 2 RAM.",
			BadForDPI:  "N/A — Isolated inside Server 2 memory.",
		},
		{
			ID: models.CP6_KharejInternetOut, ServerRole: "kharej",
			Title: "CP6: Open Internet Egress (Server 2 ➔ Target Web)", DPIZone: "🌐 PUBLIC INTERNET EGRESS", DPIVisible: false,
			WhatYouSee: "Final outbound traffic from Server 2 to destination websites (:443).",
			GoodForDPI: "🔵 Blue lines: Standard HTTPS (\\x17\\x03\\x03) to destination web servers.",
			BadForDPI:  "🔴 Red lines: Unencrypted HTTP (:80) visible to datacenter host.",
		},
	}
}
