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

// EvaluateDPIRisk scores real packet payloads against Iran DPI heuristics (TCI/MCI/GCI).
func EvaluateDPIRisk(cp models.CheckpointID, payload []byte, tls models.TLSMetadata) models.DPIVerdict {
	h := CalculateShannonEntropy(payload)
	size := len(payload)

	// Internal loopback/core checkpoints (CP2 & CP5) are isolated inside server RAM.
	if cp == models.CP2_IranTunnelCore || cp == models.CP5_KharejDecrypted {
		return models.DPIVerdict{
			ShannonEntropy: h,
			StealthScore:   100,
			Level:          models.RiskOptimal,
			ColorMeaning:   "🔵 BLUE LINE = Safe Internal Handoff (Invisible to External DPI)",
			Explanation:    "SAFE (Internal Server RAM): Traffic inside loopback/tunnel core. External ISP DPI cannot see this window.",
		}
	}

	// 1. Valid TLS 1.2 / 1.3 Framing (\x16\x03 or \x17\x03\x03)
	if tls.IsTLS {
		if tls.SNI != "" && isBlockedSNI(tls.SNI) {
			return models.DPIVerdict{
				ShannonEntropy: h,
				StealthScore:   15,
				Level:          models.RiskCritical,
				ColorMeaning:   "🔴 RED LINE = Filtered SNI Exposed in ClientHello!",
				Explanation:    fmt.Sprintf("CRITICAL LEAK: Cleartext SNI '%s' is visible to DPI inspection!", tls.SNI),
			}
		}
		score := 95
		if h >= 6.8 && h <= 7.95 {
			score = 98
		}
		return models.DPIVerdict{
			ShannonEntropy: h,
			StealthScore:   score,
			Level:          models.RiskOptimal,
			ColorMeaning:   "🔵 BLUE LINE = Safe Encrypted TLS Frame (\\x17\\x03\\x03)",
			Explanation:    fmt.Sprintf("SAFE FOR DPI (Blue): Wrapped inside valid TLS record (\\x17\\x03\\x03) with Entropy %.2f/8.00. Looks like standard HTTPS.", h),
		}
	}

	// 2. Tiny TCP Multiplexer Keep-Alives / Control Ticks (<= 16 bytes)
	// Firewalls expect occasional small keep-alive/window control frames; mark as mild warning instead of critical leak.
	if size <= 16 {
		return models.DPIVerdict{
			ShannonEntropy: h,
			StealthScore:   72,
			Level:          models.RiskWarning,
			ColorMeaning:   "🟡 YELLOW LINE = Tiny Tunnel Keep-Alive / Control Frame (<=16B)",
			Explanation:    fmt.Sprintf("LOW-VOLUME CONTROL (%dB, H=%.2f): Small multiplexer heartbeat or ACK data. Normal in moderation, avoid high-frequency bursts.", size, h),
		}
	}

	// 3. Large High-Entropy TCP Continuation Chunks (MTU fragmented TLS records without header in segment 2+)
	if size >= 256 && h >= 7.05 {
		return models.DPIVerdict{
			ShannonEntropy: h,
			StealthScore:   68,
			Level:          models.RiskWarning,
			ColorMeaning:   "🟡 YELLOW LINE = High-Entropy TCP Continuation Segment (No TLS Header at Byte 0)",
			Explanation:    fmt.Sprintf("FRAGMENTED CIPHERTEXT (%dB, H=%.2f): Likely a TCP continuation chunk of a larger TLS record, or unframed encrypted stream.", size, h),
		}
	}

	// 4. Unframed High-Entropy Small/Medium Stream (Raw Shadowsocks / V2Ray without TLS)
	if h > 7.1 {
		return models.DPIVerdict{
			ShannonEntropy: h,
			StealthScore:   18,
			Level:          models.RiskCritical,
			ColorMeaning:   "🔴 RED LINE = Unframed High-Entropy Stream (No \\x17\\x03\\x03 TLS Header!)",
			Explanation:    fmt.Sprintf("EXPOSED TO DPI (Red): High entropy (%.2f/8.00) WITHOUT a TLS header! DPI detects raw encrypted tunnels here.", h),
		}
	}

	// 5. Unencrypted Plaintext or Low-Entropy Control Headers (> 16 bytes)
	return models.DPIVerdict{
		ShannonEntropy: h,
		StealthScore:   8,
		Level:          models.RiskCritical,
		ColorMeaning:   "🔴 RED LINE = Unencrypted Plaintext / Raw Control Bytes Exposed!",
		Explanation:    fmt.Sprintf("CRITICAL LEAK (Red): Unencrypted/low-entropy raw data (%dB, H=%.2f) without TLS! Directly readable by DPI.", size, h),
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

// AllCheckpointGuides returns the 6 educational checkpoint definitions.
func AllCheckpointGuides() []models.CheckpointGuide {
	return []models.CheckpointGuide{
		{
			ID: models.CP1_IranClientIngress, ServerRole: "iran",
			Title: "CP1: Entry NIC (Client ➔ S1)", DPIZone: "🚨 CRITICAL: DOMESTIC ISP DPI", DPIVisible: true,
			WhatYouSee: "Packets arriving at your entry server from your client device.",
			GoodForDPI: "🔵 Blue lines: TLS 1.3 frames (\\x17\\x03\\x03) or safe domestic SNI.",
			BadForDPI:  "🔴 Red lines: Plaintext headers or unframed high-entropy streams.",
		},
		{
			ID: models.CP2_IranTunnelCore, ServerRole: "iran",
			Title: "CP2: Entry Server Tunnel Core (Internal)", DPIZone: "🔒 INVISIBLE TO DPI (S1 Internal)", DPIVisible: false,
			WhatYouSee: "Internal loopback & relay handoff inside S1 as your tunnel packages the stream.",
			GoodForDPI: "🔵 Blue lines: Internal proxy/tunnel frames inside S1 RAM.",
			BadForDPI:  "N/A — Isolated inside S1 server memory.",
		},
		{
			ID: models.CP3_IranBorderEgress, ServerRole: "iran",
			Title: "CP3: International Border Transit (S1 ➔ S2)", DPIZone: "🚨 CRITICAL: BORDER GATEWAY (GCI)", DPIVisible: true,
			WhatYouSee: "Tunnel packets leaving your entry server across the international border to S2.",
			GoodForDPI: "🔵 Blue lines: Valid TLS/WSS/Reality frames (\\x17\\x03\\x03) with high byte-weighted stealth.",
			BadForDPI:  "🔴 Red lines: Unmasked raw port-forwarding or plaintext sync strings.",
		},
		{
			ID: models.CP4_KharejTransitIn, ServerRole: "kharej",
			Title: "CP4: Foreign Ingress NIC (S1 ➔ S2 Arrival)", DPIZone: "👁 INT'L DATACENTER EDGE", DPIVisible: true,
			WhatYouSee: "Tunnel packets arriving at your foreign server's network card from S1.",
			GoodForDPI: "🔵 Blue lines matching CP3's [TAG:xxxx] burst after +RTT/2 delay.",
			BadForDPI:  "🔴 Red lines or missing tags (indicates border packet dropping/tampering).",
		},
		{
			ID: models.CP5_KharejDecrypted, ServerRole: "kharej",
			Title: "CP5: Foreign Decryption Core (Internal)", DPIZone: "🔒 INVISIBLE TO DPI (S2 Internal)", DPIVisible: false,
			WhatYouSee: "Decrypted inner stream inside your foreign server before heading to the web.",
			GoodForDPI: "🔵 Blue lines: Clean decrypted payloads inside S2 RAM.",
			BadForDPI:  "N/A — Inside foreign server memory.",
		},
		{
			ID: models.CP6_KharejInternetOut, ServerRole: "kharej",
			Title: "CP6: Open Internet Egress (S2 ➔ Target Web)", DPIZone: "🌐 PUBLIC INTERNET TARGET", DPIVisible: false,
			WhatYouSee: "Final outbound traffic from your foreign server to destination websites (:443).",
			GoodForDPI: "🔵 Blue lines: Standard HTTPS (\\x17\\x03\\x03) to destination web servers.",
			BadForDPI:  "🔴 Red lines: Unencrypted HTTP (:80) visible to datacenter host.",
		},
	}
}
