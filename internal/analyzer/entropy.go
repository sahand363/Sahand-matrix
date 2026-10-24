package analyzer

import (
	"fmt"
	"math"
	"strings"

	"sahand-matrix/pkg/models"
)

func CalculateShannonEntropy(payload []byte) float64 {
	if len(payload) == 0 {
		return 0.0
	}
	var freq [256]int
	for _, b := range payload {
		freq[b]++
	}
	var entropy float64
	invLen := 1.0 / float64(len(payload))
	for _, count := range freq {
		if count > 0 {
			p := float64(count) * invLen
			entropy -= p * math.Log2(p)
		}
	}
	return math.Round(entropy*100) / 100
}

func FormatPythonByteLog(payload []byte, maxBytes int) string {
	if len(payload) > maxBytes {
		payload = payload[:maxBytes]
	}
	var sb strings.Builder
	sb.WriteString("[!] Raw Data: b'")
	for _, b := range payload {
		if b >= 32 && b <= 126 && b != '\'' && b != '\\' {
			sb.WriteByte(b)
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	sb.WriteString("'")
	return sb.String()
}

// InspectRealPayload detects TLS 1.2/1.3 records (0x14 ChangeCipherSpec, 0x16 Handshake, 0x17 AppData)
// or cleartext HTTP/SSH headers.
func InspectRealPayload(payload []byte) (proto string, tls models.TLSMetadata) {
	if len(payload) < 5 {
		return "TCP-SHORT", tls
	}
	b0, b1, b2 := payload[0], payload[1], payload[2]
	if (b0 == 0x14 || b0 == 0x15 || b0 == 0x16 || b0 == 0x17) && b1 == 0x03 && b2 <= 0x04 {
		tls.IsTLS = true
		tls.Version = fmt.Sprintf("0x03%02x", b2)
		switch b0 {
		case 0x16:
			tls.RecordType = "Handshake (0x16)"
			tls.SNI = extractSNIFromClientHello(payload)
			return "TLS-Handshake", tls
		case 0x14:
			tls.RecordType = "CipherSpec (0x14)"
			return "TLS-CipherSpec", tls
		default:
			tls.RecordType = "AppData (0x17)"
			return "TLSv1.3/WSS", tls
		}
	}
	head := string(payload[:min(len(payload), 32)])
	for _, m := range []string{"GET ", "POST ", "HTTP/1.", "CONNECT ", "HEAD "} {
		if strings.HasPrefix(head, m) {
			return "HTTP-CLEARTEXT", tls
		}
	}
	if strings.HasPrefix(head, "SSH-") {
		return "SSH-STREAM", tls
	}
	return "RAW-STREAM", tls
}

func extractSNIFromClientHello(b []byte) string {
	for i := 0; i+9 < len(b); i++ {
		if b[i] == 0x00 && b[i+1] == 0x00 && b[i+6] == 0x00 {
			nameLen := int(b[i+7])<<8 | int(b[i+8])
			if nameLen > 3 && nameLen < 120 && i+9+nameLen <= len(b) {
				candidate := string(b[i+9 : i+9+nameLen])
				if strings.Contains(candidate, ".") && isPrintableDomain(candidate) {
					return candidate
				}
			}
		}
	}
	return ""
}

func isPrintableDomain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func EvaluateDPIRisk(cp models.CheckpointID, payload []byte, tls models.TLSMetadata) models.DPIAssessment {
	entropy := CalculateShannonEntropy(payload)
	if cp == models.CP2_IranTunnelCore || cp == models.CP5_KharejDecrypted {
		return models.DPIAssessment{
			ShannonEntropy: entropy,
			StealthScore:   100,
			RiskScore:      0,
			Level:          models.RiskOptimal,
			ColorMeaning:   "🔵 BLUE LINE = Safe Internal Handoff (Invisible to External DPI)",
			Explanation:    "SAFE (Internal Server Handoff): Traffic inside server memory/tunnel core. Iran DPI cannot see this window.",
		}
	}

	if tls.IsTLS {
		if tls.SNI != "" {
			return models.DPIAssessment{
				ShannonEntropy: entropy,
				StealthScore:   82,
				RiskScore:      18,
				Level:          models.RiskWarning,
				ColorMeaning:   "🟡 AMBER LINE = TLS Handshake with Cleartext SNI (" + tls.SNI + ")",
				Explanation:    fmt.Sprintf("TLS HANDSHAKE: Valid TLS header (\\x16\\x03). Domain '%s' is visible to Iran DPI—safe if whitelisted.", tls.SNI),
			}
		}
		return models.DPIAssessment{
			ShannonEntropy: entropy,
			StealthScore:   94,
			RiskScore:      6,
			Level:          models.RiskOptimal,
			ColorMeaning:   "🔵 BLUE LINE = Safe Encrypted TLS Frame (\\x17\\x03\\x03)",
			Explanation:    fmt.Sprintf("SAFE FOR DPI (Blue): Wrapped inside valid TLS record (\\x17\\x03\\x03) with Entropy %.2f/8.00. Looks like standard HTTPS.", entropy),
		}
	}

	// Non-TLS external packet -> RED (Exposed)
	if entropy > 6.5 {
		return models.DPIAssessment{
			ShannonEntropy: entropy,
			StealthScore:   12,
			RiskScore:      88,
			Level:          models.RiskCritical,
			ColorMeaning:   "🔴 RED LINE = Unframed High-Entropy Stream (No \\x17\\x03\\x03 TLS Header!)",
			Triggers:       []string{"NO_TLS_HEADER", "RAW_CIPHERTEXT"},
			Explanation:    fmt.Sprintf("EXPOSED TO DPI (Red): High entropy (%.2f/8.00) WITHOUT a TLS header! Iran DPI detects raw encrypted tunnels or segmented TCP chunks here.", entropy),
		}
	}

	return models.DPIAssessment{
		ShannonEntropy: entropy,
		StealthScore:   5,
		RiskScore:      95,
		Level:          models.RiskCritical,
		ColorMeaning:   "🔴 RED LINE = Unencrypted Plaintext / Raw Control Bytes Exposed!",
		Triggers:       []string{"PLAINTEXT_EXPOSED"},
		Explanation:    fmt.Sprintf("CRITICAL LEAK (Red): Unencrypted/low-entropy raw data (H=%.2f) without TLS! Directly readable by Iran DPI.", entropy),
	}
}

func AllCheckpointGuides() []models.CheckpointGuide {
	return []models.CheckpointGuide{
		{
			ID:         models.CP1_IranClientIngress,
			Title:      "CP1: Iran Entry NIC (Client ➔ S1)",
			ServerRole: "iran",
			DPIVisible: true,
			DPIZone:    "🚨 CRITICAL: IRAN DOMESTIC DPI (TCI/MCI)",
			WhatYouSee: "Packets arriving at your Iran server from your PC/Phone in Iran.",
			GoodForDPI: "🔵 Blue lines: TLS 1.3 frames (\\x17\\x03\\x03) or safe domestic SNI.",
			BadForDPI:  "🔴 Red lines: Plaintext headers or raw high-entropy noise without TLS.",
		},
		{
			ID:         models.CP2_IranTunnelCore,
			Title:      "CP2: Iran Server Tunnel Core / Relay Handoff (Internal)",
			ServerRole: "iran",
			DPIVisible: false,
			DPIZone:    "🔒 INVISIBLE TO DPI (S1 Internal)",
			WhatYouSee: "Internal loopback & relay handoff inside S1 as your tunnel packages the stream.",
			GoodForDPI: "🔵 Blue lines: Internal proxy/tunnel frames inside S1 RAM.",
			BadForDPI:  "N/A — Isolated inside Iran server.",
		},
		{
			ID:         models.CP3_IranBorderEgress,
			Title:      "CP3: International Border Transit (S1 ➔ S2)",
			ServerRole: "iran",
			DPIVisible: true,
			DPIZone:    "🚨 CRITICAL: IRAN BORDER GATEWAY (GCI)",
			WhatYouSee: "Tunnel packets leaving your Iran server across the border to Kharej (S2).",
			GoodForDPI: "🔵 Blue lines: Valid TLS/WSS/Reality frames (\\x17\\x03\\x03).",
			BadForDPI:  "🔴 Red lines: Unmasked raw port-forwarding or plaintext sync strings.",
		},
		{
			ID:         models.CP4_KharejTransitIn,
			Title:      "CP4: Kharej Ingress NIC (S1 ➔ S2 Arrival)",
			ServerRole: "kharej",
			DPIVisible: true,
			DPIZone:    "👁 INT'L DATACENTER EDGE",
			WhatYouSee: "Tunnel packets arriving at your Kharej server's network card from Iran.",
			GoodForDPI: "🔵 Blue lines matching CP3's [TAG:xxxx] burst after +RTT/2 delay.",
			BadForDPI:  "🔴 Red lines or missing tags (indicates GCI border packet tampering).",
		},
		{
			ID:         models.CP5_KharejDecrypted,
			Title:      "CP5: Kharej Decryption Core (Internal)",
			ServerRole: "kharej",
			DPIVisible: false,
			DPIZone:    "🔒 INVISIBLE TO DPI (S2 Internal)",
			WhatYouSee: "Decrypted inner stream inside your Kharej server before heading to the web.",
			GoodForDPI: "🔵 Blue lines: Clean internal handoff.",
			BadForDPI:  "N/A — Inside foreign server memory.",
		},
		{
			ID:         models.CP6_KharejInternetOut,
			Title:      "CP6: Open Internet Egress (S2 ➔ YouTube/Telegram)",
			ServerRole: "kharej",
			DPIVisible: false,
			DPIZone:    "🌍 OPEN GLOBAL INTERNET",
			WhatYouSee: "Final outbound traffic from your Kharej server to YouTube, Telegram, or APIs.",
			GoodForDPI: "🔵 Blue lines: Standard HTTPS (Port 443) to global destinations.",
			BadForDPI:  "None — Safely outside Iran's national firewall.",
		},
	}
}
