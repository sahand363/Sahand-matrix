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

// InspectRealPayload parses actual captured TCP payload bytes for TLS headers, SNI, or HTTP leaks.
func InspectRealPayload(payload []byte) (proto string, tls models.TLSMetadata) {
	if len(payload) < 5 {
		return "TCP/RAW", tls
	}
	// Check real TLS framing: 0x16 (Handshake) or 0x17 (Application Data) followed by 0x03 0x01..0x04
	if (payload[0] == 0x16 || payload[0] == 0x17) && payload[1] == 0x03 && payload[2] <= 0x04 {
		tls.IsTLS = true
		tls.Version = fmt.Sprintf("0x03%02x", payload[2])
		if payload[0] == 0x16 {
			tls.RecordType = "TLS Handshake (0x16)"
			tls.SNI = extractSNIFromClientHello(payload)
			return "TLS-Handshake", tls
		}
		tls.RecordType = "TLS AppData (0x17)"
		return "TLSv1.3/WSS", tls
	}
	// Check for cleartext HTTP / WebSocket upgrade
	head := string(payload[:min(len(payload), 32)])
	for _, m := range []string{"GET ", "POST ", "HTTP/1.", "CONNECT ", "HEAD "} {
		if strings.HasPrefix(head, m) {
			return "HTTP-CLEARTEXT", tls
		}
	}
	if strings.HasPrefix(head, "SSH-") {
		return "SSH-TUNNEL", tls
	}
	return "RAW-BINARY", tls
}

func extractSNIFromClientHello(b []byte) string {
	// Lightweight scan for printable domain-like ASCII inside TLS ClientHello extension 0x0000
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
			Explanation:    "SAFE (Internal Server Loopback): Inside server memory. Iran DPI has zero visibility here.",
		}
	}

	risk := 0
	var triggers []string
	var explanation string

	if !tls.IsTLS && entropy > 6.7 {
		risk = 88
		triggers = append(triggers, "UNFRAMED_HIGH_ENTROPY", "NO_TLS_HEADER")
		explanation = fmt.Sprintf("DANGER (Red Alert): High entropy (%.2f/8.00) with NO TLS header (\\x17\\x03\\x03)! Iran DPI flags raw encrypted ports (Rathole/Raw-SS) via entropy & active probing.", entropy)
	} else if !tls.IsTLS && entropy <= 6.7 && len(payload) > 10 {
		risk = 95
		triggers = append(triggers, "CLEARTEXT_LEAK")
		explanation = "CRITICAL LEAK: Unencrypted plaintext bytes detected on an external interface! Iran DPI can read payload keywords directly."
	} else if tls.IsTLS && tls.SNI != "" {
		risk = 15
		explanation = fmt.Sprintf("TLS HANDSHAKE: Valid TLS header (\\x16\\x03\\x03). Cleartext SNI '%s' is visible to DPI—ensure this domain is whitelisted.", tls.SNI)
	} else {
		risk = 8
		explanation = fmt.Sprintf("OPTIMAL STEALTH: Valid TLS Application Data (\\x17\\x03\\x03) with H(X)=%.2f. Looks like standard HTTPS/WSS traffic to Iran DPI.", entropy)
	}

	level := models.RiskOptimal
	if risk >= 70 {
		level = models.RiskCritical
	} else if risk >= 35 {
		level = models.RiskWarning
	}
	return models.DPIAssessment{
		ShannonEntropy: entropy,
		StealthScore:   max(0, 100-risk),
		RiskScore:      risk,
		Level:          level,
		Triggers:       triggers,
		Explanation:    explanation,
	}
}

func AllCheckpointGuides() []models.CheckpointGuide {
	return []models.CheckpointGuide{
		{
			ID:          models.CP1_IranClientIngress,
			Title:       "CP1: Iran Entry NIC (Client ➔ S1)",
			ServerRole:  "iran",
			DPIVisible:  true,
			DPIZone:     "🚨 CRITICAL: IRAN DOMESTIC DPI (TCI/MCI)",
			WhatYouSee:  "Raw packets arriving at your Iran server from your PC/Phone in Iran.",
			GoodForDPI:  "TLS 1.3 frames (\\x17\\x03\\x03) or whitelisted domestic SNI.",
			BadForDPI:   "Unencrypted HTTP headers, blocked foreign SNIs, or raw high-entropy noise.",
		},
		{
			ID:          models.CP2_IranTunnelCore,
			Title:       "CP2: Iran Server Tunnel Core (Internal)",
			ServerRole:  "iran",
			DPIVisible:  false,
			DPIZone:     "🔒 INVISIBLE TO DPI (S1 Internal)",
			WhatYouSee:  "Local loopback traffic inside S1 as X-UI / Rathole / WSS packages your stream.",
			GoodForDPI:  "Any internal proxy framing is safe here because DPI cannot see inside S1.",
			BadForDPI:   "N/A — Completely isolated inside Iran server RAM.",
		},
		{
			ID:          models.CP3_IranBorderEgress,
			Title:       "CP3: International Border Transit (S1 ➔ S2)",
			ServerRole:  "iran",
			DPIVisible:  true,
			DPIZone:     "🚨 CRITICAL: IRAN BORDER GATEWAY (GCI)",
			WhatYouSee:  "Tunnel packets leaving your Iran server across the border to your Kharej server.",
			GoodForDPI:  "WSS/Reality/TLS framing (\\x17\\x03\\x03) with normal packet-size distribution.",
			BadForDPI:   "Raw unmasked port-forwarding or high-entropy streams without TLS headers.",
		},
		{
			ID:          models.CP4_KharejTransitIn,
			Title:       "CP4: Kharej Ingress NIC (S1 ➔ S2 Arrival)",
			ServerRole:  "kharej",
			DPIVisible:  true,
			DPIZone:     "👁 INT'L DATACENTER EDGE",
			WhatYouSee:  "Tunnel packets arriving at your Kharej server's network card from Iran.",
			GoodForDPI:  "Should match CP3 byte-for-byte (delayed by RTT/2 transit time).",
			BadForDPI:   "Missing packets or altered TCP payloads (indicates GCI border tampering).",
		},
		{
			ID:          models.CP5_KharejDecrypted,
			Title:       "CP5: Kharej Decryption Core (Internal)",
			ServerRole:  "kharej",
			DPIVisible:  false,
			DPIZone:     "🔒 INVISIBLE TO DPI (S2 Internal)",
			WhatYouSee:  "Unwrapped inner request inside your Kharej server before heading to the web.",
			GoodForDPI:  "Clean decrypted streams ready for outbound routing.",
			BadForDPI:   "N/A — Inside foreign server memory.",
		},
		{
			ID:          models.CP6_KharejInternetOut,
			Title:       "CP6: Open Internet Egress (S2 ➔ YouTube/Telegram)",
			ServerRole:  "kharej",
			DPIVisible:  false,
			DPIZone:     "🌍 OPEN GLOBAL INTERNET",
			WhatYouSee:  "Final outbound traffic from your Kharej server to YouTube, Telegram, or APIs.",
			GoodForDPI:  "Standard HTTPS/TLS (Port 443) to destination services.",
			BadForDPI:   "None — Safely outside Iran's national firewall.",
		},
	}
}
