package analyzer

import (
	"fmt"
	"math"
	"strings"

	"sahand-matrix/pkg/models"
)

// CalculateShannonEntropy computes 0.00 to 8.00 bits/byte randomness.
func CalculateShannonEntropy(payload []byte) float64 {
	length := len(payload)
	if length == 0 {
		return 0.0
	}
	var freq [256]int
	for _, b := range payload {
		freq[b]++
	}
	var entropy float64
	invLen := 1.0 / float64(length)
	for _, count := range freq {
		if count > 0 {
			p := float64(count) * invLen
			entropy -= p * math.Log2(p)
		}
	}
	return math.Round(entropy*100) / 100
}

// FormatPythonByteLog formats raw packet bytes like: [!] Raw Data: b'\x17\x03\x03\x00...'
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

// EvaluateDPIRisk scores what Iran DPI sees and writes a clear explanation.
func EvaluateDPIRisk(cp models.CheckpointID, payload []byte, tls models.TLSMetadata) models.DPIAssessment {
	entropy := CalculateShannonEntropy(payload)
	isInnerWindow := cp == models.CP2_RemoteDecrypted || cp == models.CP6_IranAppOutput

	// Checkpoints 2 & 6 are inside the server memory (Invisible to external DPI)
	if isInnerWindow {
		return models.DPIAssessment{
			ShannonEntropy: entropy,
			StealthScore:   100,
			RiskScore:      0,
			Level:          models.RiskOptimal,
			Explanation:    "SAFE (Internal Server Memory): Decrypted payload inside your server. Iran DPI has NO access to this window.",
		}
	}

	risk := 0
	var triggers []string
	var explanation string

	if !tls.IsTLS && entropy > 6.8 {
		risk += 85
		triggers = append(triggers, "UNMASKED_HIGH_ENTROPY", "NO_TLS_HANDSHAKE")
		explanation = "DANGER (Red Alert): Iran DPI sees high-entropy encrypted bytes (H=" +
			fmt.Sprintf("%.2f", entropy) + ") with NO TLS 1.3 header! Active probers will flag & block this IP/port."
	} else if !tls.IsTLS && entropy <= 6.8 {
		risk += 95
		triggers = append(triggers, "PLAINTEXT_HTTP_LEAK", "DPI_KEYWORD_MATCH")
		explanation = "CRITICAL LEAK: Unencrypted plaintext headers are passing across a public link! Iran DPI can directly read the HTTP/Host strings."
	} else if tls.IsTLS && tls.SNI == "blocked-proxy.org" {
		risk += 80
		triggers = append(triggers, "BLACKLISTED_SNI")
		explanation = "DANGER: TLS header is valid, but SNI (" + tls.SNI + ") is visible in cleartext and blacklisted by Iran DPI."
	} else if tls.IsTLS && tls.IsRealityMimicry {
		risk = 4
		explanation = "OPTIMAL STEALTH: Iran DPI sees a genuine TLS 1.3 record (\x17\x03\x03) with trusted SNI (" + tls.SNI + "). Indistinguishable from HTTPS."
	} else {
		risk = 12
		explanation = "GOOD STEALTH (WSS/TLS): Traffic is wrapped inside TLS 1.3 Application Data (\x17\x03\x03). DPI sees standard Web/CDN HTTPS frames."
	}

	stealth := 100 - risk
	if stealth < 0 {
		stealth = 0
	}

	level := models.RiskOptimal
	if risk >= 70 {
		level = models.RiskCritical
	} else if risk >= 35 {
		level = models.RiskWarning
	}

	return models.DPIAssessment{
		ShannonEntropy: entropy,
		StealthScore:   stealth,
		RiskScore:      risk,
		Level:          level,
		Triggers:       triggers,
		Explanation:    explanation,
	}
}
