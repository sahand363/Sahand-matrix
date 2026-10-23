package analyzer

import (
	"math"
	"sahand-matrix/pkg/models"
)

// CalculateShannonEntropy computes the bits-per-byte entropy (0.0 to 8.0) of a packet payload.
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

	return math.Round(entropy*1000) / 1000
}

// EvaluateDPIRisk scores a packet based on checkpoint context, entropy, and TLS visibility.
func EvaluateDPIRisk(cp models.CheckpointID, payload []byte, tls models.TLSMetadata) models.DPIAssessment {
	entropy := CalculateShannonEntropy(payload)
	score := 0
	var triggers []string

	// Rule 1: High entropy on exterior transit checkpoints without valid TLS framing
	if (cp == models.CP1_RemoteEdgeIngress || cp == models.CP3_InternationalFlight || cp == models.CP5_IranEgressEdge) &&
		entropy > 7.1 && !tls.IsTLS {
		score += 65
		triggers = append(triggers, "UNFRAMED_HIGH_ENTROPY")
	}

	// Rule 2: Plaintext leak on domestic egress when tunnel encapsulation is expected
	if cp == models.CP3_InternationalFlight && entropy < 4.2 && len(payload) > 64 {
		score += 50
		triggers = append(triggers, "LOW_ENTROPY_PLAINTEXT_EXPOSURE")
	}

	// Rule 3: Exposed or suspicious SNI at Edge Checkpoints
	if tls.IsTLS && tls.SNI == "" {
		score += 40
		triggers = append(triggers, "EMPTY_SNI_EXTENSION")
	}

	level := models.RiskOptimal
	if score >= 70 {
		level = models.RiskCritical
	} else if score >= 35 {
		level = models.RiskWarning
	}

	return models.DPIAssessment{
		ShannonEntropy: entropy,
		RiskScore:      score,
		Level:          level,
		Triggers:       triggers,
	}
}
