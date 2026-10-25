package analyzer

import (
	"fmt"
	"strings"

	"sahand-matrix/pkg/models"
)

// InspectRealPayload dissects raw TCP payload bytes to detect TLS 1.2/1.3 records, SNI, HTTP, or WSS.
func InspectRealPayload(payload []byte) (string, models.TLSMetadata) {
	meta := models.TLSMetadata{}
	n := len(payload)
	if n == 0 {
		return "EMPTY", meta
	}

	// Detect TLS Record Header: 0x14 (ChangeCipherSpec), 0x15 (Alert), 0x16 (Handshake), 0x17 (AppData)
	if n >= 5 && (payload[0] >= 0x14 && payload[0] <= 0x17) && payload[1] == 0x03 && payload[2] <= 0x04 {
		meta.IsTLS = true
		switch payload[0] {
		case 0x16:
			meta.RecordType = "Handshake"
			meta.SNI = extractSNI(payload)
		case 0x17:
			meta.RecordType = "AppData"
		default:
			meta.RecordType = "TLSRecord"
		}
		meta.Version = "TLS1.3/1.2"
		return "TLSv1.3/WSS", meta
	}

	if n >= 4 {
		head := string(payload[:minInt(n, 32)])
		if strings.HasPrefix(head, "GET ") || strings.HasPrefix(head, "POST ") || strings.HasPrefix(head, "HTTP/") {
			if strings.Contains(strings.ToLower(head), "upgrade: websocket") {
				return "WS-PLAINTEXT", meta
			}
			return "HTTP-PLAIN", meta
		}
	}

	if n <= 16 {
		return "TCP-KEEPALIVE", meta
	}
	return "RAW-STREAM", meta
}

func extractSNI(b []byte) string {
	if len(b) < 43 || b[0] != 0x16 || b[5] != 0x01 {
		return ""
	}
	for i := 38; i+9 < len(b); i++ {
		if b[i] == 0x00 && b[i+1] == 0x00 && b[i+4] == 0x00 && b[i+7] == 0x00 {
			nameLen := int(b[i+8])
			if nameLen > 2 && nameLen < 64 && i+9+nameLen <= len(b) {
				candidate := string(b[i+9 : i+9+nameLen])
				if isValidHostname(candidate) {
					return candidate
				}
			}
		}
	}
	return ""
}

func isValidHostname(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// FormatPythonByteLog formats raw bytes as b'\x17\x03\x03...' for clear inspection.
func FormatPythonByteLog(payload []byte, maxBytes int) string {
	limit := len(payload)
	if limit > maxBytes {
		limit = maxBytes
	}
	var sb strings.Builder
	sb.WriteString("Raw Data: b'")
	for i := 0; i < limit; i++ {
		c := payload[i]
		if c >= 32 && c <= 126 && c != '\'' && c != '\\' {
			sb.WriteByte(c)
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", c))
		}
	}
	sb.WriteByte('\'')
	return sb.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
