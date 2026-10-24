package tunnels

import (
	"fmt"
	"time"

	"sahand-matrix/internal/analyzer"
	"sahand-matrix/pkg/models"
)

type TunnelInfo struct {
	ID          models.TunnelType `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
}

func AvailableTunnels() []TunnelInfo {
	return []TunnelInfo{
		{models.TunnelWSS, "WSS (WebSocket + TLS 1.3)", "Wraps proxy frames inside HTTP/1.1 WebSocket Upgrade + TLS 1.3 (\x17\x03\x03). Looks like CDN/Web traffic to Iran DPI."},
		{models.TunnelReality, "VLESS + XTLS-Reality", "Borrows a real foreign site TLS certificate (www.microsoft.com). 0% active-probing footprint."},
		{models.TunnelGRPC, "gRPC + TLS 1.3 (HTTP/2)", "Multiplexes streams inside HTTP/2 application frames over TLS 1.3."},
		{models.TunnelShadowsocks, "Shadowsocks-2022 (AEAD)", "Pure high-entropy encrypted TCP stream WITHOUT TLS headers. Vulnerable to Iran DPI entropy filters!"},
		{models.TunnelRawTCP, "Raw Unmasked Tunnel (BAD)", "Unprotected tunnel without TLS encapsulation. Immediately triggers RED DPI alerts at Checkpoints 3, 4 & 5."},
	}
}

// Build6CheckpointSnapshot generates synchronized packet events across all 6 windows for the selected tunnel.
func Build6CheckpointSnapshot(tunnel models.TunnelType, seq uint64, oneWayOffset time.Duration) []models.PacketEvent {
	now := time.Now().UTC()

	// Inner decrypted application data (what is inside the tunnel at CP2 and CP6)
	innerPlain := []byte(fmt.Sprintf("GET /api/v2/feed?seq=%d HTTP/1.1\r\nHost: internal.app\r\nUser-Agent: SahandMatrix/2.0\r\n\r\n", seq))

	// TLS 1.3 Application Data header (0x17 0x03 0x03 + length + encrypted ciphertext)
	tlsWrapped := makeTLS13Record(seq, 64)

	// Pure high-entropy random stream (no 0x17 0x03 0x03 TLS header - e.g. raw Shadowsocks)
	rawEncrypted := makeHighEntropyRaw(seq, 64)

	type cpConfig struct {
		id         models.CheckpointID
		title      string
		node       string
		dpiVisible bool
		dpiZone    string
		proto      string
		sni        string
		isTLS      bool
		isReality  bool
		payload    []byte
		offset     time.Duration
	}

	// Configure how the selected tunnel looks at exterior checkpoints (CP1, CP3, CP4, CP5)
	extProto := "WSS (TLS1.3)"
	extSNI := "cdn.cloudflare-edge.com"
	extIsTLS := true
	extReality := false
	extPayload := tlsWrapped

	switch tunnel {
	case models.TunnelReality:
		extProto = "REALITY/TLS1.3"
		extSNI = "www.microsoft.com"
		extIsTLS = true
		extReality = true
		extPayload = tlsWrapped
	case models.TunnelGRPC:
		extProto = "gRPC/TLS1.3"
		extSNI = "api.google.com"
		extIsTLS = true
		extPayload = tlsWrapped
	case models.TunnelShadowsocks:
		extProto = "SS-2022 (RAW)"
		extSNI = "NONE (No TLS!)"
		extIsTLS = false
		extPayload = rawEncrypted
	case models.TunnelRawTCP:
		extProto = "RAW-TCP (LEAK)"
		extSNI = "NONE (Cleartext!)"
		extIsTLS = false
		extPayload = innerPlain
	}

	configs := []cpConfig{
		{models.CP1_RemoteEdgeIngress, "CP1: Edge Raw Ingress", "Remote Server NIC", true, "👁 INT'L EDGE DPI", extProto, extSNI, extIsTLS, extReality, extPayload, 0},
		{models.CP2_RemoteDecrypted, "CP2: Decrypted Core", "Remote X-UI Core", false, "🔒 INVISIBLE TO DPI", "PLAINTEXT/INNER", "—", false, false, innerPlain, 1 * time.Millisecond},
		{models.CP3_InternationalFlight, "CP3: Int'l Transit", "Cross-Border Link", true, "👁 IRAN BORDER GATEWAY (GCI)", extProto, extSNI, extIsTLS, extReality, extPayload, oneWayOffset / 2},
		{models.CP4_IranInternalIngress, "CP4: Iran Ingress", "Iran Server NIC", true, "👁 IRAN INGRESS DPI", extProto, extSNI, extIsTLS, extReality, extPayload, oneWayOffset},
		{models.CP5_IranEgressEdge, "CP5: Iran Egress Edge", "Iran Domestic NIC", true, "🚨 IRAN DOMESTIC DPI (TCI/MCI)", extProto, extSNI, extIsTLS, extReality, extPayload, oneWayOffset + 1*time.Millisecond},
		{models.CP6_IranAppOutput, "CP6: Final App Output", "Iran Target Service", false, "🔒 INVISIBLE TO DPI", "HTTP/2 PAYLOAD", "—", false, false, innerPlain, oneWayOffset + 2*time.Millisecond},
	}

	var out []models.PacketEvent
	for _, c := range configs {
		tlsMeta := models.TLSMetadata{
			IsTLS:            c.isTLS,
			SNI:              c.sni,
			IsRealityMimicry: c.isReality,
		}
		dpi := analyzer.EvaluateDPIRisk(c.id, c.payload, tlsMeta)
		out = append(out, models.PacketEvent{
			FlowID:          "FLW-" + string(tunnel),
			SequenceNum:     seq,
			Checkpoint:      c.id,
			CheckpointTitle: c.title,
			NodeName:        c.node,
			DPIVisible:      c.dpiVisible,
			DPIZone:         c.dpiZone,
			LogicalTime:     now.Add(c.offset),
			OffsetMs:        float64(c.offset.Microseconds()) / 1000.0,
			Length:          uint32(len(c.payload) + 1280),
			Protocol:        c.proto,
			PayloadSample:   c.payload,
			RawByteLog:      analyzer.FormatPythonByteLog(c.payload, 38),
			TLS:             tlsMeta,
			DPI:             dpi,
		})
	}
	return out
}

// makeTLS13Record creates a realistic TLS 1.3 Application Data frame starting with \x17\x03\x03
func makeTLS13Record(seed uint64, length int) []byte {
	buf := make([]byte, length)
	buf[0] = 0x17 // TLS Application Data record type
	buf[1] = 0x03 // TLS major version 3
	buf[2] = 0x03 // TLS minor version 3 (TLS 1.2/1.3 framing)
	buf[3] = 0x00
	buf[4] = byte(length - 5)
	for i := 5; i < length; i++ {
		buf[i] = byte((uint64(i)*73 + seed*31 + 0x9a) % 256)
	}
	return buf
}

// makeHighEntropyRaw creates unframed random bytes (triggers high-entropy non-TLS DPI alerts)
func makeHighEntropyRaw(seed uint64, length int) []byte {
	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = byte((uint64(i)*101 + seed*43 + 0x5f) % 256)
	}
	return buf
}
