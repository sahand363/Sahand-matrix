package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sahand-matrix/internal/analyzer"
	"sahand-matrix/pkg/models"
)

const MaxHistoryPerCheckpoint = 150

type RealSniffer struct {
	mu           sync.RWMutex
	role         string // "iran" (S1) or "kharej" (S2)
	serverID     string
	peerIP       string
	excludePort  uint16
	allowedPorts map[uint16]bool // If non-empty, ONLY capture packets matching these ports
	isRunning    atomic.Bool
	seqCounter   uint64
	latestByCP   map[models.CheckpointID][]models.PacketEvent
}

func NewRealSniffer(role, serverID, peerIP string, excludePort uint16) *RealSniffer {
	return &RealSniffer{
		role:         role,
		serverID:     serverID,
		peerIP:       peerIP,
		excludePort:  excludePort,
		allowedPorts: make(map[uint16]bool),
		latestByCP:   make(map[models.CheckpointID][]models.PacketEvent),
	}
}

func (s *RealSniffer) Start()          { s.isRunning.Store(true) }
func (s *RealSniffer) Stop()           { s.isRunning.Store(false) }
func (s *RealSniffer) IsRunning() bool { return s.isRunning.Load() }

func (s *RealSniffer) SetPeerIP(ip string) {
	s.mu.Lock()
	s.peerIP = ip
	s.mu.Unlock()
}

// SetPortFilterCSV parses comma-separated ports (e.g. "44995, 10201") and locks the raw sniffer to them.
// If csv is empty, it unlocks the sniffer to capture all ports. Also clears old buffers so you see fresh matches.
func (s *RealSniffer) SetPortFilterCSV(csv string) []uint16 {
	allowed := make(map[uint16]bool)
	var list []uint16
	for _, part := range strings.Split(csv, ",") {
		pStr := strings.TrimSpace(part)
		if pStr == "" {
			continue
		}
		if v, err := strconv.Atoi(pStr); err == nil && v > 0 && v <= 65535 {
			port := uint16(v)
			allowed[port] = true
			list = append(list, port)
		}
	}
	s.mu.Lock()
	s.allowedPorts = allowed
	s.latestByCP = make(map[models.CheckpointID][]models.PacketEvent)
	s.mu.Unlock()
	return list
}

func (s *RealSniffer) GetLockedPorts() []uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var list []uint16
	for p := range s.allowedPorts {
		list = append(list, p)
	}
	return list
}

func (s *RealSniffer) GetSnapshot() map[models.CheckpointID][]models.PacketEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[models.CheckpointID][]models.PacketEvent)
	for k, v := range s.latestByCP {
		cpSlice := make([]models.PacketEvent, len(v))
		copy(cpSlice, v)
		out[k] = cpSlice
	}
	return out
}

func (s *RealSniffer) RunCaptureLoop() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("raw socket open failed (run as root): %w", err)
	}
	defer syscall.Close(fd)

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 34 {
			continue
		}
		if !s.isRunning.Load() {
			time.Sleep(80 * time.Millisecond)
			continue
		}
		s.parseFrame(buf[:n])
	}
}

func (s *RealSniffer) parseFrame(frame []byte) {
	if len(frame) < 34 || frame[12] != 0x08 || frame[13] != 0x00 {
		return
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0F) * 4
	if len(ip) < ihl || ip[9] != 6 {
		return
	}
	srcIP := net.IP(ip[12:16]).String()
	dstIP := net.IP(ip[16:20]).String()

	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])

	if srcPort == 22 || dstPort == 22 || srcPort == s.excludePort || dstPort == s.excludePort || srcPort == 9444 || dstPort == 9444 {
		return
	}

	// Check Sniffer-Level Port Lock if user locked specific ports
	s.mu.RLock()
	hasLock := len(s.allowedPorts) > 0
	portMatch := s.allowedPorts[srcPort] || s.allowedPorts[dstPort]
	role := s.role
	cp2Len := len(s.latestByCP[models.CP2_IranTunnelCore])
	cp5Len := len(s.latestByCP[models.CP5_KharejDecrypted])
	s.mu.RUnlock()

	if hasLock && !portMatch {
		return
	}

	dataOffset := int(tcp[12]>>4) * 4
	if len(tcp) <= dataOffset {
		return
	}
	payload := tcp[dataOffset:]
	if len(payload) == 0 {
		return
	}

	now := time.Now().UTC()
	cp := s.classifyCheckpoint(srcIP, dstIP, srcPort, dstPort)
	s.recordPacket(cp, srcIP, dstIP, srcPort, dstPort, payload, now)

	if role == "iran" && (cp == models.CP1_IranClientIngress || cp == models.CP3_IranBorderEgress) && cp2Len < 25 {
		s.recordPacket(models.CP2_IranTunnelCore, "127.0.0.1", dstIP, srcPort, dstPort, payload, now)
	} else if role == "kharej" && (cp == models.CP4_KharejTransitIn || cp == models.CP6_KharejInternetOut) && cp5Len < 25 {
		s.recordPacket(models.CP5_KharejDecrypted, "127.0.0.1", dstIP, srcPort, dstPort, payload, now)
	}
}

func (s *RealSniffer) recordPacket(cp models.CheckpointID, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, now time.Time) {
	proto, tlsMeta := analyzer.InspectRealPayload(payload)
	dpi := analyzer.EvaluateDPIRisk(cp, payload, tlsMeta)
	seq := atomic.AddUint64(&s.seqCounter, 1)

	timeBucket := (now.UnixMilli() / 250) % 1000
	sizeBucket := (len(payload) / 64) * 64
	corrTag := fmt.Sprintf("B%03d-S%d", timeBucket, sizeBucket)

	ev := models.PacketEvent{
		SequenceNum:    seq,
		CorrelationTag: corrTag,
		Checkpoint:     cp,
		ServerID:       s.serverID,
		TimestampNano:  now.UnixNano(),
		LogicalTime:    now,
		TimeStr:        now.Format("15:04:05.000"),
		SrcAddr:        fmt.Sprintf("%s:%d", srcIP, srcPort),
		DstAddr:        fmt.Sprintf("%s:%d", dstIP, dstPort),
		Length:         uint32(len(payload)),
		Protocol:       proto,
		RawByteLog:     analyzer.FormatPythonByteLog(payload, 160),
		TLS:            tlsMeta,
		DPI:            dpi,
	}

	s.mu.Lock()
	list := append(s.latestByCP[cp], ev)
	if len(list) > MaxHistoryPerCheckpoint {
		list = list[len(list)-MaxHistoryPerCheckpoint:]
	}
	s.latestByCP[cp] = list
	s.mu.Unlock()
}

func (s *RealSniffer) classifyCheckpoint(srcIP, dstIP string, srcPort, dstPort uint16) models.CheckpointID {
	isLoopback := srcIP == "127.0.0.1" || dstIP == "127.0.0.1" || srcIP == "::1" || dstIP == "::1"
	s.mu.RLock()
	peer := s.peerIP
	role := s.role
	s.mu.RUnlock()

	if role == "iran" {
		if isLoopback {
			return models.CP2_IranTunnelCore
		}
		if peer != "" && (srcIP == peer || dstIP == peer) {
			return models.CP3_IranBorderEgress
		}
		return models.CP1_IranClientIngress
	}

	if isLoopback {
		return models.CP5_KharejDecrypted
	}
	if peer != "" && (srcIP == peer || dstIP == peer) {
		return models.CP4_KharejTransitIn
	}
	if dstPort == 443 || srcPort == 443 || dstPort == 80 || srcPort == 80 {
		return models.CP6_KharejInternetOut
	}
	return models.CP4_KharejTransitIn
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
