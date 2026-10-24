package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"sahand-matrix/internal/analyzer"
	"sahand-matrix/pkg/models"
)

type RealSniffer struct {
	mu          sync.RWMutex
	role        string // "iran" (S1) or "kharej" (S2)
	serverID    string
	peerIP      string // IP of the other server to distinguish CP3/CP4 tunnel transit
	excludePort uint16 // Exclude panel/agent control port so we only see real user/tunnel data
	isRunning   atomic.Bool
	seqCounter  uint64
	latestByCP  map[models.CheckpointID][]models.PacketEvent
}

func NewRealSniffer(role, serverID, peerIP string, excludePort uint16) *RealSniffer {
	return &RealSniffer{
		role:        role,
		serverID:    serverID,
		peerIP:      peerIP,
		excludePort: excludePort,
		latestByCP:  make(map[models.CheckpointID][]models.PacketEvent),
	}
}

func (s *RealSniffer) Start() { s.isRunning.Store(true) }
func (s *RealSniffer) Stop()  { s.isRunning.Store(false) }
func (s *RealSniffer) IsRunning() bool { return s.isRunning.Load() }

func (s *RealSniffer) SetPeerIP(ip string) {
	s.mu.Lock()
	s.peerIP = ip
	s.mu.Unlock()
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

// RunCaptureLoop opens a Linux AF_PACKET raw socket and captures real network packets when Start() is active.
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
	// Ethernet header is 14 bytes; check EtherType == 0x0800 (IPv4)
	if len(frame) < 34 || frame[12] != 0x08 || frame[13] != 0x00 {
		return
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0F) * 4
	if len(ip) < ihl || ip[9] != 6 { // Protocol 6 == TCP
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

	// Ignore SSH (22) and our own Sahand Matrix control ports (8443 / 9444)
	if srcPort == 22 || dstPort == 22 || srcPort == s.excludePort || dstPort == s.excludePort || srcPort == 9444 || dstPort == 9444 {
		return
	}

	dataOffset := int(tcp[12]>>4) * 4
	if len(tcp) <= dataOffset {
		return // Pure ACK/SYN with 0 payload bytes
	}
	payload := tcp[dataOffset:]
	if len(payload) == 0 {
		return
	}

	cp := s.classifyCheckpoint(srcIP, dstIP, srcPort, dstPort)
	proto, tlsMeta := analyzer.InspectRealPayload(payload)
	dpi := analyzer.EvaluateDPIRisk(cp, payload, tlsMeta)
	seq := atomic.AddUint64(&s.seqCounter, 1)
	now := time.Now().UTC()

	ev := models.PacketEvent{
		SequenceNum:   seq,
		Checkpoint:    cp,
		ServerID:      s.serverID,
		TimestampNano: now.UnixNano(),
		LogicalTime:   now,
		SrcAddr:       fmt.Sprintf("%s:%d", srcIP, srcPort),
		DstAddr:       fmt.Sprintf("%s:%d", dstIP, dstPort),
		Length:        uint32(len(payload)),
		Protocol:      proto,
		RawByteLog:    analyzer.FormatPythonByteLog(payload, 52),
		TLS:           tlsMeta,
		DPI:           dpi,
	}

	s.mu.Lock()
	list := append(s.latestByCP[cp], ev)
	if len(list) > 10 {
		list = list[len(list)-10:]
	}
	s.latestByCP[cp] = list
	s.mu.Unlock()
}

func (s *RealSniffer) classifyCheckpoint(srcIP, dstIP string, srcPort, dstPort uint16) models.CheckpointID {
	isLoopback := srcIP == "127.0.0.1" || dstIP == "127.0.0.1"
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

	// Role == "kharej" (S2)
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
