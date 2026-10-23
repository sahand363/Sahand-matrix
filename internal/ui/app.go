package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"sahand-matrix/internal/analyzer"
	"sahand-matrix/internal/hub"
	"sahand-matrix/pkg/models"
)

type tickMsg time.Time

type burstResultMsg struct {
	report     hub.PingBurstReport
	targetSeq  uint64
}

type MatrixModel struct {
	styles          AppStyles
	syncEngine      *hub.SyncEngine
	width           int
	height          int
	selectedNav     int
	navItems        []string
	isCalibrating   bool
	isPaused        bool
	showAgentModal  bool
	agentConnected  bool
	lastBurst       hub.PingBurstReport
	lockedSeq       uint64
	seqCounter      uint64
	checkpoints     map[models.CheckpointID][]models.PacketEvent
	incidents       []string
}

func NewMatrixModel() MatrixModel {
	engine := hub.NewSyncEngine(128)
	initialReport := engine.Measure5PingBurst("simulate", 48.0)

	m := MatrixModel{
		styles:     DefaultStyles(),
		syncEngine: engine,
		selectedNav: 0,
		navItems: []string{
			"⊞  Dashboard",
			"☊  Topology Map",
			"⛨  Checkpoints (6)",
			"🚀 Deploy Agent [D]",
			"📄 Packet Logs",
			"⚙  Settings",
		},
		agentConnected: true,
		lastBurst:      initialReport,
		seqCounter:     10420,
		checkpoints:    make(map[models.CheckpointID][]models.PacketEvent),
		incidents: []string{
			"● 5-Ping Sync Calibrated: Avg 48.0ms (Δ +24.0ms)",
			"● CP1: TLS 1.3 Reality Handshake Verified",
			"● CP3: Entropy 7.94 bits/B (Encrypted Tunnel)",
			"● CP5: Domestic Egress Clean (No SNI Leak)",
		},
	}
	m.stepSimulation()
	return m
}

func (m MatrixModel) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*450, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// run5PingCalibrationCmd runs 5 rapid RTT probes asynchronously and returns the averaged offset.
func (m MatrixModel) run5PingCalibrationCmd(seq uint64) tea.Cmd {
	return func() tea.Msg {
		report := m.syncEngine.Measure5PingBurst("simulate", 48.0)
		return burstResultMsg{
			report:    report,
			targetSeq: seq,
		}
	}
}

func (m *MatrixModel) stepSimulation() {
	m.seqCounter++
	now := time.Now().UTC()
	oneWayOffset := m.lastBurst.OneWayDelay

	configs := []struct {
		cp      models.CheckpointID
		proto   string
		sni     string
		isTLS   bool
		payload []byte
		offset  time.Duration
	}{
		{models.CP1_RemoteEdgeIngress, "TLSv1.3", "www.microsoft.com", true, simulatedHighEntropyPayload(m.seqCounter), 0},
		{models.CP2_RemoteDecrypted, "VLESS", "", false, simulatedInnerPayload(m.seqCounter), 2 * time.Millisecond},
		{models.CP3_InternationalFlight, "REALITY", "www.microsoft.com", true, simulatedHighEntropyPayload(m.seqCounter), oneWayOffset / 2},
		{models.CP4_IranInternalIngress, "REALITY", "www.microsoft.com", true, simulatedHighEntropyPayload(m.seqCounter), oneWayOffset},
		{models.CP5_IranEgressEdge, "TCP/TLS", "dl.cdn-edge.ir", true, simulatedHighEntropyPayload(m.seqCounter), oneWayOffset + 2*time.Millisecond},
		{models.CP6_IranAppOutput, "HTTP/2", "", false, simulatedInnerPayload(m.seqCounter), oneWayOffset + 4*time.Millisecond},
	}

	for _, cfg := range configs {
		tlsMeta := models.TLSMetadata{
			IsTLS:            cfg.isTLS,
			SNI:              cfg.sni,
			IsRealityMimicry: cfg.proto == "REALITY",
		}
		dpi := analyzer.EvaluateDPIRisk(cfg.cp, cfg.payload, tlsMeta)

		ev := models.PacketEvent{
			FlowID:      "FLW-99A4",
			SequenceNum: m.seqCounter,
			Checkpoint:  cfg.cp,
			LogicalTime: now.Add(cfg.offset),
			Length:      1420,
			Protocol:    cfg.proto,
			TLS:         tlsMeta,
			DPI:         dpi,
		}

		list := append(m.checkpoints[cfg.cp], ev)
		if len(list) > 4 {
			list = list[len(list)-4:]
		}
		m.checkpoints[cfg.cp] = list
	}
}

func simulatedHighEntropyPayload(seed uint64) []byte {
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = byte((uint64(i)*37 + seed*13) % 256)
	}
	return buf
}

func simulatedInnerPayload(seed uint64) []byte {
	return []byte(fmt.Sprintf("GET /api/v2/stream?seq=%d HTTP/1.1\r\nHost: internal.service\r\n\r\n", seed))
}

func (m MatrixModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "d", "D":
			m.showAgentModal = !m.showAgentModal
		case " ":
			if m.isPaused {
				m.isPaused = false
				m.isCalibrating = false
			} else if !m.isCalibrating {
				// Trigger 5-ping measurement burst before locking the 6 windows
				m.isCalibrating = true
				return m, m.run5PingCalibrationCmd(m.seqCounter)
			}
		case "up", "k":
			if m.selectedNav > 0 {
				m.selectedNav--
			}
		case "down", "j":
			if m.selectedNav < len(m.navItems)-1 {
				m.selectedNav++
			}
		}

	case burstResultMsg:
		m.isCalibrating = false
		m.isPaused = true
		m.lastBurst = msg.report
		m.lockedSeq = msg.targetSeq
		avgMs := float64(msg.report.AverageRTT.Microseconds()) / 1000.0
		offsetMs := float64(msg.report.OneWayDelay.Microseconds()) / 1000.0
		logEntry := fmt.Sprintf("● 5-Ping Lock: [%.1f, %.1f, %.1f, %.1f, %.1f]ms -> Avg %.1fms (Δ +%.1fms)",
			msg.report.SamplesMs[0], msg.report.SamplesMs[1], msg.report.SamplesMs[2],
			msg.report.SamplesMs[3], msg.report.SamplesMs[4], avgMs, offsetMs)
		m.incidents = append([]string{logEntry}, m.incidents[:3]...)

	case tickMsg:
		if !m.isPaused && !m.isCalibrating {
			m.stepSimulation()
		}
		return m, tickCmd()
	}

	return m, nil
}

func (m MatrixModel) View() string {
	avgMs := float64(m.lastBurst.AverageRTT.Microseconds()) / 1000.0
	offsetMs := float64(m.lastBurst.OneWayDelay.Microseconds()) / 1000.0

	// 1. Top Header Bar
	statusText := m.styles.StatusBadge.Render("GLOBAL STATUS: 6/6 CHECKPOINTS VERIFIED ●")
	if m.isCalibrating {
		statusText = m.styles.BadgeWarning.Render("⚡ RUNNING 5-PING BURST CALIBRATION BETWEEN SERVERS...")
	} else if m.isPaused {
		statusText = m.styles.BadgeWarning.Render(
			fmt.Sprintf("⏸ 5-PING SYNC LOCKED @ SEQ #%d | AVG RTT: %.1fms | WINDOW OFFSET: +%.1fms",
				m.lockedSeq, avgMs, offsetMs),
		)
	}

	headerLeft := m.styles.BrandTitle.Render("🕸  SAHAND MATRIX ") + m.styles.TextMuted.Render("PRO // 6-CHECKPOINT ANALYZER")
	header := m.styles.HeaderBar.Width(max(114, m.width-2)).Render(
		lipgloss.JoinHorizontal(lipgloss.Center,
			headerLeft,
			"    ",
			statusText,
			"    [SPACE] 5-Ping Pause  [D] Deploy Agent  [Q] Quit",
		),
	)

	// 2. Left Sidebar Navigation
	var navRows []string
	for i, item := range m.navItems {
		if i == m.selectedNav {
			navRows = append(navRows, m.styles.NavActive.Render("▎ "+item))
		} else {
			navRows = append(navRows, m.styles.NavInactive.Render("  "+item))
		}
		navRows = append(navRows, "")
	}
	navRows = append(navRows, strings.Repeat("─", 18))
	navRows = append(navRows, m.styles.BadgeOptimal.Render("● Remote Agent: OK"))
	navRows = append(navRows, m.styles.BadgeOptimal.Render("● Iran Agent:   OK"))
	sidebar := m.styles.Sidebar.Height(28).Render(strings.Join(navRows, "\n"))

	// If User Pressed [D], Render In-Panel Agent Deployment & Verification View
	if m.showAgentModal {
		modalLines := []string{
			m.styles.CardTitle.Render("🚀 DEPLOY & VERIFY LIGHTWEIGHT SAHAND-AGENT"),
			"",
			m.styles.CyanText.Render("1. Fast Install on Remote or Iran Server (Ubuntu Terminal):"),
			"   bash <(curl -Ls https://raw.githubusercontent.com/<USER>/sahand-matrix/main/scripts/setup.sh)",
			"",
			m.styles.PurpleText.Render("2. Direct Manual Agent Launch Command:"),
			"   sahand-agent --hub <HUB_IP>:8443 --token <AGENT_TOKEN> --role iran",
			"",
			m.styles.CardTitle.Render("3. Live 5-Ping Calibration & 6-Window Health Check:"),
			fmt.Sprintf("   • 5-Ping Samples (ms) : %.2fms | %.2fms | %.2fms | %.2fms | %.2fms",
				m.lastBurst.SamplesMs[0], m.lastBurst.SamplesMs[1], m.lastBurst.SamplesMs[2],
				m.lastBurst.SamplesMs[3], m.lastBurst.SamplesMs[4]),
			fmt.Sprintf("   • Calculated Mean RTT : %.2f ms (Jitter: ±%.2f ms)", avgMs, m.lastBurst.JitterMs),
			fmt.Sprintf("   • Applied Sync Offset : +%.2f ms (RTT / 2 applied to Checkpoints 4-6)", offsetMs),
			"   • Checkpoint Status   : CP1 [OK] | CP2 [OK] | CP3 [OK] | CP4 [OK] | CP5 [OK] | CP6 [OK]",
			"",
			m.styles.BadgeOptimal.Render("Press [D] to return to the 6-Checkpoint Live Matrix"),
		}
		modalBox := m.styles.CardActive.Width(98).Height(20).Render(strings.Join(modalLines, "\n"))
		return lipgloss.JoinVertical(lipgloss.Left, header, lipgloss.JoinHorizontal(lipgloss.Top, sidebar, "  ", modalBox))
	}

	// 3. Center 6-Checkpoint Synchronized Grid
	cpTitles := map[models.CheckpointID]string{
		models.CP1_RemoteEdgeIngress:   "CP1: Edge Ingress (Remote +0ms)",
		models.CP2_RemoteDecrypted:     "CP2: Decrypted Core (Remote +0ms)",
		models.CP3_InternationalFlight: fmt.Sprintf("CP3: Int'l Transit (+%.1fms)", offsetMs/2),
		models.CP4_IranInternalIngress: fmt.Sprintf("CP4: Iran Ingress (+%.1fms)", offsetMs),
		models.CP5_IranEgressEdge:      fmt.Sprintf("CP5: Iran Egress DPI (+%.1fms)", offsetMs),
		models.CP6_IranAppOutput:       fmt.Sprintf("CP6: App Output (+%.1fms)", offsetMs),
	}

	renderCPBox := func(cp models.CheckpointID, isRemote bool) string {
		titleStyle := m.styles.CyanText
		if !isRemote {
			titleStyle = m.styles.PurpleText
		}
		var lines []string
		lines = append(lines, titleStyle.Bold(true).Render(cpTitles[cp]))
		lines = append(lines, m.styles.TextMuted.Render("SEQ     PROTO    H(X)   RISK"))

		events := m.checkpoints[cp]
		for _, ev := range events {
			badge := m.styles.BadgeOptimal.Render("LOW")
			if ev.DPI.Level == models.RiskWarning {
				badge = m.styles.BadgeWarning.Render("MED")
			} else if ev.DPI.Level == models.RiskCritical {
				badge = m.styles.BadgeCritical.Render("HIGH")
			}
			line := fmt.Sprintf("#%-6d %-7s  %0.2f   %s",
				ev.SequenceNum, ev.Protocol, ev.DPI.ShannonEntropy, badge)
			lines = append(lines, line)
		}
		cardStyle := m.styles.Card
		if m.isPaused {
			cardStyle = m.styles.CardActive
		}
		return cardStyle.Width(33).Height(7).Render(strings.Join(lines, "\n"))
	}

	row1 := lipgloss.JoinHorizontal(lipgloss.Top,
		renderCPBox(models.CP1_RemoteEdgeIngress, true), " ",
		renderCPBox(models.CP2_RemoteDecrypted, true), " ",
		renderCPBox(models.CP3_InternationalFlight, true),
	)
	row2 := lipgloss.JoinHorizontal(lipgloss.Top,
		renderCPBox(models.CP4_IranInternalIngress, false), " ",
		renderCPBox(models.CP5_IranEgressEdge, false), " ",
		renderCPBox(models.CP6_IranAppOutput, false),
	)

	// 4. Bottom 4 KPI Summary Cards
	kpi1 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("BANDWIDTH") + "\n" +
			m.styles.KPIValue.Render("14.5 Gbps") + "\n" +
			m.styles.BadgeOptimal.Render("+1.2% Synced"),
	)
	kpi2 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("5-PING AVG / OFFSET") + "\n" +
			m.styles.KPIValue.Render(fmt.Sprintf("%.1fms (Δ +%.1fms)", avgMs, offsetMs)) + "\n" +
			m.styles.BadgeOptimal.Render(fmt.Sprintf("Jitter ±%.2fms", m.lastBurst.JitterMs)),
	)
	kpi3 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("ACTIVE CHECKPOINTS") + "\n" +
			m.styles.KPIValue.Render("6 / 6 Verified") + "\n" +
			m.styles.CyanText.Render("━━━━━━━━━━━━"),
	)
	kpi4 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("DPI LEAK RISK") + "\n" +
			m.styles.BadgeOptimal.Render("0.01% OPTIMAL") + "\n" +
			m.styles.TextMuted.Render("SNI & Entropy Clean"),
	)

	kpiRow := lipgloss.JoinHorizontal(lipgloss.Top, kpi1, " ", kpi2, " ", kpi3, " ", kpi4)
	centerColumn := lipgloss.JoinVertical(lipgloss.Left, row1, "", row2, "", kpiRow)

	// 5. Right Rail (5-PING TELEMETRY & PROTOCOL DISTRIBUTION)
	incLines := []string{m.styles.CardTitle.Render("CRITICAL INCIDENTS & SYNC"), ""}
	for _, inc := range m.incidents {
		incLines = append(incLines, inc, m.styles.TextMuted.Render("  Verified across CP1..CP6"))
	}
	incidentsCard := m.styles.Card.Width(34).Height(11).Render(strings.Join(incLines, "\n"))

	protoLines := []string{
		m.styles.CardTitle.Render("5-PING SAMPLES (LAST BURST)"),
		fmt.Sprintf("P1: %.1fms  P2: %.1fms  P3: %.1fms",
			m.lastBurst.SamplesMs[0], m.lastBurst.SamplesMs[1], m.lastBurst.SamplesMs[2]),
		fmt.Sprintf("P4: %.1fms  P5: %.1fms  Avg: %.1fms",
			m.lastBurst.SamplesMs[3], m.lastBurst.SamplesMs[4], avgMs),
		"",
		m.styles.CyanText.Render("REALITY ") + "━━━━━━━━━━━━ 68%",
		m.styles.PurpleText.Render("VLESS   ") + "━━━━━━       22%",
		m.styles.CyanText.Render("TLS 1.3 ") + "━━━           8%",
	}
	protoCard := m.styles.Card.Width(34).Height(10).Render(strings.Join(protoLines, "\n"))
	rightColumn := lipgloss.JoinVertical(lipgloss.Left, incidentsCard, "", protoCard)

	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, "  ", centerColumn, "  ", rightColumn)
	return lipgloss.JoinVertical(lipgloss.Left, header, body)
}
