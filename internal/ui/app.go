package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"sahand-matrix/internal/analyzer"
	"sahand-matrix/pkg/models"
)

type tickMsg time.Time

type MatrixModel struct {
	styles         AppStyles
	width          int
	height         int
	selectedNav    int
	navItems       []string
	isPaused       bool
	rttMillis      int
	seqCounter     uint64
	checkpoints    map[models.CheckpointID][]models.PacketEvent
	incidents      []string
}

func NewMatrixModel() MatrixModel {
	m := MatrixModel{
		styles:      DefaultStyles(),
		selectedNav: 0,
		navItems: []string{
			"⊞  Dashboard",
			"☊  Topology Map",
			"⛨  Checkpoints (6)",
			"📈 Performance",
			"📄 Packet Logs",
			"⚙  Settings",
		},
		isPaused:    false,
		rttMillis:   48, // Simulated 48ms Remote <-> Iran RTT (24ms one-way offset)
		seqCounter:  10420,
		checkpoints: make(map[models.CheckpointID][]models.PacketEvent),
		incidents: []string{
			"● CP1: TLS 1.3 Reality Handshake Verified",
			"● CP3: Entropy 7.94 bits/B (Encrypted Tunnel)",
			"● CP5: Domestic Egress Clean (No SNI Leak)",
			"● CP1: High Entropy Spike on Port 443",
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

func (m *MatrixModel) stepSimulation() {
	m.seqCounter++
	now := time.Now().UTC()
	oneWayOffset := time.Duration(m.rttMillis/2) * time.Millisecond

	// Simulate the exact same logical packet traversing all 6 checkpoints
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

func (m MatrixModel) Update(msg tea.Msg) (tea.Model, tea.Msg) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case " ":
			// Toggle Smart Time-Synced Pause (freezes all 6 panes at RTT/2 offset)
			m.isPaused = !m.isPaused
		case "up", "k":
			if m.selectedNav > 0 {
				m.selectedNav--
			}
		case "down", "j":
			if m.selectedNav < len(m.navItems)-1 {
				m.selectedNav++
			}
		}

	case tickMsg:
		if !m.isPaused {
			m.stepSimulation()
		}
		return m, tickCmd()
	}

	return m, nil
}

func (m MatrixModel) View() string {
	// 1. Top Header Bar
	statusText := m.styles.StatusBadge.Render("GLOBAL STATUS: OPTIMAL ●")
	if m.isPaused {
		statusText = m.styles.BadgeWarning.Render(
			fmt.Sprintf("⏸ SMART PAUSE ACTIVE (LOCKED @ SEQ #%d | OFFSET +%dms)", m.seqCounter, m.rttMillis/2),
		)
	}

	headerLeft := m.styles.BrandTitle.Render("🕸  SAHAND MATRIX ") + m.styles.TextMuted.Render("PRO // DPI ANALYZER")
	header := m.styles.HeaderBar.Width(max(110, m.width-2)).Render(
		lipgloss.JoinHorizontal(lipgloss.Center,
			headerLeft,
			strings.Repeat(" ", max(4, 52-lipgloss.Width(headerLeft))),
			statusText,
			"   [SPACE] Sync-Pause  [Q] Quit",
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
	navRows = append(navRows, m.styles.TextMuted.Render("System Status: OK"))
	sidebar := m.styles.Sidebar.Height(28).Render(strings.Join(navRows, "\n"))

	// 3. Center 6-Checkpoint Synchronized Grid (2 rows x 3 columns)
	cpTitles := map[models.CheckpointID]string{
		models.CP1_RemoteEdgeIngress:   "CP1: Edge Raw Ingress (Remote)",
		models.CP2_RemoteDecrypted:     "CP2: Decrypted Core (Remote)",
		models.CP3_InternationalFlight: "CP3: Int'l Transit (In-Flight)",
		models.CP4_IranInternalIngress: "CP4: Internal Ingress (Iran)",
		models.CP5_IranEgressEdge:      "CP5: Egress Edge (Iran DPI)",
		models.CP6_IranAppOutput:       "CP6: App Output (Iran Local)",
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
		return cardStyle.Width(32).Height(7).Render(strings.Join(lines, "\n"))
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

	// 4. Bottom 4 KPI Summary Cards (Matching Netview Pro Layout)
	kpi1 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("BANDWIDTH") + "\n" +
			m.styles.KPIValue.Render("14.5 Gbps") + "\n" +
			m.styles.BadgeOptimal.Render("+1.2% Synced"),
	)
	kpi2 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("LATENCY / OFFSET") + "\n" +
			m.styles.KPIValue.Render(fmt.Sprintf("%d ms (Δ +%dms)", m.rttMillis, m.rttMillis/2)) + "\n" +
			m.styles.BadgeOptimal.Render("RTT/2 Locked"),
	)
	kpi3 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("ACTIVE CHECKPOINTS") + "\n" +
			m.styles.KPIValue.Render("6 / 6 Nodes") + "\n" +
			m.styles.CyanText.Render("━━━━━━━━━━━━"),
	)
	kpi4 := m.styles.KPICard.Render(
		m.styles.KPILabel.Render("DPI LEAK RISK") + "\n" +
			m.styles.BadgeOptimal.Render("0.01% OPTIMAL") + "\n" +
			m.styles.TextMuted.Render("SNI & Entropy Clean"),
	)

	kpiRow := lipgloss.JoinHorizontal(lipgloss.Top, kpi1, " ", kpi2, " ", kpi3, " ", kpi4)
	centerColumn := lipgloss.JoinVertical(lipgloss.Left, row1, "", row2, "", kpiRow)

	// 5. Right Rail (CRITICAL INCIDENTS & TRAFFIC BY PROTOCOL)
	incLines := []string{m.styles.CardTitle.Render("CRITICAL INCIDENTS"), ""}
	for _, inc := range m.incidents {
		incLines = append(incLines, inc, m.styles.TextMuted.Render("  Synced Logical Stream"))
	}
	incidentsCard := m.styles.Card.Width(32).Height(11).Render(strings.Join(incLines, "\n"))

	protoLines := []string{
		m.styles.CardTitle.Render("TRAFFIC BY PROTOCOL"),
		"",
		m.styles.CyanText.Render("REALITY ") + "━━━━━━━━━━━━ 68%",
		m.styles.PurpleText.Render("VLESS   ") + "━━━━━━       22%",
		m.styles.CyanText.Render("TLS 1.3 ") + "━━━           8%",
		m.styles.BadgeOptimal.Render("UDP/DNS ") + "━             2%",
	}
	protoCard := m.styles.Card.Width(32).Height(10).Render(strings.Join(protoLines, "\n"))
	rightColumn := lipgloss.JoinVertical(lipgloss.Left, incidentsCard, "", protoCard)

	// Combine Main Body
	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, "  ", centerColumn, "  ", rightColumn)
	return lipgloss.JoinVertical(lipgloss.Left, header, body)
}
