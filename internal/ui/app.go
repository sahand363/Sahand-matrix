package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"sahand-matrix/internal/hub"
	"sahand-matrix/internal/tunnels"
	"sahand-matrix/pkg/models"
)

type tickMsg time.Time

type burstResultMsg struct {
	report    hub.PingBurstReport
	targetSeq uint64
}

type MatrixModel struct {
	styles         AppStyles
	syncEngine     *hub.SyncEngine
	width          int
	height         int
	tunnelIdx      int
	tunnelList     []tunnels.TunnelInfo
	isCalibrating  bool
	isPaused       bool
	showAgentModal bool
	lastBurst      hub.PingBurstReport
	lockedSeq      uint64
	seqCounter     uint64
	snapshots      []models.PacketEvent
}

func NewMatrixModel() MatrixModel {
	engine := hub.NewSyncEngine(128)
	initialReport := engine.Measure5PingBurst("simulate", 48.0)
	tList := tunnels.AvailableTunnels()

	m := MatrixModel{
		styles:     DefaultStyles(),
		syncEngine: engine,
		tunnelIdx:  0,
		tunnelList: tList,
		lastBurst:  initialReport,
		seqCounter: 10420,
	}
	m.stepSimulation()
	return m
}

func (m MatrixModel) Init() tea.Cmd {
	return tickCmd()
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Millisecond*650, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m MatrixModel) run5PingCalibrationCmd(seq uint64) tea.Cmd {
	return func() tea.Msg {
		report := m.syncEngine.Measure5PingBurst("simulate", 48.0)
		return burstResultMsg{report: report, targetSeq: seq}
	}
}

func (m *MatrixModel) stepSimulation() {
	m.seqCounter++
	activeTunnel := m.tunnelList[m.tunnelIdx].ID
	m.snapshots = tunnels.Build6CheckpointSnapshot(activeTunnel, m.seqCounter, m.lastBurst.OneWayDelay)
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
		case "t", "T":
			m.tunnelIdx = (m.tunnelIdx + 1) % len(m.tunnelList)
			m.stepSimulation()
		case " ":
			if m.isPaused {
				m.isPaused = false
				m.isCalibrating = false
			} else if !m.isCalibrating {
				m.isCalibrating = true
				return m, m.run5PingCalibrationCmd(m.seqCounter)
			}
		}

	case burstResultMsg:
		m.isCalibrating = false
		m.isPaused = true
		m.lastBurst = msg.report
		m.lockedSeq = msg.targetSeq

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
	tInfo := m.tunnelList[m.tunnelIdx]

	statusText := m.styles.StatusBadge.Render("● LIVE (6/6 SYNCED)")
	if m.isCalibrating {
		statusText = m.styles.BadgeWarning.Render("⚡ 5-PING CALIBRATING...")
	} else if m.isPaused {
		statusText = m.styles.BadgeWarning.Render(
			fmt.Sprintf("⏸ PAUSED @ #%d (+%.1fms OFFSET)", m.lockedSeq, offsetMs),
		)
	}

	header := m.styles.HeaderBar.Width(max(118, m.width-2)).Render(
		fmt.Sprintf("🕸 SAHAND MATRIX  |  Tunnel: %s  |  %s  |  [T] Switch Tunnel  [SPACE] 5-Ping Pause  [D] Agent  [Q] Quit",
			m.styles.CyanText.Bold(true).Render(tInfo.Name), statusText),
	)

	if m.showAgentModal {
		modalLines := []string{
			m.styles.CardTitle.Render("🚀 DEPLOY & VERIFY LIGHTWEIGHT SAHAND-AGENT"),
			"",
			"1. Fast Ubuntu Setup Menu:",
			"   bash <(curl -Ls https://raw.githubusercontent.com/sahand363/sahand-matrix/main/scripts/setup.sh)",
			"",
			fmt.Sprintf("2. 5-Ping Calibration: [%.1f, %.1f, %.1f, %.1f, %.1f] ms -> Avg: %.1fms (Offset +%.1fms)",
				m.lastBurst.SamplesMs[0], m.lastBurst.SamplesMs[1], m.lastBurst.SamplesMs[2],
				m.lastBurst.SamplesMs[3], m.lastBurst.SamplesMs[4], avgMs, offsetMs),
			"",
			m.styles.BadgeOptimal.Render("Press [D] to return to the 6-Checkpoint Live Matrix"),
		}
		return lipgloss.JoinVertical(lipgloss.Left, header, m.styles.CardActive.Width(96).Height(12).Render(strings.Join(modalLines, "\n")))
	}

	renderBox := func(ev models.PacketEvent) string {
		border := m.styles.Card
		badge := m.styles.BadgeOptimal.Render(fmt.Sprintf("STEALTH %d%%", ev.DPI.StealthScore))
		if ev.DPI.Level == models.RiskCritical {
			border = m.styles.Card.BorderForeground(ColorCrimson)
			badge = m.styles.BadgeCritical.Render(fmt.Sprintf("DANGER %d%%", ev.DPI.StealthScore))
		} else if m.isPaused {
			border = m.styles.CardActive
		}

		visTag := m.styles.BadgeWarning.Render(ev.DPIZone)
		if !ev.DPIVisible {
			visTag = m.styles.BadgeOptimal.Render(ev.DPIZone)
		} else if ev.Checkpoint == models.CP5_IranEgressEdge {
			visTag = m.styles.BadgeCritical.Render(ev.DPIZone)
		}

		rawLine := ev.RawByteLog
		if len(rawLine) > 48 {
			rawLine = rawLine[:48] + "'"
		}
		explain := ev.DPI.Explanation
		if len(explain) > 50 {
			explain = explain[:50] + "..."
		}

		lines := []string{
			m.styles.CardTitle.Render(ev.CheckpointTitle),
			visTag,
			fmt.Sprintf("Seq: #%d (+%.1fms) | %s", ev.SequenceNum, ev.OffsetMs, ev.Protocol),
			fmt.Sprintf("Entropy: %.2f/8.00 | %s", ev.DPI.ShannonEntropy, badge),
			m.styles.CyanText.Render(rawLine),
			m.styles.TextMuted.Render(explain),
		}
		return border.Width(52).Height(8).Render(strings.Join(lines, "\n"))
	}

	if len(m.snapshots) < 6 {
		return header
	}

	row1 := lipgloss.JoinHorizontal(lipgloss.Top, renderBox(m.snapshots[0]), " ", renderBox(m.snapshots[1]), " ", renderBox(m.snapshots[2]))
	row2 := lipgloss.JoinHorizontal(lipgloss.Top, renderBox(m.snapshots[3]), " ", renderBox(m.snapshots[4]), " ", renderBox(m.snapshots[5]))
	footer := m.styles.Card.Width(158).Render(
		fmt.Sprintf("Active Profile: %s — %s | 5-Ping Avg: %.1fms (Window Offset: +%.1fms)",
			tInfo.Name, tInfo.Description, avgMs, offsetMs),
	)

	return lipgloss.JoinVertical(lipgloss.Left, header, "", row1, "", row2, "", footer)
}
