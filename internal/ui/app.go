package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"sahand-matrix/internal/agent"
	"sahand-matrix/internal/analyzer"
	"sahand-matrix/internal/hub"
	"sahand-matrix/pkg/models"
)

type tickMsg time.Time

type MatrixModel struct {
	styles     AppStyles
	sniffer    *agent.RealSniffer
	syncEngine *hub.SyncEngine
	guides     []models.CheckpointGuide
	lastPing   hub.PingBurstReport
	isPaused   bool
	width      int
}

func NewMatrixModel() MatrixModel {
	sniffer := agent.NewRealSniffer("iran", "local-s1", "", 8443)
	go func() { _ = sniffer.RunCaptureLoop() }()

	return MatrixModel{
		styles:     DefaultStyles(),
		sniffer:    sniffer,
		syncEngine: hub.NewSyncEngine(128),
		guides:     analyzer.AllCheckpointGuides(),
	}
}

func (m MatrixModel) Init() tea.Cmd {
	return tea.Tick(time.Millisecond*700, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m MatrixModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "s", "S":
			if m.sniffer.IsRunning() {
				m.sniffer.Stop()
			} else {
				m.sniffer.Start()
			}
		case " ":
			if !m.isPaused {
				m.lastPing = m.syncEngine.GetOrMeasure5Pings("127.0.0.1:9444", "", false)
				m.isPaused = true
			} else {
				m.isPaused = false
			}
		}
	case tickMsg:
		return m, tea.Tick(time.Millisecond*700, func(t time.Time) tea.Msg { return tickMsg(t) })
	}
	return m, nil
}

func (m MatrixModel) View() string {
	stateBadge := m.styles.BadgeWarning.Render("● STOPPED (Press [S] to Start Capture)")
	if m.isPaused {
		stateBadge = m.styles.BadgeWarning.Render(fmt.Sprintf("⏸ PAUSED (5-Ping Avg: %.1fms | Offset: +%.1fms)", m.lastPing.AverageMs, m.lastPing.OffsetMs))
	} else if m.sniffer.IsRunning() {
		stateBadge = m.styles.BadgeOptimal.Render("● CAPTURING REAL PACKETS")
	}

	header := m.styles.HeaderBar.Width(max(110, m.width-2)).Render(
		fmt.Sprintf("🕸 SAHAND MATRIX (REAL PACKET LAB)  |  %s  |  [S] Start/Stop  [SPACE] 5-Ping Pause  [Q] Quit", stateBadge),
	)

	snap := m.sniffer.GetSnapshot()
	var rows []string
	for _, g := range m.guides {
		evs := snap[g.ID]
		rawLine := "Waiting for real packets (Press [S] to Start)..."
		metaLine := fmt.Sprintf("What you see: %s | Good: %s", g.WhatYouSee, g.GoodForDPI)
		border := m.styles.Card

		if len(evs) > 0 {
			last := evs[len(evs)-1]
			rawLine = fmt.Sprintf("[#%d %s->%s] %s", last.SequenceNum, last.SrcAddr, last.DstAddr, last.RawByteLog)
			metaLine = fmt.Sprintf("Proto: %s | H(X): %.2f/8.00 | Stealth: %d%% | %s",
				last.Protocol, last.DPI.ShannonEntropy, last.DPI.StealthScore, last.DPI.Explanation)
			if last.DPI.Level == models.RiskCritical {
				border = m.styles.Card.BorderForeground(ColorCrimson)
			}
		}

		content := fmt.Sprintf("%s  [%s]\n%s\n%s",
			m.styles.CyanText.Bold(true).Render(g.Title),
			g.DPIZone,
			rawLine,
			m.styles.TextMuted.Render(metaLine),
		)
		rows = append(rows, border.Width(max(110, m.width-4)).Render(content))
	}

	return lipgloss.JoinVertical(lipgloss.Left, append([]string{header}, rows...)...)
}
