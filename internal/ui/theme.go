package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Core Palette (Derived from Netview Pro dark UI reference)
	ColorBgDark      = lipgloss.Color("#0B0F19") // Deep Obsidian background
	ColorCardBg      = lipgloss.Color("#111827") // Dark Slate card surface
	ColorBorder      = lipgloss.Color("#1E293B") // Subtle panel border
	ColorBorderFocus = lipgloss.Color("#38BDF8") // Active Neon Cyan border

	ColorCyan        = lipgloss.Color("#38BDF8") // Remote / Inbound stream accent
	ColorPurple      = lipgloss.Color("#A855F7") // Iran / Transit stream accent
	ColorEmerald     = lipgloss.Color("#10B981") // Optimal / Safe status
	ColorAmber       = lipgloss.Color("#F59E0B") // Warning / High Entropy alert
	ColorCrimson     = lipgloss.Color("#EF4444") // Critical DPI trigger

	ColorTextPrimary = lipgloss.Color("#F8FAFC") // Crisp white/slate text
	ColorTextMuted   = lipgloss.Color("#64748B") // Muted secondary labels
)

// AppStyles holds all pre-computed Lipgloss styles for the TUI dashboard.
type AppStyles struct {
	HeaderBar     lipgloss.Style
	BrandTitle    lipgloss.Style
	StatusBadge   lipgloss.Style
	Sidebar       lipgloss.Style
	NavActive     lipgloss.Style
	NavInactive   lipgloss.Style
	Card          lipgloss.Style
	CardActive    lipgloss.Style
	CardTitle     lipgloss.Style
	KPICard       lipgloss.Style
	KPIValue      lipgloss.Style
	KPILabel      lipgloss.Style
	TextMuted     lipgloss.Style
	BadgeOptimal  lipgloss.Style
	BadgeWarning  lipgloss.Style
	BadgeCritical lipgloss.Style
	CyanText      lipgloss.Style
	PurpleText    lipgloss.Style
}

func DefaultStyles() AppStyles {
	baseCard := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(ColorBorder).
		Background(ColorCardBg).
		Padding(0, 1)

	return AppStyles{
		HeaderBar: lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(ColorBorder).
			Padding(0, 2),

		BrandTitle: lipgloss.NewStyle().
			Foreground(ColorTextPrimary).
			Bold(true),

		StatusBadge: lipgloss.NewStyle().
			Foreground(ColorEmerald).
			Bold(true),

		Sidebar: lipgloss.NewStyle().
			Width(22).
			BorderStyle(lipgloss.NormalBorder()).
			BorderRight(true).
			BorderForeground(ColorBorder).
			Padding(1, 1),

		NavActive: lipgloss.NewStyle().
			Foreground(ColorCyan).
			Bold(true).
			Padding(0, 1),

		NavInactive: lipgloss.NewStyle().
			Foreground(ColorTextMuted).
			Padding(0, 1),

		Card: baseCard,

		CardActive: baseCard.
			BorderForeground(ColorBorderFocus),

		CardTitle: lipgloss.NewStyle().
			Foreground(ColorTextPrimary).
			Bold(true),

		KPICard: baseCard.
			Width(24).
			Height(5),

		KPIValue: lipgloss.NewStyle().
			Foreground(ColorTextPrimary).
			Bold(true),

		KPILabel: lipgloss.NewStyle().
			Foreground(ColorTextMuted),

		TextMuted: lipgloss.NewStyle().
			Foreground(ColorTextMuted),

		BadgeOptimal: lipgloss.NewStyle().
			Foreground(ColorEmerald).
			Bold(true),

		BadgeWarning: lipgloss.NewStyle().
			Foreground(ColorAmber).
			Bold(true),

		BadgeCritical: lipgloss.NewStyle().
			Foreground(ColorCrimson).
			Bold(true),

		CyanText: lipgloss.NewStyle().
			Foreground(ColorCyan),

		PurpleText: lipgloss.NewStyle().
			Foreground(ColorPurple),
	}
}
