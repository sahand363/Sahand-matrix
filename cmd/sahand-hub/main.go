package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"sahand-matrix/internal/ui"
)

func main() {
	p := tea.NewProgram(
		ui.NewMatrixModel(),
		tea.WithAltScreen(),
	)

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting Sahand Traffic Matrix: %v\n", err)
		os.Exit(1)
	}
}
